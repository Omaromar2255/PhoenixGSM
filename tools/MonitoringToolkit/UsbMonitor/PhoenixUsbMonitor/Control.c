#include "Control.h"

NTSTATUS ControlCreateDevice(WDFDRIVER Driver, PPHOENIX_PACKET_QUEUE SharedQueue)
{
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDEVICE controlDevice;
    PCONTROL_DEVICE_CONTEXT context;
    WDF_IO_QUEUE_CONFIG queueConfig;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;
    NTSTATUS status;

    DECLARE_CONST_UNICODE_STRING(sddlString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)");

    deviceInit = WdfControlDeviceInitAllocate(Driver, &sddlString);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&devName, PHOENIX_DEVICE_NAME_KERNEL);
    status = WdfDeviceInitAssignName(deviceInit, &devName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, CONTROL_DEVICE_CONTEXT);

    status = WdfDeviceCreate(&deviceInit, &attributes, &controlDevice);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    context = GetControlDeviceContext(controlDevice);
    context->Queue = SharedQueue;

    // Create Symbolic Link for User-Mode access (\\.\PhoenixUsbMonitor)
    RtlInitUnicodeString(&symLink, PHOENIX_SYMBOLIC_NAME_KERNEL);
    status = WdfDeviceCreateSymbolicLink(controlDevice, &symLink);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Configure I/O Queue for User-Mode IOCTLs
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = ControlEvtIoDeviceControl;

    status = WdfIoQueueCreate(controlDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdfControlFinishInitializing(controlDevice);
    return STATUS_SUCCESS;
}

VOID ControlEvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode)
{
    PCONTROL_DEVICE_CONTEXT context;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesReturned = 0;
    PVOID outputBuf = NULL;

    UNREFERENCED_PARAMETER(InputBufferLength);

    context = GetControlDeviceContext(WdfIoQueueGetDevice(Queue));

    switch (IoControlCode)
    {
    case IOCTL_PHOENIX_GET_STATS:
        if (OutputBufferLength < sizeof(PHOENIX_DRIVER_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PHOENIX_DRIVER_STATS), &outputBuf, NULL);
        if (NT_SUCCESS(status) && outputBuf != NULL) {
            PhoenixQueueGetStats(context->Queue, (PPHOENIX_DRIVER_STATS)outputBuf);
            bytesReturned = sizeof(PHOENIX_DRIVER_STATS);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_PHOENIX_GET_PACKET:
        if (OutputBufferLength < sizeof(PHOENIX_USB_PACKET)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PHOENIX_USB_PACKET), &outputBuf, NULL);
        if (NT_SUCCESS(status) && outputBuf != NULL) {
            if (PhoenixQueueDequeue(context->Queue, (PPHOENIX_USB_PACKET)outputBuf)) {
                bytesReturned = sizeof(PHOENIX_USB_PACKET);
                status = STATUS_SUCCESS;
            } else {
                bytesReturned = 0;
                status = STATUS_NO_MORE_ENTRIES; // Empty queue
            }
        }
        break;

    case IOCTL_PHOENIX_CLEAR_BUFFER:
        PhoenixQueueClear(context->Queue);
        bytesReturned = 0;
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
