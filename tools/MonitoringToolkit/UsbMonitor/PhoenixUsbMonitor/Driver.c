#include "Driver.h"

static PPHOENIX_PACKET_QUEUE g_SharedQueue = NULL;

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;
    NTSTATUS status;

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[PhoenixUsbMonitor] DriverEntry starting...\n"));

    WDF_DRIVER_CONFIG_INIT(&config, PhoenixEvtDeviceAdd);
    config.EvtDriverUnload = PhoenixEvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, &driver);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[PhoenixUsbMonitor] WdfDriverCreate failed: 0x%08X\n", status));
        return status;
    }

    // Initialize Shared Bounded Queue
    status = PhoenixQueueInitialize(&g_SharedQueue, driver);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[PhoenixUsbMonitor] PhoenixQueueInitialize failed: 0x%08X\n", status));
        return status;
    }

    // Create Control Device for User Mode IOCTL communication
    status = ControlCreateDevice(driver, g_SharedQueue);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[PhoenixUsbMonitor] ControlCreateDevice failed: 0x%08X\n", status));
        // Continue even if control device fails, but log error
    }

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[PhoenixUsbMonitor] Driver initialized successfully (v1.0.0)\n"));
    return STATUS_SUCCESS;
}

NTSTATUS PhoenixEvtDeviceAdd(
    WDFDRIVER Driver,
    PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[PhoenixUsbMonitor] EvtDeviceAdd: Attaching as UpperFilter to USB device\n"));

    // Attach as transparent UpperFilter on target device
    return FilterCreateDevice(DeviceInit, g_SharedQueue);
}

VOID PhoenixEvtDriverUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[PhoenixUsbMonitor] Driver unloading...\n"));

    if (g_SharedQueue != NULL) {
        PhoenixQueueDestroy(g_SharedQueue);
        g_SharedQueue = NULL;
    }
}
