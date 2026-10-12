#include "Filter.h"

#define PHOENIX_CTX_TAG 'pCxP'

NTSTATUS FilterCreateDevice(PWDFDEVICE_INIT DeviceInit, PPHOENIX_PACKET_QUEUE SharedQueue)
{
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES requestAttributes;
    WDFDEVICE device;
    PFILTER_DEVICE_CONTEXT context;
    WDF_IO_QUEUE_CONFIG queueConfig;
    NTSTATUS status;

    WdfFdoInitSetFilter(DeviceInit);

    // Intercept every request in the originating thread so METHOD_NEITHER
    // user buffers (used by many vendor serial/modem drivers) can be captured.
    WdfDeviceInitSetIoInCallerContextCallback(DeviceInit, FilterEvtIoInCallerContext);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&requestAttributes, FILTER_REQUEST_CONTEXT);
    WdfDeviceInitSetRequestAttributes(DeviceInit, &requestAttributes);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, FILTER_DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    context = GetFilterDeviceContext(device);
    context->WdfDevice = device;
    context->Target = WdfDeviceGetIoTarget(device);
    context->Queue = SharedQueue;

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[PhoenixUsbMonitor] Filter attached. DO Flags=0x%08X (BUFFERED=%d DIRECT=%d)\n",
        WdfDeviceWdmGetDeviceObject(device)->Flags,
        (WdfDeviceWdmGetDeviceObject(device)->Flags & DO_BUFFERED_IO) ? 1 : 0,
        (WdfDeviceWdmGetDeviceObject(device)->Flags & DO_DIRECT_IO) ? 1 : 0));

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoRead = FilterEvtIoRead;
    queueConfig.EvtIoWrite = FilterEvtIoWrite;
    queueConfig.EvtIoDeviceControl = FilterEvtIoDeviceControl;
    queueConfig.EvtIoInternalDeviceControl = FilterEvtIoInternalDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    return status;
}

// Returns a kernel-safe system buffer for buffered / direct I/O, or NULL for METHOD_NEITHER.
static PVOID FilterGetSystemIrpBuffer(WDFDEVICE Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);

    if (Irp->AssociatedIrp.SystemBuffer != NULL) {
        return Irp->AssociatedIrp.SystemBuffer;
    }
    if (Irp->MdlAddress != NULL) {
        return MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
    }
    return NULL;
}

static VOID FilterEnqueueSerialPacket(PFILTER_DEVICE_CONTEXT Ctx, ULONG Direction, PVOID Buffer, ULONG Length)
{
    PHOENIX_USB_PACKET pkt;
    RtlZeroMemory(&pkt, sizeof(PHOENIX_USB_PACKET));
    KeQuerySystemTime(&pkt.Timestamp);
    pkt.Direction = Direction;
    pkt.EndpointAddress = (Direction == PHOENIX_DIR_OUT) ? 0x02 : 0x81; // Serial/modem UpperFilter marker
    pkt.TransferType = 4; // Serial transfer (distinct from USB Bulk 2)
    pkt.ActualLength = Length;
    pkt.CapturedLength = (Length > PHOENIX_MAX_PAYLOAD_CAPTURE) ? PHOENIX_MAX_PAYLOAD_CAPTURE : Length;
    RtlCopyMemory(pkt.Data, Buffer, pkt.CapturedLength);
    PhoenixQueueEnqueue(Ctx->Queue, &pkt);
}

VOID FilterEvtIoInCallerContext(WDFDEVICE Device, WDFREQUEST Request)
{
    PFILTER_DEVICE_CONTEXT context = GetFilterDeviceContext(Device);
    WDF_REQUEST_PARAMETERS params;
    NTSTATUS status;

    WDF_REQUEST_PARAMETERS_INIT(&params);
    WdfRequestGetParameters(Request, &params);

    if (params.Type == WdfRequestTypeWrite && params.Parameters.Write.Length > 0) {
        // Capture outgoing AT / modem payload synchronously in the caller's thread.
        PIRP irp = WdfRequestWdmGetIrp(Request);
        ULONG len = (ULONG)params.Parameters.Write.Length;
        __try {
            PVOID buf = NULL;
            size_t inLen = 0;
            if (NT_SUCCESS(WdfRequestRetrieveInputBuffer(Request, 1, &buf, &inLen))) {
                if (inLen > 0) len = (ULONG)inLen;
            }
            if (buf == NULL) {
                buf = FilterGetSystemIrpBuffer(Device, irp);
            }
            if (buf == NULL && irp->UserBuffer != NULL) {
                buf = irp->UserBuffer;
                if (irp->RequestorMode == UserMode) {
                    ProbeForRead(buf, (len > PHOENIX_MAX_PAYLOAD_CAPTURE) ? PHOENIX_MAX_PAYLOAD_CAPTURE : len, 1);
                }
            }
            if (buf != NULL && len > 0) {
                FilterEnqueueSerialPacket(context, PHOENIX_DIR_OUT, buf, len);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Never break the I/O path because of a capture fault
        }
    }
    else if (params.Type == WdfRequestTypeRead && params.Parameters.Read.Length > 0) {
        PIRP irp = WdfRequestWdmGetIrp(Request);
        PFILTER_REQUEST_CONTEXT reqCtx = GetFilterRequestContext(Request);
        reqCtx->LockedReadBuffer = NULL;

        if (FilterGetSystemIrpBuffer(Device, irp) == NULL && irp->UserBuffer != NULL && irp->RequestorMode == UserMode) {
            // METHOD_NEITHER read: lock the user buffer now so completion can read it safely.
            WDFMEMORY mem;
            if (NT_SUCCESS(WdfRequestProbeAndLockUserBufferForWrite(Request, irp->UserBuffer, params.Parameters.Read.Length, &mem))) {
                reqCtx->LockedReadBuffer = mem;
            }
        }
    }

    status = WdfDeviceEnqueueRequest(Device, Request);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
    }
}

VOID FilterEvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode)
{
    PFILTER_DEVICE_CONTEXT context = GetFilterDeviceContext(WdfIoQueueGetDevice(Queue));
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(IoControlCode);

    // Transparent pass-through of all DeviceIoControl (e.g. IOCTL_SERIAL_*)
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(Request, context->Target, &sendOptions)) {
        WdfRequestComplete(Request, WdfRequestGetStatus(Request));
    }
}

VOID FilterEvtIoWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
    PFILTER_DEVICE_CONTEXT context = GetFilterDeviceContext(WdfIoQueueGetDevice(Queue));
    UNREFERENCED_PARAMETER(Length);

    // Payload already captured in FilterEvtIoInCallerContext; just forward.
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(Request, context->Target, &sendOptions)) {
        WdfRequestComplete(Request, WdfRequestGetStatus(Request));
    }
}

VOID FilterEvtIoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
    PFILTER_DEVICE_CONTEXT context = GetFilterDeviceContext(WdfIoQueueGetDevice(Queue));
    UNREFERENCED_PARAMETER(Length);

    // When setting a completion routine, format the request using CurrentType
    WdfRequestFormatRequestUsingCurrentType(Request);
    WdfRequestSetCompletionRoutine(Request, FilterEvtReadComplete, context);
    if (!WdfRequestSend(Request, context->Target, WDF_NO_SEND_OPTIONS)) {
        WdfRequestComplete(Request, WdfRequestGetStatus(Request));
    }
}

VOID FilterEvtReadComplete(WDFREQUEST Request, WDFIOTARGET Target, PWDF_REQUEST_COMPLETION_PARAMS Params, WDFCONTEXT Context)
{
    PFILTER_DEVICE_CONTEXT devCtx = (PFILTER_DEVICE_CONTEXT)Context;
    UNREFERENCED_PARAMETER(Target);

    __try {
        if (NT_SUCCESS(Params->IoStatus.Status) && Params->IoStatus.Information > 0 && devCtx != NULL) {
            PIRP irp = WdfRequestWdmGetIrp(Request);
            PVOID buffer = NULL;
            size_t outLen = 0;

            if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, 1, &buffer, &outLen))) {
                // Buffer successfully retrieved via KMDF
            }
            if (buffer == NULL) {
                buffer = FilterGetSystemIrpBuffer(devCtx->WdfDevice, irp);
            }
            if (buffer == NULL) {
                PFILTER_REQUEST_CONTEXT reqCtx = GetFilterRequestContext(Request);
                if (reqCtx->LockedReadBuffer != NULL) {
                    size_t sz = 0;
                    buffer = WdfMemoryGetBuffer(reqCtx->LockedReadBuffer, &sz);
                }
            }

            if (buffer != NULL) {
                FilterEnqueueSerialPacket(devCtx, PHOENIX_DIR_IN, buffer, (ULONG)Params->IoStatus.Information);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Guard against any memory fault
    }

    // Complete with accurate information bytes
    WdfRequestCompleteWithInformation(Request, Params->IoStatus.Status, Params->IoStatus.Information);
}

VOID FilterEvtIoInternalDeviceControlComplete(WDFREQUEST Request, WDFIOTARGET Target, PWDF_REQUEST_COMPLETION_PARAMS Params, WDFCONTEXT Context)
{
    PCOMPLETION_CTX cmpCtx = (PCOMPLETION_CTX)Context;
    UNREFERENCED_PARAMETER(Target);

    if (cmpCtx != NULL) {
        __try {
            PURB urb = cmpCtx->Urb;
            PFILTER_DEVICE_CONTEXT devCtx = cmpCtx->DevCtx;
            UCHAR ep = cmpCtx->EndpointAddress;
            USHORT func = cmpCtx->Function;

            if (NT_SUCCESS(Params->IoStatus.Status) && urb != NULL && devCtx != NULL) {
                PVOID buffer = NULL;
                ULONG len = 0;

                if (func == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER || func == 0x0037) {
                    buffer = urb->UrbBulkOrInterruptTransfer.TransferBuffer;
                    if (!buffer && urb->UrbBulkOrInterruptTransfer.TransferBufferMDL) {
                        buffer = MmGetSystemAddressForMdlSafe(urb->UrbBulkOrInterruptTransfer.TransferBufferMDL, NormalPagePriority);
                    }
                    len = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
                } else if (func == URB_FUNCTION_CONTROL_TRANSFER || func == 0x0032) {
                    buffer = urb->UrbControlTransfer.TransferBuffer;
                    if (!buffer && urb->UrbControlTransfer.TransferBufferMDL) {
                        buffer = MmGetSystemAddressForMdlSafe(urb->UrbControlTransfer.TransferBufferMDL, NormalPagePriority);
                    }
                    len = urb->UrbControlTransfer.TransferBufferLength;
                } else if (func >= 0x0017 && func <= 0x0020) {
                    struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST* req = (struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST*)urb;
                    buffer = req->TransferBuffer;
                    if (!buffer && req->TransferBufferMDL) {
                        buffer = MmGetSystemAddressForMdlSafe(req->TransferBufferMDL, NormalPagePriority);
                    }
                    len = req->TransferBufferLength;
                }

                if (buffer != NULL && len > 0) {
                    PHOENIX_USB_PACKET pkt;
                    RtlZeroMemory(&pkt, sizeof(PHOENIX_USB_PACKET));
                    KeQuerySystemTime(&pkt.Timestamp);
                    pkt.Direction = PHOENIX_DIR_IN;
                    pkt.EndpointAddress = (ep != 0) ? ep : ((func == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER || func == 0x0037) ? 0x81 : 0x80);
                    pkt.TransferType = (func == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER || func == 0x0037) ? 2 : 0;
                    pkt.ActualLength = len;
                    pkt.CapturedLength = (len > PHOENIX_MAX_PAYLOAD_CAPTURE) ? PHOENIX_MAX_PAYLOAD_CAPTURE : len;
                    RtlCopyMemory(pkt.Data, buffer, pkt.CapturedLength);
                    PhoenixQueueEnqueue(devCtx->Queue, &pkt);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Guard against any memory fault in completion
        }

        ExFreePoolWithTag(cmpCtx, PHOENIX_CTX_TAG);
    }

    // Complete with accurate information bytes
    WdfRequestCompleteWithInformation(Request, Params->IoStatus.Status, Params->IoStatus.Information);
}

VOID FilterEvtIoInternalDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    PFILTER_DEVICE_CONTEXT context = GetFilterDeviceContext(WdfIoQueueGetDevice(Queue));
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (IoControlCode == IOCTL_INTERNAL_USB_SUBMIT_URB) {
        PIRP irp = WdfRequestWdmGetIrp(Request);
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);
        PURB urb = (PURB)irpSp->Parameters.Others.Argument1;
        if (urb != NULL) {
            __try {
                USHORT func = urb->UrbHeader.Function;
                BOOLEAN isControl = (func == URB_FUNCTION_CONTROL_TRANSFER || 
                                     func == 0x0032 || 
                                     (func >= 0x0017 && func <= 0x0020));
                BOOLEAN isBulk = (func == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER || 
                                  func == 0x0037);

                if (isControl || isBulk) {
                    UCHAR epAddr = 0;
                    if (isBulk && urb->UrbBulkOrInterruptTransfer.PipeHandle != NULL) {
                        PUSBD_PIPE_INFORMATION pipe = (PUSBD_PIPE_INFORMATION)urb->UrbBulkOrInterruptTransfer.PipeHandle;
                        if (MmIsAddressValid(pipe)) {
                            epAddr = pipe->EndpointAddress;
                        }
                    }

                    if (isControl) {
                        PHOENIX_USB_PACKET setupPkt;
                        RtlZeroMemory(&setupPkt, sizeof(PHOENIX_USB_PACKET));
                        KeQuerySystemTime(&setupPkt.Timestamp);
                        setupPkt.Direction = PHOENIX_DIR_OUT;
                        setupPkt.EndpointAddress = 0x00; // Control EP 0
                        setupPkt.TransferType = 0; // Control
                        setupPkt.ActualLength = 8;
                        setupPkt.CapturedLength = 8;

                        if (func == URB_FUNCTION_CONTROL_TRANSFER) {
                            struct _URB_CONTROL_TRANSFER* ctrlUrb = (struct _URB_CONTROL_TRANSFER*)urb;
                            RtlCopyMemory(setupPkt.Data, ctrlUrb->SetupPacket, 8);
                        } else if (func >= 0x0017 && func <= 0x0020) {
                            struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST* req = (struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST*)urb;
                            setupPkt.Data[0] = req->RequestTypeReservedBits;
                            setupPkt.Data[1] = req->Request;
                            setupPkt.Data[2] = (UCHAR)(req->Value & 0xFF);
                            setupPkt.Data[3] = (UCHAR)((req->Value >> 8) & 0xFF);
                            setupPkt.Data[4] = (UCHAR)(req->Index & 0xFF);
                            setupPkt.Data[5] = (UCHAR)((req->Index >> 8) & 0xFF);
                            setupPkt.Data[6] = (UCHAR)(req->TransferBufferLength & 0xFF);
                            setupPkt.Data[7] = (UCHAR)((req->TransferBufferLength >> 8) & 0xFF);
                        }
                        PhoenixQueueEnqueue(context->Queue, &setupPkt);
                    }

                    BOOLEAN isDirectionIn = FALSE;
                    if (isBulk) {
                        isDirectionIn = (urb->UrbBulkOrInterruptTransfer.TransferFlags & USBD_TRANSFER_DIRECTION_IN) != 0;
                        if (epAddr == 0) {
                            epAddr = isDirectionIn ? 0x81 : 0x02;
                        }
                    } else {
                        isDirectionIn = (urb->UrbControlTransfer.TransferFlags & USBD_TRANSFER_DIRECTION_IN) != 0;
                        if (epAddr == 0) {
                            epAddr = isDirectionIn ? 0x80 : 0x00;
                        }
                    }

                    if (!isDirectionIn) {
                        // OUT Transfer (Host -> Target)
                        PVOID buffer = NULL;
                        ULONG len = 0;

                        if (isBulk) {
                            buffer = urb->UrbBulkOrInterruptTransfer.TransferBuffer;
                            if (!buffer && urb->UrbBulkOrInterruptTransfer.TransferBufferMDL) {
                                buffer = MmGetSystemAddressForMdlSafe(urb->UrbBulkOrInterruptTransfer.TransferBufferMDL, NormalPagePriority);
                            }
                            len = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
                        } else if (func == URB_FUNCTION_CONTROL_TRANSFER || func == 0x0032) {
                            buffer = urb->UrbControlTransfer.TransferBuffer;
                            if (!buffer && urb->UrbControlTransfer.TransferBufferMDL) {
                                buffer = MmGetSystemAddressForMdlSafe(urb->UrbControlTransfer.TransferBufferMDL, NormalPagePriority);
                            }
                            len = urb->UrbControlTransfer.TransferBufferLength;
                        } else if (func >= 0x0017 && func <= 0x0020) {
                            struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST* req = (struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST*)urb;
                            buffer = req->TransferBuffer;
                            if (!buffer && req->TransferBufferMDL) {
                                buffer = MmGetSystemAddressForMdlSafe(req->TransferBufferMDL, NormalPagePriority);
                            }
                            len = req->TransferBufferLength;
                        }

                        if (buffer != NULL && len > 0) {
                            PHOENIX_USB_PACKET pkt;
                            RtlZeroMemory(&pkt, sizeof(PHOENIX_USB_PACKET));
                            KeQuerySystemTime(&pkt.Timestamp);
                            pkt.Direction = PHOENIX_DIR_OUT;
                            pkt.EndpointAddress = epAddr;
                            pkt.TransferType = isBulk ? 2 : 0;
                            pkt.ActualLength = len;
                            pkt.CapturedLength = (len > PHOENIX_MAX_PAYLOAD_CAPTURE) ? PHOENIX_MAX_PAYLOAD_CAPTURE : len;
                            RtlCopyMemory(pkt.Data, buffer, pkt.CapturedLength);
                            PhoenixQueueEnqueue(context->Queue, &pkt);
                        }

                        // Forward without formatting when using SEND_AND_FORGET
                        WDF_REQUEST_SEND_OPTIONS sendOptions;
                        WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
                        if (!WdfRequestSend(Request, context->Target, &sendOptions)) {
                            WdfRequestComplete(Request, WdfRequestGetStatus(Request));
                        }
                        return;
                    } else {
                        // IN Transfer (Target -> Host)
                        PCOMPLETION_CTX cmpCtx = (PCOMPLETION_CTX)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(COMPLETION_CTX), PHOENIX_CTX_TAG);
                        if (cmpCtx != NULL) {
                            cmpCtx->DevCtx = context;
                            cmpCtx->Urb = urb;
                            cmpCtx->EndpointAddress = epAddr;
                            cmpCtx->Function = func;

                            WdfRequestFormatRequestUsingCurrentType(Request);
                            WdfRequestSetCompletionRoutine(Request, FilterEvtIoInternalDeviceControlComplete, cmpCtx);
                            if (!WdfRequestSend(Request, context->Target, WDF_NO_SEND_OPTIONS)) {
                                ExFreePoolWithTag(cmpCtx, PHOENIX_CTX_TAG);
                                WdfRequestComplete(Request, WdfRequestGetStatus(Request));
                            }
                            return;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore any fault during URB parsing and pass request through safely
            }
        }
    }

    // Default transparent pass-through
    // Forward without formatting when using SEND_AND_FORGET
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(Request, context->Target, &sendOptions)) {
        WdfRequestComplete(Request, WdfRequestGetStatus(Request));
    }
}
