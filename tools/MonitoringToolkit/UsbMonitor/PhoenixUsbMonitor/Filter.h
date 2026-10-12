#ifndef _PHOENIX_FILTER_H_
#define _PHOENIX_FILTER_H_

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <usbdlib.h>
#include <usbioctl.h>
#include "Ioctl.h"
#include "Queue.h"

typedef struct _FILTER_DEVICE_CONTEXT {
    WDFDEVICE WdfDevice;
    WDFIOTARGET Target;
    PPHOENIX_PACKET_QUEUE Queue;
} FILTER_DEVICE_CONTEXT, *PFILTER_DEVICE_CONTEXT;

typedef struct _COMPLETION_CTX {
    PFILTER_DEVICE_CONTEXT DevCtx;
    PURB Urb;
    UCHAR EndpointAddress;
    USHORT Function;
} COMPLETION_CTX, *PCOMPLETION_CTX;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FILTER_DEVICE_CONTEXT, GetFilterDeviceContext)

// Per-request context: holds a locked user buffer for METHOD_NEITHER reads so the
// completion routine (arbitrary thread context) can safely read the returned data.
typedef struct _FILTER_REQUEST_CONTEXT {
    WDFMEMORY LockedReadBuffer;
} FILTER_REQUEST_CONTEXT, *PFILTER_REQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FILTER_REQUEST_CONTEXT, GetFilterRequestContext)

NTSTATUS FilterCreateDevice(PWDFDEVICE_INIT DeviceInit, PPHOENIX_PACKET_QUEUE SharedQueue);

EVT_WDF_IO_IN_CALLER_CONTEXT FilterEvtIoInCallerContext;
EVT_WDF_IO_QUEUE_IO_READ FilterEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE FilterEvtIoWrite;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL FilterEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL FilterEvtIoInternalDeviceControl;
EVT_WDF_REQUEST_COMPLETION_ROUTINE FilterEvtReadComplete;
EVT_WDF_REQUEST_COMPLETION_ROUTINE FilterEvtIoInternalDeviceControlComplete;

#endif // _PHOENIX_FILTER_H_
