#ifndef _PHOENIX_CONTROL_H_
#define _PHOENIX_CONTROL_H_

#include <ntddk.h>
#include <wdf.h>
#include "Ioctl.h"
#include "Queue.h"

typedef struct _CONTROL_DEVICE_CONTEXT {
    PPHOENIX_PACKET_QUEUE Queue;
} CONTROL_DEVICE_CONTEXT, *PCONTROL_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CONTROL_DEVICE_CONTEXT, GetControlDeviceContext)

NTSTATUS ControlCreateDevice(WDFDRIVER Driver, PPHOENIX_PACKET_QUEUE SharedQueue);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ControlEvtIoDeviceControl;

#endif // _PHOENIX_CONTROL_H_
