#ifndef _PHOENIX_DRIVER_H_
#define _PHOENIX_DRIVER_H_

#include <ntddk.h>
#include <wdf.h>
#include "Ioctl.h"
#include "Queue.h"
#include "Filter.h"
#include "Control.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD PhoenixEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD PhoenixEvtDriverUnload;

#endif // _PHOENIX_DRIVER_H_
