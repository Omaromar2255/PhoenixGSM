#ifndef _PHOENIX_IOCTL_H_
#define _PHOENIX_IOCTL_H_

#define PHOENIX_DEVICE_NAME_KERNEL      L"\\Device\\PhoenixUsbMonitor"
#define PHOENIX_SYMBOLIC_NAME_KERNEL    L"\\DosDevices\\PhoenixUsbMonitor"
#define PHOENIX_USER_DEVICE_PATH        L"\\\\.\\PhoenixUsbMonitor"

#define PHOENIX_DRIVER_VERSION          0x00010000 // v1.0.0

#define FILE_DEVICE_PHOENIX_MONITOR     0x8890

#define IOCTL_PHOENIX_GET_STATS \
    CTL_CODE(FILE_DEVICE_PHOENIX_MONITOR, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PHOENIX_GET_PACKET \
    CTL_CODE(FILE_DEVICE_PHOENIX_MONITOR, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PHOENIX_CLEAR_BUFFER \
    CTL_CODE(FILE_DEVICE_PHOENIX_MONITOR, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PHOENIX_MAX_PAYLOAD_CAPTURE     1024
#define PHOENIX_MAX_QUEUE_CAPACITY      512

#define PHOENIX_DIR_OUT                 0 // Host to Device
#define PHOENIX_DIR_IN                  1 // Device to Host

#pragma pack(push, 1)

typedef struct _PHOENIX_DRIVER_STATS {
    ULONG DriverVersion;
    ULONG64 TotalPacketsCaptured;
    ULONG64 TotalPacketsDropped;
    ULONG64 TotalBytesCaptured;
    ULONG CurrentlyQueued;
    ULONG MaxQueueCapacity;
} PHOENIX_DRIVER_STATS, *PPHOENIX_DRIVER_STATS;

typedef struct _PHOENIX_USB_PACKET {
    LARGE_INTEGER Timestamp;
    ULONG Direction;          // 0 = OUT, 1 = IN
    ULONG TransferType;       // 2 = BULK, etc.
    ULONG EndpointAddress;    // 0x02, 0x81, etc.
    ULONG ActualLength;       // Real size in USB IRP
    ULONG CapturedLength;     // Size captured in Data array
    UCHAR Data[PHOENIX_MAX_PAYLOAD_CAPTURE];
} PHOENIX_USB_PACKET, *PPHOENIX_USB_PACKET;

#pragma pack(pop)

#endif // _PHOENIX_IOCTL_H_
