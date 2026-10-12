#ifndef _PHOENIX_QUEUE_H_
#define _PHOENIX_QUEUE_H_

#include <ntddk.h>
#include <wdf.h>
#include "Ioctl.h"

typedef struct _PHOENIX_PACKET_QUEUE {
    WDFSPINLOCK Lock;
    ULONG Head;
    ULONG Tail;
    ULONG Count;
    ULONG Capacity;
    ULONG64 TotalCaptured;
    ULONG64 TotalDropped;
    ULONG64 TotalBytes;
    PHOENIX_USB_PACKET Items[PHOENIX_MAX_QUEUE_CAPACITY];
} PHOENIX_PACKET_QUEUE, *PPHOENIX_PACKET_QUEUE;

NTSTATUS PhoenixQueueInitialize(PPHOENIX_PACKET_QUEUE* Queue, WDFDRIVER Driver);
VOID PhoenixQueueDestroy(PPHOENIX_PACKET_QUEUE Queue);
BOOLEAN PhoenixQueueEnqueue(PPHOENIX_PACKET_QUEUE Queue, PPHOENIX_USB_PACKET Packet);
BOOLEAN PhoenixQueueDequeue(PPHOENIX_PACKET_QUEUE Queue, PPHOENIX_USB_PACKET Packet);
VOID PhoenixQueueClear(PPHOENIX_PACKET_QUEUE Queue);
VOID PhoenixQueueGetStats(PPHOENIX_PACKET_QUEUE Queue, PPHOENIX_DRIVER_STATS Stats);

#endif // _PHOENIX_QUEUE_H_
