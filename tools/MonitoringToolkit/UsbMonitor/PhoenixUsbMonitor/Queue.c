#include "Queue.h"

#define PHOENIX_POOL_TAG 'mUxP' // 'PxUm' Phoenix USB Monitor

NTSTATUS PhoenixQueueInitialize(PPHOENIX_PACKET_QUEUE* OutQueue, WDFDRIVER Driver)
{
    PPHOENIX_PACKET_QUEUE q = NULL;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

    q = (PPHOENIX_PACKET_QUEUE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PHOENIX_PACKET_QUEUE), PHOENIX_POOL_TAG);
    if (q == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(q, sizeof(PHOENIX_PACKET_QUEUE));
    q->Capacity = PHOENIX_MAX_QUEUE_CAPACITY;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Driver;

    status = WdfSpinLockCreate(&attributes, &q->Lock);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(q, PHOENIX_POOL_TAG);
        return status;
    }

    *OutQueue = q;
    return STATUS_SUCCESS;
}

VOID PhoenixQueueDestroy(PPHOENIX_PACKET_QUEUE Queue)
{
    if (Queue != NULL) {
        ExFreePoolWithTag(Queue, PHOENIX_POOL_TAG);
    }
}

BOOLEAN PhoenixQueueEnqueue(PPHOENIX_PACKET_QUEUE Queue, PPHOENIX_USB_PACKET Packet)
{
    if (Queue == NULL || Packet == NULL) return FALSE;

    WdfSpinLockAcquire(Queue->Lock);

    // If bounded queue is full: drop copy, do NOT block the USB pipe!
    if (Queue->Count >= Queue->Capacity) {
        Queue->TotalDropped++;
        WdfSpinLockRelease(Queue->Lock);
        return FALSE;
    }

    // Insert at Head
    RtlCopyMemory(&Queue->Items[Queue->Head], Packet, sizeof(PHOENIX_USB_PACKET));
    Queue->Head = (Queue->Head + 1) % Queue->Capacity;
    Queue->Count++;
    Queue->TotalCaptured++;
    Queue->TotalBytes += Packet->ActualLength;

    WdfSpinLockRelease(Queue->Lock);
    return TRUE;
}

BOOLEAN PhoenixQueueDequeue(PPHOENIX_PACKET_QUEUE Queue, PPHOENIX_USB_PACKET Packet)
{
    if (Queue == NULL || Packet == NULL) return FALSE;

    WdfSpinLockAcquire(Queue->Lock);

    if (Queue->Count == 0) {
        WdfSpinLockRelease(Queue->Lock);
        return FALSE;
    }

    // Pop from Tail
    RtlCopyMemory(Packet, &Queue->Items[Queue->Tail], sizeof(PHOENIX_USB_PACKET));
    Queue->Tail = (Queue->Tail + 1) % Queue->Capacity;
    Queue->Count--;

    WdfSpinLockRelease(Queue->Lock);
    return TRUE;
}

VOID PhoenixQueueClear(PPHOENIX_PACKET_QUEUE Queue)
{
    if (Queue == NULL) return;

    WdfSpinLockAcquire(Queue->Lock);
    Queue->Head = 0;
    Queue->Tail = 0;
    Queue->Count = 0;
    WdfSpinLockRelease(Queue->Lock);
}

VOID PhoenixQueueGetStats(PPHOENIX_PACKET_QUEUE Queue, PPHOENIX_DRIVER_STATS Stats)
{
    if (Queue == NULL || Stats == NULL) return;

    WdfSpinLockAcquire(Queue->Lock);
    Stats->DriverVersion = PHOENIX_DRIVER_VERSION;
    Stats->TotalPacketsCaptured = Queue->TotalCaptured;
    Stats->TotalPacketsDropped = Queue->TotalDropped;
    Stats->TotalBytesCaptured = Queue->TotalBytes;
    Stats->CurrentlyQueued = Queue->Count;
    Stats->MaxQueueCapacity = Queue->Capacity;
    WdfSpinLockRelease(Queue->Lock);
}
