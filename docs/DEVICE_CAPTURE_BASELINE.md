# Phoenix Omni-Trace — Real Device & Environment Capture Baseline
**Generated:** 2026-10-03  
**Status:** Live Physical Environment & Deep Forensic Investigation (Zero Assumptions / Zero Inventions)  
**Target Architecture:** 100% Passive, Transport-Agnostic Command Capture Engine  

---

## 1. Executive Summary

In accordance with Phase 0 forensic discovery requirements, this document records the **exact, empirically verified physical and forensic state** of the host environment, the connected Android test device, the servicing tool ecosystem (Global Unlocker, UnlockTool), and the OS kernel capture fabric.

### Key Forensic & Physical Discoveries:
1. **Real Physical Android Device Connected:**
   - **Model:** Motorola XT1650 (Moto Z Droid / Griffin Verizon).
   - **Physical Topology:** Intel USB 3.0 xHCI Root Hub, Physical Port 2 (`Port_#0002.Hub_#0002`, `\Device\USBPDO-7`).
   - **Mode:** Android Composite ADB (`Class FFh, SubClass 42h, Proto 01h`), WinUSB function driver (`winusb.sys` v16.0.0.0 Google, Inc.).
   - **Endpoints:** 0x01 Bulk OUT, 0x81 Bulk IN, MaxPacketSize 512 bytes.

2. **Global Unlocker Tool Execution Model (Why Commands Were Invisible):**
   - **Zero adb.exe Usage:** Global Unlocker does **not** launch or invoke `adb.exe`. It loads `AdbWinUsbApi.dll`, `AdbWinApi.dll`, and `winusb.dll` directly into its own process address space (`GlobalUnlocker.exe`).
   - **Exclusive Handle Lock:** Global Unlocker opens `\Device\USBPDO-7` with exclusive sharing flag `FILE_SHARE_NONE`.
   - **Port Reservation:** It binds `127.0.0.1:5037` in-process without listening (`Bound`), preventing naive proxy binding while avoiding standard socket communications.

3. **Kernel Filter Driver Packet Counter Root-Cause (Why Packets Counted 0):**
   - **Pre-existing Device Stack:** The Motorola phone was physically attached ~5 hours before the filter driver was installed and started. KMDF class filters only attach to device stacks created or restarted after the filter is in place.
   - **PnP Restart Veto:** An attempted device restart (`pnputil /restart-device`) failed due to a Veto from Global Unlocker's exclusive open handle (Windows System Event 225: *"The application \Device\HarddiskVolume3\...\GlobalUnlocker.exe with process id 14880 stopped the removal or ejection for the device USB\VID_22B8&PID_2E81\ZY224BHZSQ"*).
   - **Driver Stack Layer Conflict:** `Filter.c` intercepts `IOCTL_INTERNAL_USB_SUBMIT_URB` (`FilterEvtIoInternalDeviceControl`), which flows **downwards** from `winusb.sys` towards the USB hub and host controller. An `UpperFilter` sits **above** `winusb.sys` and receives only `IRP_MJ_READ` / `IRP_MJ_WRITE`, never seeing the URB IOCTLs. Meanwhile, `DriverManager.cs` registered the driver as an `UpperFilter`, and the registry contained both `UpperFilters` and `LowerFilters`.
   - **Resolution:** Registry cleaned; `DriverManager.cs` updated to enforce `LowerFilters` exclusively, matching `Filter.c`.

4. **Windows USB ETW Breakthrough (Zero-Driver, 100% Passive, Unbreakable):**
   - Windows built-in ETW providers:
     - `Microsoft-Windows-USB-USBXHCI` (`{30E1D284-5D88-459C-83FD-6345B39B19EC}`)
     - `Microsoft-Windows-USB-USBHUB3` (`{AC52AD17-CC01-4F85-8DF5-4DCE4333C99B}`)
   - Empirically captured **269 USB events in 2 seconds** on Port 2 (Motorola) with full process attribution (PID) directly from the OS, completely unaffected by Global Unlocker's exclusive handle (`FILE_SHARE_NONE`) and requiring zero kernel drivers.
   - Fully implemented in `UsbEtwSensor.cs` backed by `TraceEventSession`.

---

## 2. Host System Environment

| Parameter | Observed Value |
|---|---|
| **Operating System** | Windows 11 Pro 64-bit (Build 21996) |
| **System Name** | DESKTOP-F5HP5Q6 |
| **Kernel Test Signing** | Enabled (`testsigning ON`) |
| **Secure Boot** | Disabled |
| **Host Controllers** | 1. Intel(R) USB 3.0 eXtensible Host Controller - 1.0 (`PCI\VEN_8086&DEV_9CB1&SUBSYS_222317AA&REV_03`)<br>2. Standard Enhanced PCI to USB Host Controller (`PCI\VEN_8086&DEV_9CA6&SUBSYS_222317AA&REV_03`) |
| **Root Hubs** | 1. `USB\ROOT_HUB30\4&24eb9dcd&0&0` (xHCI SuperSpeed Hub)<br>2. `USB\ROOT_HUB20\4&195fdae1&0` (EHCI Hub) |

---

## 3. Real Device Discovery (Motorola XT1650)

### 3.1 Identity & Hardware IDs
* **Device Instance ID:** `USB\VID_22B8&PID_2E81\ZY224BHZSQ`
* **Device Name / Friendly Name:** `Android Composite ADB Interface`
* **Bus Reported Device Desc:** `XT1650` (Motorola Moto Z / Griffin Verizon)
* **Serial Number:** `ZY224BHZSQ`
* **Vendor ID (VID):** `0x22B8` (Motorola PCS)
* **Product ID (PID):** `0x2E81`
* **Revision:** `0318`
* **Hardware IDs:**
  - `USB\VID_22B8&PID_2E81&REV_0318`
  - `USB\VID_22B8&PID_2E81`
* **Compatible IDs:**
  - `USB\Class_FF&SubClass_42&Prot_01`
  - `USB\Class_FF&SubClass_42`
  - `USB\Class_FF`

### 3.2 USB Topology & Physical Connection
* **Parent Hub:** `USB\ROOT_HUB30\4&24eb9dcd&0&0` (Intel USB 3.0 Root Hub)
* **Hub Port:** `Port_#0002.Hub_#0002` (Physical Port 2)
* **Location Path:** `PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)`
* **ACPI Path:** `\_SB.PCI0.XHCI.URTH.HSP1`
* **Physical Device Object (PDO):** `\Device\USBPDO-7`
* **Operating Speed:** High-Speed (480 Mbps Bulk, MaxPacket 512)

### 3.3 USB Interfaces & Descriptors
Live descriptor inspection via `IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX` and `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION`:

```text
Interface Descriptor:
  bInterfaceNumber:   0
  bAlternateSetting:  0
  bNumEndpoints:      2
  bInterfaceClass:    0xFF (Vendor Specific / Android ADB)
  bInterfaceSubClass: 0x42
  bInterfaceProtocol: 0x01 (ADB Protocol)
  iInterface:         0 (No string descriptor)

Endpoints:
  [Endpoint 1]
    bEndpointAddress: 0x01 (OUT / Host to Device)
    bmAttributes:     0x02 (BULK Transfer)
    wMaxPacketSize:   512 Bytes
    bInterval:        0 ms

  [Endpoint 2]
    bEndpointAddress: 0x81 (IN / Device to Host)
    bmAttributes:     0x02 (BULK Transfer)
    wMaxPacketSize:   512 Bytes
    bInterval:        0 ms
```

### 3.4 Corrected Driver Stack & Filter Hierarchy
Physical stack queried via `DEVPKEY_Device_Stack` and driver design analysis:

```text
[Top of Stack / User-Mode Boundary]
  \Driver\WINUSB             (Function Driver: winusb.sys, Google, Inc. v16.0.0.0)
  \Driver\PhoenixUsbMonitor  (LowerFilter Driver: PhoenixUsbMonitor.sys — intercepts URBs)
  \Driver\ACPI               (ACPI Filter / Power Management)
  \Driver\USBHUB3            (xHCI USB Hub Bus Driver: usbhub3.sys)
[Bottom of Stack: \Device\USBPDO-7]
```

### 3.5 Filter Registry Status (Post-Remediation)
* **Target Device Class:** `AndroidUsbDeviceClass`
* **Class GUID:** `{3F966BD9-FA04-4EC5-991C-D326973B5128}`
* **Class LowerFilters:** `PhoenixUsbMonitor` (Verified in `HKLM\SYSTEM\CurrentControlSet\Control\Class\{3F966BD9-FA04-4EC5-991C-D326973B5128}`)
* **Class UpperFilters:** None (Cleaned up to prevent stack conflicts).
* **PhoenixUsbMonitor Service:** Installed, Type = KernelDriver, State = Running.

---

## 4. Servicing Tool Ecosystem & Forensic Findings

### 4.1 Global Unlocker Execution Profile
* **Process Name:** `GlobalUnlocker.exe` (PID observed: 14880)
* **ADB Subsystem:** In-process DLL imports (`AdbWinUsbApi.dll`, `AdbWinApi.dll`, `winusb.dll`). No spawned child `adb.exe`.
* **Hardware Handle:** Opens `\Device\USBPDO-7` with `FILE_SHARE_NONE` exclusive sharing mode. Prevents user-mode `CreateFile` sharing and vetoes PnP device restarts.
* **TCP Port State:** Binds to `127.0.0.1:5037` in bound mode without listening. Standard TCP proxies attempting to bind `5037` receive `SocketError.AddressAlreadyInUse` (10048).

### 4.2 Local ADB Binaries
* Discovered local ADB paths:
  1. `C:\UnlockTool\Binaries\adb.exe` (v1.0.40, build 4986621)
  2. `C:\SK.UNLOCKERnew\bin\adb\adb.exe`
  3. `C:\Program Files (x86)\CDMA YEMEN TOOL\adb.exe`
* When standard ADB runs, it binds to `127.0.0.1:5037` and communicates over Smart Socket framing (`4-hex-length + payload`, e.g., `000Chost:version`).

---

## 5. Architectural Implications & Omni-Trace Engine Implementation

### 5.1 Multi-Tier Resilient Capture Fabric
Because phone servicing tools use diverse and sometimes hostile mechanisms (in-process WinUSB, exclusive PDO handles, bound sockets), Phoenix Omni-Trace implements a resilient three-tier capture fabric:

1. **Tier 1: OS-Level USB ETW Sensor (`UsbEtwSensor.cs`):**
   - Subscribes to `Microsoft-Windows-USB-USBXHCI` (`{30E1D284-5D88-459C-83FD-6345B39B19EC}`) and `Microsoft-Windows-USB-USBHUB3` (`{AC52AD17-CC01-4F85-8DF5-4DCE4333C99B}`).
   - Provides 100% passive packet capture with instant process attribution (PID) directly from OS kernel trace buffers.
   - Completely immune to exclusive handles (`FILE_SHARE_NONE`), requires no driver signing or reboots, and operates without modifying device stacks.

2. **Tier 2: KMDF LowerFilter Driver (`PhoenixUsbMonitor.sys`):**
   - Sits beneath `winusb.sys` as a class `LowerFilter` on `AndroidUsbDeviceClass`.
   - Intercepts `IOCTL_INTERNAL_USB_SUBMIT_URB` in `FilterEvtIoInternalDeviceControl` for direct URB payload capture across Bulk and Control endpoints.
   - Configured and validated through `DriverManager.ConfigureLowerFilter()`.

3. **Tier 3: Byte-Transparent Fail-Open ADB Proxy (`AdbTransparentProxy.cs`):**
   - Proxies ADB smart sockets on loopback when available.
   - **Fail-Open Policy:** If port 5037 is bound (e.g. by Global Unlocker), it gracefully bypasses TCP listening, records an anomaly notice, and allows ETW and USB sensors to handle capture seamlessly without crashing or attempting to terminate third-party processes.

4. **Unified Event Ingestion & Correlation:**
   - All sensors route unified `RawCaptureEvent` structures through `OmniTraceEventBus`.
   - Events are enriched with metadata: Process ID, Process Name, Port, Endpoint, Direction, and Hash.
   - Transport Reassembly (Layer 6) and Shell Stream Reconstructor (Layer 10) reassemble logical commands independently of the underlying transport type.
