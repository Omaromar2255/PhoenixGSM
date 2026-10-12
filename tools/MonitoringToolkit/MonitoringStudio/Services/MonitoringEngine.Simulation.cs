using System;
using System.Text;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    #region Realistic Traffic Simulation for UI Demonstration
    public async Task SimulateTrafficAsync()
    {
        var scenarios = new (EventSourceCategory Cat, string Source, string Dir, string Target, string Proto, string Cmd, string Summary, string Payload, string Details)[]
        {
            (
                EventSourceCategory.Process, "PROCESS", "SYS", "SamFW_Tool.exe", "GSM-TOOL", "LAUNCH",
                "SamFW Tool started (PID 14280) — User initiated FRP Bypass sequence",
                "Process: SamFW_Tool.exe\nPID: 14280\nModules: AdbWinApi.dll, libusb-1.0.dll",
                "Tool Binary: C:\\Program Files\\SamFW\\SamFW_Tool.exe"
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "OUT", "EP 0x02", "ADB-USB", "CNXN",
                "CNXN: Host ADB Daemon Handshake | Version: 0x01000000, MaxData=262144",
                "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir",
                "Host handshake initiating ADB session with connected Samsung device."
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "IN", "EP 0x81", "ADB-USB", "CNXN",
                "CNXN: Samsung S22 Ultra response (ro.product.model=SM-S908B, ro.boot.serialno=R5CR5182YYD)",
                "device::ro.product.model=SM-S908B;ro.build.version.release=13;ro.build.id=TP1A.220624.014;ro.boot.serialno=R5CR5182YYD",
                "Device negotiated ADB 256KB bulk buffers successfully."
            ),
            (
                EventSourceCategory.SerialPort, "SERIAL", "OUT", "COM4", "AT CMD", "AT+DEVINFO",
                "Sent AT command to Samsung Modem: AT+DEVINFO",
                "AT+DEVINFO\r\n",
                "Port: COM4 | Baud: 115200 | Samsung Mobile USB Modem"
            ),
            (
                EventSourceCategory.SerialPort, "SERIAL", "IN", "COM4", "AT CMD", "+DEVINFO: OK",
                "Modem response: Model: SM-S908B, Baseband: S908BXXU2BVL1, IMEI: 354891100234567",
                "+DEVINFO: SM-S908B,S908BXXU2BVL1,354891100234567,OK\r\n",
                "Extracted IMEI: 354891100234567 | Baseband: S908BXXU2BVL1"
            ),
            (
                EventSourceCategory.AdbProxy, "ADB-PROXY", "OUT", "SamFW_Tool.exe", "ADB-CLI", "SHELL",
                "Executing: adb shell getprop ro.frp.pst",
                "/dev/block/persistent",
                "Checking Samsung Factory Reset Protection persistent partition"
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "OUT", "EP 0x02", "ADB-USB", "OPEN",
                "OPEN: Stream ID=1 -> Destination: \"shell:content insert --uri content://settings/secure --bind name:s:user_setup_complete --bind value:s:1\"",
                "shell:content insert --uri content://settings/secure --bind name:s:user_setup_complete --bind value:s:1\0",
                "FRP Bypass Step 1: Injecting user_setup_complete=1 into Android Secure Settings"
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "IN", "EP 0x81", "ADB-USB", "OKAY",
                "OKAY: Device accepted injection stream (LocalID=1, RemoteID=1)",
                "",
                "Stream status: READY"
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "IN", "EP 0x81", "ADB-USB", "WRTE",
                "WRTE: Insert operation result: Status 200 OK (Content Provider updated)",
                "Row: 1 inserted successfully\n",
                "Settings provider modified without root."
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "IN", "EP 0x81", "ADB-USB", "CLSE",
                "CLSE: Stream closed (LocalID=1, RemoteID=1)",
                "",
                "Stream status: CLOSED"
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "OUT", "EP 0x02", "ADB-USB", "OPEN",
                "OPEN: Stream ID=2 -> Destination: \"shell:am start -n com.google.android.gsf.login/\"",
                "shell:am start -n com.google.android.gsf.login/\0",
                "FRP Bypass Step 2: Triggering Google Services Framework Login activity"
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "IN", "EP 0x81", "ADB-USB", "WRTE",
                "WRTE: Starting: Intent { cmp=com.google.android.gsf.login/ }",
                "Starting: Intent { cmp=com.google.android.gsf.login/ }\n",
                "Google Account setup bypassed on device screen."
            ),
            (
                EventSourceCategory.AdbProxy, "ADB-PROXY", "OUT", "SamFW_Tool.exe", "ADB-CLI", "REBOOT",
                "Executing: adb reboot -> Rebooting device to finalize FRP unlock",
                "",
                "Reboot command dispatched to phone."
            ),
            (
                EventSourceCategory.Process, "PROCESS", "SYS", "SamFW_Tool.exe", "GSM-TOOL", "COMPLETED",
                "SamFW Tool operation finished: Samsung FRP Bypass Completed Successfully in 4.2s",
                "Operation: Samsung FRP (MTP/ADB)\nDuration: 4.2 seconds\nStatus: SUCCESS",
                "All commands captured and decoded across USB, Serial, ADB, and Process layers."
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "OUT", "EP 0x01", "FASTBOOT", "getvar",
                "[FASTBOOT] Host Query: getvar:version (WinUSB Mode)",
                "getvar:version",
                "Tool communicating directly over WinUSB Fastboot interface without ADB."
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "IN", "EP 0x81", "FASTBOOT", "OKAY0.5",
                "[FASTBOOT] Device Response: OKAY0.5",
                "OKAY0.5",
                "Bootloader acknowledged command over WinUSB bulk IN pipe."
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "OUT", "EP 0x02", "QUALCOMM_FIREHOSE", "XML_COMMAND",
                "[QUALCOMM_FIREHOSE] XML Handshake: configure MemoryName=\"ufs\"",
                "<?xml version=\"1.0\" ?><data><configure MemoryName=\"ufs\" Verbose=\"0\" MaxPayloadSizeToTargetInBytes=\"1048576\"/></data>",
                "Emergency Download (EDL 9008) protocol packet captured below WinUSB."
            ),
            (
                EventSourceCategory.UsbDriver, "USB-DRV", "OUT", "EP 0x03", "WINUSB_RAW", "DATA",
                "[WINUSB_RAW] Raw USB Tool Packet: 10 bytes [55 AA 10 20 30 40 01 FF FE FD]",
                "U\xaa\x10 0@\x01\xff\xfe\xfd",
                "Custom vendor command captured by PhoenixUsbMonitor LowerFilter."
            )
        };

        foreach (var sc in scenarios)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(sc.Payload);
            EmitEvent(new LiveEventItem
            {
                Category = sc.Cat,
                SourceTag = sc.Source,
                Direction = sc.Dir,
                EndpointOrTarget = sc.Target,
                Protocol = sc.Proto,
                Command = sc.Cmd,
                Summary = sc.Summary,
                RawPayload = bytes,
                PayloadAscii = sc.Payload,
                PayloadHex = LiveEventItem.FormatHexDump(bytes),
                AdditionalDetails = sc.Details
            });

            await Task.Delay(250);
        }
    }
    #endregion
}
