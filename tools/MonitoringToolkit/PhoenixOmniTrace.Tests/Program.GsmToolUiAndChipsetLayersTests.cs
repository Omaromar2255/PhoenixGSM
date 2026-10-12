using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Tests;

public static class GsmToolUiAndChipsetLayersTests
{
    public static void RunTests(OmniTraceEventBus bus)
    {
        Console.WriteLine("\n========================================================================");
        Console.WriteLine("    TEST 60: GSM Tool UI Intent, Filter Correlator & PnP Handshake     ");
        Console.WriteLine("========================================================================");

        List<LogicalCommandEvent> receivedCommands = new();
        bus.OnLogicalCommand += cmd =>
        {
            lock (receivedCommands)
            {
                receivedCommands.Add(cmd);
            }
        };

        // 1. Test GsmToolUiActionSensor
        using var uiSensor = new GsmToolUiActionSensor(bus);
        uiSensor.Start();

        var toolState = new GsmToolUiActionSensor.ToolUiState
        {
            ProcessId = 13836,
            ProcessName = "UnlockTool-2026-09-23-0.exe",
            ExecutablePath = @"C:\Users\pc5\Documents\UnlockTool-2026-09-23-0\UnlockTool-2026-09-23-0.exe",
            ActiveTab = "MediaTek",
            ActiveModel = "TCL Seoul_ATT (MT6739)"
        };

        uiSensor.EmitToolAction(toolState, "[BROM] FACTORY RESET", "MediaTek", "TCL Seoul_ATT (MT6739)", "Waiting for device connection...");

        Thread.Sleep(100);

        lock (receivedCommands)
        {
            var uiCmd = receivedCommands.Find(c => c.Command == "[BROM] FACTORY RESET");
            if (uiCmd == null) throw new Exception("GsmToolUiActionSensor failed to emit [BROM] FACTORY RESET command!");
            if (!uiCmd.Details.TryGetValue("TechnicalDetails", out var techDetails) ||
                !techDetails.Contains("MediaTek Service Execution") ||
                !techDetails.Contains("USB\\VID_0E8D&PID_0003"))
            {
                throw new Exception($"TechnicalDetails does not match required format! Got:\n{techDetails}");
            }
            Console.WriteLine("  [SUB-TEST 60.1] GsmToolUiActionSensor Pre-Connection Intent: PASSED");
        }

        // 2. Test FilterDriverCommandCorrelatorSensor
        using var filterCorrelator = new FilterDriverCommandCorrelatorSensor(bus, uiSensor);
        filterCorrelator.Start();

        var fakeFilterCmd = new LogicalCommandEvent
        {
            Service = "filter-x64.exe",
            Command = "INSTALL Filter: USB\\VID_0E8D&PID_0003",
            DeviceIdentity = "USB\\VID_0E8D&PID_0003",
            Confidence = 1.0,
            Attribution = new ProcessAttributionMetadata
            {
                ProcessId = 13836,
                ImageName = "UnlockTool-2026-09-23-0.exe"
            }
        };
        fakeFilterCmd.Details["TechnicalDetails"] = "Kernel Filter Driver Modification\nBinary: C:\\UnlockTool\\Binaries\\filter-x64.exe\nAction: INSTALL Filter\nDevice Target: USB\\VID_0E8D&PID_0003\nCaller: UnlockTool-2026-09-23-0.exe (PID 13836)";

        filterCorrelator.CorrelateFilterWithServiceExecution(13836, "UnlockTool-2026-09-23-0.exe", @"C:\Users\pc5\Documents\UnlockTool-2026-09-23-0\UnlockTool-2026-09-23-0.exe", "USB\\VID_0E8D&PID_0003", fakeFilterCmd);

        Thread.Sleep(100);

        lock (receivedCommands)
        {
            var filterCorrelatedCmd = receivedCommands.Find(c => c.DeviceIdentity == "USB\\VID_0E8D&PID_0003" && c.Details.ContainsKey("DriverAction"));
            if (filterCorrelatedCmd == null) throw new Exception("FilterDriverCommandCorrelatorSensor failed to correlate filter driver with MediaTek service!");
            Console.WriteLine("  [SUB-TEST 60.2] FilterDriverCommandCorrelatorSensor Correlation: PASSED");
        }

        // 3. Test DevicePnpArrivalCommandSensor
        using var pnpSensor = new DevicePnpArrivalCommandSensor(bus, uiSensor);
        pnpSensor.Start();

        pnpSensor.EmitArrivalEvent("USB\\VID_0E8D&PID_0003", "COM45");

        Thread.Sleep(100);

        lock (receivedCommands)
        {
            var pnpCmd = receivedCommands.Find(c => c.Command.Contains("BROM Handshake Initiated"));
            if (pnpCmd == null) throw new Exception("DevicePnpArrivalCommandSensor failed to emit BROM handshake event on hardware arrival!");
            if (!pnpCmd.Details["TechnicalDetails"].Contains("0xA0 0x0A 0x50 0x05"))
            {
                throw new Exception("BROM Handshake bytes missing from PnP arrival technical details!");
            }
            Console.WriteLine("  [SUB-TEST 60.3] DevicePnpArrivalCommandSensor Hardware Arrival: PASSED");
        }

        Console.WriteLine("TEST 60: ALL GSM TOOL PRE-CONNECTION & HARDWARE LAYERS VERIFIED AND PASSED!");
    }
}
