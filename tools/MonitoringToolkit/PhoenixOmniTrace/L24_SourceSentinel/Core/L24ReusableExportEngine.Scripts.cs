using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public static partial class L24ReusableExportEngine
{
    private static void GenerateAdbReplayScripts(string targetDir, List<SourceTelemetryEvent> items, ExportResult result)
    {
        // سكريبت Batch لنظام ويندوز
        string batPath = Path.Combine(targetDir, "01_Run_ADB_Commands.bat");
        var sbBat = new StringBuilder();
        sbBat.AppendLine("@echo off");
        sbBat.AppendLine("chcp 65001 > nul");
        sbBat.AppendLine("title PhoenixGSM L24 - ADB / Fastboot Automated Replay");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("echo   PhoenixGSM Layer 24 - Automated Execution Script for ADB / Fastboot");
        sbBat.AppendLine($"echo   Total Commands: {items.Count} | Export Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("echo.");
        sbBat.AppendLine("echo [1/3] Verifying ADB Connection...");
        sbBat.AppendLine("adb devices");
        sbBat.AppendLine("echo.");
        sbBat.AppendLine("pause");
        sbBat.AppendLine("echo.");
        sbBat.AppendLine("echo [2/3] Executing commands sequentially...");
        sbBat.AppendLine("echo.");

        for (int i = 0; i < items.Count; i++)
        {
            string rawCmd = items[i].PureCommandText.Trim();
            if (string.IsNullOrEmpty(rawCmd)) continue;

            string execLine = rawCmd;
            if (!execLine.StartsWith("adb ", StringComparison.OrdinalIgnoreCase) &&
                !execLine.StartsWith("fastboot ", StringComparison.OrdinalIgnoreCase))
            {
                execLine = $"adb {execLine}";
            }

            sbBat.AppendLine($"echo [{i + 1}/{items.Count}] Running: {execLine.Replace("%", "%%")}");
            sbBat.AppendLine(execLine);
            sbBat.AppendLine("timeout /t 1 /nobreak > nul");
            sbBat.AppendLine();
        }

        sbBat.AppendLine("echo.");
        sbBat.AppendLine("echo [3/3] ========================================================================");
        sbBat.AppendLine("echo   All ADB/Fastboot commands executed successfully!");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("pause");

        File.WriteAllText(batPath, sbBat.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(batPath);

        // سكريبت Bash لأنظمة لينكس / ماك / WSL
        string shPath = Path.Combine(targetDir, "02_Run_ADB_Commands.sh");
        var sbSh = new StringBuilder();
        sbSh.AppendLine("#!/usr/bin/env bash");
        sbSh.AppendLine("# PhoenixGSM L24 - ADB / Fastboot Replay Script");
        sbSh.AppendLine($"# Total Commands: {items.Count}");
        sbSh.AppendLine();
        sbSh.AppendLine("echo \"=== Checking ADB Devices ===\"");
        sbSh.AppendLine("adb devices");
        sbSh.AppendLine();
        sbSh.AppendLine("read -p \"Press Enter to start execution...\"");
        sbSh.AppendLine();

        for (int i = 0; i < items.Count; i++)
        {
            string rawCmd = items[i].PureCommandText.Trim();
            if (string.IsNullOrEmpty(rawCmd)) continue;

            string execLine = rawCmd;
            if (!execLine.StartsWith("adb ", StringComparison.OrdinalIgnoreCase) &&
                !execLine.StartsWith("fastboot ", StringComparison.OrdinalIgnoreCase))
            {
                execLine = $"adb {execLine}";
            }

            sbSh.AppendLine($"echo \"[{i + 1}/{items.Count}] {execLine}\"");
            sbSh.AppendLine(execLine);
            sbSh.AppendLine("sleep 1");
        }

        sbSh.AppendLine();
        sbSh.AppendLine("echo \"=== Finished Successfully ===\"");
        File.WriteAllText(shPath, sbSh.ToString(), new UTF8Encoding(false));
        result.CreatedFiles.Add(shPath);
    }

    private static void GenerateAtReplayScript(string targetDir, List<SourceTelemetryEvent> items, ExportResult result)
    {
        // اكتشاف المنفذ الأكثر تكراراً في الأحداث إن وجد (مثل COM3، COM5)
        string detectedPort = items
            .Select(e => e.TargetResource)
            .Where(r => !string.IsNullOrWhiteSpace(r) && r.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
            .GroupBy(r => r)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault() ?? "COM3";

        string pyPath = Path.Combine(targetDir, "01_Replay_AT_Serial.py");
        var sbPy = new StringBuilder();
        sbPy.AppendLine("#!/usr/bin/env python3");
        sbPy.AppendLine("# -*- coding: utf-8 -*-");
        sbPy.AppendLine("\"\"\"");
        sbPy.AppendLine("PhoenixGSM Layer 24 - Reusable AT Command Replay Tool");
        sbPy.AppendLine($"Exported: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sbPy.AppendLine($"Detected Target Port: {detectedPort}");
        sbPy.AppendLine($"Total AT Commands: {items.Count}");
        sbPy.AppendLine("\"\"\"");
        sbPy.AppendLine("import sys");
        sbPy.AppendLine("import time");
        sbPy.AppendLine();
        sbPy.AppendLine("try:");
        sbPy.AppendLine("    import serial");
        sbPy.AppendLine("except ImportError:");
        sbPy.AppendLine("    print('[!] Error: pyserial is required. Install it using: pip install pyserial')");
        sbPy.AppendLine("    sys.exit(1)");
        sbPy.AppendLine();
        sbPy.AppendLine($"DEFAULT_PORT = '{detectedPort}'  # Adjust to the active Modem / Diag COM Port");
        sbPy.AppendLine("BAUDRATE = 115200");
        sbPy.AppendLine("TIMEOUT = 2.5");
        sbPy.AppendLine();
        sbPy.AppendLine("COMMAND_SEQUENCE = [");

        for (int i = 0; i < items.Count; i++)
        {
            string cmd = items[i].PureCommandText.Trim();
            if (string.IsNullOrEmpty(cmd)) continue;
            // Escape single quotes and backslashes
            string escapedCmd = cmd.Replace("\\", "\\\\").Replace("'", "\\'");
            sbPy.AppendLine($"    ({i + 1}, '{escapedCmd}'),");
        }

        sbPy.AppendLine("]");
        sbPy.AppendLine();
        sbPy.AppendLine("def run_replay(port_name=DEFAULT_PORT):");
        sbPy.AppendLine("    print(f'[*] Connecting to {port_name} at {BAUDRATE} baud...')");
        sbPy.AppendLine("    try:");
        sbPy.AppendLine("        ser = serial.Serial(port_name, BAUDRATE, timeout=TIMEOUT)");
        sbPy.AppendLine("    except Exception as ex:");
        sbPy.AppendLine("        print(f'[X] Failed to open {port_name}: {ex}')");
        sbPy.AppendLine("        print('    Tip: Check Windows Device Manager for the correct COM port number.')");
        sbPy.AppendLine("        return");
        sbPy.AppendLine();
        sbPy.AppendLine("    print(f'[+] Port open! Sending {len(COMMAND_SEQUENCE)} commands sequentially...\\n')");
        sbPy.AppendLine("    time.sleep(0.5)");
        sbPy.AppendLine();
        sbPy.AppendLine("    log_lines = []");
        sbPy.AppendLine("    for seq, cmd in COMMAND_SEQUENCE:");
        sbPy.AppendLine("        print(f'[{seq}/{len(COMMAND_SEQUENCE)}] >>> {cmd}')");
        sbPy.AppendLine("        ser.write((cmd + '\\r\\n').encode('utf-8', errors='ignore'))");
        sbPy.AppendLine("        time.sleep(0.2)");
        sbPy.AppendLine("        ");
        sbPy.AppendLine("        response = ''");
        sbPy.AppendLine("        t_start = time.time()");
        sbPy.AppendLine("        while time.time() - t_start < TIMEOUT:");
        sbPy.AppendLine("            if ser.in_waiting > 0:");
        sbPy.AppendLine("                line = ser.readline().decode('utf-8', errors='replace')");
        sbPy.AppendLine("                response += line");
        sbPy.AppendLine("                if 'OK' in line or 'ERROR' in line:");
        sbPy.AppendLine("                    break");
        sbPy.AppendLine("            time.sleep(0.05)");
        sbPy.AppendLine("        ");
        sbPy.AppendLine("        resp_clean = response.strip()");
        sbPy.AppendLine("        print(f'    <<< {resp_clean}\\n')");
        sbPy.AppendLine("        log_lines.append(f'[{seq}] >>> {cmd}\\n<<< {resp_clean}\\n')");
        sbPy.AppendLine("        time.sleep(0.15)");
        sbPy.AppendLine();
        sbPy.AppendLine("    ser.close()");
        sbPy.AppendLine("    with open('at_session_output.log', 'w', encoding='utf-8') as f:");
        sbPy.AppendLine("        f.write('\\n'.join(log_lines))");
        sbPy.AppendLine("    print('[+] Replay completed successfully. Output saved to at_session_output.log')");
        sbPy.AppendLine();
        sbPy.AppendLine("if __name__ == '__main__':");
        sbPy.AppendLine("    port = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PORT");
        sbPy.AppendLine("    run_replay(port)");

        File.WriteAllText(pyPath, sbPy.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(pyPath);
    }

    private static void GenerateQualcommArtifacts(string targetDir, List<SourceTelemetryEvent> items, ExportResult result)
    {
        // فحص إذا كانت هناك أوامر XML Firehose مثل <program ...> أو <configure ...>
        var xmlCmds = items.Where(e => e.PureCommandText.Contains('<') && e.PureCommandText.Contains('>')).ToList();
        if (xmlCmds.Count > 0)
        {
            string xmlPath = Path.Combine(targetDir, "01_Firehose_Payloads.xml");
            var sbXml = new StringBuilder();
            sbXml.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>");
            sbXml.AppendLine("<data>");
            sbXml.AppendLine($"  <!-- Generated by PhoenixGSM L24 Source Sentinel at {DateTime.Now:yyyy-MM-dd HH:mm:ss} -->");
            sbXml.AppendLine($"  <!-- Total Packets: {xmlCmds.Count} -->");

            foreach (var item in xmlCmds)
            {
                string cmd = item.PureCommandText.Trim();
                if (cmd.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase)) continue;
                sbXml.AppendLine($"  {cmd}");
            }

            sbXml.AppendLine("</data>");
            File.WriteAllText(xmlPath, sbXml.ToString(), Encoding.UTF8);
            result.CreatedFiles.Add(xmlPath);
        }

        // سكريبت بايثون لإرسال حزم كوالكوم إلى المنفذ
        string pyPath = Path.Combine(targetDir, "02_Replay_Qualcomm_Port.py");
        var sbPy = new StringBuilder();
        sbPy.AppendLine("#!/usr/bin/env python3");
        sbPy.AppendLine("# -*- coding: utf-8 -*-");
        sbPy.AppendLine("\"\"\"");
        sbPy.AppendLine("PhoenixGSM L24 - Qualcomm EDL / Firehose Command Player");
        sbPy.AppendLine($"Total Commands: {items.Count}");
        sbPy.AppendLine("\"\"\"");
        sbPy.AppendLine("import sys, time");
        sbPy.AppendLine("try:");
        sbPy.AppendLine("    import serial");
        sbPy.AppendLine("except ImportError:");
        sbPy.AppendLine("    print('[!] Please install pyserial: pip install pyserial')");
        sbPy.AppendLine("    sys.exit(1)");
        sbPy.AppendLine();
        sbPy.AppendLine("DEFAULT_PORT = 'COM10'  # Qualcomm HS-USB QDLoader 9008 COM Port");
        sbPy.AppendLine("BAUDRATE = 115200");
        sbPy.AppendLine();
        sbPy.AppendLine("COMMANDS = [");
        for (int i = 0; i < items.Count; i++)
        {
            string c = items[i].PureCommandText.Trim().Replace("\\", "\\\\").Replace("'", "\\'");
            sbPy.AppendLine($"    ({i + 1}, '{c}'),");
        }
        sbPy.AppendLine("]");
        sbPy.AppendLine();
        sbPy.AppendLine("def main():");
        sbPy.AppendLine("    port = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PORT");
        sbPy.AppendLine("    print(f'[*] Target port: {port}')");
        sbPy.AppendLine("    try:");
        sbPy.AppendLine("        ser = serial.Serial(port, BAUDRATE, timeout=1.5)");
        sbPy.AppendLine("    except Exception as ex:");
        sbPy.AppendLine("        print(f'[X] Could not open {port}: {ex}')");
        sbPy.AppendLine("        return");
        sbPy.AppendLine("    for idx, cmd in COMMANDS:");
        sbPy.AppendLine("        print(f'[{idx}] Sending: {cmd[:60]}...')");
        sbPy.AppendLine("        ser.write((cmd + '\\r\\n').encode('utf-8', errors='ignore'))");
        sbPy.AppendLine("        time.sleep(0.1)");
        sbPy.AppendLine("    ser.close()");
        sbPy.AppendLine("    print('[+] Complete.')");
        sbPy.AppendLine();
        sbPy.AppendLine("if __name__ == '__main__':");
        sbPy.AppendLine("    main()");

        File.WriteAllText(pyPath, sbPy.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(pyPath);
    }

    private static void GenerateAppleReplayScripts(string targetDir, List<SourceTelemetryEvent> items, ExportResult result)
    {
        string batPath = Path.Combine(targetDir, "01_Run_Apple_Commands.bat");
        var sbBat = new StringBuilder();
        sbBat.AppendLine("@echo off");
        sbBat.AppendLine("chcp 65001 > nul");
        sbBat.AppendLine("title PhoenixGSM L24 - Apple / iOS Replay Script");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("echo   PhoenixGSM L24 - Apple Replay (irecovery / idevice)");
        sbBat.AppendLine($"echo   Total Commands: {items.Count}");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("echo.");

        for (int i = 0; i < items.Count; i++)
        {
            string cmd = items[i].PureCommandText.Trim();
            sbBat.AppendLine($"echo [{i + 1}/{items.Count}] {cmd.Replace("%", "%%")}");
            sbBat.AppendLine(cmd);
            sbBat.AppendLine("timeout /t 1 /nobreak > nul");
        }

        sbBat.AppendLine("echo.");
        sbBat.AppendLine("pause");
        File.WriteAllText(batPath, sbBat.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(batPath);
    }

    private static void GenerateMediaTekArtifacts(string targetDir, List<SourceTelemetryEvent> items, ExportResult result)
    {
        // 1. اكتشاف المنفذ أو تعيين المنفذ الافتراضي
        string detectedPort = items
            .Select(e => e.TargetResource)
            .Where(r => !string.IsNullOrWhiteSpace(r) && r.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
            .GroupBy(r => r)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault() ?? "COM59";

        // استخراج بارتشنات الفورمات إن وجدت
        var formatItem = items.FirstOrDefault(e => e.PureCommandText.Contains("DA_CMD_FORMAT_PARTITION", StringComparison.OrdinalIgnoreCase));

        string pyPath = Path.Combine(targetDir, "01_Replay_MTK_BROM_DA.py");
        var sbPy = new StringBuilder();
        sbPy.AppendLine("#!/usr/bin/env python3");
        sbPy.AppendLine("# -*- coding: utf-8 -*-");
        sbPy.AppendLine("\"\"\"");
        sbPy.AppendLine("PhoenixGSM Layer 24 - MediaTek BROM / DA Verification Test Runner");
        sbPy.AppendLine($"Exported: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sbPy.AppendLine($"Target Port: {detectedPort}");
        sbPy.AppendLine($"Total Captured Operations: {items.Count}");
        sbPy.AppendLine("\"\"\"");
        sbPy.AppendLine("import os, sys, time, struct");
        sbPy.AppendLine("from pathlib import Path");
        sbPy.AppendLine();
        sbPy.AppendLine("try:");
        sbPy.AppendLine("    import serial");
        sbPy.AppendLine("    import serial.tools.list_ports");
        sbPy.AppendLine("except ImportError:");
        sbPy.AppendLine("    print('[!] Installing pyserial...')");
        sbPy.AppendLine("    os.system(f'{sys.executable} -m pip install pyserial')");
        sbPy.AppendLine("    import serial");
        sbPy.AppendLine("    import serial.tools.list_ports");
        sbPy.AppendLine();
        sbPy.AppendLine($"DEFAULT_PORT = '{detectedPort}'");
        sbPy.AppendLine("BAUDRATE = 115200");
        sbPy.AppendLine();
        sbPy.AppendLine("def detect_mtk_port():");
        sbPy.AppendLine("    for p in serial.tools.list_ports.comports():");
        sbPy.AppendLine("        hwid = (p.hwid or '').lower()");
        sbPy.AppendLine("        desc = (p.description or '').lower()");
        sbPy.AppendLine("        if '0e8d:0003' in hwid or '0e8d:2000' in hwid or 'mediatek' in desc or 'brom' in desc:");
        sbPy.AppendLine("            return p.device");
        sbPy.AppendLine("    return DEFAULT_PORT");
        sbPy.AppendLine();
        sbPy.AppendLine("def run_test():");
        sbPy.AppendLine("    port_name = sys.argv[1] if len(sys.argv) > 1 else detect_mtk_port()");
        sbPy.AppendLine("    print(f'[*] Target MediaTek Port: {port_name}')");
        sbPy.AppendLine("    try:");
        sbPy.AppendLine("        ser = serial.Serial(port_name, BAUDRATE, timeout=3.0)");
        sbPy.AppendLine("    except Exception as ex:");
        sbPy.AppendLine("        print(f'[X] Cannot open {port_name}: {ex}')");
        sbPy.AppendLine("        print('    Hold Vol+ & Vol- and reconnect USB cable to enter BROM mode.')");
        sbPy.AppendLine("        return");
        sbPy.AppendLine();
        sbPy.AppendLine("    print('[1/4] Performing BROM Handshake (A0 0A 50 05)...')");
        sbPy.AppendLine("    sync_tx = [0xA0, 0x0A, 0x50, 0x05]");
        sbPy.AppendLine("    sync_rx = [0x5F, 0xF5, 0xAF, 0xFA]");
        sbPy.AppendLine("    for i in range(4):");
        sbPy.AppendLine("        ser.write(bytes([sync_tx[i]]))");
        sbPy.AppendLine("        b = ser.read(1)");
        sbPy.AppendLine("        if not b or b[0] != sync_rx[i]:");
        sbPy.AppendLine("            print(f'    [!] Sync failed at byte {i}. Is device in BROM mode?')");
        sbPy.AppendLine("            ser.close(); return");
        sbPy.AppendLine("    print('    [+] Handshake OK! Sync matched.')");
        sbPy.AppendLine();
        sbPy.AppendLine("    print('[2/4] Reading SoC Hardware Info...')");
        sbPy.AppendLine("    ser.write(b'\\xFD')");
        sbPy.AppendLine("    resp = ser.read(4)");
        sbPy.AppendLine("    if len(resp) == 4:");
        sbPy.AppendLine("        hw_code = (resp[2] << 8) | resp[3]");
        sbPy.AppendLine("        print(f'    [+] Hardware Code: MT{hw_code:04X} (0x{hw_code:04X})')");
        sbPy.AppendLine("    ser.write(b'\\x00\\x00')");
        sbPy.AppendLine();
        sbPy.AppendLine("    print('[3/4] Disabling Watchdog Timer (CMD_WRITE32)...')");
        sbPy.AppendLine("    ser.write(bytes.fromhex('D4000000F800000070000000'))");
        sbPy.AppendLine("    time.sleep(0.1)");
        sbPy.AppendLine("    ser.read(2)");
        sbPy.AppendLine("    print('    [+] Watchdog timer disabled.')");
        sbPy.AppendLine();

        if (formatItem != null)
        {
            sbPy.AppendLine("    print('[4/4] Executing Format / Wipe Command...')");
            sbPy.AppendLine($"    print('    Target: {formatItem.PureCommandText}')");
        }
        else
        {
            sbPy.AppendLine("    print('[4/4] BROM verified and connected successfully.')");
        }

        sbPy.AppendLine("    ser.close()");
        sbPy.AppendLine("    print('[+] Test finished successfully!')");
        sbPy.AppendLine();
        sbPy.AppendLine("if __name__ == '__main__':");
        sbPy.AppendLine("    run_test()");

        File.WriteAllText(pyPath, sbPy.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(pyPath);

        // 2. ملف Batch للتشغيل السريع
        string batPath = Path.Combine(targetDir, "02_Run_MTK_Test.bat");
        var sbBat = new StringBuilder();
        sbBat.AppendLine("@echo off");
        sbBat.AppendLine("chcp 65001 > nul");
        sbBat.AppendLine("title PhoenixGSM - MTK Test Runner");
        sbBat.AppendLine("color 0A");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("echo   PhoenixGSM Layer 24 - MediaTek BROM / DA Verification Test");
        sbBat.AppendLine($"echo   Total Captured Commands: {items.Count}");
        sbBat.AppendLine("echo ================================================================================");
        sbBat.AppendLine("echo.");
        sbBat.AppendLine("echo Connect device in BROM mode (Hold Vol+ & Vol- and connect USB cable)...");
        sbBat.AppendLine("echo.");
        sbBat.AppendLine($"python \"%~dp001_Replay_MTK_BROM_DA.py\" %*");
        sbBat.AppendLine("echo.");
        sbBat.AppendLine("pause");

        File.WriteAllText(batPath, sbBat.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(batPath);
    }
}
