using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    /// <summary>
    /// TEST 48: Pre-Push Host File Snapshotting & Rapid Deletion Resilience (Vector A).
    /// Intercepts "adb push <local> <remote>" commands and snaps local binary files
    /// with micro-retry before GSM tools delete them from %TEMP%.
    /// </summary>
    public static bool Test48_HostPrePushFileSnapshotting()
    {
        string tempTestDir = Path.Combine(Path.GetTempPath(), "PhoenixOmniTest_48_" + Guid.NewGuid().ToString("N"));
        string customVaultDir = Path.Combine(tempTestDir, "Vault");
        Directory.CreateDirectory(tempTestDir);
        Directory.CreateDirectory(customVaultDir);

        try
        {
            using var bus = new OmniTraceEventBus();
            using var sensor = new AdbPushArtifactSensor(bus, customVaultDir);
            sensor.Start();

            // 1. Synthesize an ELF exploit executable staged in host %TEMP%
            string localFilePath = Path.Combine(tempTestDir, "athun");
            byte[] elfBytes = CreateSyntheticElf32ArmBinary();
            File.WriteAllBytes(localFilePath, elfBytes);

            PushedArtifactInfo? capturedArtifact = null;
            var captureWait = new ManualResetEventSlim(false);
            sensor.OnArtifactCaptured += artifact =>
            {
                capturedArtifact = artifact;
                captureWait.Set();
            };

            // 2. Test command-line parsing of complex quoted push invocation
            string cmdLine = $"\"C:\\Tools\\adb.exe\" -s RF8M12345 push \"{localFilePath}\" /data/local/tmp/athun";
            bool parseOk = AdbPushArtifactSensor.TryParseAdbPushCommand(cmdLine, out string parsedSrc, out string parsedDst);
            if (!parseOk || parsedSrc != localFilePath || parsedDst != "/data/local/tmp/athun")
            {
                Console.WriteLine($"[FAIL] TryParseAdbPushCommand failed: src='{parsedSrc}', dst='{parsedDst}'");
                return false;
            }

            // 3. Dispatch simulated logical command on the event bus
            var logicalCmd = bus.Correlation.Correlate(
                cmdLine,
                KnownProtocol.ADB,
                "push",
                TransportType.BULK,
                "RF8M12345",
                "CMD_SESSION_01",
                PacketDirection.HOST_TO_DEVICE,
                [101],
                ["HASH_CMD"],
                confidence: 0.99,
                suspectedPid: 5412,
                suspectedToolName: "GSM_Tool_Pro.exe"
            );
            logicalCmd.Details["CommandLine"] = cmdLine;

            bus.ReportLogicalCommand(logicalCmd);

            // Wait for sensor interception
            bool signaled = captureWait.Wait(2000);
            if (!signaled || capturedArtifact == null)
            {
                Console.WriteLine("[FAIL] Sensor did not capture pushed artifact from bus logical command!");
                return false;
            }

            // 4. Immediately delete staged file (simulating rapid cleanup by GSM servicing tool)
            try
            {
                File.Delete(localFilePath);
            }
            catch { }

            // 5. Verify captured artifact in vault
            if (capturedArtifact.FileName != "athun")
            {
                Console.WriteLine($"[FAIL] Incorrect file name: {capturedArtifact.FileName}");
                return false;
            }

            if (capturedArtifact.TargetDevicePath != "/data/local/tmp/athun")
            {
                Console.WriteLine($"[FAIL] Incorrect target path: {capturedArtifact.TargetDevicePath}");
                return false;
            }

            if (capturedArtifact.FileClassification != "ELF_EXECUTABLE")
            {
                Console.WriteLine($"[FAIL] File not classified as ELF: {capturedArtifact.FileClassification}");
                return false;
            }

            if (!capturedArtifact.IsExecutableOrExploit)
            {
                Console.WriteLine("[FAIL] ELF not flagged as executable/exploit!");
                return false;
            }

            if (capturedArtifact.SourceVector != "HostPrePush")
            {
                Console.WriteLine($"[FAIL] Expected HostPrePush vector, got: {capturedArtifact.SourceVector}");
                return false;
            }

            // 6. Verify stored vault file and manifest on disk
            if (!File.Exists(capturedArtifact.VaultFilePath))
            {
                Console.WriteLine($"[FAIL] Vault file does not exist: {capturedArtifact.VaultFilePath}");
                return false;
            }

            byte[] vaultBytes = File.ReadAllBytes(capturedArtifact.VaultFilePath);
            if (vaultBytes.Length != elfBytes.Length || Convert.ToHexString(SHA256.HashData(vaultBytes)) != capturedArtifact.Sha256)
            {
                Console.WriteLine("[FAIL] Vault file hash mismatch!");
                return false;
            }

            if (!File.Exists(capturedArtifact.VaultManifestPath))
            {
                Console.WriteLine($"[FAIL] Forensics manifest JSON does not exist: {capturedArtifact.VaultManifestPath}");
                return false;
            }

            string manifestJson = File.ReadAllText(capturedArtifact.VaultManifestPath);
            if (!manifestJson.Contains("GSM_Tool_Pro.exe") || !manifestJson.Contains("ELF_EXECUTABLE"))
            {
                Console.WriteLine($"[FAIL] Manifest JSON missing critical forensics attributes: {manifestJson}");
                return false;
            }

            return true;
        }
        finally
        {
            try { Directory.Delete(tempTestDir, recursive: true); } catch { }
        }
    }

    /// <summary>
    /// TEST 49: In-Flight ADB Sync Wire Reassembly (Vector B).
    /// Reconstructs binaries and files transferred directly from memory / in-process tools
    /// using raw ADB sync packets (SEND -> DATA chunks -> DONE) with zero host disk trace.
    /// </summary>
    public static bool Test49_AdbSyncWireReassembly()
    {
        string tempTestDir = Path.Combine(Path.GetTempPath(), "PhoenixOmniTest_49_" + Guid.NewGuid().ToString("N"));
        string customVaultDir = Path.Combine(tempTestDir, "Vault");
        Directory.CreateDirectory(tempTestDir);
        Directory.CreateDirectory(customVaultDir);

        try
        {
            using var bus = new OmniTraceEventBus();
            using var sensor = new AdbPushArtifactSensor(bus, customVaultDir);
            sensor.Start();

            PushedArtifactInfo? capturedArtifact = null;
            var captureWait = new ManualResetEventSlim(false);
            sensor.OnArtifactCaptured += artifact =>
            {
                capturedArtifact = artifact;
                captureWait.Set();
            };

            // 1. Synthesize an in-memory Android DEX bytecode payload
            byte[] dexBytes = CreateSyntheticDexPayload(payloadSize: 32768);
            string targetDevicePath = "/data/local/tmp/classes.dex";

            // 2. Stream through in-flight wire simulation (channel ID 0x1337)
            var result = sensor.SimulateSyncStream(
                channelId: 0x1337,
                remoteTargetPath: targetDevicePath,
                fileBytes: dexBytes,
                toolName: "Octopus_Samsung.exe",
                pid: 7720,
                serial: "SM-G998B-SERIAL"
            );

            bool signaled = captureWait.Wait(2000);
            if (!signaled || capturedArtifact == null)
            {
                Console.WriteLine("[FAIL] Wire reassembler did not emit completed artifact!");
                return false;
            }

            // 3. Verify reconstructed artifact forensics
            if (capturedArtifact.FileName != "classes.dex")
            {
                Console.WriteLine($"[FAIL] Unexpected file name: {capturedArtifact.FileName}");
                return false;
            }

            if (capturedArtifact.TargetDevicePath != targetDevicePath)
            {
                Console.WriteLine($"[FAIL] Unexpected target path: {capturedArtifact.TargetDevicePath}");
                return false;
            }

            if (capturedArtifact.FileClassification != "ANDROID_DEX")
            {
                Console.WriteLine($"[FAIL] File not classified as DexBytecode: {capturedArtifact.FileClassification}");
                return false;
            }

            if (capturedArtifact.SourceVector != "AdbSyncWire")
            {
                Console.WriteLine($"[FAIL] Unexpected source vector: {capturedArtifact.SourceVector}");
                return false;
            }

            if (capturedArtifact.ProcessName != "Octopus_Samsung.exe" || capturedArtifact.ProcessId != 7720)
            {
                Console.WriteLine($"[FAIL] Attribution mismatch: {capturedArtifact.ProcessName} / {capturedArtifact.ProcessId}");
                return false;
            }

            if (!capturedArtifact.Attributes.TryGetValue("RemoteMode", out var mode) || mode != "33261")
            {
                Console.WriteLine($"[FAIL] RemoteMode attribute missing or invalid: {mode}");
                return false;
            }

            // 4. Verify disk retention and bit-for-bit integrity
            if (!File.Exists(capturedArtifact.VaultFilePath))
            {
                Console.WriteLine($"[FAIL] Reconstructed file missing from vault: {capturedArtifact.VaultFilePath}");
                return false;
            }

            byte[] vaultBytes = File.ReadAllBytes(capturedArtifact.VaultFilePath);
            if (vaultBytes.Length != dexBytes.Length)
            {
                Console.WriteLine($"[FAIL] Length mismatch: original={dexBytes.Length}, vault={vaultBytes.Length}");
                return false;
            }

            string expectedSha = Convert.ToHexString(SHA256.HashData(dexBytes));
            if (capturedArtifact.Sha256 != expectedSha)
            {
                Console.WriteLine($"[FAIL] SHA256 mismatch: expected={expectedSha}, actual={capturedArtifact.Sha256}");
                return false;
            }

            return true;
        }
        finally
        {
            try { Directory.Delete(tempTestDir, recursive: true); } catch { }
        }
    }

    /// <summary>
    /// TEST 50: Smart Binary Classification & CAS SHA-256 Deduplication.
    /// Validates zero-copy deduplication, shell script exploit detection, APK classification,
    /// and ensures identical binaries pushed across different vectors share CAS storage.
    /// </summary>
    public static bool Test50_ClassificationAndCasDeduplication()
    {
        string tempTestDir = Path.Combine(Path.GetTempPath(), "PhoenixOmniTest_50_" + Guid.NewGuid().ToString("N"));
        string customVaultDir = Path.Combine(tempTestDir, "Vault");
        Directory.CreateDirectory(tempTestDir);
        Directory.CreateDirectory(customVaultDir);

        try
        {
            var vault = new AdbPushArtifactVault(customVaultDir);

            // 1. Test Shell Script Exploit Classifier (shebang + root commands)
            string shellContent = "#!/system/bin/sh\nchmod 777 /data/local/tmp/athun\n/data/local/tmp/athun --root\n";
            byte[] shellBytes = Encoding.UTF8.GetBytes(shellContent);
            var shellArtifact = vault.StoreArtifact(
                shellBytes,
                "inject.sh",
                "/data/local/tmp/inject.sh",
                "ChimeraTool.exe",
                3344,
                "HostPrePush"
            );

            if (shellArtifact.FileClassification != "SHELL_SCRIPT" || !shellArtifact.IsExecutableOrExploit)
            {
                Console.WriteLine($"[FAIL] Shell exploit not properly classified: {shellArtifact.FileClassification}, IsExec={shellArtifact.IsExecutableOrExploit}");
                return false;
            }

            // 2. Test Synthetic APK Package Classifier (PK\x03\x04 + AndroidManifest.xml)
            byte[] apkBytes = CreateSyntheticApkPayload();
            var apkArtifact = vault.StoreArtifact(
                apkBytes,
                "magisk_agent.apk",
                "/data/local/tmp/magisk_agent.apk",
                "UnlockTool.exe",
                9911,
                "AdbSyncWire"
            );

            if (apkArtifact.FileClassification != "ANDROID_APK" || !apkArtifact.IsExecutableOrExploit)
            {
                Console.WriteLine($"[FAIL] APK package not properly classified: {apkArtifact.FileClassification}");
                return false;
            }

            // 3. Test CAS (Content-Addressable Storage) SHA-256 Deduplication
            // Push same ELF binary twice: First through Vector A, Second through Vector B
            byte[] binary = CreateSyntheticElf32ArmBinary();

            var firstArtifact = vault.StoreArtifact(
                binary,
                "athun",
                "/data/local/tmp/athun",
                "SamFW_Tool.exe",
                5512,
                "HostPrePush"
            );

            if (firstArtifact.IsDeduplicated)
            {
                Console.WriteLine("[FAIL] First artifact should NOT be marked deduplicated!");
                return false;
            }

            var secondArtifact = vault.StoreArtifact(
                binary,
                "athun_renamed",
                "/data/local/tmp/athun_renamed",
                "AnotherGSMTool.exe",
                6621,
                "AdbSyncWire"
            );

            if (!secondArtifact.IsDeduplicated)
            {
                Console.WriteLine("[FAIL] Second identical artifact MUST be marked as deduplicated!");
                return false;
            }

            if (vault.DeduplicatedCount != 1)
            {
                Console.WriteLine($"[FAIL] Expected DeduplicatedCount=1, got {vault.DeduplicatedCount}");
                return false;
            }

            // Verify both point to identical vault physical file on disk
            if (firstArtifact.VaultFilePath != secondArtifact.VaultFilePath)
            {
                Console.WriteLine($"[FAIL] CAS Storage failure: Vault file paths are different!\n1: {firstArtifact.VaultFilePath}\n2: {secondArtifact.VaultFilePath}");
                return false;
            }

            if (firstArtifact.Sha256 != secondArtifact.Sha256)
            {
                Console.WriteLine("[FAIL] CAS Hashes must match exactly!");
                return false;
            }

            // Verify that only ONE physical binary file was written to disk for this hash
            if (!File.Exists(firstArtifact.VaultFilePath))
            {
                Console.WriteLine($"[FAIL] Vault file does not exist: {firstArtifact.VaultFilePath}");
                return false;
            }

            int matchingShaFiles = 0;
            string prefix = firstArtifact.Sha256[..12];
            foreach (var f in Directory.GetFiles(customVaultDir))
            {
                if (!f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) && Path.GetFileName(f).Contains(prefix))
                {
                    matchingShaFiles++;
                }
            }

            if (matchingShaFiles != 1)
            {
                Console.WriteLine($"[FAIL] Expected 1 physical binary file in vault for this SHA, found {matchingShaFiles}");
                return false;
            }

            return true;
        }
        finally
        {
            try { Directory.Delete(tempTestDir, recursive: true); } catch { }
        }
    }

    #region Synthetic Payload Generators

    private static byte[] CreateSyntheticElf32ArmBinary()
    {
        // 52-byte ELF32 header:
        // Magic: 0x7F, 'E', 'L', 'F'
        // Class: 1 (ELFCLASS32)
        // Endian: 1 (ELFDATA2LSB)
        // Version: 1
        // OS ABI: 0 (System V)
        // Type: 2 (ET_EXEC)
        // Machine: 40 (0x0028 -> EM_ARM)
        byte[] buffer = new byte[256];
        buffer[0] = 0x7F;
        buffer[1] = (byte)'E';
        buffer[2] = (byte)'L';
        buffer[3] = (byte)'F';
        buffer[4] = 1; // 32-bit
        buffer[5] = 1; // Little-endian
        buffer[6] = 1; // ELF Version
        buffer[16] = 2; // ET_EXEC
        buffer[18] = 0x28; // EM_ARM (40)
        buffer[19] = 0x00;

        // Fill remaining with synthetic ARM instructions
        for (int i = 52; i < buffer.Length; i++)
        {
            buffer[i] = (byte)(i % 251);
        }

        return buffer;
    }

    private static byte[] CreateSyntheticDexPayload(int payloadSize)
    {
        byte[] buffer = new byte[payloadSize];
        // "dex\n035\0"
        byte[] dexMagic = [0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00];
        Array.Copy(dexMagic, 0, buffer, 0, dexMagic.Length);

        for (int i = dexMagic.Length; i < buffer.Length; i++)
        {
            buffer[i] = (byte)((i * 3) % 256);
        }

        return buffer;
    }

    private static byte[] CreateSyntheticApkPayload()
    {
        // ZIP / APK header: PK\x03\x04
        byte[] zipHeader = [0x50, 0x4B, 0x03, 0x04];
        string entryName = "AndroidManifest.xml";
        byte[] entryBytes = Encoding.UTF8.GetBytes(entryName);

        using var ms = new MemoryStream();
        ms.Write(zipHeader);
        ms.Write(new byte[22]); // dummy fields
        ms.Write(BitConverter.GetBytes((ushort)entryBytes.Length));
        ms.Write(new byte[2]); // extra field len
        ms.Write(entryBytes);
        ms.Write(Encoding.UTF8.GetBytes("<manifest package=\"com.phoenix.exploit\"></manifest>"));
        return ms.ToArray();
    }

    /// <summary>
    /// TEST 86: Smart File Push Archiver Multi-Vector Recovery & Single-File Preservation.
    /// Verifies wire stream reassembly with split headers, DATA/DONE stripping,
    /// asynchronous background processing, and strictly saving ONE clean file with original name.
    /// </summary>
    public static bool Test86_SmartFilePushArchiverMultiVector()
    {
        using var archiver = new SmartFilePushArchiver();
        var capturedRecords = new System.Collections.Concurrent.ConcurrentBag<CapturedPushedFileRecord>();
        var captureWait = new AutoResetEvent(false);

        archiver.OnFileArchivedAsync += (rec, ep) =>
        {
            capturedRecords.Add(rec);
            captureWait.Set();
        };

        // 1. Test Split SEND Header across two packets with mode 33206 (e.g. R2.zip)
        // Packet 1: Partial SEND command
        byte[] p1 = Encoding.ASCII.GetBytes("SEND ");
        bool res1 = archiver.ProcessOutboundSyncOrBulkChunk(p1, "OUT", "0x01", (uint)p1.Length, out var rec1);
        if (res1 || rec1 != null) return false;

        // Packet 2: Path, mode 33206, DATA header with synthetic zip payload and DONE trailer
        using var zipMs = new MemoryStream();
        using (var za = new System.IO.Compression.ZipArchive(zipMs, System.IO.Compression.ZipArchiveMode.Create, true))
        {
            var entry = za.CreateEntry("payload.sh");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("#!/system/bin/sh\necho pwned\n");
        }
        byte[] zipPayload = zipMs.ToArray();

        using var p2Ms = new MemoryStream();
        p2Ms.Write(Encoding.ASCII.GetBytes("/data/local/tmp/R2.zip,33206"));
        p2Ms.Write(Encoding.ASCII.GetBytes("DATA"));
        p2Ms.Write(BitConverter.GetBytes((uint)zipPayload.Length));
        p2Ms.Write(zipPayload);
        p2Ms.Write(Encoding.ASCII.GetBytes("DONE"));
        p2Ms.Write(BitConverter.GetBytes(1700000000u)); // mtime
        byte[] p2 = p2Ms.ToArray();

        bool res2 = archiver.ProcessOutboundSyncOrBulkChunk(p2, "OUT", "0x01", (uint)p2.Length, out _);
        if (!res2) return false;

        // Wait for background worker to save R2.zip
        if (!captureWait.WaitOne(3000)) return false;
        var rec2 = capturedRecords.FirstOrDefault(r => r.FileName == "R2.zip");
        if (rec2 == null || rec2.FileSizeBytes != zipPayload.Length) return false;
        if (!File.Exists(rec2.LocalSavedPath)) return false;

        // 2. Test Single Clean File Preservation on Extensionless APK (/data/local/tmp/SRV4)
        byte[] apkPayload = CreateSyntheticApkPayload();
        using var apkMs = new MemoryStream();
        apkMs.Write(Encoding.ASCII.GetBytes("SEND /data/local/tmp/SRV4,33188"));
        apkMs.Write(Encoding.ASCII.GetBytes("DATA"));
        apkMs.Write(BitConverter.GetBytes((uint)apkPayload.Length));
        apkMs.Write(apkPayload);
        apkMs.Write(Encoding.ASCII.GetBytes("DONE"));
        apkMs.Write(BitConverter.GetBytes(1700000000u));
        byte[] apkPacket = apkMs.ToArray();

        bool resApk = archiver.ProcessOutboundSyncOrBulkChunk(apkPacket, "OUT", "0x01", (uint)apkPacket.Length, out _);
        if (!resApk) return false;

        if (!captureWait.WaitOne(3000)) return false;
        var recApk = capturedRecords.FirstOrDefault(r => r.FileName == "SRV4");
        if (recApk == null || !File.Exists(recApk.LocalSavedPath) || recApk.FileSizeBytes != apkPayload.Length) return false;

        // 3. Test Auto-Flush on Shell command (e.g. chmod before DONE arrives)
        using var flushMs = new MemoryStream();
        flushMs.Write(Encoding.ASCII.GetBytes("SEND /data/local/tmp/AT,33188"));
        flushMs.Write(Encoding.ASCII.GetBytes("DATA"));
        byte[] elfPayload = CreateSyntheticElf32ArmBinary();
        flushMs.Write(BitConverter.GetBytes((uint)elfPayload.Length));
        flushMs.Write(elfPayload);
        byte[] flushPacket = flushMs.ToArray();

        archiver.ProcessOutboundSyncOrBulkChunk(flushPacket, "OUT", "0x01", (uint)flushPacket.Length, out _);
        if (!archiver.IsInsideTransfer) return false;

        // Simulating immediate chmod command
        archiver.CheckShellCommandForInlineFileOrFlush("shell:chmod 777 /data/local/tmp/AT", 1234, "SamFW.exe", out _);
        if (archiver.IsInsideTransfer) return false;

        if (!captureWait.WaitOne(3000)) return false;
        var recChmod = capturedRecords.FirstOrDefault(r => r.FileName == "AT");
        if (recChmod == null || recChmod.FileName != "AT" || !File.Exists(recChmod.LocalSavedPath)) return false;

        // 4. Test Inline Base64 File Push (echo '...' | base64 -d > /data/local/tmp/script.sh)
        string testScript = "#!/bin/sh\nid\n";
        string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(testScript));
        string b64Cmd = $"echo '{b64}' | base64 -d > /data/local/tmp/script.sh";
        archiver.CheckShellCommandForInlineFileOrFlush(b64Cmd, 5678, "adb.exe", out _);

        if (!captureWait.WaitOne(3000)) return false;
        var recB64 = capturedRecords.FirstOrDefault(r => r.FileName == "script.sh");
        if (recB64 == null || recB64.TargetDevicePath != "/data/local/tmp/script.sh" || recB64.CaptureVector != "Base64 Inline Stream") return false;

        return true;
    }

    #endregion
}
