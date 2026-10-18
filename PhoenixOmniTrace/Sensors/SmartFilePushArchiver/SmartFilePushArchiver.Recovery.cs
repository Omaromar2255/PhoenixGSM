using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class SmartFilePushArchiver
{
    #region P/Invoke Definitions for 64-Bit & 32-Bit Process RAM Carving
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    #endregion

    /// <summary>
    /// Starts an immediate, non-blocking background snapshot from Host Disk & Target Tool RAM
    /// at the exact moment the first DATA chunk starts flowing over USB.
    /// </summary>
    private void StartEagerMidTransferSnapshot(string targetPath, byte[]? signature, long estimatedSize)
    {
        if (string.IsNullOrWhiteSpace(targetPath) || _eagerSnapshotTask != null) return;
        string fileName = Path.GetFileName(targetPath);
        if (string.IsNullOrWhiteSpace(fileName)) return;

        byte[]? sigCopy = signature != null ? (byte[])signature.Clone() : null;
        long est = estimatedSize;

        _eagerSnapshotTask = Task.Run(() =>
        {
            byte[]? disk = TryRecoverFromHostDisk(fileName, sigCopy);
            if (disk != null && disk.Length > 0 && (est <= 0 || disk.Length >= est))
            {
                return disk;
            }

            byte[]? ram = TryCarveFileFromTargetProcessRam(sigCopy, est);
            if (ram != null && (disk == null || ram.Length > disk.Length))
            {
                return ram;
            }

            return disk;
        });
    }

    /// <summary>
    /// Searches the active GSM tool's installation directory (all subdirectories) as well as %TEMP%
    /// for either an exact filename match or a recent temporary file whose header matches HeaderSignature.
    /// Supports files as small as 1 byte (e.g. 72-byte ASKSW.xml).
    /// </summary>
    private static byte[]? TryRecoverFromHostDisk(string fileName, byte[]? headerSig)
    {
        if (string.IsNullOrWhiteSpace(fileName) || IsIgnoredNoiseFile(fileName)) return null;

        var rootDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(),
            Environment.CurrentDirectory,
            AppDomain.CurrentDomain.BaseDirectory,
            @"C:\Program Files (x86)\KEY-Tool",
            @"C:\Program Files\KEY-Tool",
            @"C:\UnlockTool"
        };

        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Environment.ProcessId) continue;
                    string pn = p.ProcessName.ToLowerInvariant();
                    if (pn.Contains("key") || pn.Contains("tool") || pn.Contains("adb") ||
                        pn.Contains("samfw") || pn.Contains("chimera") || pn.Contains("unlock") ||
                        pn.Contains("odin") || pn.Contains("gsm"))
                    {
                        string? exe = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(exe))
                        {
                            string? d = Path.GetDirectoryName(exe);
                            if (!string.IsNullOrEmpty(d)) rootDirs.Add(d);
                        }
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        // Pass 1: Recursive filename search across tool folders (finds retail\ASKSW.xml at any depth!)
        foreach (string dir in rootDirs)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;

                string directCandidate = Path.Combine(dir, fileName);
                byte[]? directBytes = TryReadSharedFile(directCandidate, headerSig);
                if (directBytes != null) return directBytes;

                var enumOpts = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 4,
                    MatchCasing = MatchCasing.CaseInsensitive
                };

                foreach (string matchPath in Directory.EnumerateFiles(dir, fileName, enumOpts))
                {
                    byte[]? subBytes = TryReadSharedFile(matchPath, headerSig);
                    if (subBytes != null) return subBytes;
                }
            }
            catch { }
        }

        // Pass 2: If the tool staged a randomly-named file in %TEMP% within the last 2 minutes, match by header signature (supports >= 4 bytes)
        if (headerSig != null && headerSig.Length >= 4)
        {
            try
            {
                string tempDir = Path.GetTempPath();
                DateTime cutoff = DateTime.UtcNow.AddMinutes(-2);
                int sigCheckLen = Math.Min(headerSig.Length, 32);
                byte[] headBuf = new byte[sigCheckLen];

                foreach (string file in Directory.EnumerateFiles(tempDir))
                {
                    try
                    {
                        if (IsIgnoredNoiseFile(file)) continue;
                        var fi = new FileInfo(file);
                        if (fi.LastWriteTimeUtc < cutoff || fi.Length < sigCheckLen || fi.Length > 128 * 1024 * 1024)
                            continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        if (fs.Read(headBuf, 0, sigCheckLen) == sigCheckLen &&
                            headBuf.AsSpan(0, sigCheckLen).SequenceEqual(headerSig.AsSpan(0, sigCheckLen)))
                        {
                            fs.Position = 0;
                            byte[] full = new byte[fi.Length];
                            if (fs.Read(full, 0, full.Length) == full.Length)
                                return full;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        return null;
    }

    private static byte[]? TryReadSharedFile(string path, byte[]? expectedHeader)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= 0 || fs.Length > 128 * 1024 * 1024) return null;

            byte[] buf = new byte[fs.Length];
            int total = 0;
            while (total < buf.Length)
            {
                int r = fs.Read(buf, total, buf.Length - total);
                if (r <= 0) break;
                total += r;
            }
            if (total != buf.Length) return null;

            if (expectedHeader != null && expectedHeader.Length >= 4 && buf.Length >= 4)
            {
                int checkLen = Math.Min(8, Math.Min(expectedHeader.Length, buf.Length));
                if (!buf.AsSpan(0, checkLen).SequenceEqual(expectedHeader.AsSpan(0, checkLen)))
                {
                    return null;
                }
            }

            return buf;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Fast, targeted 64-bit & 32-bit RAM carver.
    /// Supports small signatures (>= 4 bytes) and full 64-bit address space.
    /// </summary>
    public byte[]? TryCarveFileFromTargetProcessRam(byte[]? signature, long estimatedSize)
    {
        if (signature == null || signature.Length < 4) return null;

        int sigLen = Math.Min(signature.Length, 64);
        byte[] sigPattern = signature[..sigLen];

        var targetPids = new List<int>();

        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Environment.ProcessId) continue;
                    string pn = p.ProcessName.ToLowerInvariant();
                    if (pn.Contains("key") || pn.Contains("tool") || pn.Contains("samfw") ||
                        pn.Contains("unlock") || pn.Contains("chimera") || pn.Contains("odin") ||
                        pn.Contains("fastboot") || pn.Contains("gsm"))
                    {
                        if (!targetPids.Contains(p.Id)) targetPids.Insert(0, p.Id);
                    }
                    else if (pn.Contains("adb"))
                    {
                        if (!targetPids.Contains(p.Id)) targetPids.Add(p.Id);
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        foreach (int pid in _candidatePids.Keys)
        {
            if (!targetPids.Contains(pid)) targetPids.Add(pid);
        }

        byte[]? bestFound = null;

        foreach (int pid in targetPids)
        {
            IntPtr hProc = IntPtr.Zero;
            try
            {
                hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (hProc == IntPtr.Zero)
                {
                    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
                }
                if (hProc == IntPtr.Zero) continue;

                long currentAddr = 0x10000;
                long maxAddr = Environment.Is64BitOperatingSystem ? 0x00007FFFFFFF0000L : 0x7FFF0000L;
                uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                byte[] chunkBuf = new byte[256 * 1024];

                while (currentAddr < maxAddr)
                {
                    if (VirtualQueryEx(hProc, (IntPtr)currentAddr, out var mbi, mbiSize) == 0)
                        break;

                    long baseAddr = mbi.BaseAddress.ToInt64();
                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    bool isReadable = mbi.State == MEM_COMMIT &&
                                      (mbi.Protect & PAGE_NOACCESS) == 0 &&
                                      (mbi.Protect & PAGE_GUARD) == 0 &&
                                      (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
                                       mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READ ||
                                       mbi.Protect == PAGE_EXECUTE_READWRITE);

                    if (isReadable && regionSize >= sigLen && regionSize <= 128 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize)
                        {
                            int toRead = (int)Math.Min(chunkBuf.Length, regionSize - offset);
                            if (ReadProcessMemory(hProc, (IntPtr)(baseAddr + offset), chunkBuf, toRead, out int bytesRead) && bytesRead >= sigLen)
                            {
                                int searchOffset = 0;
                                while (searchOffset <= bytesRead - sigLen)
                                {
                                    int relIdx = IndexOfSequence(chunkBuf.AsSpan(searchOffset, bytesRead - searchOffset), sigPattern);
                                    if (relIdx < 0) break;

                                    int foundIdx = searchOffset + relIdx;
                                    long fileStartAddr = baseAddr + offset + foundIdx;
                                    long maxAvailableInRegion = regionSize - (offset + foundIdx);

                                    bool isWirePacketCopy = false;
                                    if (foundIdx >= 8 &&
                                        chunkBuf[foundIdx - 8] == (byte)'D' &&
                                        chunkBuf[foundIdx - 7] == (byte)'A' &&
                                        chunkBuf[foundIdx - 6] == (byte)'T' &&
                                        chunkBuf[foundIdx - 5] == (byte)'A')
                                    {
                                        isWirePacketCopy = true;
                                    }

                                    byte[]? carved = ReadExactFileFromProcessMemory(hProc, fileStartAddr, maxAvailableInRegion, estimatedSize, sigPattern);
                                    if (carved != null && carved.Length > (bestFound?.Length ?? 0))
                                    {
                                        bestFound = carved;
                                        if (!isWirePacketCopy && (estimatedSize <= 0 || bestFound.Length >= estimatedSize))
                                        {
                                            return bestFound;
                                        }
                                    }

                                    searchOffset = foundIdx + sigLen;
                                }
                            }
                            if (toRead <= sigLen) break;
                            offset += toRead - sigLen;
                        }
                    }

                    long nextAddr = baseAddr + regionSize;
                    if (nextAddr <= currentAddr) break;
                    currentAddr = nextAddr;
                }
            }
            catch { }
            finally
            {
                if (hProc != IntPtr.Zero) CloseHandle(hProc);
            }
        }

        return bestFound;
    }

    private static byte[]? ReadExactFileFromProcessMemory(
        IntPtr hProc,
        long fileStartAddr,
        long maxAvailableInRegion,
        long estimatedSize,
        byte[] sigPattern)
    {
        int targetSize = 0;

        // 1. ELF Binary (0x7F 'E' 'L' 'F')
        if (sigPattern.Length >= 4 && sigPattern[0] == 0x7F && sigPattern[1] == 0x45 && sigPattern[2] == 0x4C && sigPattern[3] == 0x46)
        {
            byte[] elfHdr = new byte[64];
            if (ReadProcessMemory(hProc, (IntPtr)fileStartAddr, elfHdr, 64, out int hdrRead) && hdrRead >= 52)
            {
                bool is64 = elfHdr[4] == 2;
                long maxEnd = 0;

                if (is64 && hdrRead >= 64)
                {
                    ulong phoff = BitConverter.ToUInt64(elfHdr, 32);
                    ulong shoff = BitConverter.ToUInt64(elfHdr, 40);
                    ushort phentsize = BitConverter.ToUInt16(elfHdr, 54);
                    ushort phnum = BitConverter.ToUInt16(elfHdr, 56);
                    ushort shentsize = BitConverter.ToUInt16(elfHdr, 58);
                    ushort shnum = BitConverter.ToUInt16(elfHdr, 60);

                    if (shoff > 0 && shnum > 0 && shentsize > 0 && shnum <= 4096 && shentsize <= 256)
                    {
                        long shEnd = (long)(shoff + (ulong)(shentsize * shnum));
                        if (shEnd > 0 && shEnd <= 64 * 1024 * 1024) maxEnd = Math.Max(maxEnd, shEnd);
                    }

                    if (phoff > 0 && phnum > 0 && phentsize >= 56 && phnum <= 128)
                    {
                        byte[] phTable = new byte[phentsize * phnum];
                        if (ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + (long)phoff), phTable, phTable.Length, out int phRead) && phRead == phTable.Length)
                        {
                            for (int i = 0; i < phnum; i++)
                            {
                                int pPos = i * phentsize;
                                ulong pOffset = BitConverter.ToUInt64(phTable, pPos + 8);
                                ulong pFilesz = BitConverter.ToUInt64(phTable, pPos + 32);
                                long segEnd = (long)(pOffset + pFilesz);
                                if (segEnd > maxEnd && segEnd <= 64 * 1024 * 1024)
                                    maxEnd = segEnd;
                            }
                        }
                    }
                }
                else
                {
                    uint phoff = BitConverter.ToUInt32(elfHdr, 28);
                    uint shoff = BitConverter.ToUInt32(elfHdr, 32);
                    ushort phentsize = BitConverter.ToUInt16(elfHdr, 42);
                    ushort phnum = BitConverter.ToUInt16(elfHdr, 44);
                    ushort shentsize = BitConverter.ToUInt16(elfHdr, 46);
                    ushort shnum = BitConverter.ToUInt16(elfHdr, 48);

                    if (shoff > 0 && shnum > 0 && shentsize > 0 && shnum <= 4096 && shentsize <= 256)
                    {
                        long shEnd = shoff + (long)(shentsize * shnum);
                        if (shEnd > 0 && shEnd <= 64 * 1024 * 1024) maxEnd = Math.Max(maxEnd, shEnd);
                    }

                    if (phoff > 0 && phnum > 0 && phentsize >= 32 && phnum <= 128)
                    {
                        byte[] phTable = new byte[phentsize * phnum];
                        if (ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + phoff), phTable, phTable.Length, out int phRead) && phRead == phTable.Length)
                        {
                            for (int i = 0; i < phnum; i++)
                            {
                                int pPos = i * phentsize;
                                uint pOffset = BitConverter.ToUInt32(phTable, pPos + 4);
                                uint pFilesz = BitConverter.ToUInt32(phTable, pPos + 16);
                                long segEnd = pOffset + pFilesz;
                                if (segEnd > maxEnd && segEnd <= 64 * 1024 * 1024)
                                    maxEnd = segEnd;
                            }
                        }
                    }
                }

                if (maxEnd > 64 && maxEnd <= 64 * 1024 * 1024)
                {
                    targetSize = (int)maxEnd;
                }
            }
        }
        // 2. DEX Header ("dex\n03")
        else if (sigPattern.Length >= 8 && sigPattern[0] == 0x64 && sigPattern[1] == 0x65 && sigPattern[2] == 0x78 && sigPattern[3] == 0x0A)
        {
            byte[] dexHdr = new byte[36];
            if (ReadProcessMemory(hProc, (IntPtr)fileStartAddr, dexHdr, 36, out int dRead) && dRead == 36)
            {
                uint dSize = BitConverter.ToUInt32(dexHdr, 32);
                if (dSize > 36 && dSize <= 64 * 1024 * 1024)
                {
                    targetSize = (int)dSize;
                }
            }
        }
        // 3. ZIP / APK (0x50 0x4B 0x03 0x04)
        else if (sigPattern.Length >= 4 && sigPattern[0] == 0x50 && sigPattern[1] == 0x4B && sigPattern[2] == 0x03 && sigPattern[3] == 0x04)
        {
            int maxScanBytes = (int)Math.Min(Math.Max(maxAvailableInRegion, 32 * 1024 * 1024L), 64 * 1024 * 1024L);
            byte[] winBuf = new byte[512 * 1024];
            int scanned = 0;

            while (scanned < maxScanBytes)
            {
                int toRead = Math.Min(winBuf.Length, maxScanBytes - scanned);
                if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + scanned), winBuf, toRead, out int r) || r < 22)
                    break;

                for (int i = 0; i <= r - 22; i++)
                {
                    if (winBuf[i] == 0x50 && winBuf[i + 1] == 0x4B && winBuf[i + 2] == 0x05 && winBuf[i + 3] == 0x06)
                    {
                        uint cdSize = BitConverter.ToUInt32(winBuf, i + 12);
                        uint cdOffset = BitConverter.ToUInt32(winBuf, i + 16);
                        ushort commentLen = BitConverter.ToUInt16(winBuf, i + 20);
                        long eocdPosFromStart = scanned + i;

                        if (cdOffset + cdSize == (ulong)eocdPosFromStart)
                        {
                            targetSize = (int)(eocdPosFromStart + 22 + commentLen);
                            break;
                        }
                    }
                }

                if (targetSize > 0) break;
                if (r < 64) break;
                scanned += r - 32;
            }
        }
        // 4. XML / Text / Policy Files (e.g. ADP.xml, ASKSW.xml, trustedTime)
        else if (sigPattern.Length >= 4 && (sigPattern[0] == (byte)'<' || IsMostlyPrintableAscii(sigPattern)))
        {
            int maxTextScan = (int)Math.Min(Math.Max(maxAvailableInRegion, 256 * 1024L), 2 * 1024 * 1024L);
            byte[] textBuf = new byte[Math.Min(maxTextScan, 512 * 1024)];
            if (ReadProcessMemory(hProc, (IntPtr)fileStartAddr, textBuf, textBuf.Length, out int tRead) && tRead > 0)
            {
                int endIdx = 0;
                while (endIdx < tRead)
                {
                    byte b = textBuf[endIdx];
                    if (b == 0) break;
                    if (b < 0x09 || (b > 0x0D && b < 0x20)) break;
                    endIdx++;
                }

                if (endIdx > 0)
                {
                    targetSize = (estimatedSize > 0 && estimatedSize <= endIdx) ? (int)estimatedSize : endIdx;
                }
            }
        }

        if (targetSize <= 0 && estimatedSize > 0 && estimatedSize <= 64 * 1024 * 1024)
        {
            targetSize = (int)estimatedSize;
        }

        if (targetSize > 0 && targetSize <= 64 * 1024 * 1024)
        {
            byte[] fullBytes = new byte[targetSize];
            byte[] tempChunk = new byte[Math.Min(256 * 1024, targetSize)];
            int totalRead = 0;

            while (totalRead < targetSize)
            {
                int chunkLen = Math.Min(tempChunk.Length, targetSize - totalRead);
                if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + totalRead), tempChunk, chunkLen, out int got) || got <= 0)
                {
                    int pageLen = Math.Min(4096, targetSize - totalRead);
                    if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + totalRead), tempChunk, pageLen, out got) || got <= 0)
                        break;
                }

                Buffer.BlockCopy(tempChunk, 0, fullBytes, totalRead, got);
                totalRead += got;
            }

            if (totalRead > 0)
            {
                return totalRead == targetSize ? fullBytes : fullBytes[..totalRead];
            }
        }

        return null;
    }
}
