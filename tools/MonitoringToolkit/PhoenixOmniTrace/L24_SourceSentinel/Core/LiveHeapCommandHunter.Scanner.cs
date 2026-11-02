using System;
using System.Text;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter
{
    private static bool HasPrintableAsciiRun(byte[] buf, int len)
    {
        int run = 0;
        for (int i = 0; i < len; i++)
        {
            byte b = buf[i];
            if (b is >= 32 and <= 126)
            {
                if (++run >= 4) return true;
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    private static bool HasPrintableUtf16Run(byte[] buf, int len)
    {
        int run = 0;
        for (int i = 0; i < len - 1; i += 2)
        {
            if (buf[i] is >= 32 and <= 126 && buf[i + 1] == 0)
            {
                if (++run >= 4) return true;
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    public void InspectBufferForTesting(int pid, string processName, long memAddress, byte[] buffer, int length)
    {
        InspectBinaryAndTextBuffer(IntPtr.Zero, pid, processName, memAddress, buffer, length, isExecutableCodeSection: false, recordAsBaselineOnly: false);
    }

    private void InspectBinaryAndTextBuffer(IntPtr hProc, int pid, string processName, long memAddress, byte[] buffer, int length, bool isExecutableCodeSection, bool recordAsBaselineOnly)
    {
        InspectRawBinarySignaturesAndCarveLoaders(hProc, pid, processName, memAddress, buffer, length, isExecutableCodeSection);

        // فحص سريع: لا نحول الـ 64KB إلى String إلا إذا كانت تحتوي على أحرف قابلة للطباعة
        if (HasPrintableAsciiRun(buffer, length))
        {
            ScanStringContent(pid, processName, memAddress, Encoding.UTF8.GetString(buffer, 0, length), recordAsBaselineOnly);
        }
        if (HasPrintableUtf16Run(buffer, length))
        {
            ScanStringContent(pid, processName, memAddress, Encoding.Unicode.GetString(buffer, 0, length), recordAsBaselineOnly);
        }
    }
}
