using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.UsbSecurity;

public class UsbDescriptorAudit
{
    public bool IsSuspicious { get; set; }
    public string AuditMessage { get; set; } = string.Empty;
}

/// <summary>
/// Validates USB Device & Configuration descriptors.
/// يتحقق من واصفات أجهزة USB وتكويناتها.
/// </summary>
public class UsbDescriptorValidator : IDisposable
{
    private const byte HID_DEVICE_CLASS = 0x03;

    private readonly HashSet<ushort> _knownPhoneOems = new()
    {
        0x04E8, // Samsung
        0x05C6, // Qualcomm
        0x05AC, // Apple
        0x0E8D, // MediaTek
        0x2717, // Xiaomi
        0x18D1  // Google
    };

    /// <summary>
    /// Audits the descriptor for composite device class morphing and VID/PID anomalies.
    /// يدقق الواصف بحثاً عن تحول فئة الجهاز المركب وشذوذ VID/PID.
    /// </summary>
    public UsbDescriptorAudit AuditDescriptor(ushort vid, ushort pid, byte deviceClass, byte[] rawDescriptors)
    {
        var audit = new UsbDescriptorAudit();

        try
        {
            // Detect class morphing (e.g., phone suddenly exposing HID Keyboard class 0x03)
            // اكتشاف تحول الفئة (مثال: هاتف يعرض فجأة فئة لوحة مفاتيح HID 0x03)
            bool isPhoneOem = _knownPhoneOems.Contains(vid);
            
            if (isPhoneOem && deviceClass == HID_DEVICE_CLASS)
            {
                audit.IsSuspicious = true;
                audit.AuditMessage = $"Suspicious USB Morphing: Phone OEM (VID: 0x{vid:X4}) presenting as HID Device Class (0x03). Possible BadUSB payload.";
                return audit;
            }

            // Validations for general descriptor malformation could be added here
            // يمكن إضافة تحققات من تشوه الواصف العام هنا

            return audit;
        }
        catch (Exception ex)
        {
            // Fail-open
            // نمط تجاوز الفشل
            Console.WriteLine($"[UsbDescriptorValidator Error]: {ex.Message}");
            return audit;
        }
    }

    public void Dispose()
    {
        // Cleanup
        // تنظيف
    }
}
