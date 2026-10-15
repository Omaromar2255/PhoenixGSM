namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Operational hardware and protocol modes targeted by GSM servicing tools.
/// أوضاع التشغيل والبروتوكولات المستهدفة من أدوات وبرامج الصيانة
/// </summary>
public enum ToolSourceMode
{
    /// <summary>
    /// All Modes (Filter token)
    /// جميع الأوضاع
    /// </summary>
    All,

    /// <summary>
    /// Media Transfer Protocol (MTP) / Picture Transfer Protocol (PTP) mode.
    /// وضع نقل الملفات MTP واستخراج البيانات
    /// </summary>
    Mtp,

    /// <summary>
    /// MediaTek BROM / Preloader / Download-Agent (DA) mode.
    /// وضع ميديا تيك (BROM و Preloader وتجاوز الحماية SLA/DAA)
    /// </summary>
    MtkBrom,

    /// <summary>
    /// Samsung Download Mode / Odin / Loke flashing protocol.
    /// وضع سامسونج داونلود وأوامر الأودين (بروتوكول Loke)
    /// </summary>
    SamsungOdin,

    /// <summary>
    /// Virtual / Physical COM port, Modem, and Serial AT commands mode.
    /// وضع المنافذ التسلسلية ومنافذ المودم وأوامر AT المباشرة
    /// </summary>
    SerialPort,

    /// <summary>
    /// Qualcomm Emergency Download (EDL 9008) Sahara &amp; Firehose mode.
    /// وضع كوالكوم وضع الطوارئ EDL 9008
    /// </summary>
    QualcommEdl,

    /// <summary>
    /// Unisoc / Spreadtrum FDL1 / FDL2 Diag mode.
    /// وضع أجهزة سبريدترم ويونيسوك FDL
    /// </summary>
    UnisocSpd,

    /// <summary>
    /// Generic / Universal Tool-Source command.
    /// أمر عام صادر من الأداة
    /// </summary>
    Universal
}
