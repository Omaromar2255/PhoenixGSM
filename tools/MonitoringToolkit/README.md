# 🔥 PhoenixGSM — Monitoring Toolkit
# مجموعة أدوات المراقبة والتحليل

> **الهدف:** التقاط وتحليل أوامر وبروتوكولات أدوات الجوالات لبناء PhoenixGSM Pro

---

## 📋 المتطلبات

### 1. تثبيت .NET 8 SDK
```powershell
# تحميل من الموقع الرسمي:
# https://dotnet.microsoft.com/download/dotnet/8.0

# أو عبر winget:
winget install Microsoft.DotNet.SDK.8
```

### 2. بناء جميع الأدوات
```powershell
cd C:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit
dotnet build PhoenixGSM.Monitor.sln
```

---

## 🛠️ الأدوات المتاحة

### 1. 🔌 ADB Monitor — مراقب أوامر ADB
يعترض ويسجل كل أمر ADB يُرسل من أي أداة.

```powershell
cd AdbMonitor\bin\Debug\net8.0

# تثبيت المراقب (يستبدل adb.exe)
.\AdbMonitor.exe --install "C:\path\to\adb\folder"

# الآن أي أداة تستدعي adb ستُسجل أوامرها تلقائياً!

# عرض الإحصائيات
.\AdbMonitor.exe --stats

# عرض السجلات
.\AdbMonitor.exe --logs

# إزالة المراقب واستعادة الأصلي
.\AdbMonitor.exe --uninstall "C:\path\to\adb\folder"
```

**السجلات تُحفظ في:** `%LOCALAPPDATA%\PhoenixGSM\Logs\ADB\`

---

### 2. 📡 Serial Sniffer — مراقب المنافذ التسلسلية
يلتقط بيانات COM/UART ويكشف البروتوكولات (AT, Odin, Qualcomm, MTK).

```powershell
cd SerialSniffer\bin\Debug\net8.0

# عرض المنافذ المتاحة
.\SerialSniffer.exe --list

# مراقبة منفذ محدد
.\SerialSniffer.exe --port COM3
.\SerialSniffer.exe --port COM3 --baud 9600

# مراقبة ظهور منافذ جديدة (عند توصيل جهاز)
.\SerialSniffer.exe --watch

# مسح سرعات البود على منفذ
.\SerialSniffer.exe --scan COM3
```

**السجلات تُحفظ في:** `%LOCALAPPDATA%\PhoenixGSM\Logs\Serial\`

---

### 3. 👁️ Process Monitor — مراقب نشاط العمليات
يتتبع ما تفعله الأدوات: ملفات، عمليات فرعية، DLLs، شبكة.

```powershell
cd ProcessMonitor\bin\Debug\net8.0

# عرض أدوات الجوالات النشطة حالياً
.\ProcessMonitor.exe --list

# مراقبة أداة محددة
.\ProcessMonitor.exe --target z3x_samsung_tool
.\ProcessMonitor.exe --target 3utools
.\ProcessMonitor.exe --target octoplus
```

**السجلات تُحفظ في:** `%LOCALAPPDATA%\PhoenixGSM\Logs\Process\`

---

### 4. 📊 Command Analyzer — محلل الأوامر
يجمع كل البيانات من الأدوات الثلاث ويحللها.

```powershell
cd CommandAnalyzer\bin\Debug\net8.0

# ملخص السجلات المتاحة
.\CommandAnalyzer.exe --summary

# تحليل شامل
.\CommandAnalyzer.exe --analyze

# تصدير تقرير
.\CommandAnalyzer.exe --export markdown
.\CommandAnalyzer.exe --export json
```

**التقارير تُحفظ في:** `%LOCALAPPDATA%\PhoenixGSM\Reports\`

---

## 📋 خطوات العمل المقترحة

### 5. 🔌 USB Monitor & Discovery — مراقب ومكتشف حركة الـ USB الشامل (ADB & WinUSB)
يلتقط ويفك تشفير بروتوكولات الـ USB مباشرة (ADB, WinUSB, Fastboot, Qualcomm Sahara/Firehose, Odin, MTK) بدون الاعتماد على adb.exe.

```powershell
# اكتشاف توبولوجيا الـ USB والـ Descriptors ونقاط النهاية
.\UsbMonitor\UsbMonitorDiscovery\bin\Debug\net8.0-windows\UsbMonitorDiscovery.exe
.\UsbMonitorDiscovery.exe --adb      # كشف أجهزة الأندرويد فقط
.\UsbMonitorDiscovery.exe --watch    # مراقبة توصيل وفصل الأجهزة لحظياً

# مراقبة وتحليل حركة الـ USB الشاملة
.\UsbMonitor\UsbMonitor\bin\Debug\net8.0-windows\UsbMonitor.exe --list
.\UsbMonitor.exe --test              # فحص واختبار محرك فك تشفير الحزم
.\UsbMonitor.exe --simulate          # محاكاة جلسة تفاعلية متعددة البروتوكولات (ADB + WinUSB)
.\UsbMonitor.exe --stats             # إحصائيات الحزم المصنفة حسب البروتوكول

# ربط الفلتر بالأجهزة التي لا تستخدم ADB (أجهزة WinUSB أو Qualcomm أو MTK أو Odin):
# 1. ربط بجهاز محدد عبر معرّف الجهاز (Device Instance ID) — الطريقة الأكثر أماناً:
.\UsbMonitor.exe --attach-device "USB\VID_05C6&PID_9008\5&18D4..."
.\UsbMonitor.exe --detach-device "USB\VID_05C6&PID_9008\5&18D4..."

# 2. ربط بفئة تعريف كاملة (Class LowerFilter):
.\UsbMonitor.exe --attach-class winusb   # لأجهزة WinUSB
.\UsbMonitor.exe --attach-class ports    # لمنافذ COM وEDL
.\UsbMonitor.exe --attach-class android  # لأجهزة الأندرويد
.\UsbMonitor.exe --detach-class winusb

# 3. إزالة جميع الفلاتر واستعادة حالة النظام الأصلية فوراً (Rollback):
.\UsbMonitor.exe --rollback

# 4. بدء الالتقاط المباشر لجميع الأجهزة:
.\UsbMonitor.exe --capture --all
```

**السجلات تُحفظ في:** `%LOCALAPPDATA%\PhoenixGSM\Logs\USB\`

---

## 🔄 دورة العمل المتكاملة

```
الخطوة 1: ثبّت .NET 8 SDK وابنِ المشروع
    ↓
الخطوة 2: اكتشف نقاط النهاية عبر UsbMonitorDiscovery
    ↓
الخطوة 3: ثبّت ADB Monitor أو فعّل مراقبة الـ USB
    ↓
الخطوة 4: شغّل Process Monitor على الأداة المراد دراستها
    ↓
الخطوة 5: شغّل Serial Sniffer إذا كنت تستخدم بوكس أو منفذ COM
    ↓
الخطوة 6: استخدم أداتك بشكل طبيعي (Z3X, UMT, etc.)
    ↓
الخطوة 7: شغّل Command Analyzer لربط السجلات زمنياً
    ↓
الخطوة 8: راجع التقارير واستخدمها لبناء PhoenixGSM Pro
```

---

## 📂 هيكل السجلات

```
%LOCALAPPDATA%\PhoenixGSM\
├── Logs\
│   ├── ADB\
│   │   └── adb_log_2026-10-02.jsonl
│   ├── USB\
│   │   └── usb_log_2026-10-02.jsonl
│   ├── Serial\
│   │   └── serial_log_COM3_2026-10-02.jsonl
│   └── Process\
│       └── process_log_z3x_samsung_tool_2026-10-02.jsonl
└── Reports\
    ├── analysis_2026-10-02_143000.md
    └── analysis_2026-10-02_143000.json
```

---

## 💡 نصائح مهمة

1. **ابدأ بـ ADB Monitor** — معظم الأدوات تستخدم ADB، فهذا يلتقط أكبر كمية بيانات
2. **سجّل عمليات مختلفة** — لا تكتفِ بعملية واحدة، جرّب FRP, Unlock, Flash, إلخ
3. **كرر العمليات** — المحلل يكتشف الأنماط المتكررة تلقائياً
4. **راجع التقارير بانتظام** — كلما جمعت بيانات أكثر، أصبح التحليل أدق
