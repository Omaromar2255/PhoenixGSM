# Samsung AT RIL Tool Bridge & Telemetry Extractor (Standalone)

> أداة مستقلة تماماً لرفع ملف `AT` إلى هاتف سامسونج المتصل عبر ADB، تشغيله، واستخراج كامل بيانات الهاتف وتحدي التوكن (`Token AuthKey`) وحفظها على الكمبيوتر.

---

## 📁 محتويات المجلد (`C:\Users\pc5\Documents\GitHub\PhoenixGSM\AT`)

| الملف | الوصف |
|---|---|
| [`AT`](file:///C:/Users/pc5/Documents/GitHub/PhoenixGSM/AT/AT) | الملف التنفيذي الأصلي لأداة Samsung AT RIL Tool (حجم 26,534 بايت). |
| [`at_device_bridge.py`](file:///C:/Users/pc5/Documents/GitHub/PhoenixGSM/AT/at_device_bridge.py) | سكربت بايثون المستقل للرفع والتشغيل وسحب البيانات وحفظها. |
| [`run_at.bat`](file:///C:/Users/pc5/Documents/GitHub/PhoenixGSM/AT/run_at.bat) | ملف تشغيل سريع بنقرة واحدة (Batch script). |
| `at_device_info.json` | ملف الإخراج المهيكل (JSON) الذي يحتوي على كامل البيانات والبصمات والوقت. |
| `at_device_info.txt` | تقرير نصي مقروء ومنظم بكافة تفاصيل الهاتف المستخرجة. |
| `at_raw_output.log` | السجل الخام لمخرجات الأداة والشعار من داخل الهاتف. |

---

## 🚀 طريقة الاستخدام

### 1. التشغيل السريع المباشر:
يمكنك ببساطة النقر مرتين على:
```cmd
run_at.bat
```
أو عبر موجه الأوامر (CMD / PowerShell):
```cmd
python at_device_bridge.py
```

### 2. التشغيل مع خيارات متقدمة:

- **التشغيل بوضع R2 (للحصول على IMEI والرقم التسلسلي إذا كان متاحاً):**
```cmd
python at_device_bridge.py --mode R2
```

- **التشغيل دون إعادة رفع الملف إذا كان موجوداً مسبقاً على الهاتف:**
```cmd
python at_device_bridge.py --no-push
```

- **تنظيف الملف من الهاتف بعد الانتهاء (`/data/local/tmp/AT`):**
```cmd
python at_device_bridge.py --cleanup
```

- **تمرير مفتاح AuthKey لفك التشفير ودخول وضع الأوامر:**
```cmd
python at_device_bridge.py --authkey <AUTHKEY_HEX>
```

---

## 📊 البيانات المستخرجة والمحفوظة:

يقوم السكربت بالتقاط وتوثيق الحقول التالية تلقائياً:
- **Product Name** (اسم المنتج)
- **Product Model** (طراز الهاتف الدقيق، مثل `SM-F936U1`)
- **Device Carrier** (كود الموزع/الشبكة، مثل `XAA`)
- **Build Number** (إصدار البناء، مثل `F936U1UES8IZA1`)
- **Android Ver** (إصدار أندرويد، مثل `16`)
- **Security Patch** (تاريخ التحديث الأمني، مثل `2026-01-01`)
- **Token AuthKey** (رمز التحدي المشفر المولد من الأداة)
- **بصمات التجزئة** (MD5 و SHA-256 للملف التنفيذي وحجمه بالبايت)
