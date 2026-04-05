# Meteor Security CLI

<div align="center">
  <h3>Modular CLI tool for port scanning, process mapping, log analysis, and Shodan integration</h3>
</div>

---


## 🚀 المميزات الرئيسية (Features)
1. **الماسح الضوئي للمنافذ (Port Scanning)**: رصد أسرع للمنافذ المحلية المفتوحة (TCP/UDP) للتحقق مما يستمع في الخلفية.
2. **مدير العمليات (Process Mapping)**: ربط كل منفذ مفتوح بمعرّف العملية (PID) واستخراج مسارها التنفيذي (Executable Path).
3. **محلل السجلات الأمنية (Log Analyzer)**: مسح مستمر وسريع لسجلات تفويض النظام (مثل `/var/log/syslog` و `/var/log/auth.log` في لينكس) للبحث عن أنماط مشبوهة (محاولات الدخول الفاشلة، عمليات تصفية السجل).
4. **تكامل شودان (Shodan Integration)**: القدرة على استخدام مفتاح API الخاص بـ Shodan للحصول على تقرير المخاطر الخارجي لعنوان الـ IP العام.
5. **الخزنة المشفرة (Encrypted Vault)**: نظام إدارة مفاتيح API محمي بتشفير AES-256 و PBKDF2، حيث تُشتق المفاتيح من كلمة مرور رئيسية (Master Password) لحماية بياناتك الحساسة.
6. **فحص الهاردوير (Hardware Audit)**: تحليل مباشر لثغرات المعالج (CPU Vulnerabilities) مثل Spectre و Meltdown عبر واجهات نظام لينكس العميقة.
7. **حارس الهوية (Identity Guard)**: اكتشاف تسريبات البريد الإلكتروني باستخدام تقنية K-Anonymity (SHA-1 hashing) لضمان الخصوصية التامة أثناء فحص قواعد البيانات المسربة.
8. **محلل سلسلة القتل (Kill Chain Analyzer)**: محرك ارتباط متقدم يجمع نتائج فحص المنافذ، السجلات، وثغرات الهاردوير ليعطيك "درجة خطر عالمية" (Global Risk Score) من 0-100%.
9. **محلل كلمات المرور (Password Analyzer)**: تقييم تفاعلي لقوة كلمة المرور، حساب زمن الكسر التقني، والتحقق من وجودها في قواميس الاختراق العالمية.
10. **الوضع القتالي (Combat Mode)**: ميزة "الفحص العميق" (Deep Scanning) التي تفعل تلقائياً عند التشغيل بصلاحيات Root لاكتشاف حقن العمليات (Process Injection) وفحص الشبكة عبر حزم SYN الخام.

## 🛠️ التثبيت (Installation)

```bash
# 1. نسخ المستودع
git clone https://github.com/your-username/meteor.git
cd meteor

# 2. إنشاء بيئة وهمية (اختياري لكن مستحسن)
python3 -m venv venv
source venv/bin/activate

# 3. تثبيت المتطلبات والأداة داخلياً
pip install -e .
```

## 💻 طريقة الاستخدام (Usage)

بمجرد تثبيت الحزمة، يمكنك استخدام أمر `meteor` المباشر في الطرفية (Terminal):

```bash
# 1. التقرير المحلي: فحص المنافذ ومستوى خطورتها
meteor scan

# 2. فحص السجلات: جلب محاولات الدخول الفاشلة والأنشطة المشبوهة
meteor logs

# 3. فحص خارجي للـ IP باستخدام Shodan API 
meteor shodan --key <YOUR_SHODAN_API_KEY> --ip <TARGET_IP>

# 4. التقرير الشامل: يفعل كل الخصائص في آن واحد
meteor full --key <YOUR_SHODAN_API_KEY> --ip <TARGET_IP>

# 5. إدارة الخزنة: إضافة مفتاح API مشفر
meteor vault add shodan

# 6. فحص الهاردوير: التأكد من سلامة المعالج
meteor hardware

# 7. فحص البريد: التأكد من عدم تسريب إيميلك
meteor check-email user@example.com

# 8. تحليل سلسلة القتل: تقرير الارتباط الشامل ودرجة الخطر
meteor killchain

# 9. فحص كلمة المرور: تقييم تفاعلي للقوة والزمن المتوقع للكسر
meteor password
```

## 🛡️ الفحص العميق (Combat Mode)
عند تشغيل Meteor بصلاحيات الجذر (`sudo`) على أنظمة لينكس، يتم تفعيل "الوضع القتالي" الذي يتيح:
* **Process Integrity**: مقارنة مخرجات الذاكرة مع الملفات على القرص لاكتشاف (Process Hollowing).
* **SYN Scanning**: فحص شبكي متطور عبر حزم TCP الخام (Raw Packets).

> **تنبيه أمني:** لمزيد من الأمان، يتم طلب كلمة المرور الرئيسية (Master Password) عند محاولة الوصول للبيانات الحساسة في الخزنة أو فحص الإيميلات.

> **ملاحظة:** لكي يتم تفعيل الفحص على كافة العمليات، يُفضل تشغيل الـ CLI بصلاحيات الإدارة (`sudo`) حتى لا يتم تقييد الأداة من قراءة مسارات العمليات المحمية أو سجلات التفويض `/var/log/auth.log`.
> `sudo /path/to/venv/bin/meteor scan`

## 📚 التوثيق المعماري الرسمي (Documentation)
للمزيد من التفاصيل المعمارية حول كيفية تطبيق مبادئ `SOLID` داخل الكود المصدري، وطرق توسعة البرنامج لدعم أنظمة Windows و macOS باستخدام نظام "المزودين - Providers":
- [إقرأ التوثيق الرسمي الشامل (بالعربية)](docs/official_documentation_ar.md)

## 🤝 المساهمة (Contributing)
للمساهمة، الرجاء عمل Fork للمستودع وإضافة `WindowsProvider` بداخل مجلد `providers/windows.py` لبرمجته ليتوافق مع أجهزة الويندوز دون كسر الطبقة الخاصة بالـ Core Engines.
