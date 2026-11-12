# TV-ONE
Console-based passive reconnaissance tool for domains — security headers, SSL/TLS, WHOIS, DNS, and subdomain enumeration — built for authorized bug bounty and penetration testing recon. By Mr_TV.

ابزار کنسولی پایتون برای شناسایی غیرتهاجمی دامنه‌ها (هدر امنیتی، SSL، WHOIS، DNS و ساب‌دامین) — مناسب فاز Recon در باگ بانتی و تست نفوذ قانونی. ساخته‌شده توسط Mr_TV.


# TV-ONE

**Passive reconnaissance toolkit for authorized bug bounty hunting and legal penetration testing.**

## Overview

TV-ONE is an open-source, console-based tool that collects only information a target already makes public — the same data your browser, `nslookup`, or a WHOIS website would see. It never scans ports, never sends attack payloads, and never performs exploitation. It only reads and reports.

## Features

| Module | What it does |
|---|---|
| Security Headers | Checks HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) |
| TLS / Certificate | Inspects the SSL certificate: issuer, expiry date, cipher in use |
| WHOIS | Domain registration data (registrar, creation/expiry dates, name servers) |
| DNS Records | A, AAAA, NS, MX, TXT, SOA records via a lightweight built-in resolver |
| Subdomain Enumeration | Finds subdomains from public Certificate Transparency logs (crt.sh) |

## How it works

TV-ONE runs as an interactive console app:

1. Launch it (double-click the file or run it from a terminal)
2. Enter the target domain or URL
3. Pick a module from the menu by number or name (e.g. `4` or `dns`)
4. View the result, then return to the menu automatically
5. Use the `target` option anytime to switch to a new domain without restarting

It can also run non-interactively from the command line:

```bash
python tv_one.py example.com --all      # run every module
python tv_one.py example.com --dns      # run one module
```

## Requirements

- Python 3.8 or newer
- Two dependencies, installed with one command:

```bash
pip install -r requirements.txt
```

(`requests` and `colorama` — no other system tools needed; runs the same on Windows and Linux)

## Legal notice

Only use TV-ONE against systems you own or are explicitly authorized to test (e.g. an in-scope bug bounty target or a signed pentest agreement). All data comes from public, passive sources.



# TV-ONE

ابزار شناسایی غیرتهاجمی (Passive Reconnaissance) برای باگ بانتی و تست نفوذ قانونی

## معرفی

TV-ONE یک ابزار کنسولی و متن‌باز است که فقط اطلاعات عمومی و در دسترس درباره‌ی یک دامنه را جمع‌آوری می‌کند؛ دقیقاً همان داده‌هایی که مرورگر، nslookup یا سایت‌های whois هم می‌بینند. این ابزار هیچ پورتی را اسکن نمی‌کند، هیچ payload‌ای ارسال نمی‌کند و هیچ بهره‌برداری (exploit) انجام نمی‌دهد؛ فقط می‌خواند و گزارش می‌دهد.

## قابلیت‌ها

| ماژول | کاری که انجام می‌دهد |
|---|---|
| Security Headers | بررسی هدرهای امنیتی HTTP سایت (HSTS, CSP, X-Frame-Options و…) |
| TLS / Certificate | بررسی گواهی SSL، تاریخ انقضا، صادرکننده و cipher مورد استفاده |
| WHOIS | اطلاعات ثبت دامنه (رجیسترار، تاریخ ثبت/انقضا، name serverها) |
| DNS Records | رکوردهای A, AAAA, NS, MX, TXT, SOA با یک resolver سبک و داخلی |
| Subdomain Enumeration | پیدا کردن ساب‌دامین‌ها از لاگ‌های عمومی Certificate Transparency (crt.sh) |

## نحوه‌ی کار

TV-ONE به‌صورت تعاملی اجرا می‌شود:

۱. برنامه را اجرا کن (با دابل‌کلیک یا از ترمینال)
۲. آدرس دامنه یا URL هدف را وارد کن
۳. از منو، ماژول موردنظر را با عدد یا نام آن انتخاب کن (مثلاً 4 یا dns)
۴. نتیجه نمایش داده می‌شود و دوباره به منو برمی‌گردی
۵. هر زمان خواستی، با گزینه‌ی target می‌توانی بدون بستن برنامه، دامنه‌ی جدیدی بدهی

همچنین از خط فرمان هم قابل اجراست:

python tv_one.py example.com --all      (اجرای همه‌ی ماژول‌ها)
python tv_one.py example.com --dns      (اجرای فقط یک ماژول)

## پیش‌نیازها

- Python نسخه‌ی ۳.۸ یا بالاتر
- دو کتابخونه که با یک دستور نصب می‌شن:

pip install -r requirements.txt

(شامل requests و colorama؛ بدون نیاز به ابزار یا نصب سیستمی اضافه، روی ویندوز و لینوکس یکسان کار می‌کند)

## نکته‌ی قانونی

فقط روی سیستم‌هایی استفاده کن که مالکشونی یا مجوز صریح برای تست داری (مثل یک برنامه‌ی باگ بانتی یا قرارداد پنتست). همه‌ی داده‌ها از منابع عمومی و غیرتهاجمی خوانده می‌شوند.

## سازنده

Mr_TV — تلگرام: @Mr_TV_ir — گیت‌هاب: github.com/TV-CENTER
## Author

Mr_TV — Telegram: [@Mr_TV_ir](https://t.me/Mr_TV_ir) — GitHub: [TV-CENTER](https://github.com/TV-CENTER)
