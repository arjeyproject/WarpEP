# Install WarpEP on Windows (CMD / PowerShell) · نصب روی ویندوز

[English](#english) · [فارسی](#فارسی)

---

## English

### 1. Open CMD

Press `Win + R`, type `cmd`, hit Enter. PowerShell and Windows Terminal work too.

### 2. One line, done

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

What it does: finds Python 3.8+ (installs it with `winget` if missing), downloads
WarpEP into `%LOCALAPPDATA%\WarpEP`, creates `warpep.cmd` on your PATH, and runs a
selftest.

Install **and** scan in one line:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:WARPEP_RUN=1; irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

### 3. Open a NEW CMD window

PATH changes only apply to new windows. Then:

```bat
warpep
warpep scan --fast
warpep scan --deep --top 20
```

### 4. Use the winner

```bat
warpep scan -o %USERPROFILE%\Desktop\best-endpoints.txt
warpep register
warpep config -o %USERPROFILE%\Desktop\warp.conf
```

Import `warp.conf` in the official WireGuard for Windows app ("Add Tunnel" →
"Import tunnel(s) from file"), or paste the `ip:port` line into your WARP client.

### No-install option

```bat
curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz
python warpep.pyz scan --fast
```

Or download the standalone `warpep-windows-x86_64.exe` from the
[releases](https://github.com/arjeyproject/WarpEP/releases) page: no Python needed.

### Troubleshooting

| Symptom | Fix |
| --- | --- |
| `'warpep' is not recognized` | open a **new** CMD, or run `%LOCALAPPDATA%\WarpEP\bin\warpep.cmd` |
| `running scripts is disabled` | use the one-liner above, it includes `-ExecutionPolicy Bypass` |
| `python was not found` | the installer uses winget; otherwise install from python.org and tick "Add python.exe to PATH" |
| Boxes instead of table lines | run `chcp 65001` first, or use Windows Terminal |
| Everything 100% loss | your firewall or ISP blocks UDP. Try `warpep scan -p all`, allow Python through Windows Firewall |
| Corporate proxy | UDP scanning does not traverse HTTP proxies; try a home or mobile network |

### Uninstall

```powershell
irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 -OutFile i.ps1; ./i.ps1 -Uninstall
```

---

## فارسی

<div dir="rtl">

### ۱. باز کردن CMD

کلید `Win + R` را بزنید، `cmd` را تایپ کنید و Enter بزنید. پاورشل و Windows
Terminal هم کار می‌کنند.

### ۲. یک خط و تمام

</div>

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

<div dir="rtl">

چه کاری می‌کند: پایتون ۳.۸ یا بالاتر را پیدا می‌کند (اگر نبود با `winget` نصب
می‌کند)، WarpEP را در `%LOCALAPPDATA%\WarpEP` می‌ریزد، دستور `warpep.cmd` را روی
PATH می‌سازد و در آخر selftest می‌گیرد.

نصب **و** اسکن با یک خط:

</div>

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:WARPEP_RUN=1; irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

<div dir="rtl">

### ۳. یک پنجره‌ی جدید CMD باز کنید

تغییرات PATH فقط در پنجره‌های جدید اعمال می‌شود. بعد:

</div>

```bat
warpep
warpep scan --fast
warpep scan --deep --top 20
```

<div dir="rtl">

### ۴. استفاده از برنده

</div>

```bat
warpep scan -o %USERPROFILE%\Desktop\best-endpoints.txt
warpep register
warpep config -o %USERPROFILE%\Desktop\warp.conf
```

<div dir="rtl">

فایل `warp.conf` را در اپ رسمی WireGuard ویندوز ایمپورت کنید (گزینه‌ی
Add Tunnel و بعد Import tunnel(s) from file) یا خط `ip:port` را در کلاینت وارپ
خودتان پیست کنید.

### گزینه‌ی بدون نصب

</div>

```bat
curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz
python warpep.pyz scan --fast
```

<div dir="rtl">

یا فایل اجرایی مستقل `warpep-windows-x86_64.exe` را از صفحه‌ی
[ریلیزها](https://github.com/arjeyproject/WarpEP/releases) بگیرید؛ حتی به پایتون
هم نیاز ندارد.

### رفع اشکال

| مشکل | راه‌حل |
| --- | --- |
| پیام `'warpep' is not recognized` | یک CMD **جدید** باز کنید یا مستقیم `%LOCALAPPDATA%\WarpEP\bin\warpep.cmd` را اجرا کنید |
| پیام `running scripts is disabled` | همان دستور تک‌خطی بالا را بزنید؛ `-ExecutionPolicy Bypass` داخلش هست |
| پیام `python was not found` | نصب‌کننده از winget استفاده می‌کند؛ در غیر این صورت از python.org نصب کنید و تیک «Add python.exe to PATH» را بزنید |
| به‌جای خطوط جدول مربع می‌بینید | اول `chcp 65001` را بزنید یا از Windows Terminal استفاده کنید |
| همه ۱۰۰٪ لاس | فایروال یا اپراتور UDP را بسته؛ `warpep scan -p all` را امتحان کنید و به پایتون در فایروال ویندوز اجازه بدهید |
| پروکسی سازمانی | اسکن UDP از پروکسی HTTP رد نمی‌شود؛ شبکه‌ی خانگی یا موبایل را امتحان کنید |

### حذف نصب

</div>

```powershell
irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 -OutFile i.ps1; ./i.ps1 -Uninstall
```
