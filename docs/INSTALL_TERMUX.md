# Install WarpEP on Android (Termux) · نصب روی اندروید (ترموکس)

[English](#english) · [فارسی](#فارسی)

---

## English

### 1. Get Termux

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[GitHub releases](https://github.com/termux/termux-app/releases). The Play Store
build is outdated and will fight you.

### 2. One line, done

```bash
pkg update -y && pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

The installer detects Termux, installs Python if it is missing, copies WarpEP into
`$PREFIX/lib/warpep`, drops a `warpep` command into `$PREFIX/bin` and runs a
selftest so you know the crypto works on your phone.

### 3. Scan

```bash
warpep scan --fast
```

Install and scan in a single line:

```bash
pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run --fast
```

### 4. Use the winner

```bash
warpep scan --fast -o best.txt
cat best.txt
```

Copy the top line into your WARP client (v2rayNG, Hiddify, NekoBox, WARP+ apps) as
the endpoint. Want a full WireGuard config instead?

```bash
warpep register
warpep config -o warp.conf
cat warp.conf
```

`termux-setup-storage` then `cp warp.conf ~/storage/downloads/` puts it somewhere
your VPN app can import it.

### Mobile tips

- Mobile data and Wi-Fi give genuinely different winners. Scan on the network you
  will actually use.
- Battery/CPU friendly: `warpep scan --fast --rate 400`.
- Screen off kills background CPU. Keep Termux in the foreground, or run
  `termux-wake-lock` first.
- Scan blocked entirely? `warpep scan -p all` sweeps all 53 published ports.

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```

---

## فارسی

<div dir="rtl">

### ۱. نصب ترموکس

ترموکس را از [F-Droid](https://f-droid.org/packages/com.termux/) یا
[ریلیزهای گیت‌هاب](https://github.com/termux/termux-app/releases) نصب کنید. نسخه‌ی
گوگل‌پلی قدیمی است و دردسر درست می‌کند.

### ۲. یک خط و تمام

</div>

```bash
pkg update -y && pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

<div dir="rtl">

اسکریپت نصب خودش تشخیص می‌دهد که در ترموکس هستید، اگر پایتون نبود نصبش می‌کند،
WarpEP را در `$PREFIX/lib/warpep` می‌گذارد، دستور `warpep` را در `$PREFIX/bin`
می‌سازد و در پایان یک selftest اجرا می‌کند تا مطمئن شوید رمزنگاری روی گوشی شما
درست کار می‌کند.

### ۳. اسکن

</div>

```bash
warpep scan --fast
```

<div dir="rtl">

نصب و اسکن با یک خط:

</div>

```bash
pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run --fast
```

<div dir="rtl">

### ۴. استفاده از برنده

</div>

```bash
warpep scan --fast -o best.txt
cat best.txt
```

<div dir="rtl">

خط اول را به‌عنوان اندپوینت در کلاینت وارپ خودتان (v2rayNG، هیدیفای، NekoBox،
اپ‌های WARP+) پیست کنید. کانفیگ کامل WireGuard می‌خواهید؟

</div>

```bash
warpep register
warpep config -o warp.conf
cat warp.conf
```

<div dir="rtl">

با `termux-setup-storage` و بعد `cp warp.conf ~/storage/downloads/` فایل را جایی
می‌گذارید که اپ VPN بتواند ایمپورتش کند.

### نکته‌های موبایلی

- دیتای موبایل و وای‌فای واقعاً برنده‌های متفاوتی می‌دهند؛ روی همان شبکه‌ای اسکن
  کنید که می‌خواهید استفاده کنید.
- مهربان با باتری و CPU: `warpep scan --fast --rate 400`
- با خاموش شدن صفحه، پردازش پس‌زمینه قطع می‌شود. ترموکس را جلو نگه دارید یا اول
  `termux-wake-lock` بزنید.
- اسکن کاملاً بسته است؟ `warpep scan -p all` هر ۵۳ پورت منتشرشده را جارو می‌کند.

### حذف نصب

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```
