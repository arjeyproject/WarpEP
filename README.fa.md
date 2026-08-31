<div align="center">

```
 __        __                 _____ ____
 \ \      / /_ _ _ __ _ __   | ____|  _ \
  \ \ /\ / / _` | '__| '_ \  |  _| | |_) |
   \ V  V / (_| | |  | |_) | | |___|  __/
    \_/\_/ \__,_|_|  | .__/  |_____|_|
                     |_|
```

# WarpEP · ساخته‌شده توسط ArJey

**یک اسکنر واقعی اندپوینت کلادفلر وارپ.** نه ابزار پینگ، نه چک کردن ساده‌ی پورت:
هر پروب یک هند‌شیک کامل و معتبر WireGuard است و هر نتیجه پیش از نمایش،
به‌صورت رمزنگاری‌شده اعتبارسنجی می‌شود.

[![CI](https://github.com/arjeyproject/WarpEP/actions/workflows/ci.yml/badge.svg)](https://github.com/arjeyproject/WarpEP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776ab.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

[English](README.md) · **فارسی**

</div>

---

<div dir="rtl">

## فهرست مطالب

- [چرا WarpEP؟](#چرا-warpep)
- [ویژگی‌ها](#ویژگیها)
- [نصب](#نصب)
  - [اندروید · ترموکس](#اندروید--ترموکس)
  - [ویندوز · CMD یا پاورشل](#ویندوز--cmd-یا-پاورشل)
  - [لینوکس · اوبونتو و بقیه](#لینوکس--اوبونتو-و-بقیه)
  - [مک](#مک)
  - [اجرا بدون نصب](#اجرا-بدون-نصب)
  - [pip و pipx و داکر](#pip-و-pipx-و-داکر)
- [جدول نصب تک‌خطی و اسکن تک‌خطی](#جدول-نصب-تکخطی-و-اسکن-تکخطی)
- [طریقه استفاده](#طریقه-استفاده)
- [راهنمای کامل دستورها](#راهنمای-کامل-دستورها)
- [خواندن خروجی](#خواندن-خروجی)
- [استفاده از نتیجه‌ها](#استفاده-از-نتیجهها)
- [موتور اسکن واقعاً چطور کار می‌کند؟](#موتور-اسکن-واقعاً-چطور-کار-میکند)
- [تنظیم دقیق](#تنظیم-دقیق)
- [رفع اشکال](#رفع-اشکال)
- [پرسش‌های پرتکرار](#پرسشهای-پرتکرار)
- [توسعه](#توسعه)
- [لایسنس و اعتبارها](#لایسنس-و-اعتبارها)

---

## چرا WarpEP؟

کلادفلر وارپ روی صدها ترکیب آی‌پی و پورت anycast در دسترس است. این‌که کدام‌یک
**برای شما** سریع است به اپراتور، شهر، سیم‌کارت و حتی ساعت روز بستگی دارد. بیشتر
«اسکنرهای اندپوینت» این سؤال را بد جواب می‌دهند:

| روش | واقعاً چه چیزی را می‌سنجد | مشکل |
| --- | --- | --- |
| پینگ ICMP | این‌که لبه‌ی کلادفلر به پینگ جواب می‌دهد | ممکن است پینگ عالی باشد ولی سرویس وارپ روی آن پورت مرده باشد |
| ارسال کورکورانه‌ی UDP | هیچ‌چیز | UDP هند‌شیک ندارد؛ سکوت با موفقیت اشتباه گرفته می‌شود |
| تکرار یک پکت ضبط‌شده | یک هند‌شیک کهنه | محافظت از replay و بررسی MAC نتیجه را غیرقابل‌اعتماد می‌کند |
| **WarpEP** | **یک هند‌شیک کامل WireGuard با اعتبارسنجی رمزنگاری‌شده** | **هیچ: اگر جواب بدهد، یعنی یک ریسپاندر واقعی وارپ است** |

WarpEP خودِ پروتکل را حرف می‌زند. یک بسته‌ی
`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` واقعی می‌سازد و آن را به کلید عمومی
منتشرشده‌ی ریسپاندر وارپ می‌فرستد و فقط زمانی پاسخ را قبول می‌کند که:

۱. پاسخ دقیقاً ۹۲ بایت با نوع پیام `2` باشد،
۲. اندیس دریافت‌کننده با اندیس فرستنده‌ی *همان* پروب یکی باشد،
۳. مقدار `MAC1` با کلید عمومی استاتیک **خودِ ما** تأیید شود،
۴. کلید زنجیره‌ای ترکیب‌شده بتواند پیلود AEAD پاسخ را رمزگشایی کند.

هیچ کپتیو‌پورتال، میدل‌باکسی یا پکت جعلی از این چهار مرحله رد نمی‌شود. دستور
`warpep verify` یک قدم جلوتر می‌رود: کلیدهای ترنسپورت را می‌سازد و یک
**پکت واقعی ICMP از داخل تانل** رد می‌کند تا ثابت شود اندپوینت واقعاً ترافیک را
جابه‌جا می‌کند، نه این‌که فقط به هند‌شیک جواب بدهد.

## ویژگی‌ها

- **هند‌شیک واقعی، عدد واقعی** — بهترین، میانگین و بدترین تأخیر، جیتر (mdev) و
  درصد پکت‌لاس برای هر اندپوینت، روی چند پروب مستقل.
- **صفر وابستگی** — پیاده‌سازی X25519، ChaCha20-Poly1305، BLAKE2s و کل هند‌شیک
  WireGuard داخل همین ریپازیتوری است. نه ویل pip، نه کامپایلر، نه روت. به همین
  دلیل نصب روی ترموکس چند ثانیه طول می‌کشد.
- **همه‌جا کار می‌کند** — ویندوز (CMD و پاورشل و ترمینال)، اوبونتو/دبیان/فدورا/
  آرچ/آلپاین، مک (اینتل و اپل سیلیکون)، اندروید با ترموکس، WSL، داکر و CI.
- **اسکن دومرحله‌ای** — اول پیدا می‌کند شبکه‌ی شما کدام پورت‌های وارپ را اجازه
  می‌دهد، بعد تمام وقتش را روی همان‌ها می‌گذارد.
- **اعتبارسنجی عمیق** — `warpep verify` هند‌شیک را کامل می‌کند و ترافیک واقعی
  رمزشده از داخل تانل می‌فرستد.
- **ثبت‌نام واقعی وارپ** — `warpep register` با API عمومی کلادفلر یک پیر واقعی
  وارپ می‌سازد و کش می‌کند، پس کانفیگ خروجی بدون دستکاری کار می‌کند.
- **خروجی‌های آماده‌ی پیست** — کانفیگ WireGuard، اوت‌باند sing-box/هیدیفای،
  خطوط ساده‌ی `ip:port`، JSON و CSV.
- **IPv4 و IPv6** — کل فضای آدرس منتشرشده، یا پریفیکس‌های خودتان با `--prefix`.
- **سریع و مؤدب** — یک سوکت غیرمسدودکننده، محدودکننده‌ی نرخ token-bucket؛ یک
  اسکن کامل در چند ثانیه بدون فلود کردن کسی.
- **قابل اثبات** — `warpep selftest` بردارهای رسمی RFC 7748 و RFC 8439، یک
  هند‌شیک کامل و کل حلقه‌ی اسکن را روی دستگاه *خودتان* اجرا می‌کند.

## نصب

برای هر پلتفرم **یک خط**. مال خودتان را انتخاب کنید.

### اندروید · ترموکس

اپلیکیشن [ترموکس](https://termux.dev) را نصب کنید (نسخه‌ی F-Droid توصیه می‌شود)، بعد:

</div>

```bash
pkg update -y && pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

<div dir="rtl">

نصب **و** اسکن با یک خط:

</div>

```bash
pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run --fast
```

<div dir="rtl">

بعد از آن، هر وقت خواستید:

</div>

```bash
warpep scan --fast
```

<div dir="rtl">

> نیازی به روت نیست و لازم نیست جداگانه پایتون نصب کنید؛ خود اسکریپت نصب حلش می‌کند.
> آموزش کامل: [docs/INSTALL_TERMUX.md](docs/INSTALL_TERMUX.md)

### ویندوز · CMD یا پاورشل

پنجره‌ی **CMD** (یا پاورشل) را باز کنید و همین یک خط را پیست کنید:

</div>

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

<div dir="rtl">

نصب **و** اسکن با یک خط:

</div>

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:WARPEP_RUN=1; irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

<div dir="rtl">

بعد از نصب، یک پنجره‌ی **جدید** CMD باز کنید تا PATH به‌روز شود، بعد:

</div>

```bat
warpep
warpep scan --fast
```

<div dir="rtl">

> پایتون ندارید؟ اسکریپت نصب خودش با `winget` نصبش می‌کند.
> آموزش قدم‌به‌قدم: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md)

### لینوکس · اوبونتو و بقیه

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

<div dir="rtl">

نصب **و** اسکن با یک خط:

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
```

<div dir="rtl">

بعد:

</div>

```bash
warpep scan
```

<div dir="rtl">

روی اوبونتو، دبیان، مینت، فدورا، RHEL، آرچ، مانجارو، اوپن‌سوزه، آلپاین و WSL تست
شده. اگر `~/.local/bin` در `PATH` شما نباشد، اسکریپت نصب دقیقاً خطی که باید اضافه
کنید را چاپ می‌کند. جزئیات: [docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md)

### مک

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

<div dir="rtl">

نصب **و** اسکن با یک خط:

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
```

<div dir="rtl">

جزئیات: [docs/INSTALL_MACOS.md](docs/INSTALL_MACOS.md)

### اجرا بدون نصب

یک بار اسکن کنید، چیزی نصب نشود، هیچ اثری هم نماند (هر سیستمی با پایتون ۳.۸+):

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --no-install --fast
```

<div dir="rtl">

یا فایل تک‌تکه‌ی آخرین ریلیز را بگیرید:

</div>

```bash
curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz
python3 warpep.pyz scan --fast
```

```bat
:: ویندوز CMD
curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz
python warpep.pyz scan --fast
```

<div dir="rtl">

فایل اجرایی مستقل (بدون نیاز به پایتون) هم برای ویندوز، لینوکس و مک به هر
[ریلیز](https://github.com/arjeyproject/WarpEP/releases) پیوست می‌شود.

### pip و pipx و داکر

</div>

```bash
pipx install git+https://github.com/arjeyproject/WarpEP        # پیشنهادی
pip install --user git+https://github.com/arjeyproject/WarpEP  # pip ساده
```

```bash
git clone https://github.com/arjeyproject/WarpEP && cd WarpEP
docker build -t warpep .
docker run --rm -it warpep scan --fast
```

<div dir="rtl">

حذف نصب، هر وقت خواستید:

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```

<div dir="rtl">

## جدول نصب تک‌خطی و اسکن تک‌خطی

| پلتفرم | نصب تک‌خطی | اسکن تک‌خطی |
| --- | --- | --- |
| **اندروید (ترموکس)** | `pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh \| bash` | `warpep scan --fast` |
| **ویندوز (CMD)** | `powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 \| iex"` | `warpep scan --fast` |
| **لینوکس (اوبونتو)** | `curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh \| bash` | `warpep scan` |
| **مک** | `curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh \| bash` | `warpep scan` |
| **هر سیستمی با پایتون** | `curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz` | `python3 warpep.pyz scan --fast` |

## طریقه استفاده

</div>

```bash
warpep                       # اسکن، رتبه‌بندی و نمایش بهترین اندپوینت‌ها
warpep scan --fast           # اسکن سریع (مناسب دیتای موبایل)
warpep scan --deep           # همه‌ی پریفیکس‌ها، همه‌ی پورت‌ها، ۵ پروب برای هرکدام
warpep scan -6               # اسکن پریفیکس‌های IPv6
warpep scan -n 512 -c 5      # ۵۱۲ آدرس نمونه، ۵ هند‌شیک برای هرکدام
warpep scan --top 20         # نمایش ۲۰ ردیف به‌جای ۱۰
warpep verify 162.159.192.1:2408
warpep config -o warp.conf   # کانفیگ WireGuard برای سریع‌ترین اندپوینت
warpep register              # ساخت یک ثبت‌نام واقعی وارپ
warpep selftest              # اثبات درستی رمزنگاری و حلقه‌ی اسکن روی همین دستگاه
```

<div dir="rtl">

نمونه‌ی خروجی:

</div>

```
* address space: 1778 addresses in 7 IPv4 prefix(es), probing 128
+ reachable ports on this network: 2408, 500, 1701
* probing 384 endpoints with 3 real WireGuard handshakes each

┌─────┬────────────────────────────┬───────────┬───────────┬───────────┬──────────┬────────┐
│   # │ ENDPOINT                   │      BEST │       AVG │     WORST │   JITTER │   LOSS │
├─────┼────────────────────────────┼───────────┼───────────┼───────────┼──────────┼────────┤
│   1 │ 162.159.192.79:2408        │   28.4 ms │   31.2 ms │   35.9 ms │   3.1 ms │     0% │
│   2 │ 188.114.97.140:500         │   33.7 ms │   34.8 ms │   36.2 ms │   1.4 ms │     0% │
│   3 │ 162.159.193.10:1701        │   41.2 ms │   47.9 ms │   58.1 ms │   8.6 ms │     0% │
└─────┴────────────────────────────┴───────────┴───────────┴───────────┴──────────┴────────┘

* 37 of 384 endpoints answered in 6.4s (1152 handshakes sent)
+ best endpoint: 162.159.192.79:2408 (31.2 ms avg, 0% loss, 3.1 ms jitter)
```

<div dir="rtl">

## راهنمای کامل دستورها

### `warpep scan`

| سوییچ | کار | مقدار پیش‌فرض |
| --- | --- | --- |
| `-6, --ipv6` | اسکن پریفیکس‌های IPv6 وارپ | IPv4 |
| `-n, --sample N` | چند آدرس نمونه‌برداری شود (`0` یعنی همه) | `128` |
| `-c, --probes N` | تعداد هند‌شیک برای هر اندپوینت | `3` |
| `-p, --ports LIST` | مثل `2408` یا `500-520` یا `primary` یا `all` | تشخیص خودکار |
| `--prefix CIDR` | اسکن پریفیکس دلخواه خودتان | پریفیکس‌های وارپ |
| `--target IP:PORT` | فقط همین اندپوینت‌ها اسکن شوند | – |
| `--timeout SEC` | زمان انتظار پاسخ هر پروب | `1.2` |
| `--rate N` | تعداد پروب در ثانیه | `1500` |
| `--max-inflight N` | تعداد پروب هم‌زمان در پرواز | `512` |
| `--source-ip ADDR` | بایند کردن پروب‌ها به یک آدرس محلی | خودکار |
| `--seed N` | نمونه‌برداری تکرارپذیر | تصادفی |
| `--fast` | پریست سریع: ۴۸ آدرس، پورت ۲۴۰۸، ۲ پروب | خاموش |
| `--deep` | پریست عمیق: همه‌ی آدرس‌ها و پورت‌ها، ۵ پروب | خاموش |
| `--skip-port-scan` | پورت‌های داده‌شده را قبول کن، مرحله‌ی کشف را رد کن | خاموش |
| `-t, --top N` | تعداد ردیف نمایش | `10` |
| `--verify [N]` | اعتبارسنجی عمیق N اندپوینت برتر از داخل تانل | خاموش |
| `--json FILE` | ذخیره‌ی کل نتایج به JSON | – |
| `--csv FILE` | ذخیره‌ی کل نتایج به CSV | – |
| `-o, --out FILE` | ذخیره‌ی برنده‌ها به شکل خطوط `ip:port` | – |
| `--conf FILE` | ساخت کانفیگ WireGuard برای برنده | – |
| `--singbox FILE` | ساخت اوت‌باند sing-box/هیدیفای برای برنده | – |
| `--peer-key B64` | کلید عمومی ریسپاندر (برای سرور شخصی خودتان) | وارپ کلادفلر |

### `warpep verify IP:PORT`

| سوییچ | کار | پیش‌فرض |
| --- | --- | --- |
| `--echoes N` | تعداد پکت ICMP که از تانل رد می‌شود | `3` |
| `--target IP` | آدرسی که داخل تانل پینگ می‌شود | `162.159.192.1` |
| `--timeout SEC` | زمان انتظار هر مرحله | `2.5` |

### `warpep config [IP:PORT]`

| سوییچ | کار | پیش‌فرض |
| --- | --- | --- |
| `--format` | یکی از `wireguard` یا `singbox` یا `endpoint` | `wireguard` |
| `-o, --out FILE` | نوشتن در فایل به‌جای ترمینال | ترمینال |
| `--mtu N` | مقدار MTU اینترفیس | `1280` |
| `--no-register` | هرگز با API وارپ تماس نگیر، کلید محلی بساز | خاموش |

اگر اندپوینت را ندهید، اول اسکن می‌کند و بعد برای برنده کانفیگ می‌سازد.

### سوییچ‌های عمومی

`--no-color` و `-q/--quiet` و `-V/--version` و `-h/--help`. این‌ها هم قبل و هم بعد
از نام دستور کار می‌کنند؛ یعنی هم `warpep -q scan` درست است و هم `warpep scan -q`.

کدهای خروج: `0` موفق · `1` چیزی پیدا نشد یا خطای شبکه · `2` خطای استفاده ·
`130` قطع با Ctrl+C.

## خواندن خروجی

| ستون | معنی |
| --- | --- |
| `BEST` | سریع‌ترین هند‌شیک تأییدشده |
| `AVG` | میانگین همه‌ی هند‌شیک‌های موفق (عددی که مهم است) |
| `WORST` | کندترین هند‌شیک موفق |
| `JITTER` | میانگین اختلاف پروب‌های پشت‌سرهم، مثل mdev در پینگ |
| `LOSS` | درصد پروب‌هایی که هیچ‌وقت برنگشتند |

رتبه‌بندی با فرمول `avg + jitter/2 + loss×10` انجام می‌شود: **اول پکت‌لاس، بعد
تأخیر، بعد پایداری**. سبز یعنی تمیز و سریع، زرد یعنی قابل‌استفاده، قرمز یعنی
ناچاری. اندپوینت‌هایی که فقط cookie reply می‌دهند زنده حساب می‌شوند (ریسپاندر
هست ولی محدودیت نرخ دارد) و در JSON زیر `cookie_replies` گزارش می‌شوند.

## استفاده از نتیجه‌ها

**هر کلاینت وارپ (v2rayNG، هیدیفای، NekoBox، اپ‌های WARP+).** فقط اندپوینت را پیست کنید:

</div>

```bash
warpep scan -o best-endpoints.txt   # هر خط یک ip:port، بهترین در بالا
```

<div dir="rtl">

**WireGuard و wg-quick.** ثبت‌نام واقعی، کانفیگ واقعی:

</div>

```bash
warpep register
warpep config -o warp.conf
sudo wg-quick up ./warp.conf
```

<div dir="rtl">

**اوت‌باند sing-box یا هیدیفای:**

</div>

```bash
warpep config --format singbox -o warp-outbound.json
```

<div dir="rtl">

**اتوماسیون.** خروجی ماشین‌خوان برای کران‌جاب و داشبورد:

</div>

```bash
warpep scan --fast --json results.json --csv results.csv -q
```

<div dir="rtl">

## موتور اسکن واقعاً چطور کار می‌کند؟

۱. **فضای آدرس.** پریفیکس‌های منتشرشده‌ی وارپ کلادفلر: `162.159.192.0/24` و
   `162.159.193.0/24` و `162.159.195.0/24` و `188.114.96.0/24` و `188.114.97.0/24`
   و `188.114.98.0/24` و `188.114.99.0/24` و برای IPv6 هم `2606:4700:d0::/64` و
   `2606:4700:d1::/64`. پورت‌ها همان‌هایی هستند که کلاینت رسمی روی‌شان fallback
   می‌کند؛ `2408` اول، و در کل ۵۳ پورت.
۲. **مرحله‌ی یک — کشف پورت باز.** چند آدرس روی همه‌ی پورت‌های کاندید پروب می‌شوند
   تا معلوم شود شبکه‌ی شما اجازه‌ی چه چیزی می‌دهد. اگر هیچ پورت اصلی جواب نداد،
   قبل از تسلیم شدن همه‌ی پورت‌های منتشرشده جارو می‌شوند.
۳. **مرحله‌ی دو — تأخیر و پکت‌لاس.** هر اندپوینت به تعداد `--probes` بسته‌ی
   هند‌شیک مستقل می‌گیرد که هرکدام اندیس فرستنده و تایم‌استمپ TAI64N خودش را
   دارد. پاسخ‌ها با اندیس تطبیق داده می‌شوند، رمزنگاری‌شان بررسی می‌شود و زمان با
   `time.perf_counter` دور خودِ ارسال اندازه‌گیری می‌شود.
۴. **رتبه‌بندی.** اول پکت‌لاس، بعد میانگین تأخیر، بعد جیتر.
۵. **اعتبارسنجی عمیق (اختیاری).** کلیدهای ترنسپورت از هند‌شیک کامل‌شده ساخته
   می‌شوند، یک بسته‌ی ICMP دستی ساخته می‌شود، به شکل پیام داده‌ی نوع ۴ وایرگارد
   رمز می‌شود و پاسخ رمزگشایی و با شماره‌ی سری تطبیق داده می‌شود.

نقشه‌ی پیاده‌سازی:

| فایل | کار |
| --- | --- |
| `warpep/wireguard/x25519.py` | منحنی Curve25519 طبق RFC 7748، پایتون خالص |
| `warpep/wireguard/chacha20poly1305.py` | رمزنگاری AEAD طبق RFC 8439، پایتون خالص |
| `warpep/wireguard/noise.py` | هند‌شیک وایرگارد، هم سمت آغازگر هم پاسخ‌دهنده |
| `warpep/wireguard/transport.py` | پکت‌های لایه‌ی داده و سازنده‌ی IPv4/ICMP |
| `warpep/endpoints.py` | پریفیکس‌ها، پورت‌ها و نمونه‌برداری |
| `warpep/engine.py` | حلقه‌ی اسکن، محدودکننده‌ی نرخ، امتیازدهی، چک تانل |
| `warpep/account.py` | ثبت‌نام واقعی وارپ از طریق API کلادفلر |
| `warpep/exporters.py` | خروجی WireGuard و sing-box و JSON و CSV |
| `warpep/output.py` | بنر، نوار پیشرفت زنده، جدول رتبه‌بندی |
| `warpep/selftest.py` | بردارهای RFC و کل حلقه‌ی اسکن روی دستگاه شما |

همه‌ی این‌ها با یک مجموعه تست آفلاین پوشش داده شده که یک **ریسپاندر واقعی
وایرگارد روی لوکال‌هاست** بالا می‌آورد، پس `make test` هیچ نیازی به اینترنت ندارد.

## تنظیم دقیق

| وضعیت | کاری که باید بکنید |
| --- | --- |
| دیتای موبایل و شبکه‌ی کند | `warpep scan --fast` |
| شکار جدی بهترین اندپوینت | `warpep scan --deep -c 5 --top 20` |
| اپراتور پورت ۲۴۰۸ را بسته | `warpep scan -p all` |
| اپراتور نرخ شما را محدود می‌کند | کم کردن `--rate 300` و `--max-inflight 64` |
| چند مسیر اینترنت هم‌زمان | `warpep scan --source-ip 192.168.1.50` |
| شبکه‌ی IPv6 یا دو‌پروتکلی | `warpep scan -6` |
| بنچمارک تکرارپذیر | `warpep scan --seed 42 -n 256` |
| اطمینان کامل از برنده | `warpep scan --verify 3` |

## رفع اشکال

**پیام `warpep: command not found` در لینوکس/مک/ترموکس** — مسیر `~/.local/bin` در
PATH نیست. خط `export PATH="$HOME/.local/bin:$PATH"` را به `~/.bashrc` یا
`~/.zshrc` اضافه کنید و ترمینال را ببندید و باز کنید. یا مستقیم اجرا کنید:
`python3 -m warpep scan`

**در CMD دستور `warpep` شناخته نمی‌شود** — بعد از نصب یک پنجره‌ی **جدید** CMD باز
کنید تا PATH تازه شود. باز هم نشد؟ مستقیم اجرا کنید:
`%LOCALAPPDATA%\WarpEP\bin\warpep.cmd`

**پاورشل اجرای اسکریپت را می‌بندد** — همان دستور تک‌خطی بالا را استفاده کنید؛
`-ExecutionPolicy Bypass` داخلش هست.

**همه‌ی نتایج ۱۰۰٪ لاس نشان می‌دهند** — شبکه‌ی شما UDP به کلادفلر را بسته. اول
`warpep scan -p all` و بعد یک شبکه‌ی دیگر را امتحان کنید؛ دیتای موبایل و وای‌فای
معمولاً فرق دارند.

**روی IPv6 چیزی پیدا نمی‌شود** — احتمالاً اپراتور شما مسیر IPv6 ندارد؛ `-6` را
بردارید.

**ترموکس می‌گوید `pkg: command not found`** — شما در شل اندروید هستید نه ترموکس؛
خودِ اپلیکیشن ترموکس را باز کنید.

**نتیجه‌ها بین اجراها فرق دارند** — تأخیر anycast واقعاً نوسان دارد. برای میانگین
پایدارتر `-c 5` بدهید و برای نمونه‌ی قابل‌مقایسه از `--seed` استفاده کنید.

**پایتون من سالم است؟** دستور `warpep selftest` را بزنید. اگر بردارهای رمزنگاری
پاس شدند، اعداد قابل‌اعتمادند.

## پرسش‌های پرتکرار

**روت یا دسترسی VPN لازم است؟** نه. فقط سوکت UDP معمولی بدون دسترسی ویژه.

**تنظیمات شبکه‌ام را عوض می‌کند؟** نه. WarpEP فقط اندازه می‌گیرد و گزارش می‌دهد؛
تصمیم با شماست.

**چرا پایتون و نه Go؟** چون یک پکیج پایتونی بدون هیچ وابستگی، در چند ثانیه روی
ترموکس، CMD ویندوز، کانتینر آلپاین و رانر CI نصب می‌شود؛ بدون کامپایلر و بدون
ماتریس کراس‌کامپایل. تمام کار پروتکل داخل همین ریپو است و حلقه‌ی داغ برنامه یک
سوکت غیرمسدودکننده است، پس اسکن کامل باز هم چند ثانیه طول می‌کشد.

**ثبت‌نام هزینه یا اکانت لازم دارد؟** نه. `warpep register` از همان API عمومی
کلاینت کلادفلر استفاده می‌کند که همه‌ی ابزارهای وارپ استفاده می‌کنند و نتیجه را در
`~/.config/warpep/account.json` (در ویندوز `%APPDATA%\WarpEP`) کش می‌کند.

**می‌توانم به سرور وایرگارد خودم وصلش کنم؟** بله:
`--peer-key <کلید عمومی base64>` همراه با `--target host:port`.

**اسکن اندپوینت‌های کلادفلر مجاز است؟** WarpEP فقط پروتکل وارپ را با آدرس‌های
منتشرشده‌ی خود سرویس وارپ حرف می‌زند، با نرخ مؤدبانه، دقیقاً مثل کلاینتی که
می‌خواهد اندپوینت انتخاب کند. `--rate` را منطقی نگه دارید.

## توسعه

</div>

```bash
git clone https://github.com/arjeyproject/WarpEP && cd WarpEP
make test        # تست آفلاین با هند‌شیک واقعی روی لوکال‌هاست
make selftest    # بردارهای RFC و حلقه‌ی اسکن
make scan        # اسکن سریع
make bundle      # ساخت فایل تک‌تکه‌ی warpep.pyz
```

<div dir="rtl">

مجموعه‌ی تست یک ریسپاندر واقعی وایرگارد روی `127.0.0.1` بالا می‌آورد، پس هر
شکستگی در پروتکل سریع لو می‌رود و هیچ‌چیز به اینترنت وابسته نیست. مشارکت خوش‌آمد
است: [CONTRIBUTING.md](CONTRIBUTING.md)

## لایسنس و اعتبارها

لایسنس MIT © ArJey — فایل [LICENSE](LICENSE) را ببینید.

ساخته و برندشده با نام **WarpEP by ArJey**. پروتکل WireGuard کار Jason A.
Donenfeld است؛ نام‌های «WireGuard» و «Cloudflare WARP» متعلق به مالکان خودشان
هستند و این پروژه وابستگی‌ای به آن‌ها ندارد. با الهام از پروژه‌ی خوب
[warpscout](https://github.com/vernette/warpscout) و جامعه‌ی ابزارهای وارپ، اما
تمام کد از صفر برای همین ریپازیتوری نوشته شده است.

</div>

<div align="center">

**WarpEP by ArJey** · [ثبت مشکل](https://github.com/arjeyproject/WarpEP/issues) · [English](README.md)

</div>
