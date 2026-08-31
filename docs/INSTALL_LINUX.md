# Install WarpEP on Linux (Ubuntu and friends) · نصب روی لینوکس

[English](#english) · [فارسی](#فارسی)

---

## English

### One line

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

Install and scan together:

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
```

The installer picks the right package manager for you: `apt-get`, `dnf`, `yum`,
`pacman`, `zypper`, `apk` or Homebrew, and only touches it if Python 3.8+ is
missing. As a normal user it installs to `~/.local/share/warpep` with the launcher
at `~/.local/bin/warpep`. As root it uses `/usr/local`.

### PATH

If the installer warns you, add this to `~/.bashrc` (or `~/.zshrc`) and reopen your shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Usage

```bash
warpep scan                     # default scan
warpep scan --deep -c 5         # thorough
warpep scan -6                  # IPv6 prefixes
warpep scan --verify 3          # prove the top 3 carry traffic
warpep scan --json ~/warp.json  # machine readable
```

### Straight to a working tunnel

```bash
warpep register
warpep config -o warp.conf
sudo apt-get install -y wireguard-tools   # if needed
sudo wg-quick up ./warp.conf
curl -s https://www.cloudflare.com/cdn-cgi/trace | grep warp   # expect warp=on
sudo wg-quick down ./warp.conf
```

### Keep the best endpoint fresh (cron)

```bash
crontab -e
# every 6 hours, refresh the endpoint list quietly
0 */6 * * * $HOME/.local/bin/warpep scan --fast -q -o $HOME/.cache/warp-best.txt
```

### systemd one-shot alternative

```ini
# /etc/systemd/system/warpep-scan.service
[Unit]
Description=WarpEP endpoint scan
[Service]
Type=oneshot
ExecStart=/usr/local/bin/warpep scan --fast -q -o /var/lib/warpep/best.txt
```

### Notes

- No root and no capabilities required: unprivileged UDP only.
- Alpine/musl, WSL1 and WSL2 all work.
- Docker: `docker build -t warpep . && docker run --rm -it warpep scan --fast`.

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```

---

## فارسی

<div dir="rtl">

### یک خط

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

<div dir="rtl">

نصب و اسکن با هم:

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
```

<div dir="rtl">

نصب‌کننده خودش پکیج‌منیجر درست را انتخاب می‌کند: `apt-get`، `dnf`، `yum`،
`pacman`، `zypper`، `apk` یا Homebrew؛ و فقط وقتی سراغش می‌رود که پایتون ۳.۸+
نباشد. با کاربر معمولی در `~/.local/share/warpep` نصب می‌شود و لانچر در
`~/.local/bin/warpep` قرار می‌گیرد. با روت از `/usr/local` استفاده می‌کند.

### مسیر PATH

اگر نصب‌کننده هشدار داد، این خط را به `~/.bashrc` (یا `~/.zshrc`) اضافه کنید و
ترمینال را ببندید و باز کنید:

</div>

```bash
export PATH="$HOME/.local/bin:$PATH"
```

<div dir="rtl">

### استفاده

</div>

```bash
warpep scan                     # اسکن پیش‌فرض
warpep scan --deep -c 5         # اسکن کامل و دقیق
warpep scan -6                  # پریفیکس‌های IPv6
warpep scan --verify 3          # اثبات این‌که ۳ تای برتر ترافیک را رد می‌کنند
warpep scan --json ~/warp.json  # خروجی ماشین‌خوان
```

<div dir="rtl">

### مستقیم تا یک تانل کارآمد

</div>

```bash
warpep register
warpep config -o warp.conf
sudo apt-get install -y wireguard-tools   # اگر نصب نیست
sudo wg-quick up ./warp.conf
curl -s https://www.cloudflare.com/cdn-cgi/trace | grep warp   # باید warp=on بدهد
sudo wg-quick down ./warp.conf
```

<div dir="rtl">

### به‌روز نگه داشتن بهترین اندپوینت با cron

</div>

```bash
crontab -e
# هر ۶ ساعت، لیست اندپوینت‌ها را بی‌صدا تازه کن
0 */6 * * * $HOME/.local/bin/warpep scan --fast -q -o $HOME/.cache/warp-best.txt
```

<div dir="rtl">

### نکته‌ها

- نه روت لازم است نه capability؛ فقط UDP بدون دسترسی ویژه.
- آلپاین/musl و WSL1 و WSL2 همه کار می‌کنند.
- داکر: `docker build -t warpep . && docker run --rm -it warpep scan --fast`

### حذف نصب

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```
