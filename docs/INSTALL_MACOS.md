# Install WarpEP on macOS · نصب روی مک

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

macOS ships Python 3, so this is usually instant. If it is missing the installer
uses Homebrew. Intel and Apple silicon are both fine.

### Usage

```bash
warpep scan
warpep scan --deep --top 20
warpep verify 162.159.192.1:2408
warpep config -o ~/Desktop/warp.conf
```

Import `warp.conf` into the WireGuard app from the Mac App Store, or:

```bash
brew install wireguard-tools
sudo wg-quick up ./warp.conf
```

### Notes

- `~/.local/bin` may not be on your PATH. Add
  `export PATH="$HOME/.local/bin:$PATH"` to `~/.zshrc`.
- Standalone `warpep-macos-arm64` binaries are attached to every release.
- Gatekeeper may quarantine a downloaded binary: `xattr -d com.apple.quarantine warpep-macos-arm64`.

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

مک خودش پایتون ۳ دارد، پس معمولاً نصب لحظه‌ای است. اگر نبود، نصب‌کننده از Homebrew
استفاده می‌کند. هم اینتل و هم اپل‌سیلیکون پشتیبانی می‌شوند.

### استفاده

</div>

```bash
warpep scan
warpep scan --deep --top 20
warpep verify 162.159.192.1:2408
warpep config -o ~/Desktop/warp.conf
```

<div dir="rtl">

فایل `warp.conf` را در اپ WireGuard از App Store ایمپورت کنید، یا:

</div>

```bash
brew install wireguard-tools
sudo wg-quick up ./warp.conf
```

<div dir="rtl">

### نکته‌ها

- ممکن است `~/.local/bin` در PATH شما نباشد؛ خط
  `export PATH="$HOME/.local/bin:$PATH"` را به `~/.zshrc` اضافه کنید.
- فایل اجرایی مستقل `warpep-macos-arm64` به هر ریلیز پیوست می‌شود.
- Gatekeeper ممکن است فایل دانلودی را قرنطینه کند:
  `xattr -d com.apple.quarantine warpep-macos-arm64`

### حذف نصب

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```
