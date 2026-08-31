#!/usr/bin/env bash
# WarpEP by ArJey - one-line installer for Linux, macOS, WSL and Termux.
#
#   curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
#
# Flags:
#   --run           scan immediately after installing
#   --fast          use the fast preset for that scan
#   --no-install    run once from a temporary directory, install nothing
#   --ref REF       install a branch or tag (default: main)
#   --uninstall     remove WarpEP
#   --help          show this help
#
# Environment: WARPEP_TARBALL=/path/to/WarpEP.tar.gz installs from a local archive.
set -euo pipefail

REPO="arjeyproject/WarpEP"
REF="${WARPEP_REF:-main}"
RUN_AFTER=0
FAST=0
NO_INSTALL=0
UNINSTALL=0

BOLD=""; DIM=""; RED=""; GREEN=""; CYAN=""; YELLOW=""; RESET=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="\033[1m"; DIM="\033[2m"; RED="\033[91m"; GREEN="\033[92m"
  CYAN="\033[96m"; YELLOW="\033[93m"; RESET="\033[0m"
fi
say()  { printf "${CYAN}*${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}+${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*"; }
die()  { printf "${RED}x${RESET} %s\n" "$*" >&2; exit 1; }

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --run) RUN_AFTER=1 ;;
    --fast) FAST=1; RUN_AFTER=1 ;;
    --no-install|--temp) NO_INSTALL=1; RUN_AFTER=1 ;;
    --ref) shift; REF="${1:?--ref needs a value}" ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

banner() {
  printf "${CYAN}${BOLD}"
  cat <<'ART'
 __        __                 _____ ____
 \ \      / /_ _ _ __ _ __   | ____|  _ \
  \ \ /\ / / _` | '__| '_ \  |  _| | |_) |
   \ V  V / (_| | |  | |_) | | |___|  __/
    \_/\_/ \__,_|_|  | .__/  |_____|_|
                     |_|
ART
  printf "${RESET}  ${BOLD}WarpEP by ArJey${RESET} ${DIM}- real Cloudflare WARP endpoint scanner${RESET}\n\n"
}

is_termux() { case "${PREFIX:-}" in *com.termux*) return 0 ;; esac; [ -d "/data/data/com.termux" ]; }

have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" != "0" ] && have sudo; then SUDO="sudo"; fi

detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  if is_termux; then PLATFORM="termux"
  elif [ "$os" = "Darwin" ]; then PLATFORM="macos"
  elif [ "$os" = "Linux" ]; then PLATFORM="linux"
  else PLATFORM="$os"; fi
  say "platform: ${BOLD}${PLATFORM}${RESET} (${os} ${arch})"
}

install_python() {
  warn "python3 is missing, installing it"
  if is_termux; then pkg install -y python
  elif have apt-get; then $SUDO apt-get update -y && $SUDO apt-get install -y python3
  elif have dnf; then $SUDO dnf install -y python3
  elif have yum; then $SUDO yum install -y python3
  elif have pacman; then $SUDO pacman -Sy --noconfirm python
  elif have zypper; then $SUDO zypper install -y python3
  elif have apk; then $SUDO apk add --no-cache python3
  elif have brew; then brew install python
  else die "install Python 3.8+ manually, then re-run this installer"; fi
}

find_python() {
  for candidate in python3 python; do
    if have "$candidate" && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
      PYTHON="$candidate"; return 0
    fi
  done
  return 1
}

ensure_python() {
  if ! find_python; then
    install_python
    find_python || die "could not find a working Python 3.8+ after installation"
  fi
  say "python: $($PYTHON -V 2>&1) ($(command -v $PYTHON))"
}

pick_paths() {
  if is_termux; then
    LIBDIR="${PREFIX}/lib/warpep"; BINDIR="${PREFIX}/bin"; NEEDS_SUDO=0
  elif [ "$(id -u)" = "0" ]; then
    LIBDIR="/usr/local/lib/warpep"; BINDIR="/usr/local/bin"; NEEDS_SUDO=0
  else
    LIBDIR="${HOME}/.local/share/warpep"; BINDIR="${HOME}/.local/bin"; NEEDS_SUDO=0
  fi
}

fetch() {
  local url="$1" out="$2"
  if have curl; then curl -fsSL "$url" -o "$out"
  elif have wget; then wget -qO "$out" "$url"
  else die "need curl or wget to download WarpEP"; fi
}

download_source() {
  TMPDIR_WEP="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR_WEP"' EXIT
  # Air-gapped / mirrored installs: point WARPEP_TARBALL at a local .tar.gz.
  if [ -n "${WARPEP_TARBALL:-}" ]; then
    say "using local archive ${WARPEP_TARBALL}"
    cp "$WARPEP_TARBALL" "$TMPDIR_WEP/src.tar.gz"
    tar -xzf "$TMPDIR_WEP/src.tar.gz" -C "$TMPDIR_WEP"
    SRCDIR="$(find "$TMPDIR_WEP" -maxdepth 1 -type d -name 'WarpEP-*' | head -n 1)"
    [ -d "$SRCDIR/warpep" ] || die "local archive does not contain a warpep package"
    ok "source ready"
    return 0
  fi
  local url="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${REF}"
  say "downloading ${REPO}@${REF}"
  if ! fetch "$url" "$TMPDIR_WEP/src.tar.gz"; then
    url="https://codeload.github.com/${REPO}/tar.gz/refs/tags/${REF}"
    fetch "$url" "$TMPDIR_WEP/src.tar.gz" || die "download failed: check the network or --ref"
  fi
  tar -xzf "$TMPDIR_WEP/src.tar.gz" -C "$TMPDIR_WEP"
  SRCDIR="$(find "$TMPDIR_WEP" -maxdepth 1 -type d -name 'WarpEP-*' | head -n 1)"
  [ -d "$SRCDIR/warpep" ] || die "downloaded archive looks wrong (no warpep package)"
  ok "source ready"
}

do_uninstall() {
  pick_paths
  rm -rf "$LIBDIR" "$BINDIR/warpep"
  ok "removed $LIBDIR and $BINDIR/warpep"
  warn "your WARP registration cache is untouched: ${HOME}/.config/warpep"
  exit 0
}

install_files() {
  pick_paths
  mkdir -p "$LIBDIR" "$BINDIR"
  rm -rf "$LIBDIR/warpep"
  cp -R "$SRCDIR/warpep" "$LIBDIR/warpep"
  cp "$SRCDIR/LICENSE" "$LIBDIR/LICENSE" 2>/dev/null || true
  cat > "$BINDIR/warpep" <<LAUNCHER
#!/usr/bin/env sh
# WarpEP by ArJey launcher
PYTHONPATH="${LIBDIR}\${PYTHONPATH:+:\$PYTHONPATH}" exec ${PYTHON} -m warpep "\$@"
LAUNCHER
  chmod +x "$BINDIR/warpep"
  ok "installed to ${BOLD}${BINDIR}/warpep${RESET}"
  case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *)
      warn "$BINDIR is not on your PATH. Add this line to your shell profile:"
      printf '    export PATH="%s:$PATH"\n' "$BINDIR"
      ;;
  esac
}

verify() {
  say "verifying the install"
  if PYTHONPATH="$LIBDIR" "$PYTHON" -m warpep selftest >/dev/null 2>&1; then
    ok "selftest passed: crypto vectors and scan loop are healthy"
  else
    warn "selftest reported problems, run: warpep selftest"
  fi
}

run_scan() {
  local args="scan"
  [ "$FAST" = "1" ] && args="scan --fast"
  printf "\n"
  say "starting a real WARP endpoint scan"
  if [ "$NO_INSTALL" = "1" ]; then
    PYTHONPATH="$SRCDIR" "$PYTHON" -m warpep $args
  else
    PYTHONPATH="$LIBDIR" "$PYTHON" -m warpep $args
  fi
}

banner
[ "$UNINSTALL" = "1" ] && do_uninstall
detect_platform
ensure_python
download_source
if [ "$NO_INSTALL" = "1" ]; then
  warn "running without installing (temporary copy)"
else
  install_files
  verify
  printf "\n"
  printf "  ${BOLD}quick start${RESET}\n"
  printf "    warpep                 %s\n" "scan and rank WARP endpoints"
  printf "    warpep scan --fast     %s\n" "quick scan, great on mobile data"
  printf "    warpep scan --deep     %s\n" "sweep every published prefix and port"
  printf "    warpep verify IP:PORT  %s\n" "prove an endpoint really carries traffic"
  printf "    warpep config -o warp.conf  %s\n" "WireGuard config for the winner"
  printf "\n"
fi
[ "$RUN_AFTER" = "1" ] && run_scan
exit 0
