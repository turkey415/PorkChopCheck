#!/usr/bin/env bash
# PorkChopCheck installer for Nobara / Fedora (also works on Debian/Ubuntu).
#
#   ./install-linux.sh              install (asks for your sudo password)
#   ./install-linux.sh --uninstall  remove the app, its launcher and the app menu entry
#
# What it does:
#   1. Installs Tk, libpcap, iproute, ethtool, NetworkManager CLI, a C compiler (and iperf3 if
#      available).
#   2. Copies the app to /opt/porkchopcheck, owned by root, with a private Python that has
#      psutil + scapy.
#   3. Builds a small launcher, pcc-launch, and gives ONLY the launcher two capabilities:
#      cap_net_raw (packet capture) and cap_net_admin (link up/down for Bounce and Port finder).
#      The launcher starts the app and nothing else, so no other program can borrow them.
#      PorkChopCheck runs as you, not root.
#   4. Adds "PorkChopCheck" to your app menu and a `porkchopcheck` command.
#
# Earlier versions gave the capabilities to a Python interpreter in the unpacked folder, which
# any program could run. This installer takes them away from every such copy it finds.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/porkchopcheck"
LAUNCHER="$PREFIX/pcc-launch"
BIN="$HOME/.local/bin/porkchopcheck"
DESKTOP="$HOME/.local/share/applications/porkchopcheck.desktop"
USER_DATA="$HOME/Documents/PorkChopCheck/data"

if [[ $EUID -eq 0 ]]; then
  echo "Run this as yourself, not with sudo. It asks for your password when it needs it." >&2
  exit 1
fi

# The folder an earlier install ran from, read out of the old `porkchopcheck` command.
OLD_APP_DIR=""
if [[ -f "$BIN" ]]; then
  OLD_APP_DIR="$(sed -n 's/^exec "[^"]*" "\(.*\)\/porkchopcheck\.py".*/\1/p' "$BIN" | head -n 1)"
fi

# Take the capabilities away from every Python an earlier version granted them to.
strip_old_caps() {
  local d py
  for d in "$SRC_DIR" "$OLD_APP_DIR" "$SRC_DIR"/../PorkChopCheck-*-linux; do
    [[ -n "$d" && -d "$d/.venv/bin" ]] || continue
    for py in "$d"/.venv/bin/python*; do
      [[ -f "$py" && ! -L "$py" ]] || continue
      if [[ -n "$(getcap "$py" 2>/dev/null)" ]]; then
        echo "   removing capture permission from old copy: $py"
        sudo setcap -r "$py"
      fi
    done
  done
}

if [[ "${1:-}" == "--uninstall" ]]; then
  echo "==> Removing PorkChopCheck (sudo password needed)"
  sudo rm -rf "$PREFIX"
  strip_old_caps
  rm -rf "$SRC_DIR/.venv" "$BIN" "$DESKTOP"
  echo "PorkChopCheck removed. Your port log in $USER_DATA was kept."
  exit 0
fi

for f in porkchopcheck.py pc_net.py pc_smart.py pc_snmp.py pc_nic.py requirements.txt linux/pcc-launch.c; do
  [[ -f "$SRC_DIR/$f" ]] || { echo "Missing $f next to this script." >&2; exit 1; }
done

echo "==> Installing system packages (sudo password needed)"
if command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-tkinter libpcap tcpdump libcap iproute iputils ethtool NetworkManager gcc glibc-devel
  sudo dnf install -y iperf3 || echo "   (iperf3 not available; the iperf3 speed test will be skipped)"
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y python3 python3-venv python3-tk libpcap0.8 tcpdump libcap2-bin iproute2 iputils-ping ethtool gcc libc6-dev
  sudo apt-get install -y iperf3 || true
else
  echo "   Unknown package manager. Install python3, tkinter, libpcap, libcap, iproute2, ethtool and gcc yourself."
fi

echo "==> Building the launcher"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cc -O2 -Wall -Wextra -DPREFIX="\"$PREFIX\"" -o "$BUILD/pcc-launch" "$SRC_DIR/linux/pcc-launch.c"

echo "==> Installing PorkChopCheck to $PREFIX (owned by root)"
sudo rm -rf "$PREFIX"
sudo install -d -o root -g root -m 0755 "$PREFIX"
sudo install -o root -g root -m 0644 "$SRC_DIR/porkchopcheck.py" "$SRC_DIR/pc_net.py" "$SRC_DIR/pc_smart.py" \
  "$SRC_DIR/pc_snmp.py" "$SRC_DIR/pc_nic.py" \
  "$SRC_DIR/requirements.txt" "$PREFIX/"
for f in README.md LICENSE; do
  [[ -f "$SRC_DIR/$f" ]] && sudo install -o root -g root -m 0644 "$SRC_DIR/$f" "$PREFIX/"
done

echo "==> Creating PorkChopCheck's private Python in $PREFIX/.venv"
sudo python3 -m venv "$PREFIX/.venv"
sudo "$PREFIX/.venv/bin/python3" -m pip install --quiet --upgrade pip
# Wheels only: nothing downloaded gets to run its own build script as root.
sudo "$PREFIX/.venv/bin/python3" -m pip install --quiet --only-binary :all: -r "$PREFIX/requirements.txt"
sudo "$PREFIX/.venv/bin/python3" -m compileall -q "$PREFIX/porkchopcheck.py" "$PREFIX/pc_net.py" "$PREFIX/pc_smart.py" "$PREFIX/pc_snmp.py" "$PREFIX/pc_nic.py"

echo "==> Granting capture + link control to the launcher (and nothing else)"
# Root owns it; only your group may run it.
sudo install -o root -g "$(id -gn)" -m 0750 "$BUILD/pcc-launch" "$LAUNCHER"
sudo setcap cap_net_raw,cap_net_admin=p "$LAUNCHER"
strip_old_caps

# Bring the port log along from a copy that kept it next to the app.
if [[ ! -d "$USER_DATA" ]]; then
  for d in "$OLD_APP_DIR" "$SRC_DIR"; do
    if [[ -n "$d" && -d "$d/data" ]]; then
      mkdir -p "$(dirname "$USER_DATA")"
      cp -a "$d/data" "$USER_DATA"
      echo "==> Copied your port log from $d/data to $USER_DATA"
      break
    fi
  done
fi

mkdir -p "$(dirname "$BIN")" "$(dirname "$DESKTOP")"
cat > "$BIN" <<LAUNCH
#!/bin/sh
exec "$LAUNCHER" "\$@"
LAUNCH
chmod +x "$BIN"

cat > "$DESKTOP" <<ENTRY
[Desktop Entry]
Type=Application
Name=PorkChopCheck
Comment=Switch-port tester: link, DHCP, CDP/LLDP, 802.1X, ARP scan, mDNS
Exec=$LAUNCHER
Icon=network-wired
Terminal=false
Categories=Network;Utility;
ENTRY
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(dirname "$DESKTOP")" || true

echo
echo "Done! Launch PorkChopCheck from your app menu, or run:  porkchopcheck"
echo "On a small touchscreen use:  porkchopcheck --fullscreen"
echo "Your port log and settings are kept in $USER_DATA"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "(Add ~/.local/bin to your PATH to use the porkchopcheck command.)";; esac
