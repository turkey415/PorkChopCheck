#!/usr/bin/env bash
# PorkChopCheck installer for Nobara / Fedora (also works on Debian/Ubuntu).
#
#   ./install-linux.sh              install (asks for your sudo password)
#   ./install-linux.sh --uninstall  remove the app menu entry, launcher and private Python
#
# What it does:
#   1. Installs Tk, libpcap, iproute, ethtool, NetworkManager CLI (and iperf3 if available).
#   2. Creates a private Python in .venv next to this script and installs psutil + scapy into it.
#   3. Gives ONLY that private Python two capabilities: cap_net_raw (packet capture) and
#      cap_net_admin (link up/down for Bounce and Port finder). PorkChopCheck runs as you, not root.
#   4. Adds "PorkChopCheck" to your app menu and a `porkchopcheck` command.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/.venv"
BIN="$HOME/.local/bin/porkchopcheck"
DESKTOP="$HOME/.local/share/applications/porkchopcheck.desktop"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -rf "$VENV" "$BIN" "$DESKTOP"
  echo "PorkChopCheck removed. Your port log in $APP_DIR/data was kept."
  exit 0
fi

echo "==> Installing system packages (sudo password needed)"
if command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-tkinter libpcap tcpdump libcap iproute iputils ethtool NetworkManager
  sudo dnf install -y iperf3 || echo "   (iperf3 not available; the iperf3 speed test will be skipped)"
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y python3 python3-venv python3-tk libpcap0.8 tcpdump libcap2-bin iproute2 iputils-ping ethtool
  sudo apt-get install -y iperf3 || true
else
  echo "   Unknown package manager. Install python3, tkinter, libpcap, iproute2 and ethtool yourself."
fi

echo "==> Creating PorkChopCheck's private Python in $VENV"
python3 -m venv --copies "$VENV"
"$VENV/bin/python3" -m pip install --quiet --upgrade pip
"$VENV/bin/python3" -m pip install --quiet -r "$APP_DIR/requirements.txt"

PY="$(readlink -f "$VENV/bin/python3")"
echo "==> Granting capture + link control to $PY (and nothing else)"
sudo setcap cap_net_raw,cap_net_admin+eip "$PY"

mkdir -p "$(dirname "$BIN")" "$(dirname "$DESKTOP")"
cat > "$BIN" <<EOF
#!/bin/sh
exec "$PY" "$APP_DIR/porkchopcheck.py" "\$@"
EOF
chmod +x "$BIN" "$APP_DIR/porkchopcheck.py"

cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=PorkChopCheck
Comment=Switch-port tester: link, DHCP, CDP/LLDP, 802.1X, ARP scan, mDNS
Exec=$BIN
Icon=network-wired
Terminal=false
Categories=Network;Utility;
EOF
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(dirname "$DESKTOP")" || true

echo
echo "Done! Launch PorkChopCheck from your app menu, or run:  porkchopcheck"
echo "On a small touchscreen use:  porkchopcheck --fullscreen"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "(Add ~/.local/bin to your PATH to use the porkchopcheck command.)";; esac
