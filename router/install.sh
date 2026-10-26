#!/bin/sh
# Installs PorkChopCheck's port tester on a GL.iNet router (tried on the GL-BE3600 Slate 7), from a PC
# that can SSH to it as root:
#
#   router/install.sh root@192.168.8.1            install, or update to this copy
#   router/install.sh root@192.168.8.1 --uninstall
#
# Run it from the PorkChopCheck folder. It copies pc_net.py and router/pcc_router/ to
# /usr/share/pcc-router, adds the service, and lists those files in /etc/sysupgrade.conf so a
# firmware upgrade that keeps settings keeps the tester too. It also sets the side switch to change
# the network mode (on = Access point, off = Router) through /etc/gl-switch.d/netmode.sh.
set -eu

HOST="${1:-}"
if [ -z "$HOST" ]; then
	echo "usage: router/install.sh root@ROUTER [--uninstall]" >&2
	exit 2
fi
cd "$(dirname "$0")/.."
SSH="ssh -o ConnectTimeout=10 $HOST"
KEEP="/usr/share/pcc-router/
/etc/pcc-router/
/etc/init.d/pcc-router
/etc/gl-switch.d/netmode.sh
/etc/rc.d/S99pcc-router
/etc/rc.d/K10pcc-router"

if [ "${2:-}" = "--uninstall" ]; then
	$SSH 'set -e
		[ -x /etc/init.d/pcc-router ] && { /etc/init.d/pcc-router stop; /etc/init.d/pcc-router disable; } || true
		rm -rf /usr/share/pcc-router /etc/pcc-router /etc/init.d/pcc-router /etc/gl-switch.d/netmode.sh
		[ "$(uci -q get switch-button.@main[0].func)" = netmode ] && { uci -q delete switch-button.@main[0].func; uci commit switch-button; } || true
		sed -i "/pcc-router/d; \#/etc/gl-switch.d/netmode.sh#d" /etc/sysupgrade.conf
		/etc/init.d/gl_screen start >/dev/null 2>&1 || true
		echo "PorkChopCheck removed; the screen is GL.iNet'"'"'s again."'
	exit 0
fi

$SSH 'command -v python3 >/dev/null' || { echo "No python3 on the router." >&2; exit 1; }
echo "Copying to $HOST..."
tar -cf - pc_net.py -C router pcc_router/__init__.py pcc_router/font.py pcc_router/screen.py \
	pcc_router/service.py pcc_router/tester.py pcc_router/tools.py pcc_router/web.py pcc_router/wifi.py netmode.lua \
	| $SSH 'rm -rf /usr/share/pcc-router && mkdir -p /usr/share/pcc-router /etc/pcc-router && tar -C /usr/share/pcc-router -xf -'
$SSH 'cat > /etc/init.d/pcc-router && chmod 755 /etc/init.d/pcc-router' < router/pcc-router.init
# the side switch: GL.iNet runs /etc/gl-switch.d/<func>.sh with on/off when it is flipped
$SSH 'mkdir -p /etc/gl-switch.d && cat > /etc/gl-switch.d/netmode.sh && chmod 755 /etc/gl-switch.d/netmode.sh
	if [ -f /proc/gl-hw-info/switch-button ]; then
		uci -q get switch-button.@main[0] >/dev/null || uci add switch-button main >/dev/null
		uci set switch-button.@main[0].func=netmode; uci -q delete switch-button.@main[0].sub_func; uci commit switch-button
	fi' < router/switch-netmode.sh
printf '%s\n' "$KEEP" | $SSH 'while read -r line; do grep -qxF "$line" /etc/sysupgrade.conf || echo "$line" >> /etc/sysupgrade.conf; done'
$SSH '/etc/init.d/pcc-router enable && /etc/init.d/pcc-router restart'
echo "Installed. Join the router's Wi-Fi and open http://192.168.8.1:8088"
