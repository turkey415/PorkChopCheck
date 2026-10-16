# PorkChopCheck on a GL.iNet router

Turns a GL.iNet travel router into a pocket switch-port tester: plug its **WAN port** into a jack and
it tells you what's on the other end, on the router's own screen and on a phone page. It uses
PorkChopCheck's own decoders (`pc_net.py`), so it reads the same things the desktop app does.

Tried on the **GL-BE3600 (Slate 7)**: OpenWrt 23.05 / GL firmware 4.10, a 2.5 GbE WAN port, a
284 × 76 touchscreen, and Python 3.11 already installed. Other GL.iNet routers with Python 3 should
run the tester and phone page; the screen code is for the Slate 7's display.

This folder is separate from the desktop app: the Windows and Linux downloads and
`install-linux.sh` list their files by name and never include it.

## What it shows

| | |
|---|---|
| **Verdict** | green / amber / red, worst finding first: no link, no DHCP address, 802.1X login wanted, a second (rogue) DHCP server, gateway not answering, half duplex, a link slower than both ends can do (bad cable pair), no internet, slow to pass traffic (portfast off?), spanning-tree changes, more than one IPv6 router, no CDP/LLDP |
| **Switch** | switch name, port, data and voice VLAN, model, management IP, PoE, from CDP and LLDP |
| **Port** | link speed and duplex, address, gateway, DNS and internet with times, public IP, time from link up to an address and to the gateway answering, link drops |
| **DHCP and layer 2** | every DHCP server that answers (it sends a DISCOVER of its own a few seconds after each link up), lease, phone options 150/66/43, 802.1X, spanning tree (mode, root, role), trunk/DTP, VLAN tags seen, gateway MAC (and HSRP/VRRP), IPv6 routers, broadcasts per second |
| **Events** | link up and down, address gained or lost, CDP/LLDP heard, a second DHCP server, topology changes, the gateway answering from another MAC |

Plugging into a new jack starts over: everything learned from the last port is forgotten.

## Using it

- **The router's screen:** tap for the next page (Summary, Switch, Port, Layer 2). **Hold for 1.5 s**
  to hand the screen back to GL.iNet's own screen program.
- **The phone page:** join the router's Wi-Fi and open **http://192.168.8.1:8088**. Everything above,
  refreshed every 2 seconds, with **Re-check now**, and a **Screen: GL.iNet / PorkChopCheck** switch at
  the top. The choice is remembered across reboots. The tester keeps running with either screen.

GL.iNet's firewall keeps port 8088 closed on the WAN side: only the router's Wi-Fi and LAN reach it.

## Installing

From the PorkChopCheck folder on a PC that can SSH to the router as root (add the PC's key in LuCI:
System › Administration › SSH-Keys):

```
router/install.sh root@192.168.8.1              # install, or update to this copy
router/install.sh root@192.168.8.1 --uninstall   # remove it and give the screen back
```

It copies `pc_net.py` and `router/pcc_router/` to `/usr/share/pcc-router`, adds the service
`/etc/init.d/pcc-router`, and lists those files in `/etc/sysupgrade.conf` so a firmware upgrade that
keeps settings keeps the tester. The settings file is `/etc/pcc-router/config.json` (`screen`:
`pcc` or `gl`; `iface`, `wan`, `port`). Whenever the service stops it starts GL.iNet's screen program
again, so the screen is never left dark.

## How it works

`pcc_router/service.py` runs these threads under procd:

- the WAN's link from `/sys/class/net/eth0` and `ethtool` (what each end offered, for the cable check)
- a raw socket on the WAN, every frame through `pc_net.classify`
- the router's own DHCP client status (`ubus call network.interface.wan status`) and the gateway's MAC
- gateway, DNS and internet checks every 5 seconds, and the public address
- the screen (`screen.py`: draws straight into `/dev/fb0` with bitmap fonts made by
  `tools/make_font.py` from Noto Sans Mono, SIL Open Font License) and its touch input
- the phone page (`web.py`)

The logic is in `tester.py` with no I/O, so `tests/test_router.py` checks it on a PC with real-shaped
CDP, LLDP, DHCP and 802.1X frames, draws every screen page, and drives the phone page.

## Not yet

From the desktop app's Tools page, still to come here: ping with the event timeline, the tick test
(the router could also be the reflector at the game server), iperf3 speed test, port finder (blink the
switch port's LED), a port log with labels, and reporting results to a GXL Event Server.
