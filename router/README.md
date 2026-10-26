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

## Tools (the phone page's Tools tab)

| Tool | What it does |
|---|---|
| **Ping** | Four pings a second to the gateway, the DNS server, the internet or any address, always running. A graph of the last 30 s, 5 min or 30 min with lost pings in red and every event marked on it, and under each event what ping did around it (`2 pings lost · peak 212 ms, normally 3 ms`, or `no effect on ping`). Loss, average, jitter, 99% under. The router's screen has a Ping page too. |
| **Tick test** | Game-rate UDP (64 or 128 packets a second, 160 bytes) to a reflector, graded for Counter-Strike with the desktop's limits: loss, lost in a row, late replies, ping, jitter, the reflector's own delay taken out, and when each lost packet went missing. It sends a warm-up packet first so the first test packets are not lost to address lookup. |
| **Reflector** | The far end of a tick test, on the router: put one router at the game server and test from another at a seat. Opens UDP 27777 on the WAN only while it is on. `porkchopcheck --reflector` on any PC does the same. |
| **Speed test** | iperf3 up and down against a server you name (a GXL Event Server runs one on port 5202). The Slate 7 reaches full gigabit. |
| **Port finder** | Blinks the switch port's LED: the WAN link down for 1.5 s, then up until it is really back (about 3 s on the Slate 7) and 2 s more. The tester keeps what it knew about the port meanwhile. The router's own internet drops while it runs. |
| **Port log** | One row per switch + port, written whenever CDP/LLDP names it, and **Save** with a label (`Row C seat 7`) for history. Download as `ports.csv`. Kept in `/etc/pcc-router`, so it survives reboots. |

## Router or Access point

The router can switch between **Router** mode and **Access point** mode without a reset, and all its
settings and this tester are kept. The change uses GL.iNet's own call, the one its Network Mode page
makes. It takes a few seconds, and Wi-Fi drops briefly.

- **Side switch:** **on = Access point, off = Router**. The installer sets the switch to do this. It
  can be set back to another job in GL.iNet's admin page (the switch has one job at a time).
- **The screen:** every page shows the mode in its top corner: grey `ROUTER`, blue `AP`, or amber
  `> AP` while it changes. The **Mode** page (the last one) shows the mode, where the phone page
  is, and where the switch is. **Hold it for 3 s** to change the mode. At 1.5 s it says "Keep
  holding", and that hold doesn't hand the screen back on this page.
- **The phone page:** the Network mode card at the top, with Router and Access point buttons.

In **Access point** mode the WAN port joins the LAN, the router stops handing out addresses, and it
takes an address from the network on WAN. **192.168.8.1 stops working**; the phone page moves to
that new address (the Mode page and the Summary page show it). The tester keeps testing the port the
WAN is plugged into, in both modes. AP mode needs a cable in WAN: without one it says "Plug a cable
into WAN first" and stays a router.

After a reboot the router keeps whatever mode it was in. GL.iNet replays the switch's position at
boot, and that replay is ignored, so the mode never changes on its own. If the switch and the mode
disagree (after a change from the screen or the phone page), the next flip of the switch sets the
mode to its new position.

## Using it

- **The router's screen:** tap for the next page (Summary, Switch, Port, Layer 2, Ping, Mode), or
  swipe: right to left for the next page, left to right for the previous one. **Hold for 1.5 s** to
  hand the screen back to GL.iNet's own screen program (on the Mode page, hold 3 s to change mode).
- **The phone page:** join the router's Wi-Fi and open **https://192.168.8.1:8088** (see Login and HTTPS). Everything above,
  refreshed every 2 seconds, with **Re-check now**, and a **Screen: GL.iNet / PorkChopCheck** switch at
  the top. The choice is remembered across reboots. The tester keeps running with either screen.

GL.iNet's firewall keeps port 8088 closed on the WAN side: only the router's Wi-Fi and LAN reach it.

## Login and HTTPS

The phone page is **https://192.168.8.1:8088**. In Access point mode it's at the address on the
screen's Mode page. Plain `http://` on the same port is sent to `https://` automatically.

- **Certificate:** the router makes a self-signed one on first start (with openssl). It names the
  router, 192.168.8.1 and the WAN or Access point address. The browser warns once; to stop that,
  download the certificate from **Settings** and install it on the phone or PC. Settings can also
  make a new one with the names you give, or take **your own** certificate and key (PEM, for
  example signed by your own CA). The files are `/etc/pcc-router/tls/cert.pem` and `key.pem`.
- **Login:** the first visit makes the admin account. It asks for the router's own admin password
  (the one for GL.iNet's admin page) to prove you own the router, so whoever opens the page first
  can't claim it. After that, admins add users in **Settings** as admin or viewer. Viewers can look
  and re-check the port but not change anything: mode, Wi-Fi, screen, tools, certificate or users.
  Logins last a month. Ten wrong passwords in five minutes lock logins from that address for five
  minutes.
- **Locked out?** Over SSH:
  `PYTHONPATH=/usr/share/pcc-router python3 -m pcc_router.auth passwd NAME` (also `add NAME admin`,
  `del NAME`, `list`). Users are in `/etc/pcc-router/users.json`.

## Installing

From the PorkChopCheck folder on a PC that can SSH to the router as root (add the PC's key in LuCI:
System › Administration › SSH-Keys):

```
router/install.sh root@192.168.8.1              # install, or update to this copy
router/install.sh root@192.168.8.1 --uninstall   # remove it and give the screen back
```

It copies `pc_net.py`, `router/pcc_router/` and `router/netmode.lua` to `/usr/share/pcc-router`, adds
the service `/etc/init.d/pcc-router`, installs `router/switch-netmode.sh` as
`/etc/gl-switch.d/netmode.sh` and sets the side switch to it, and lists those files in
`/etc/sysupgrade.conf` so a firmware upgrade that
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
- ping four times a second for the event timeline, and the port log (`tools.py`, which also has the
  tick test, reflector, speed test and port finder the phone page starts)
- the phone page (`web.py`)
- the network mode and the side switch, read every 2 s (`uci` glconfig and the switch's GPIO).
  `netmode.lua` makes the change with `ubus call gl-session call` (module `netmode`, `set_mode`).
  That runs inside GL.iNet's web server, because `set_mode` needs its nginx Lua tools. It is wrapped
  in `flock` so two changes never overlap, and it writes its progress to `/tmp/pcc-netmode.json` for
  the screen and the page. In AP mode the router's own address comes from `network.interface.lan`
  instead of `wan`.

The logic is in `tester.py` with no I/O, so `tests/test_router.py` checks it on a PC with real-shaped
CDP, LLDP, DHCP and 802.1X frames, draws every screen page, and drives the phone page.

## Not yet

Reporting results to a GXL Event Server, so a tested port shows in the Ops Console. From the desktop
app, still to come: traceroute, the wire report, ARP scan, the mDNS browser and the multicast test.
