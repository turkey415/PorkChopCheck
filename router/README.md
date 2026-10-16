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

## Using it

- **The router's screen:** tap for the next page (Summary, Switch, Port, Layer 2), or swipe: right to
  left for the next page, left to right for the previous one. **Hold for 1.5 s** to hand the screen
  back to GL.iNet's own screen program.
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
- ping four times a second for the event timeline, and the port log (`tools.py`, which also has the
  tick test, reflector, speed test and port finder the phone page starts)
- the phone page (`web.py`)

The logic is in `tester.py` with no I/O, so `tests/test_router.py` checks it on a PC with real-shaped
CDP, LLDP, DHCP and 802.1X frames, draws every screen page, and drives the phone page.

## Not yet

Reporting results to a GXL Event Server, so a tested port shows in the Ops Console. From the desktop
app, still to come: traceroute, the wire report, ARP scan, the mDNS browser and the multicast test.
