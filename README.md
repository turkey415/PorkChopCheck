# PorkChopCheck 🐷

A great tool to check your network and ports on your network. CDP, LLDP, and so much more.

*Working title. The app still calls itself PortCheck on screen.*


Full-screen, big-text, touch-friendly switch-port tester for a small Windows 11 box.

**Files:** `portcheck.py` (the app) and `pc_net.py` (the network engine) must sit in the same folder, for example `C:\PortCheck`.

## Starting it

Double-click `portcheck.py` or `PortCheck.bat`. It asks for admin once through a UAC prompt, then opens fullscreen. Admin is needed for DHCP renew, link bounce, and the port finder.

## Pages

Swipe left/right or tap the bottom bar to move between pages.

| Page | What it shows |
|---|---|
| **PORT** | Speed, duplex (checked against the switch), IP, gateway ping, DHCP server and lease, DNS, time-to-IP (flags portfast off), internet |
| **SWITCH** | CDP/LLDP: switch, port, data and voice VLAN, mgmt IP, model, PoE, negotiation |
| **L2** | 802.1X detection, spanning tree (mode, VLAN, root, topology changes), trunk/DTP, DHCP server count (rogue DHCP), phone options 150/66/43, gateway MAC and vendor (HSRP/VRRP), IPv6/RA, broadcast rate |
| **STATS** | MAC, adapter, errors, discards, throughput, link drops, plus Next adapter / Reset / Renew DHCP / Bounce |
| **TOOLS** | Ping (loss, jitter, chart), Traceroute, Speed test (iperf3 + internet), ARP table, ARP scan (flags duplicate IPs), mDNS browser, Port finder (blinks the switch port LED), Port log, Re-run checks, Settings |
| **SAVE** | Logs this port with an optional label typed on the on-screen keyboard |

The banner turns red or amber for: no link, duplicate IP, 802.1X with no access, no DHCP, gateway not replying, multiple DHCP servers, and no internet.

## Port log

Every time CDP/LLDP names the switch and port, PortCheck logs it automatically to `data\ports.csv`. That file keeps one row per switch+port and is updated to the latest result. Tap **SAVE** to add a label like "Room 204 jack B". Every save also goes to `data\history.csv`. Both open in Excel.

## Announcing itself

By default, PortCheck sends LLDP and CDP every 30 s, so `show cdp neighbors` or `show lldp neighbors` on the switch shows `PortCheck-<pcname>` on the right port. You can turn this off or rename it in Settings.

## One-time setup

1. Install Python 3.12 or newer.
2. Install Npcap from npcap.org, keeping the defaults.
3. In a terminal in `C:\PortCheck`, run `py -m pip install -r requirements.txt`.
4. **Optional, for LAN speed tests:** download iperf3 for Windows and put `iperf3.exe` in `C:\PortCheck`. On another PC or server, run `iperf3 -s`. Then set that machine's address under Tools › Settings.
5. **Optional, for MAC vendor names:** they download by themselves the first time the box has internet. You can also use Settings › Download MAC vendor list.

To preview every screen with fake data, run `py portcheck.py --demo`. Demo mode uses its own `data_demo` folder.

## Notes

- CDP is sent every 60 s, LLDP every 30 s, and DTP every 30 s. Some L2 tiles say "Listening…" for up to a minute after you plug in.
- Many Windows NIC drivers strip VLAN tags. "Trunk / DTP" catches trunks via DTP even when tags are hidden.
- The DHCP server check sends one DHCP Discover from this box's MAC and counts the offers. It never accepts an offer.
- 802.1X detection sends one EAPOL-Start and listens. It doesn't try to authenticate.
- Port finder disables and re-enables the adapter on a loop. It is always re-enabled when you stop or exit, and even after a crash on the next start.
- ARP scan covers your subnet, up to 1024 hosts. Bigger subnets scan the /24 around you.

## Screenshots

Demo-mode renders (`py portcheck.py --demo`). Fonts on a real Windows box are larger and smoother.

![Main pages](docs/screenshots/main-pages.png)
![Tools](docs/screenshots/tools.png)
![Save and settings](docs/screenshots/save-settings.png)

## Tests

`python tests/test_pc_net.py` round-trips every packet decoder/builder (CDP, LLDP, DTP, STP, EAPOL, ARP, DHCP, mDNS, IPv6 RA) plus the port log. No hardware needed.
