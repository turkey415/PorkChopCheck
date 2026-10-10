# PorkChopCheck 🐷

A great tool to check your network and ports on your network. CDP, LLDP, and so much more.

Full-screen, big-text, touch-friendly switch-port tester. Plug it into a jack and it tells you what's on the other end. It runs on **Windows 10/11** and **Linux (Nobara, Fedora, Ubuntu)** from the same code.

## Download

Grab the latest build from **[Releases](https://github.com/turkey415/porkchopcheck/releases)**:

| File | For |
|---|---|
| `PorkChopCheck-<version>-windows-exe.zip` | Windows, easiest. One `.exe`, no Python needed. Install [Npcap](https://npcap.com) first. |
| `PorkChopCheck-<version>-windows-python.zip` | Windows, if you'd rather run the Python source |
| `PorkChopCheck-<version>-linux.tar.gz` | Nobara / Fedora / Ubuntu |

## Windows setup

**The .exe:**
1. Install Npcap from npcap.org, keeping the defaults.
2. Unzip the exe zip anywhere and run `PorkChopCheck.exe`. It asks for admin once, then opens fullscreen.

**From source:**
1. Install Python 3.12 or newer, and Npcap.
2. In a terminal in the unzipped folder, run `py -m pip install -r requirements.txt`.
3. Double-click `porkchopcheck.py` or `PorkChopCheck.bat`.

If it won't start, the error is saved to `crash.log` in the same folder and shown in a pop-up.

## Linux setup (Nobara / Fedora)

```bash
tar xzf PorkChopCheck-*-linux.tar.gz
cd PorkChopCheck-*-linux
./install-linux.sh
```

Then launch **PorkChopCheck** from the app menu, or run `porkchopcheck`. On a small touchscreen, use `porkchopcheck --fullscreen`.

The installer uses `dnf` to add Tk, libpcap, iproute, ethtool, a C compiler, and iperf3. It copies the app to `/opt/porkchopcheck`, owned by root, and builds a small launcher there. *Only that launcher* gets permission to capture packets and bring the link up and down, and all it can do is start PorkChopCheck. You never run the app as root. To remove it, run `./install-linux.sh --uninstall`.

Your port log, device inventory and settings live in `~/Documents/PorkChopCheck/data`. If you are upgrading from a beta that kept them next to the app, the installer copies them across.

**Upgrading from v2.0.0-beta.1 to beta.4:** those versions gave the capture permission to a Python interpreter inside the unpacked folder, which any program on the machine could run. Running the new `./install-linux.sh` removes that permission from the old copies it finds. You can then delete the old `PorkChopCheck-*-linux` folders.

On Linux the app reads link and IP details from `/sys`, `ip`, and NetworkManager (`nmcli`). Linux drivers usually pass VLAN tags and LLDP frames through, so trunk and LLDP detection tend to work even better than on Windows.

## Pages

Swipe left/right or tap the bottom bar to move between pages.

| Page | What it shows |
|---|---|
| **PORT** | Speed, duplex (checked against the switch), IP, gateway ping, DHCP server and lease, DNS, time-to-IP (flags portfast off), internet with your public IP |
| **SWITCH** | CDP/LLDP: switch, port, data and voice VLAN, mgmt IP, model, PoE, negotiation |
| **L2** | 802.1X detection, spanning tree (mode, VLAN, root, topology changes), trunk/DTP, DHCP server count (rogue DHCP), phone options 150/66/43, gateway MAC and vendor (HSRP/VRRP), IPv6/RA, broadcast rate |
| **SMART** | Every smart-home device on the network with a type icon, brand, model, serial number (when the device publishes one), IP and MAC. Search, smart-only/all-hosts toggle, tap a device for details and to label it |
| **STATS** | MAC, adapter, errors, discards, throughput, link drops, plus Next adapter / Reset / Renew DHCP / Bounce |
| **TOOLS** | Ping (loss, jitter, chart), Traceroute, Speed test (iperf3 + internet), ARP table, ARP scan (flags duplicate IPs), mDNS browser, Port finder (blinks the switch port LED), Capture (records the port to a `.pcap`), Multicast (groups, IGMP querier, join test), Port log, Re-run checks, Settings |
| **SAVE** | Logs this port with an optional label typed on the on-screen keyboard |

The banner turns red or amber for: no link, duplicate IP, 802.1X with no access, no DHCP, gateway not replying, multiple DHCP servers, and no internet.

## Port log

Every time CDP/LLDP names the switch and port, PorkChopCheck logs it automatically to `data/ports.csv`. That file keeps one row per switch+port and is updated to the latest result. Tap **SAVE** to add a label like "Room 204 jack B". Every save also goes to `data/history.csv`. Both open in Excel or LibreOffice.

## Smart home discovery

The **SMART** tab finds smart plugs, bulbs, speakers, TVs and streamers, cameras and doorbells, thermostats, locks, hubs and appliances, and documents them in `data/devices.csv`. That file is a running inventory: every device ever seen, with your labels, first-seen and last-seen times.

How it finds them, all locally with no cloud logins:

| Method | Finds |
|---|---|
| ARP sweep + reverse DNS + MAC vendor | every host, including cloud-only gadgets (Ring, Echo, Nest, Wyze…) by brand, IP and MAC |
| SSDP / UPnP | Sonos, Philips Hue, Belkin WeMo, Roku, smart TVs; usually with **serial numbers** |
| mDNS | Chromecast / Google Nest, HomeKit, AirPlay, ESPHome, WLED, Matter, printers |
| TP-Link Kasa / Tapo (UDP 9999 + 20002) | name, model, device ID, MAC |
| LIFX, Govee, WiZ, Yeelight, Tuya / Smart Life | model and device ID |
| HTTP device info | Roku serial, Hue bridge ID, Shelly ID, Cast model |

### Open services

Tap a device, then **Ports**, and PorkChopCheck checks 35 common service ports on it and lists what answers in plain words: `80 Web interface`, `554 Video stream (RTSP)`, `9100 Printing (raw)`, `22 SSH`. The result is saved to `devices.csv` in the `open_ports` and `services` columns.

A normal scan only tries nine ports, the ones that help identify a device. To run the full check on every device during a scan, turn on **Settings › Smart scan checks common services on every device**. It is off by default: it makes one connection attempt per port to every host, which takes longer on a big subnet and can look like a port scan to an intrusion detection system. Each check is a plain connect that is closed straight away; nothing is sent to the service.

Good to know:
- **Govee:** turn on *LAN Control* per device in the Govee app. **WiZ:** turn on *Allow local communication* in the WiZ app.
- Serial numbers only appear when a device publishes one on the local network. Each one shows where it came from.
- Icons are generic device-type drawings, not brand logos.
- Per-device throughput isn't shown. A normal switch port can't see other devices' traffic.

## Multicast browser

**Tools › Multicast** shows what multicast is crossing the port, and helps explain why a stream is missing.

- **Groups, busiest first.** Every IPv4 multicast group seen, with a friendly name where there is one (mDNS, SSDP, VRRP, HSRP, OSPF, PIM, PTP, Dante, sACN…), packets per second, bandwidth, who is sending, the UDP port, and which hosts have joined it.
- **IGMP querier.** Shows the querier's address, its IGMP version and how often it asks. Queriers normally ask every 125 seconds, so tap **Querier** to prompt one straight away: the box joins a scratch group for a moment and leaves it, and a querier answers a leave within about a second. If none answers and none is heard for two minutes, the page says so. A missing querier is behind a lot of "AirPlay, mDNS or video works for five minutes, then dies" problems on switches with IGMP snooping.
- **Join test.** Tap **Join…** and type a group such as `239.1.2.3`. The box joins it the way a receiver would, through the operating system, then shows whether the stream arrives and how fast. **Leave** ends the test.

With IGMP snooping on, a port only receives the groups something on it has joined, plus `224.0.0.x` link-local traffic, so an empty list on a quiet port is normal. Leaving the page stops listening and leaves any joined group. IPv6 multicast (MLD) is not covered yet.

## Capture to file

**Tools › Capture** records everything the adapter sees to a `.pcap` you can open in Wireshark or attach to a ticket. Tap the time button to pick 30 seconds, 60 seconds or 5 minutes, then **Start**. **Stop** ends it early and keeps what was recorded.

Files go in the `captures` folder inside the data folder, named with the time and, when CDP/LLDP has named them, the switch and port: `capture-20261010-101502-SW-IDF2-03-Gi1_0_14.pcap`. A capture stops by itself at 200 MB.

On a normal switch port you get this box's own traffic plus the broadcast and multicast the switch sends everyone. Plug into a mirror (SPAN) port to record other devices' traffic. A capture holds whatever crossed the port, so treat the files like any other packet trace.

## Announcing itself

By default, PorkChopCheck sends LLDP and CDP every 30 s, so `show cdp neighbors` or `show lldp neighbors` on the switch shows `PorkChopCheck-<pcname>` on the right port. You can turn this off or rename it in Settings.

## Optional extras

- **LAN speed tests:** run `iperf3 -s` on another machine and set its address under Tools › Settings. On Windows, put `iperf3.exe` next to the app. On Linux, the installer adds iperf3.
- **MAC vendor names** download by themselves the first time the box has internet. You can also use Settings › Download MAC vendor list.
- **Preview mode:** `porkchopcheck --demo` (or `py porkchopcheck.py --demo`) shows every screen with fake data and uses its own `data_demo` folder.

## Notes

- The **Internet** tile shows the public IP this port goes out as. It asks Cloudflare (`https://1.1.1.1/cdn-cgi/trace`) when the internet first answers and every five minutes after that.
- CDP is sent every 60 s, LLDP every 30 s, and DTP every 30 s. Some L2 tiles say "Listening…" for up to a minute after you plug in.
- Many Windows NIC drivers strip VLAN tags. "Trunk / DTP" catches trunks via DTP even when tags are hidden.
- The DHCP server check sends one DHCP Discover from this box's MAC and counts the offers. It never accepts an offer.
- 802.1X detection sends one EAPOL-Start and listens. It doesn't try to authenticate.
- Port finder disables and re-enables the adapter on a loop. It is always re-enabled when you stop or exit, and even after a crash on the next start.
- ARP scan covers your subnet, up to 1024 hosts. Bigger subnets scan the /24 around you.

## Screenshots

Demo-mode renders. Fonts on a real machine are larger and smoother.

![Main pages](docs/screenshots/main-pages.png)
![Smart devices](docs/screenshots/smart.png)
![Device details](docs/screenshots/smart-detail.png)
![Tools](docs/screenshots/tools.png)
![Save and settings](docs/screenshots/save-settings.png)

## Coming soon

A **VLAN tester** for trunk ports, an MTU test, a Wi-Fi survey, a soak test for flaky ports, new-device alerts, printable port reports, and a handful of quick checks.

See the full **[roadmap](ROADMAP.md)**. Ideas and pull requests welcome.

## Releasing a new version (maintainers)

Either push a tag:

```bash
git tag v2.1.0 && git push origin v2.1.0
```

or, on GitHub, go to **Actions › Release › Run workflow** and type the version (like `v2.1.0`) in the box. Leave the box empty for a test build that publishes nothing.

GitHub Actions runs the tests, builds the Windows `.exe`, the Windows zip, and the Linux tarball, and publishes them as a release. A tag with a dash, like `v2.1.0-beta.1`, is published as a pre-release.

The version is written into the app as part of the build, so you don't edit it by hand. The source always says `2.0.0-dev`; a released build shows its real version on the Settings page and from `porkchopcheck --version`.

## Tests

No hardware needed:

```bash
python tests/test_pc_net.py   # every packet decoder/builder + the port log
python tests/test_linux.py    # Linux parsers for ip / nmcli / ethtool / ping output
python tests/test_smart.py    # smart-home protocols, AES, classification, device inventory
python tests/test_launcher.py # Linux launcher: builds it and checks what it passes to Python
python tests/test_version.py  # the version line and the release step that writes it
```

## Contributing

Pull requests are welcome! Good places to start:

- **More decoders.** Add them to `pc_net.classify()`, with a round-trip check in `tests/test_pc_net.py`.
- **More smart-home brands.** Add a regex to `BRANDS` in `pc_smart.py`, or a discovery method to `SmartScan`, with a test in `tests/test_smart.py`.
- **More Linux distros.** The Linux layer lives at the bottom of `pc_net.py`, and `install-linux.sh` handles dnf and apt.
- **Bug reports from real switches.** A pcap of the frame that confused it is gold.

Run all three test files before sending a PR.

## License

MIT. See [LICENSE](LICENSE).
