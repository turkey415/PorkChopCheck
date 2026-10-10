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
| **PORT** | Speed, duplex (checked against the switch), IP, gateway ping, DHCP server and lease, DNS, time-to-IP (flags portfast off), internet |
| **SWITCH** | CDP/LLDP: switch, port, data and voice VLAN, mgmt IP, model, PoE, negotiation |
| **L2** | 802.1X detection, spanning tree (mode, VLAN, root, topology changes), trunk/DTP, DHCP server count (rogue DHCP), phone options 150/66/43, gateway MAC and vendor (HSRP/VRRP), IPv6/RA, broadcast rate |
| **SMART** | Every smart-home device on the network with a type icon, brand, model, serial number (when the device publishes one), IP and MAC. Search, smart-only/all-hosts toggle, tap a device for details and to label it |
| **STATS** | MAC, adapter, errors, discards, throughput, link drops, plus Next adapter / Reset / Renew DHCP / Bounce |
| **TOOLS** | Ping (loss, jitter, chart), Traceroute, Speed test (iperf3 + internet), ARP table, ARP scan (flags duplicate IPs), mDNS browser, Port finder (blinks the switch port LED), Port log, Re-run checks, Settings |
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

Good to know:
- **Govee:** turn on *LAN Control* per device in the Govee app. **WiZ:** turn on *Allow local communication* in the WiZ app.
- Serial numbers only appear when a device publishes one on the local network. Each one shows where it came from.
- Icons are generic device-type drawings, not brand logos.
- Per-device throughput isn't shown. A normal switch port can't see other devices' traffic.

## Announcing itself

By default, PorkChopCheck sends LLDP and CDP every 30 s, so `show cdp neighbors` or `show lldp neighbors` on the switch shows `PorkChopCheck-<pcname>` on the right port. You can turn this off or rename it in Settings.

## Optional extras

- **LAN speed tests:** run `iperf3 -s` on another machine and set its address under Tools › Settings. On Windows, put `iperf3.exe` next to the app. On Linux, the installer adds iperf3.
- **MAC vendor names** download by themselves the first time the box has internet. You can also use Settings › Download MAC vendor list.
- **Preview mode:** `porkchopcheck --demo` (or `py porkchopcheck.py --demo`) shows every screen with fake data and uses its own `data_demo` folder.

## Notes

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

The **multicast browser** (live groups, IGMP querier check, join test), **capture to .pcap**, a **VLAN tester** for trunk ports, an MTU test, a Wi-Fi survey, a soak test for flaky ports, open ports on smart devices, new-device alerts, printable port reports, and a handful of quick checks.

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
