# PorkChopCheck roadmap 🐷

What's cooking next. Nothing here is built yet. Ideas, priorities and pull requests are all welcome.

## Up next: LAN party and tournament tools

Built for a Counter-Strike tournament on a server in the room. The question these answer: a player says they lagged, so is it the seat, the network, the server, or their PC?

Setup note, not a feature: run `porkchopcheck --reflector` on the game server box, so every tick test measures the real path a player's packets take. The seat check, match watch and fairness report all measure against it.

### Seat check
One button per seat: link speed and duplex, downshift, errors, DHCP, gateway ping and a short tick test to the game server, then a pass or fail saved under the seat label. Certify every seat during setup, before the first match.

### Match watch
From the admin machine, watch ping and loss to the server and to every player for the whole match, on the event timeline. A "lag reported" button stamps the moment and saves the last 30 seconds of capture, so a complaint comes with evidence. Left running for hours on one port, this is also the soak test.

### Fairness report
Compare every player's latency and jitter to the server and flag the outlier. For when a team disputes a round.

### CS2 server check
Ask the server directly for its name, map, players and response time, and test the game, RCON and GOTV ports. Includes a wire report of the server's own switch port, the one port every player depends on.

### Player PC check
Run from a USB stick on a player's machine: Wi-Fi active alongside Ethernet, VPN running, background downloads, network card power saving, firewall blocking game ports.

The NIC settings page is the first part of this (see Already shipped). Still to do:
- Try it on Intel, Realtek and Killer cards on Windows and fill in the settings it does not recognise yet.
- A before-and-after button: run the tick test, change a setting, run it again and show the difference.
- Check the grades with real Counter-Strike players, along with the tick test grades.
- The rest of the check: VPN, background downloads and the firewall.

### Switch readout: which seat is on which port
The Switches page already reads every switch's ports (see Already shipped). Still to do: read each switch's address table to learn which port every network card is on, plus port descriptions and VLANs. This is what turns an address into a seat for the match watch and the LAN game browser.

### LAN game browser
List every game server running on the LAN, including "listen" servers a player started from inside a game: game, server name, map, players, host address and the seat it is being played at. Finds them the way the games' own LAN tabs do (a broadcast query for Source and other Steam games, listening for the announcements Minecraft and others send out) and refreshes live. The seat comes from the seat sheet, by matching the host's network card to the switch port saved for that seat.

### Pocket tester on a GL.iNet router (started)
`router/`: the port checks on a GL.iNet travel router's WAN port, shown on its screen and a phone page (Slate 7 first). Built: verdict, switch (CDP/LLDP), port and DHCP checks, rogue DHCP, layer 2. Next: ping timeline, tick test and reflector, iperf3, port finder, port log, reporting to GXL. See [router/README.md](router/README.md).

## Planned

### Loop and storm alarm
A loud alert when a loop or broadcast storm starts, naming the MAC address and the switch port it is on, so the cable can be pulled in seconds.

### DHCP pool check
How full the address pool is, and the lease time. Running out of addresses is a common failure with 100 or more guests.

### Cable test
Pair lengths and faults, on network cards that support it. Bad cables are common at a LAN party and downshift detection only hints at them.

### Internet under load
A bufferbloat test, a view of who is downloading, and a check that Steam downloads resolve to a local LAN cache.

### VLAN tester (Linux first)
On a trunk port, tag onto each VLAN in a list, request DHCP on each one, and report which VLANs hand out addresses (and from which server). Answers "is VLAN 40 actually allowed on this trunk?" in seconds.

### MTU / jumbo frame test
Find the largest packet that gets through without fragmenting, toward the gateway or any host. Catches jumbo-frame and tunnel MTU mismatches.

### Wi-Fi survey
List nearby networks with SSID, BSSID, channel, band, and signal strength, plus a channel-crowding chart for 2.4, 5, and 6 GHz.

### New-device alerts
Compare each SMART scan with the saved inventory and highlight devices that have never been seen before, so a new or rogue gadget stands out.

### Port report
One tap makes a clean, printable page for the current port: switch, port, VLANs, PoE, speed and duplex, DHCP, 802.1X, test results, and your label. Good for tickets and handoff documentation.

### This machine
Tools about the computer PorkChopCheck is running on, not the port it is plugged into:
- **Hosts file editor:** add, change or remove a hosts entry in a few taps, for when a name has to point somewhere right now. Needs admin rights to save, on Windows and Linux.
- **Routes:** show this machine's routing table: each destination, the gateway it goes through, the interface and the metric, with the default route marked.
- **All interfaces:** list every network connection on the machine, not only the Ethernet port being tested: Wi-Fi, VPN and other tunnels, bridges, virtual and loopback interfaces, each with its state, addresses, MAC address and speed.

### CGNAT and double NAT on the Internet tile
A yellow note on the PORT page's Internet tile when the connection sits behind more address translation than the one router. Both break port forwarding and hosting a game server, so they are worth knowing before anyone tries.

- **`CGNAT`:** the internet provider shares one public address between many customers. Found when this port's own address, the router's outside address or a hop just past the router is in the range set aside for it (`100.64.0.0/10`).
- **`Possible Double NAT Detected`:** a second router is translating behind the first, such as a personal router plugged into the provider's own. Found when the router's outside address is a private one, or the first hops out pass through more than one private network.

How it finds out, most reliable first:
1. Ask the router for its outside address (UPnP, NAT-PMP or PCP) and compare it with the public IP the tile already shows. If they differ, something upstream is translating again; the kind of address says which.
2. Trace the first few hops and look at the addresses after the gateway. This works when the router will not answer the question, but it is a hint, not proof: some providers use private addresses inside their own network.

The wording matches how sure the check can be. CGNAT has its own address range, so the tile says `CGNAT` outright, or `Possible CGNAT` when the only sign is a hop in the trace. Double NAT is always worded `Possible Double NAT Detected`, because a private address upstream is not proof of a second router.

### Public DNS ranking
A list of the popular public DNS servers, sorted fastest first. Testing starts when the page opens and the list keeps re-sorting as results come in. The DNS servers this port was given are shown alongside for comparison.

Each row shows:
- name and address
- latest and average ping time, and loss
- time to resolve a name, asked of that server directly, and the answer it gave

Two custom entries, set with the on-screen keyboard and saved:
- **Custom name:** the name every server is asked to resolve, in place of the built-in test name. Seeing each server's answer side by side shows when one resolves a name differently from the rest, or not at all.
- **Custom DNS server:** one more server address added to the list, such as an internal or ISP resolver, so it is ranked against the public ones.

Starting list (addresses to be checked when this is built):

| Service | Address |
|---|---|
| Cloudflare | 1.1.1.1 |
| Google | 8.8.8.8 |
| Quad9 | 9.9.9.9 |
| OpenDNS (Cisco) | 208.67.222.222 |
| AdGuard | 94.140.14.14 |
| CleanBrowsing | 185.228.168.9 |
| Control D | 76.76.2.0 |
| DNS.SB | 185.222.222.222 |
| Level3 | 4.2.2.2 |
| Comodo Secure | 8.26.56.26 |
| UltraDNS (was Verisign) | 64.6.64.6 |
| Yandex | 77.88.8.8 |

### Quick checks
Small tools that come up all the time:
- **TCP port test:** can this port reach `host:port`? (e.g. a printer on 9100)
- **Wake-on-LAN:** wake a machine by MAC
- **NTP check:** time offset against an NTP server
- **ISP name:** who the public IP belongs to (the public IP itself now shows on the PORT page)
- **Subnet calculator**

## Ideas parking lot

Not committed to, but worth thinking about:
- Flow control, EEE and error counters on Windows
- IPv6 multicast (MLD) in the multicast browser
- Per-device throughput in a "mirror port" mode, when plugged into a SPAN port
- Linux Wi-Fi fallback for the SMART scan when no cable is plugged in
- A better name than PorkChopCheck (maybe 🐷)

## Already shipped

- **NIC settings:** Tools › NIC settings lists the network card's advanced settings and marks the ones that hurt Counter-Strike in red or yellow, with what to set and why. Settings that only affect TCP are shown as having no effect.
- **Switches:** Tools › Switches finds switches over SNMP v1 or v2c (Cisco Catalyst first) and shows each as an icon that turns yellow or red when a port has errors, link trouble or is running full, with a front-panel view of every port.
- **Wire report:** flow control and PAUSE counters, Energy Efficient Ethernet, speed downshift, flooding, loudest senders, IP conflicts, IPv6 routers, LACP/UDLD/VTP, ICMP redirects and MTU notices.
- **Tick test:** UDP at 64 or 128 packets a second to a reflector (`porkchopcheck --reflector`), reporting loss bursts, jitter, late and out-of-order packets.
- **Event timeline:** the Ping graph marks link, spanning-tree, gateway, broadcast, duplicate-IP and DHCP events and says what each did to latency.
- **Multicast browser:** Tools › Multicast lists live groups with names and rates, finds the IGMP querier, and has a join test.
- **Open services on smart devices:** a Ports button on each device checks 35 common services and names them; saved to `devices.csv`.
- **Capture to file:** Tools › Capture records 30 s, 60 s or 5 min to a `.pcap` in the data folder.
- **Public IP** on the PORT page's Internet tile.
- **v2.0 betas:** port, switch (CDP/LLDP), L2 checks (802.1X, STP, trunk/DTP, rogue DHCP, phone options, IPv6, broadcast), stats, ping, traceroute, speed tests, ARP table and scan, mDNS browser, port finder, port log, the SMART home device tab, Windows `.exe`, and native Linux (Nobara) support including bridged NICs.
