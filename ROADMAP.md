# PorkChopCheck roadmap 🐷

What's cooking next. Nothing here is built yet. Ideas, priorities and pull requests are all welcome.

## Up next: LAN party and tournament tools

Built for a Counter-Strike tournament on a server in the room. The question these answer: a player says they lagged, so is it the seat, the network, the server, or their PC?

### Reflector on the game server
Run `porkchopcheck --reflector` on the server box as a service, so every tick test measures the real path a player's packets take. The seat check, match watch and fairness report all measure against it.

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

### Switch readout over SNMP
Read the table switches (Cisco Catalyst 3560 first) with a read-only login: which port every network card is on, plus uplink usage, error counters, port descriptions and VLANs. This is what turns an address into a seat for the match watch and the LAN game browser, and where congestion between the tables and the server shows up.

### LAN game browser
List every game server running on the LAN, including "listen" servers a player started from inside a game: game, server name, map, players, host address and the seat it is being played at. Finds them the way the games' own LAN tabs do (a broadcast query for Source and other Steam games, listening for the announcements Minecraft and others send out) and refreshes live. The seat comes from the seat sheet, by matching the host's network card to the switch port saved for that seat.

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

- **Wire report:** flow control and PAUSE counters, Energy Efficient Ethernet, speed downshift, flooding, loudest senders, IP conflicts, IPv6 routers, LACP/UDLD/VTP, ICMP redirects and MTU notices.
- **Tick test:** UDP at 64 or 128 packets a second to a reflector (`porkchopcheck --reflector`), reporting loss bursts, jitter, late and out-of-order packets.
- **Event timeline:** the Ping graph marks link, spanning-tree, gateway, broadcast, duplicate-IP and DHCP events and says what each did to latency.
- **Multicast browser:** Tools › Multicast lists live groups with names and rates, finds the IGMP querier, and has a join test.
- **Open services on smart devices:** a Ports button on each device checks 35 common services and names them; saved to `devices.csv`.
- **Capture to file:** Tools › Capture records 30 s, 60 s or 5 min to a `.pcap` in the data folder.
- **Public IP** on the PORT page's Internet tile.
- **v2.0 betas:** port, switch (CDP/LLDP), L2 checks (802.1X, STP, trunk/DTP, rogue DHCP, phone options, IPv6, broadcast), stats, ping, traceroute, speed tests, ARP table and scan, mDNS browser, port finder, port log, the SMART home device tab, Windows `.exe`, and native Linux (Nobara) support including bridged NICs.
