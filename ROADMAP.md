# PorkChopCheck roadmap 🐷

What's cooking next. Nothing here is built yet. Ideas, priorities and pull requests are all welcome.

## Up next

### VLAN tester (Linux first)
On a trunk port, tag onto each VLAN in a list, request DHCP on each one, and report which VLANs hand out addresses (and from which server). Answers "is VLAN 40 actually allowed on this trunk?" in seconds.

## Planned

### MTU / jumbo frame test
Find the largest packet that gets through without fragmenting, toward the gateway or any host. Catches jumbo-frame and tunnel MTU mismatches.

### Wi-Fi survey
List nearby networks with SSID, BSSID, channel, band, and signal strength, plus a channel-crowding chart for 2.4, 5, and 6 GHz.

### Soak test
Leave it running on a flaky port for hours. It logs ping loss and latency, link drops, DHCP changes, and CDP/LLDP changes with timestamps, then exports a report. Built for intermittent problems.

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
- Cable test from the wire report (pair lengths and faults), on network cards that support it
- Flow control, EEE and error counters on Windows
- IPv6 multicast (MLD) in the multicast browser
- Read port configuration from the switch over SNMP (description, VLANs, errors)
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
