# PorkChopCheck roadmap 🐷

What's cooking next. Nothing here is built yet. Ideas, priorities and pull requests are all welcome.

## Up next

### Multicast browser
See what multicast is actually flowing on the port, and why it might not be.
- **Live group list:** every multicast group seen on the wire, with friendly names (224.0.0.251 mDNS, 239.255.255.250 SSDP, 224.0.0.18 VRRP, 224.0.0.102 HSRP, OSPF, PIM…), who's sending, packets/sec, bandwidth, and last seen.
- **IGMP querier check:** is there an IGMP querier on this VLAN, what's its address, and which IGMP version. A missing querier is behind a lot of "mDNS / AirPlay / video works for 5 minutes, then dies" problems on switches with IGMP snooping.
- **Join test:** type a group (a video stream, a Dante audio flow…) and the box joins it, then shows whether traffic actually arrives and at what rate. Tests the multicast path end to end.
- With IGMP snooping on, a port only receives groups someone on it has joined, plus 224.0.0.x link-local traffic. The browser will make that distinction clear.

### Capture to file
One tap records 30–60 seconds of traffic to a `.pcap` in the data folder, ready to open in Wireshark or attach to a ticket.

### VLAN tester (Linux first)
On a trunk port, tag onto each VLAN in a list, request DHCP on each one, and report which VLANs hand out addresses (and from which server). Answers "is VLAN 40 actually allowed on this trunk?" in seconds.

## Planned

### Open ports on smart devices
Show which common services each device answers on in the SMART tab (web interface, SSH, printing, video streams, casting…), with friendly names, in the device details, and saved to `devices.csv` for documentation.

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
- **Public IP & ISP:** what the internet sees this port as
- **Subnet calculator**

## Ideas parking lot

Not committed to, but worth thinking about:
- Read port configuration from the switch over SNMP (description, VLANs, errors)
- Per-device throughput in a "mirror port" mode, when plugged into a SPAN port
- Linux Wi-Fi fallback for the SMART scan when no cable is plugged in
- A better name than PorkChopCheck (maybe 🐷)

## Already shipped

- **v2.0 betas:** port, switch (CDP/LLDP), L2 checks (802.1X, STP, trunk/DTP, rogue DHCP, phone options, IPv6, broadcast), stats, ping, traceroute, speed tests, ARP table and scan, mDNS browser, port finder, port log, the SMART home device tab, Windows `.exe`, and native Linux (Nobara) support including bridged NICs.
