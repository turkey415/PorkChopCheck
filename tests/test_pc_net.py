import os, re, sys, struct, socket, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pc_net as N
ok = 0
def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1; print("ok ", name, extra)

MAC = "00:e0:4c:68:12:9a"
# CDP round trip (our announce frame decodes)
f = N.build_cdp(MAC, "PorkChopCheck-BOX", "Ethernet", "10.20.30.147")
ev = N.classify(f); k, d = ev[0]
check("cdp build->parse", k == "CDP" and d["name"] == "PorkChopCheck-BOX" and d["mgmt_ip"] == "10.20.30.147", d)
cdp = f[22:22 + struct.unpack("!H", f[12:14])[0] - 8]
check("cdp checksum valid", N.checksum(cdp) == 0)
# LLDP round trip
f = N.build_lldp(MAC, "Ethernet", "PorkChopCheck-BOX", ip="10.20.30.147")
k, d = N.classify(f)[0]
check("lldp build->parse", k == "LLDP" and d["name"] == "PorkChopCheck-BOX" and d["port"] == "Ethernet" and d["mgmt_ip"] == "10.20.30.147", d)
# EAPOL start + a switch EAP-Request/Identity
k, d = N.classify(N.build_eapol_start(MAC))[0]
check("eapol start", k == "EAPOL" and d["code"] == "Start")
req = N.PAE_DST + bytes(6) + b"\x88\x8e" + bytes([2, 0, 0, 5, 1, 1, 0, 5, 1])
k, d = N.classify(N.pad60(req))[0]
check("eap request identity", d["code"] == "Request" and d["eap_type"] == "Identity", d)
# ARP probe + request
k, d = N.classify(N.build_arp_request(MAC, None, "10.20.30.147"))[0]
check("arp probe", k == "ARP" and d["spa"] == "0.0.0.0" and d["tpa"] == "10.20.30.147" and d["op"] == 1)
# DHCP discover (we can parse what we send)
f = N.build_dhcp_discover(MAC, 0x1234ABCD)
k, d = N.classify(f)[0]
check("dhcp discover", k == "DHCP" and d["msg"] == "DISCOVER" and d["xid"] == 0x1234ABCD and d["chaddr"] == MAC)
iph = f[14:34]; check("ipv4 header checksum", N.checksum(iph) == 0)
# DHCP offer with phone options
mb = N.mac_bytes(MAC)
bootp = struct.pack("!BBBBIHH", 2, 1, 6, 0, 0x1234ABCD, 0, 0x8000) + bytes(4) + socket.inet_aton("10.20.30.200") + bytes(8) + mb + bytes(10) + bytes(192) + N.DHCP_MAGIC
opts = bytes([53,1,2, 54,4]) + socket.inet_aton("10.20.1.10") + bytes([1,4]) + socket.inet_aton("255.255.255.0") + bytes([3,4]) + socket.inet_aton("10.20.30.1") \
     + bytes([150,8]) + socket.inet_aton("10.1.1.5") + socket.inet_aton("10.1.1.6") + bytes([66,8]) + b"cucm.lab" + bytes([43,3,1,2,3, 51,4]) + struct.pack("!I", 86400) + b"\xff"
f = N.ipv4_udp_frame("00:11:22:33:44:55", N.BCAST, "10.20.1.10", "255.255.255.255", 67, 68, bootp + opts)
k, d = N.classify(f)[0]
check("dhcp offer + opts", d["msg"] == "OFFER" and d["server"] == "10.20.1.10" and d["tftp_ips"] == ["10.1.1.5","10.1.1.6"] and d["tftp_name"] == "cucm.lab" and d["opt43"] == "010203" and d["lease"] == 86400, d)
# STP: IEEE RSTP BPDU and PVST+
bpdu = struct.pack("!HBBB", 0, 2, 2, 0x3C | 0x01) + struct.pack("!H", 0x8000 | 30) + bytes.fromhex("aabbccddeeff") + struct.pack("!I", 4) \
     + struct.pack("!H", 0x8000 | 30) + bytes.fromhex("001122334455") + struct.pack("!HHHHH", 0x8017, 0, 20*256, 2*256, 15*256) + b"\x00"
k, d = N.classify(N.pad60(N.STP_DST + bytes(6) + struct.pack("!H", 39) + b"\x42\x42\x03" + bpdu))[0]
check("rstp bpdu", k == "STP" and d["proto"] == "RSTP" and d["vlan"] == 30 and d["cost"] == 4 and d["role"] == "Designated" and d["tc"] and d["hello"] == 2, d)
k, d = N.classify(N.pad60(N.PVST_DST + bytes(6) + struct.pack("!H", 50) + bytes.fromhex("aaaa0300000c010b") + bpdu))[0]
check("pvst+ bpdu", d["proto"] == "Rapid-PVST", d)
# DTP
dtp = bytes([1]) + struct.pack("!HH", 1, 5) + b"\x00" + struct.pack("!HH", 2, 5) + b"\x03" + struct.pack("!HH", 3, 5) + b"\xa5" + struct.pack("!HH", 4, 10) + mb
k, d = N.classify(N.pad60(N.CDP_DST + bytes(6) + struct.pack("!H", 8 + len(dtp)) + bytes.fromhex("aaaa0300000c2004") + dtp))[0]
check("dtp", k == "DTP" and d["admin"] == "desirable" and d["oper"] == "access", d)
# 802.1Q tag
k, d = N.classify(N.pad60(bytes(6) + bytes(6) + b"\x81\x00" + struct.pack("!H", 120) + b"\x08\x00" + bytes(30)))[0]
check("vlan tag", k == "VLAN" and d["vlan"] == 120)
# IPv6 RA
ra = bytes([134, 0, 0, 0, 64, 0x40]) + struct.pack("!HII", 1800, 0, 0) + bytes([1, 1]) + mb \
   + bytes([3, 4, 64, 0xC0]) + struct.pack("!III", 2592000, 604800, 0) + socket.inet_pton(socket.AF_INET6, "2001:db8:30::")
ip6 = struct.pack("!IHBB", 0x60000000, len(ra), 58, 255) + socket.inet_pton(socket.AF_INET6, "fe80::1") + socket.inet_pton(socket.AF_INET6, "ff02::1")
k, d = N.classify(N.pad60(bytes(6) + mb + b"\x86\xdd" + ip6 + ra))[0]
check("ipv6 RA", k == "RA" and d["router"] == "fe80::1" and d["o"] and not d["m"] and d["prefixes"] == ["2001:db8:30::/64"], d)
# mDNS response with compression -> browser
def rr(name_b, t, rdata, ttl=120): return name_b + struct.pack("!HHIH", t, 0x8001, ttl, len(rdata)) + rdata
inst = N.encode_labels(["Living Room.TV", "_airplay", "_tcp", "local"])
ans = rr(N.encode_name("_airplay._tcp.local"), 12, inst) + rr(inst, 33, struct.pack("!HHH", 0, 0, 7000) + N.encode_name("lr-tv.local")) \
    + rr(inst, 16, b"\x0bmodel=AppTV") + rr(N.encode_name("lr-tv.local"), 1, socket.inet_aton("10.20.30.55")) \
    + rr(N.encode_name(N.SERVICES), 12, N.encode_name("_googlecast._tcp.local"))
msg = struct.pack("!6H", 0, 0x8400, 0, 5, 0, 0) + ans
f = N.ipv4_udp_frame("00:11:22:33:44:66", bytes.fromhex("01005e0000fb"), "10.20.30.55", "224.0.0.251", 5353, 5353, msg)
k, d = N.classify(f)[0]
check("mdns parse", k == "MDNS" and len(d["records"]) == 5)
b = N.MdnsBrowser(); b.ingest(d, d["ip_src"], multicast=True)
rows = N.mdns_rows(b.snapshot())
check("mdns rows (dotted instance name kept)", rows[0][0].startswith("AirPlay") and rows[1][0] == "Living Room.TV  ·  10.20.30.55:7000", rows)
check("mdns query builder", N.parse_dns(N.build_dns_query([(N.encode_name(N.SERVICES), 12)]))["qr"] is False)
# compressed pointer
cmp_msg = struct.pack("!6H", 1, 0x8400, 0, 1, 0, 0) + N.encode_name("host.local") + struct.pack("!HHIH", 12, 1, 10, 2) + b"\xc0\x0c"
check("dns compression", N.parse_dns(cmp_msg)["records"][0]["ptr"] == "host.local")
# misc
check("mac_kind HSRP", N.mac_kind("00-00-0C-07-AC-1E") == "HSRPv1 group 30")
check("mac_kind HSRPv2", N.mac_kind("00:00:0c:9f:f1:23") == "HSRPv2 group 291")
check("mac_kind VRRP", N.mac_kind("00:00:5e:00:01:0a") == "VRRP VRID 10")
net, hosts, lim = N.scan_hosts("10.20.30.147", "255.255.255.0"); check("scan /24", len(hosts) == 253 and not lim)
net, hosts, lim = N.scan_hosts("10.20.30.147", "255.255.0.0"); check("scan /16 limited", lim and str(net) == "10.20.30.0/24")
# port log
tmp = tempfile.mkdtemp()
pl = N.PortLog(tmp)
r = {"switch": "SW01", "port": "Gi1/0/10", "vlan": 30, "speed": "1 Gbps"}
new, err = pl.upsert(r); check("portlog new", new and err is None)
pl.upsert(dict(r, switch="SW01", port="Gi1/0/9"))
new, err = pl.upsert(dict(r, label="Room 204"), manual=True); check("portlog update", not new and pl.label_for(r) == "Room 204")
lines = open(os.path.join(tmp, "ports.csv"), encoding="utf-8-sig").read().splitlines()
check("ports.csv sorted naturally", "Gi1/0/9" in lines[1] and "Gi1/0/10" in lines[2], lines[1][:60])
hist = open(os.path.join(tmp, "history.csv"), encoding="utf-8-sig").read().splitlines()
check("history rows", len(hist) == 4, len(hist))
pl2 = N.PortLog(tmp); check("portlog reload", len(pl2.rows()) == 2)
# a switch that names itself with a spreadsheet formula
evil = dict(r, switch='=HYPERLINK("http://x","SW")', port="Gi1/0/1", label="@SUM(1+1)", model="-2+3", vlan="+1")
pl.upsert(evil, manual=True)
import csv as _csv
for name in ("ports.csv", "history.csv"):
    cells = [c for row in _csv.reader(open(os.path.join(tmp, name), encoding="utf-8-sig")) for c in row]
    check(f"{name}: no cell starts a formula", not any(c and c[0] in "=+-@" for c in cells), [c for c in cells if c and c[0] in "=+-@"])
    check(f"{name}: the text is kept, quoted", "'=HYPERLINK(\"http://x\",\"SW\")" in cells and "'@SUM(1+1)" in cells)
check("csv_safe leaves ordinary values alone", N.csv_safe({"a": "SW01", "b": 12, "c": "", "d": "10.0.0.1"}) == {"a": "SW01", "b": 12, "c": "", "d": "10.0.0.1"})
check("ports.json keeps the raw value", N.PortLog(tmp).label_for(evil) == "@SUM(1+1)")
# capture to file: the .pcap writer
cap_dir = os.path.join(tmp, "captures"); os.makedirs(cap_dir)
cap = os.path.join(cap_dir, N.capture_name(1791612003.25, "SW-IDF2-03-Gi1/0/14"))
check("capture name: stamped, tag made filename-safe", re.fullmatch(r"capture-\d{8}-\d{6}-SW_IDF2_03_Gi1_0_14\.pcap", os.path.basename(cap)), os.path.basename(cap))
check("capture name: no tag", re.fullmatch(r"capture-\d{8}-\d{6}\.pcap", N.capture_name(1791612003)))
check("capture name: a hostile tag can't leave the folder", "/" not in N.capture_name(1, "../../etc/passwd") and ".." not in N.capture_name(1, "../../etc/passwd"))
w = N.PcapWriter(cap)
f1 = bytes.fromhex("ffffffffffff0011223344550806") + b"\x00" * 46
f2 = bytes.fromhex("01005e0000fb0011223344550800") + b"\x45" + b"\x00" * 99
w.add(f1, 1791612003.250001); w.add(f2, 1791612004.5)
check("pcap writer counts frames and bytes", w.frames == 2 and w.bytes == 24 + 16 + len(f1) + 16 + len(f2), (w.frames, w.bytes))
w.close(); w.add(f1, 1791612005.0)
check("pcap file size matches, nothing written after close", os.path.getsize(cap) == w.bytes and w.frames == 2)
raw = open(cap, "rb").read()
check("pcap global header: magic, v2.4, Ethernet", raw[:8] == bytes.fromhex("d4c3b2a102000400") and raw[20:24] == b"\x01\x00\x00\x00")
back = N.read_pcap(cap)
check("pcap reads back frame for frame", [b for _, b in back] == [f1, f2])
check("pcap timestamps keep microseconds", abs(back[0][0] - 1791612003.250001) < 2e-6 and abs(back[1][0] - 1791612004.5) < 2e-6, back[0][0])
open(os.path.join(cap_dir, "notes.txt"), "w").write("x")
rows = N.list_captures(cap_dir)
check("capture list: only .pcap files, with sizes", [r[0] for r in rows] == [os.path.basename(cap)] and rows[0][1] == w.bytes)
check("capture list: a missing folder is just empty", N.list_captures(os.path.join(tmp, "nope")) == [])
check("fmt_bytes", [N.fmt_bytes(n) for n in (0, 999, 1024, 1536, 5 << 20, 3 << 30)] == ["0 B", "999 B", "1.0 kB", "1.5 kB", "5.0 MB", "3.0 GB"])
# event timeline: the log, the chart columns and what ping did around an event
import collections
evs = collections.deque(maxlen=4)
e1 = N.add_event(evs, "stp", "Spanning-tree topology change", "warn", 100.0, quiet=30)
e2 = N.add_event(evs, "stp", "Spanning-tree topology change", "warn", 112.0, quiet=30)
check("events: a repeat inside the quiet time is counted, not added", e2 is e1 and len(evs) == 1 and (e1["count"], e1["ts"], e1["last"]) == (2, 100.0, 112.0))
N.add_event(evs, "link", "Link down", "bad", 113.0)
check("events: a different event is its own entry", [e["kind"] for e in evs] == ["stp", "link"])
N.add_event(evs, "stp", "Spanning-tree topology change", "warn", 130.0, quiet=30)
check("events: the quiet time runs from the last repeat", len(evs) == 2 and evs[0]["count"] == 3)
N.add_event(evs, "stp", "Spanning-tree topology change", "warn", 200.0, quiet=30)
check("events: after the quiet time it is a new entry", len(evs) == 3 and evs[-1]["count"] == 1 and evs[-1]["ts"] == 200.0)
N.add_event(evs, "link", "Link down", "bad", 201.0); N.add_event(evs, "link", "Link down", "bad", 202.0)
check("events: with no quiet time every one is logged, and the log is capped", len(evs) == 4 and [e["ts"] for e in evs][-2:] == [201.0, 202.0])
check("percentile: nearest rank", (N.percentile([1, 2, 3, 4, 100], 50), N.percentile([1, 2, 3, 4, 100], 95), N.percentile(range(1, 101), 99), N.percentile([7], 99)) == (3, 100, 99, 7))
check("percentile: ignores lost pings, None when empty", N.percentile([None, 5, None], 50) == 5 and N.percentile([], 50) is None and N.percentile([None], 99) is None)
smp = [(t / 4, 3.0) for t in range(400)]          # 100 s of steady 3 ms pings, 4 a second
smp[200] = (50.0, None); smp[201] = (50.25, None); smp[202] = (50.5, 180.0)
cols = N.bucket_samples(smp, 60.0, 30.0, 6)
check("chart columns: worst reply, lost count, sent count", cols[4] == (180.0, 2, 20) and cols[0] == (3.0, 0, 20), cols)
check("chart columns: nothing outside the window, empty columns stay empty", N.bucket_samples(smp, 200.0, 30.0, 6) == [(None, 0, 0)] * 6)
check("chart columns: a column of only lost pings has no reply time", N.bucket_samples([(1.0, None), (1.1, None)], 2.0, 2.0, 2) == [(None, 0, 0), (None, 2, 2)])
imp = N.event_impact(smp, 50.0)
check("impact: loss and a spike around the event", imp == {"lost": 2, "peak": 180.0, "normal": 3.0, "hit": True}, imp)
check("impact text: loss and peak", N.impact_text(imp) == "2 pings lost · peak 180 ms, normally 3 ms")
check("impact: a quiet moment is no effect", N.impact_text(N.event_impact(smp, 20.0)) == "no effect on ping")
check("impact: no pings then", N.event_impact(smp, 500.0) is None and N.impact_text(None) == "ping wasn't running")
slow = [(t / 4, 40.0 + (t % 3)) for t in range(400)]
check("impact: a steady slow link is not a spike", N.event_impact(slow, 50.0)["hit"] is False)
one = [(t / 4, 3.0) for t in range(400)]; one[200] = (50.0, None)
check("impact text: one lost ping, singular", N.impact_text(N.event_impact(one, 50.0)) == "1 ping lost")
# wire report: the extra protocols, flooding and talkers, address conflicts, adapter readings
ETH = lambda dst, et, body, src="70db981a0001": bytes.fromhex(dst + src) + struct.pack("!H", et) + body
lacp = bytes([1, 1, 1, 20]) + struct.pack("!H", 32768) + bytes.fromhex("70db981a0000") + struct.pack("!HHH", 13, 255, 23) + bytes([0x3F]) + bytes(90)
k, i = N.classify(ETH("0180c2000002", 0x8809, lacp))[0]
check("classify: LACP with the switch's system, key and state", k == "LACP" and (i["system"], i["key"], i["port"], i["active"], i["fast"], i["in_sync"]) == ("70:db:98:1a:00:00", 13, 23, True, True, True), i)
check("classify: a marker PDU on the same ethertype is not LACP", N.classify(ETH("0180c2000002", 0x8809, bytes([2, 1]) + bytes(40))) == [])
k, i = N.classify(ETH("0180c2000001", 0x8808, struct.pack("!HH", 1, 0xFFFF) + bytes(42)))[0]
check("classify: 802.3x PAUSE with its quanta", (k, i["kind"], i["quanta"]) == ("PAUSE", "PAUSE", 0xFFFF))
k, i = N.classify(ETH("0180c2000001", 0x8808, struct.pack("!HH8H", 0x0101, 0xFF, 0, 0, 0, 500, 0, 0, 0, 0) + bytes(20)))[0]
check("classify: priority flow control", (k, i["kind"], i["quanta"]) == ("PAUSE", "PFC", 500))
check("classify: Cisco loopback keepalive", N.classify(ETH("70db981a0001", 0x9000, bytes(46)))[0][0] == "LOOP")
snap_ = lambda pid, body: ETH("01000ccccccc", 8 + len(body), bytes.fromhex("aaaa0300000c") + struct.pack("!H", pid) + body)
udld = bytes([0x21, 0, 0, 0]) + struct.pack("!HH", 1, 15) + b"FOC2145Z0AB" + struct.pack("!HH", 2, 12) + b"Gi1/0/23"
k, i = N.classify(snap_(0x0111, udld))[0]
check("classify: UDLD with device and port", (k, i["op"], i["device"], i["port"]) == ("UDLD", "probe", "FOC2145Z0AB", "Gi1/0/23"), i)
k, i = N.classify(snap_(0x2003, bytes([2, 1, 0, 6]) + b"CAMPUS".ljust(32, b"\x00") + bytes(8)))[0]
check("classify: VTP with its domain", (k, i["domain"], i["version"]) == ("VTP", "CAMPUS", 2), i)
check("classify: PAgP", N.classify(snap_(0x0104, bytes(20)))[0][0] == "PAGP")
check("classify: truncated UDLD and VTP don't raise", N.classify(snap_(0x0111, b"\x21"))  == [] and N.classify(snap_(0x2003, b"\x02"))[0][1] == {"kind": "VTP", "src": "70:db:98:1a:00:01", "dst": "01:00:0c:cc:cc:cc", "vlan_tag": None})
def ip4(src, dst, proto, body):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", N.checksum(h)) + h[12:] + body
inner = ip4("10.20.30.147", "172.16.9.20", 6, bytes(8))
red = ETH("001122334455", 0x0800, ip4("10.20.30.1", "10.20.30.147", 1, bytes([5, 1, 0, 0]) + socket.inet_aton("10.20.30.2") + inner))
k, i = N.classify(red)[0]
check("classify: ICMP redirect names the better gateway", (k, i["what"], i["from"], i["use"], i["about"]) == ("ICMP", "redirect", "10.20.30.1", "10.20.30.2", "172.16.9.20"), i)
frag = ETH("001122334455", 0x0800, ip4("10.20.0.1", "10.20.30.147", 1, bytes([3, 4, 0, 0, 0, 0]) + struct.pack("!H", 1400) + inner))
k, i = N.classify(frag)[0]
check("classify: fragmentation needed carries the path MTU", (i["what"], i["mtu"], i["about"]) == ("fragneeded", 1400, "172.16.9.20"), i)
check("classify: an ordinary ping reply is not a notice", N.classify(ETH("001122334455", 0x0800, ip4("10.20.30.1", "10.20.30.147", 1, bytes([0, 0, 0, 0, 0, 1, 0, 1])))) == [])
aw = N.ArpWatch()
arp = lambda ip, mac, tpa="10.20.30.1": {"op": 2, "sha": mac, "spa": ip, "tha": "00:00:00:00:00:00", "tpa": tpa}
check("arp watch: first sighting and a repeat are quiet", aw.feed(arp("10.20.30.88", "3c:22:fb:10:20:30"), 1.0) is None and aw.feed(arp("10.20.30.88", "3c:22:fb:10:20:30"), 2.0) is None and not aw.conflicts)
check("arp watch: a second MAC for the same IP is a conflict", aw.feed(arp("10.20.30.88", "a4:83:e7:44:55:66"), 3.0) == ("10.20.30.88", "3c:22:fb:10:20:30", "a4:83:e7:44:55:66") and aw.conflicts["10.20.30.88"]["macs"] == ["3c:22:fb:10:20:30", "a4:83:e7:44:55:66"])
aw.feed(arp("10.20.30.88", "3c:22:fb:10:20:30"), 4.0)
check("arp watch: flipping back doesn't list a MAC twice", aw.conflicts["10.20.30.88"]["macs"] == ["3c:22:fb:10:20:30", "a4:83:e7:44:55:66"] and aw.conflicts["10.20.30.88"]["ts"] == 4.0)
aw.feed(arp("10.20.30.50", "aa:bb:cc:00:00:01", tpa="10.20.30.50"), 5.0)
check("arp watch: gratuitous ARP counted, probes from 0.0.0.0 ignored", aw.gratuitous == 1 and aw.feed(arp("0.0.0.0", "aa:bb:cc:00:00:02"), 6.0) is None and "0.0.0.0" not in aw.owner)
ww = N.WireWatch(["FC-9D-05-07-AD-E3", "52:54:00:51:66:96"], now=0.0)
me, vm = "fc9d0507ade3", "525400516696"
for _ in range(100):
    ww.feed(ETH("ffffffffffff", 0x0806, bytes(46), src="9c7613aa0102"))
for _ in range(30):
    ww.feed(ETH("01005e0000fb", 0x0800, bytes(60), src="48a6b8c1d2e3"))
for _ in range(40):
    ww.feed(ETH("ecb5fa123456", 0x0800, bytes(60), src="d83134aabbcc"))      # for someone else: flooded
ww.feed(ETH(vm, 0x0800, bytes(60), src="d83134aabbcc"))                     # for our VM: fine
ww.feed(ETH("ffffffffffff", 0x0806, bytes(46), src=me))                     # our own broadcast: ignored
ww.feed(b"\x00")
ww.tick(2.0)
ws = ww.snapshot()
check("wire watch: loudest sender first, with rates", (ws["talkers"][0]["mac"], ws["talkers"][0]["bc"], ws["talkers"][0]["bc_pps"]) == ("9c:76:13:aa:01:02", 100, 50.0) and ws["talkers"][1]["mc_pps"] == 15.0, ws["talkers"])
check("wire watch: flooded frames counted, ours and our VM's are not", (ws["flood"], ws["flood_pps"], ws["flood_dst"]) == (40, 20.0, ["ec:b5:fa:12:34:56"]) and ws["n_talkers"] == 2, ws)
ww.tick(4.0)
check("wire watch: rates fall to zero when it goes quiet", ww.snapshot()["flood_pps"] == 0 and ww.snapshot()["talkers"][0]["bc_pps"] == 0)
check("wire filter: with and without a MAC", N.wire_bpf("FC-9D-05-07-AD-E3") == "ether multicast or not ether dst fc:9d:05:07:ad:e3" and N.wire_bpf("") == "ether multicast")
PAUSE_OUT = "Pause parameters for enp14s0:\nAutonegotiate:\ton\nRX:\t\ton\nTX:\t\toff\n"
check("ethtool -a", N.parse_ethtool_pause(PAUSE_OUT) == {"autoneg": True, "rx": True, "tx": False} and N.parse_ethtool_pause("netlink error: Operation not supported") == {})
EEE_INACTIVE = "EEE settings for enp14s0:\n\tEEE status: enabled - inactive\n\tTx LPI: 2 (us)\n\tSupported EEE link modes:  100baseT/Full\n\t                           1000baseT/Full\n\tAdvertised EEE link modes:  100baseT/Full\n\tLink partner advertised EEE link modes:  Not reported\n"
check("ethtool --show-eee: enabled but not in use", N.parse_ethtool_eee(EEE_INACTIVE) == {"supported": True, "enabled": True, "active": False, "partner": False}, N.parse_ethtool_eee(EEE_INACTIVE))
check("ethtool --show-eee: active", N.parse_ethtool_eee(EEE_INACTIVE.replace("enabled - inactive", "enabled - active").replace("Not reported", "1000baseT/Full")) == {"supported": True, "enabled": True, "active": True, "partner": True})
check("ethtool --show-eee: disabled, unsupported, no output", N.parse_ethtool_eee("\tEEE status: disabled\n")["enabled"] is False and N.parse_ethtool_eee("\tEEE status: not supported\n") == {"supported": False, "enabled": False, "active": False} and N.parse_ethtool_eee("") == {})
LINK_OUT = """Settings for enp3s0:
\tSupported ports: [ TP ]
\tSupported link modes:   10baseT/Half 10baseT/Full
\t                        100baseT/Half 100baseT/Full
\t                        1000baseT/Full
\tAdvertised link modes:  10baseT/Half 10baseT/Full
\t                        100baseT/Half 100baseT/Full
\t                        1000baseT/Full
\tAdvertised pause frame use: Symmetric Receive-only
\tLink partner advertised link modes:  10baseT/Half 10baseT/Full
\t                                     100baseT/Half 100baseT/Full
\t                                     1000baseT/Full
\tLink partner advertised auto-negotiation: Yes
\tSpeed: 100Mb/s
\tDuplex: Full
"""
lk = N.parse_ethtool_link(LINK_OUT)
check("ethtool: what each end offered and what was agreed", lk == {"speed": 100, "duplex": "Full", "ours": [10, 100, 1000], "partner": [10, 100, 1000]}, lk)
check("downshift: both offer 1 Gb but it linked at 100 Mb", N.downshift(lk) == 1000)
check("downshift: none at full speed, or when the partner offers less, or isn't reported", N.downshift(dict(lk, speed=1000)) is None
      and N.downshift({"speed": 100, "ours": [10, 100, 1000], "partner": [10, 100]}) is None and N.downshift({"speed": 100, "ours": [10, 100, 1000], "partner": []}) is None)
STATS_OUT = "NIC statistics:\n     tx_packets: 1107860\n     rx_errors: 0\n     rx_missed: 2\n     align_errors: 0\n     rx_crc_errors: 7\n     rx_pause: 1840\n     tx_flow_control_xoff: 3\n     [0]: rx_xdp_drop: 0\n     unicast: 1984818\n"
pz, er = N.parse_nic_stats(STATS_OUT)
check("ethtool -S: pause and error counters picked out by name", pz == {"rx_pause": 1840, "tx_flow_control_xoff": 3} and er == {"rx_errors": 0, "rx_missed": 2, "align_errors": 0, "rx_crc_errors": 7}, (pz, er))
check("counter rises", N.counter_rises({"a": 1, "b": 5, "c": 9}, {"a": 4, "b": 5, "c": 2, "d": 7}) == {"a": 3})
clean = N.new_wire(); clean["nic"] = {"pause": {"rx": False, "tx": False}, "eee": {"supported": True, "enabled": False, "active": False},
                                     "link": dict(lk, speed=1000), "stats": ({}, {"rx_errors": 0})}
clean["talk"] = {"talkers": [], "n_talkers": 0, "flood": 0, "flood_pps": 0.0, "pps": 0.0, "flood_dst": []}
cf = N.wire_findings(clean)
check("wire report: a clean port has nothing to flag", N.wire_headline(cf) == ("Nothing unusual on the wire", "ok") and all(lv in ("ok", "info") for _, lv, _ in cf), cf)
sick = N.new_wire()
sick.update(nic={"pause": {"rx": True, "tx": False}, "eee": {"supported": True, "enabled": True, "active": True}, "link": lk, "stats": ({"rx_pause": 9}, {"rx_crc_errors": 7})},
            rises={"rx_pause": 4, "rx_crc_errors": 3}, lacp={"kind": "LACP", "system": "70:db:98:1a:00:00", "key": 13, "active": True, "fast": False},
            talk={"talkers": [{"mac": "9c:76:13:aa:01:02", "bc": 9000, "mc": 0, "bytes": 0, "bc_pps": 300.0, "mc_pps": 0.0}], "n_talkers": 1, "flood": 500, "flood_pps": 60.0, "pps": 400.0, "flood_dst": ["ec:b5:fa:12:34:56"]},
            conflicts=[{"ip": "10.20.30.88", "macs": ["3c:22:fb:10:20:30", "a4:83:e7:44:55:66"], "ts": 1}],
            routers={"70:db:98:1a:00:01": {"prefix": "2001:db8:30::/64"}, "a4:83:e7:44:55:66": {"prefix": ""}},
            icmp=[{"what": "redirect", "from": "10.20.30.1", "use": "10.20.30.2", "about": "172.16.9.20"}], pause_frames=2)
sf = N.wire_findings(sick, vendor=lambda m: "Ring LLC" if m.startswith("9c:76") else "")
txt = " | ".join(t for _, _, t in sf)
for needle in ("PAUSE frames counted since the report started: rx_pause +4", "Energy Efficient Ethernet is active", "Linked at 100 Mbps although both ends offer 1 Gbps",
               "Error counters rising: rx_crc_errors +3", "60 frames a second meant for other machines", "9c:76:13:aa:01:02 (Ring LLC): 300 broadcast",
               "10.20.30.88 is claimed by 3c:22:fb:10:20:30 and a4:83:e7:44:55:66", "More than one machine is doing this", "LACP (switch 70:db:98:1a:00:00, key 13, active, slow timer)",
               "2 PAUSE frames seen on the wire", "use 10.20.30.2 instead"):
    check(f"wire report flags: {needle[:44]}", needle in txt, txt[:300])
hl = N.wire_headline(sf)
check("wire report: headline counts what needs a look and takes the worst level", hl[1] == "bad" and hl[0].endswith("things worth a look") and int(hl[0].split()[0]) == sum(1 for _, lv, _ in sf if lv in ("warn", "bad")), hl)
check("wire report: without ethtool data it says why", "Linux only" in N.wire_findings(N.new_wire(), platform_linux=False)[0][2] and "ethtool is not installed" in N.wire_findings(N.new_wire())[0][2])
busy = N.new_wire(); busy["paused"] = True
check("wire report: too busy to count is said plainly", any("Too much traffic to count" in t for _, _, t in N.wire_findings(busy)))
# tick-rate test: packets, the buffer, the figures, the verdict, and a real run over loopback
pk = N.tick_packet(0xDEADBEEF, 41)
check("tick packet: marker, session, sequence, padded to size", len(pk) == N.TICK_SIZE and N.parse_tick(pk) == (0xDEADBEEF, 41))
check("tick packet: anything else is not ours", N.parse_tick(b"PCC1") is None and N.parse_tick(b"XXXX" + bytes(20)) is None and N.parse_tick(b"") is None)
check("tick server: address forms", [N.parse_tick_server(t) for t in ("10.1.2.3", " 10.1.2.3:27015 ", "10.1.2.3 27015", "cs-server.lan")] ==
      [("10.1.2.3", N.TICK_PORT), ("10.1.2.3", 27015), ("10.1.2.3", 27015), ("cs-server.lan", N.TICK_PORT)])
for bad in ("", None, "10.1.2.3:0", "10.1.2.3:99999", "host; rm -rf /", "-oProxyCommand=x", "a b c"):
    check(f"tick server refused: {bad!r}", N.parse_tick_server(bad) is None)
tb = N.TickBuffer()
seqs = [tb.add_sent(100.0 + i / 64) for i in range(10)]
for q in (0, 1, 2, 4, 3, 6, 6, 9):               # 5, 7 and 8 never answered; 3 late and out of order; 6 twice
    tb.add_reply(q, 1.5)
tb.add_reply(999, 1.0)
check("tick buffer: counters", tb.counters() == {"sent": 10, "recv": 7, "reorder": 1, "dup": 1}, tb.counters())
check("tick buffer: unanswered packets wait out their timeout before counting as lost",
      len(tb.samples(100.2)) == 7 and len(tb.samples(102.0)) == 10)
sm = N.tick_summary(tb.samples(102.0), 64)
check("tick summary: loss and the longest run of lost packets", (sm["n"], sm["lost"], sm["burst"]) == (10, 3, 2) and abs(sm["loss_pct"] - 30) < 1e-9, sm)
tb2 = N.TickBuffer(); tb2.MAX = 4
for i in range(10):
    tb2.add_sent(200.0 + i)
check("tick buffer: old packets fall off the front and sequence numbers carry on", (tb2.base, len(tb2.rows), tb2.add_sent(300.0)) == (6, 4, 10), (tb2.base, len(tb2.rows)))
tb2.add_reply(10, 2.0); tb2.add_reply(3, 2.0)
check("tick buffer: a reply for a packet no longer held is ignored", tb2.rows[-1][1] == 2.0 and tb2.counters()["recv"] == 1)
steady = [(i / 64, 1.2 + (0.05 if i % 2 else 0)) for i in range(640)]
ss = N.tick_summary(steady, 64)
check("tick summary: a clean run", (ss["lost"], ss["burst"], ss["late"]) == (0, 0, 0) and abs(ss["jitter"] - 0.05) < 1e-9 and ss["p50"] == 1.2 and ss["max"] == 1.25, ss)
check("tick verdict: clean is excellent", N.tick_verdict(ss, 64) == ("Excellent for Counter-Strike", "excellent"))
check("tick ratings: every figure, with its value and grade", N.tick_ratings(ss, 64, True) == [("loss", "0.00%", "excellent"), ("burst", "0", "excellent"), ("jitter", "0.05 ms", "excellent"), ("late", "0", "excellent"), ("ping", "1.2 ms", "excellent")], N.tick_ratings(ss, 64, True))
check("tick ratings: jitter is shown but not graded unless asked", [r for r in N.tick_ratings(ss, 64) if r[0] == "jitter"] == [("jitter", "0.05 ms", "info")] and N.tick_verdict(ss, 64) == ("Excellent for Counter-Strike", "excellent"))
check("tick grade: limits are inclusive", [N.tick_grade("ping", x) for x in (20, 20.1, 50, 100, 100.1)] == ["excellent", "good", "good", "fair", "bad"])
one = steady * 3; one[300] = (one[300][0], None)
check("tick verdict: one lost packet in thirty seconds is still good", N.tick_verdict(N.tick_summary(one, 64), 64) == ("Good for Counter-Strike", "good"))
two = list(one); two[900] = (two[900][0], None)
check("tick verdict: two lost apart in thirty seconds is fair", N.tick_verdict(N.tick_summary(two, 64), 64) == ("Fair for Counter-Strike: packet loss", "fair"))
check("tick verdict, Claude settings: jitter between a sixteenth and an eighth of a tick is good", N.tick_verdict(N.tick_summary([(i / 64, 1.0 + (1.5 if i % 2 else 0)) for i in range(640)], 64), 64, True)[1] == "good")
check("tick verdict, Claude settings: the same jitter is only fair at 128 a second", N.tick_verdict(N.tick_summary([(i / 128, 1.0 + (1.5 if i % 2 else 0)) for i in range(640)], 128), 128, True) == ("Fair for Counter-Strike: jitter", "fair"))
check("tick verdict: a slow but steady path is rated on its ping", N.tick_verdict(N.tick_summary([(i / 64, 60.0) for i in range(640)], 64), 64) == ("Fair for Counter-Strike: ping", "fair"))
late = list(steady); late[100] = (late[100][0], 1.2 + 16.0)
check("tick summary: a reply over one tick slow is late", N.tick_summary(late, 64)["late"] == 1 and N.tick_summary(late, 128)["late"] == 1)
check("tick verdict, Claude settings: one late reply in ten seconds is fair", N.tick_verdict(N.tick_summary(late, 64), 64, True) == ("Fair for Counter-Strike: late replies", "fair"))
check("tick verdict: one late reply in ten seconds is good", N.tick_verdict(N.tick_summary(late, 64), 64) == ("Good for Counter-Strike", "good"))
def lates(n):
    out = steady * 3
    for i in range(n):
        out[100 + 40 * i] = (out[100 + 40 * i][0], 1.2 + 16.0)
    return N.tick_verdict(N.tick_summary(out, 64), 64)[1]
check("tick verdict: late replies in thirty seconds, 1 excellent, 2 to 9 good, 10 to 38 fair, more bad", [lates(n) for n in (1, 2, 9, 10, 38, 39)] == ["excellent", "good", "good", "fair", "fair", "bad"], [lates(n) for n in (1, 2, 9, 10, 38, 39)])
gap = list(steady)
for i in (200, 201, 202):
    gap[i] = (gap[i][0], None)
check("tick verdict: three lost in a row is bad even under 1% loss", N.tick_summary(gap, 64)["burst"] == 3 and N.tick_summary(gap, 64)["loss_pct"] < 1 and N.tick_verdict(N.tick_summary(gap, 64), 64) == ("Bad for Counter-Strike: lost in a row", "bad"))
jittery = [(i / 64, 1.0 + (10.0 if i % 2 else 0)) for i in range(640)]
check("tick verdict, Claude settings: jitter over half a tick is bad", N.tick_verdict(N.tick_summary(jittery, 64), 64, True) == ("Bad for Counter-Strike: jitter", "bad"))
check("tick verdict: jitter that makes no reply late does not lower the grade", N.tick_verdict(N.tick_summary(jittery, 64), 64) == ("Excellent for Counter-Strike", "excellent"))
check("settings: Claude's tick settings are off until switched on", N.Settings(tempfile.mkdtemp()).get("tick_claude") is False)
check("tick verdict: nothing back at all", N.tick_verdict(N.tick_summary([(i / 64, None) for i in range(64)], 64), 64) == ("No replies", "bad"))
check("tick verdict: nothing sent yet", N.tick_verdict(N.tick_summary([], 64), 64)[1] == "wait")
import time as _t
rf = N.Reflector(0, "127.0.0.1"); rport = rf.sock.getsockname()[1]; rf.start()
tt = N.TickTest("127.0.0.1", "127.0.0.1", rport, 128); tt.start(); _t.sleep(1.3); tt.stop(); _t.sleep(0.3)
cn = tt.buf.counters()
check("live run on loopback: the reflector reports its hold time, from the system's stamp on Linux", tt.buf.hold_mode == ("stamped" if N.IS_LINUX else "timed") and len(tt.buf.holds(0)) == cn["recv"] and max(tt.buf.holds(0)) < 50, (tt.buf.hold_mode, cn))
rp = N.tick_reply(pk, 1234, True)
check("tick reply: same size, same packet, hold time written in", len(rp) == len(pk) and N.parse_tick(rp) == (0xDEADBEEF, 41) and N.parse_tick_hold(rp) == (1.234, True) and N.parse_tick_hold(N.tick_reply(pk, -5, False)) == (0.0, False))
check("tick reply: an old reflector's plain echo carries no hold time", N.parse_tick_hold(pk) is None and N.parse_tick_hold(b"PCC1") is None and N.tick_reply(b"PCC1short", 5, True) == b"PCC1short")
check("hold summary: typical, longest, and how many were over a tick", N.hold_summary([0.2, 0.3, 0.4, 20.0], 64) == {"n": 4, "p50": 0.3, "max": 20.0, "over": 1} and N.hold_summary([], 64)["n"] == 0)
tb3 = N.TickBuffer(); tb3.add_sent(1.0); tb3.add_sent(2.0); tb3.add_reply(0, 1.0, 0.5, True); tb3.add_reply(1, 1.0, 0.7, True)
check("tick buffer: hold times kept with their packets", tb3.holds(0) == [0.5, 0.7] and tb3.holds(1.5) == [0.7] and tb3.hold_mode == "stamped" and tb3.samples(3.0) == [(1.0, 1.0), (2.0, 1.0)])
tb3.add_sent(3.0); tb3.add_reply(2, 1.0)
check("tick buffer: a reply with no hold time marks the reflector as an old one", tb3.hold_mode == "none")
import threading as _th
class SlowReflector(N.Reflector):
    """Sits on every packet for 12 ms, as a busy machine would."""
    def serve(self):
        while not self.stop_ev.is_set():
            try:
                data, addr, came, stamped = N.recv_stamped(self.sock, self.stamped)
            except OSError:
                continue
            _t.sleep(0.012)
            self.sock.sendto(N.tick_reply(data, (_t.time_ns() - came) // 1000, stamped), addr)
sr = SlowReflector(0, "127.0.0.1"); sr.start()
st2 = N.TickTest("127.0.0.1", "127.0.0.1", sr.sock.getsockname()[1], 64); st2.start(); _t.sleep(1.5); st2.stop(); sr.stop(); _t.sleep(0.4)
ssum = N.tick_summary(st2.buf.samples(_t.time() + 2), 64); hs = N.hold_summary(st2.buf.holds(0), 64)
check("live run, slow reflector: its 12 ms is taken out and the network still reads as fast", hs["p50"] >= 12 and ssum["p50"] < 3 and ssum["late"] == 0, (ssum, hs))
check("live run on loopback: about 128 a second, every packet back", 140 <= cn["sent"] <= 190 and cn["recv"] >= cn["sent"] - 2 and cn["dup"] == 0, cn)
check("live run: reply times are sane and the reflector counted them", 0 < N.tick_summary(tt.buf.samples(_t.time() + 2), 128)["p50"] < 50 and rf.count >= cn["recv"] and "127.0.0.1" in rf.peers)
junk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); junk.settimeout(0.4); junk.sendto(b"not a test packet", ("127.0.0.1", rport))
try:
    junk.recvfrom(100); echoed = True
except socket.timeout:
    echoed = False
check("reflector ignores anything without the test marker", echoed is False)
junk.close(); rf.stop()
try:
    N.TickTest("127.0.0.1", "no-such-host.invalid", 1, 64); opened = True
except OSError:
    opened = False
check("tick test: an unknown host fails cleanly", opened is False)
check("impact text names what was running", N.impact_text(N.event_impact(smp, 50.0), "the test", "packet") == "2 packets lost · peak 180 ms, normally 3 ms"
      and N.impact_text(None, "the test", "packet") == "the test wasn't running")
# multicast browser: names, frames, IGMP, the tracker and the querier verdict
MAC = "00:11:22:33:44:55"
check("mcast names: exact, range, unknown", (N.mcast_name("224.0.0.251"), N.mcast_name("239.69.4.4"), N.mcast_name("239.1.2.3")) == ("mDNS", "Dante / AES67 audio", ""))
check("mcast: SSDP is not mistaken for sACN", N.mcast_name("239.255.255.250") == "SSDP / UPnP" and N.mcast_name("239.255.0.1") == "sACN lighting")
check("mcast: link-local scope", N.mcast_is_link_local("224.0.0.18") and not N.mcast_is_link_local("224.0.1.129"))
check("mcast mac", N.mcast_mac("239.129.2.3").hex() == "01005e010203" and N.mcast_mac("224.0.0.251").hex() == "01005e0000fb")
check("join target: group", N.parse_mcast_target(" 239.1.2.3 ") == ("239.1.2.3", None))
check("join target: group and port, any separator", [N.parse_mcast_target(t) for t in ("239.1.2.3:5004", "239.1.2.3 5004", "239.1.2.3/5004")] == [("239.1.2.3", 5004)] * 3)
for bad in ("10.1.2.3", "239.1.2", "239.1.2.300", "239.1.2.3:0", "239.1.2.3:70000", "stream.local", "", None, "239.1.2.3; rm -rf /"):
    check(f"join target refused: {bad!r}", N.parse_mcast_target(bad) is None)
udp = lambda port, n: struct.pack("!HHHH", 40000, port, 8 + n, 0) + bytes(n)
fr = N.mcast_frame(MAC, "10.1.1.5", "239.1.1.10", 17, udp(5004, 1316), ttl=16)
pm = N.parse_mcast(fr)
check("parse: a UDP stream frame", (pm["src"], pm["group"], pm["proto"], pm["port"], pm["len"], pm["vlan"]) == ("10.1.1.5", "239.1.1.10", 17, 5004, len(fr), None), pm)
check("built frame has a valid IP checksum and the right MACs", N.checksum(fr[14:34]) == 0 and fr[:6].hex() == "01005e01010a" and fr[6:12].hex() == "001122334455")
pv = N.parse_mcast(N.mcast_frame(MAC, "10.1.1.5", "239.1.1.10", 17, udp(5004, 100), vlan=30))
check("parse: a VLAN-tagged frame", pv["vlan"] == 30 and pv["group"] == "239.1.1.10" and pv["port"] == 5004)
check("parse: unicast, ARP and runts are ignored", N.parse_mcast(N.mcast_frame(MAC, "10.1.1.5", "239.1.1.10", 17, udp(1, 8), dst_ip="10.1.1.9")) is None
      and N.parse_mcast(bytes.fromhex("ffffffffffff0011223344550806") + bytes(46)) is None and N.parse_mcast(b"\x01\x00") is None)
q = lambda **kw: N.parse_mcast(N.mcast_frame(MAC, "10.20.30.1", "224.0.0.1", 2, N.igmp_payload("query", **kw)))["igmp"][0]
check("igmp: v2 general query", q() == ("query", "0.0.0.0", {"max_resp": 10.0, "version": 2, "general": True}), q())
check("igmp: v3 general query carries its interval", q(version=3)[2]["version"] == 3 and q(version=3)[2]["qqic"] == 125)
check("igmp: v1 query", q(version=1)[2]["version"] == 1)
check("igmp: group-specific query", q(group="239.1.1.10")[1:] == ("239.1.1.10", {"max_resp": 10.0, "version": 2, "general": False}))
check("igmp: query message checksums to zero", N.checksum(N.igmp_payload("query", version=3)) == 0)
ig = lambda kind, g, **kw: N.parse_igmp(N.igmp_payload(kind, g, **kw))
check("igmp: v2 report and leave", ig("report", "239.1.1.10") == [("join", "239.1.1.10", {"version": 2})] and ig("leave", "239.1.1.10") == [("leave", "239.1.1.10", {"version": 2})])
check("igmp: v3 join and leave records", ig("report3", "239.1.1.10") == [("join", "239.1.1.10", {"version": 3})] and ig("leave3", "239.1.1.10") == [("leave", "239.1.1.10", {"version": 3})])
check("igmp: v3 exponent-coded times", [N.igmp_code(v) for v in (0, 125, 127, 128, 0x8F, 0xFF)] == [0, 125, 127, 128, 248, 31744])
check("igmp: a truncated v3 report doesn't raise", N.parse_igmp(N.igmp_payload("report3", "239.1.1.10")[:12]) == [])
tr = N.McastTracker(now=1000.0)
snap0 = tr.snapshot(1010.0)
check("querier: still waiting early on", N.querier_verdict(snap0)[1] == "wait")
check("querier: none after a probe got no answer", N.querier_verdict(snap0, probed=True)[1] == "warn")
check("querier: none after two minutes of silence", N.querier_verdict(tr.snapshot(1131.0))[:2] == ("No IGMP querier found", "warn"))
for ts in (1001.0, 1126.0):
    tr.feed(N.mcast_frame(MAC, "10.20.30.1", "224.0.0.1", 2, N.igmp_payload("query")), ts)
tr.feed(N.mcast_frame(MAC, "10.20.30.60", "224.0.0.22", 2, N.igmp_payload("report3", "239.1.1.10")), 1002.0)
tr.feed(N.mcast_frame(MAC, "10.20.30.61", "239.9.9.9", 2, N.igmp_payload("report", "239.9.9.9")), 1002.0)
for i in range(50):
    tr.feed(fr, 1002.0 + i / 50)
tr.feed(N.mcast_frame(MAC, "10.20.30.21", "239.255.255.250", 17, udp(1900, 300)), 1002.5)
tr.feed(bytes.fromhex("ffffffffffff0011223344550806") + bytes(46), 1002.6)
tr.tick(1003.0)
sn = tr.snapshot(1130.0)
by = {g["group"]: g for g in sn["groups"]}
check("tracker: the busiest group is first", sn["groups"][0]["group"] == "239.1.1.10")
g = by["239.1.1.10"]
check("tracker: packets, bytes, source, port, members", (g["pkts"], g["bytes"], g["sources"], g["port"], g["members"]) == (50, 50 * len(fr), ["10.1.1.5"], 5004, ["10.20.30.60"]), g)
check("tracker: rate since the group was first seen, one second before the tick", abs(g["pps"] - 50) < 0.01 and abs(g["bps"] - 50 * len(fr) * 8) < 1, (g["pps"], g["bps"]))
check("tracker: a joined group with no traffic is still listed", by["239.9.9.9"]["pkts"] == 0 and by["239.9.9.9"]["members"] == ["10.20.30.61"])
check("tracker: IGMP itself is not counted as group traffic", "224.0.0.22" not in by and "224.0.0.1" not in by and sn["frames"] == 55)
check("tracker: names attached", by["239.255.255.250"]["name"] == "SSDP / UPnP")
check("querier: found, with version and measured interval", N.querier_verdict(sn) == ("Querier: 10.20.30.1", "ok", "IGMPv2 · asks every 125 s"), N.querier_verdict(sn))
tr.feed(N.mcast_frame(MAC, "10.20.30.60", "224.0.0.22", 2, N.igmp_payload("leave3", "239.1.1.10")), 1128.0)
tr.feed(N.mcast_frame(MAC, "10.20.30.0", "224.0.0.1", 2, N.igmp_payload("query", version=3)), 1129.0)
sn2 = tr.snapshot(1130.0)
check("tracker: a leave removes the member", {g["group"]: g for g in sn2["groups"]}["239.1.1.10"]["members"] == [])
check("querier: two seen, the lowest address is the one named", N.querier_verdict(sn2)[0] == "Querier: 10.20.30.0" and "2 queriers" in N.querier_verdict(sn2)[2])
tr2 = N.McastTracker(now=0.0)
tr2.feed(N.mcast_frame(MAC, "10.20.30.1", "239.192.137.251", 2, N.igmp_payload("query", group="239.192.137.251")), 3.0)
check("querier: a reply to our leave is enough to name it", N.querier_verdict(tr2.snapshot(4.0), probed=True)[:2] == ("Querier: 10.20.30.1", "ok"))
tr3 = N.McastTracker(now=0.0); tr3.MAX_GROUPS = 3
for i in range(10):
    tr3.feed(N.mcast_frame(MAC, "10.1.1.5", f"239.1.1.{i + 1}", 17, udp(5004, 10)), 1.0)
check("tracker: the group table is capped", len(tr3.snapshot(2.0)["groups"]) == 3)
# a real membership through the OS, on loopback
try:
    js = N.mcast_join_socket("239.192.137.251", "127.0.0.1"); js.close(); joined = True
except OSError as e:
    joined = str(e)
check("mcast_join_socket joins and leaves through the OS", joined is True, joined)
try:
    N.mcast_join_socket("10.1.2.3", "127.0.0.1"); refused = False
except OSError:
    refused = True
check("mcast_join_socket refuses a non-multicast address", refused)
# public IP: Cloudflare trace reply
TRACE = "fl=29f85\nh=1.1.1.1\nip=203.0.113.47\nts=1791612003.1\nvisit_scheme=https\nuag=PorkChopCheck\ncolo=DFW\nloc=US\ntls=TLSv1.3\n"
check("trace: public IPv4", N.parse_trace_ip(TRACE) == "203.0.113.47")
check("trace: public IPv6 is normalised", N.parse_trace_ip("h=x\nip=2001:DB8:0:0::1\n") == "2001:db8::1")
for bad in ("", "h=1.1.1.1\ncolo=DFW\n", "ip=<script>alert(1)</script>\n", "ip=999.1.1.1\n", "xip=1.2.3.4\n", "ip=1.2.3.4 extra\n"):
    check(f"trace: not an address -> None: {bad[:24]!r}", N.parse_trace_ip(bad) is None)
# Oui parsing
p = os.path.join(tmp, "manuf"); open(p, "w").write("# c\n00:00:0C\tCisco\tCisco Systems, Inc\n00:1B:C5:00:00:00/36\tX\n")
o = N.Oui(p); check("oui lookup", o.lookup("00:00:0c:07:ac:01") == "Cisco · HSRPv1 group 1", o.lookup("00:00:0c:07:ac:01"))
print(f"\nALL {ok} CHECKS PASSED")
