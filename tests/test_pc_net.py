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
