"""
pc_net - the networking engine behind PorkChopCheck.

Packet decoders / builders (CDP, LLDP, DTP, STP, EAPOL, ARP, DHCP, mDNS, IPv6 RA),
ICMP ping + traceroute, iperf3 / HTTP speed tests, MAC vendor lookup, port log, settings.
No GUI code in here, so it can be tested on any OS.
"""

import csv
import ctypes
import http.client
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.request

IS_WIN = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
NO_WINDOW = 0x08000000 if IS_WIN else 0


# ====================================================================== helpers
def run(cmd, timeout=15):
    """Run a command (list, or a raw command-line string on Windows). Returns (code, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def powershell(script, timeout=15):
    return run(["powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


def ps_json(script, timeout=15):
    _, out, _ = powershell(script, timeout)
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def psq(s):
    return "'" + str(s).replace("'", "''") + "'"


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def is_ipv4(s):
    try:
        socket.inet_aton(s)
        return isinstance(s, str) and s.count(".") == 3
    except (OSError, TypeError):
        return False


def first_v4(values):
    for v in as_list(values):
        if is_ipv4(v):
            return v
    return None


def prefix_len(mask):
    try:
        return sum(bin(int(x)).count("1") for x in mask.split("."))
    except (ValueError, AttributeError):
        return None


def norm_mac(m):
    return (m or "").lower().replace("-", ":")


def mac_bytes(m):
    return bytes.fromhex(norm_mac(m).replace(":", ""))


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def fmt_speed(mbps):
    if not mbps:
        return "—"
    if mbps >= 1000:
        return f"{mbps / 1000:g} Gbps"
    return f"{mbps} Mbps"


def fmt_rate(bps):
    if bps is None:
        return "—"
    for unit, div in (("Gb/s", 1e9), ("Mb/s", 1e6), ("kb/s", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{bps:.0f} b/s"


def fmt_mbps(bps):
    return "—" if bps is None else f"{bps / 1e6:,.0f} Mbps"


def txt(b):
    return b.decode("utf-8", "replace").strip("\x00 \r\n\t")


def u16(b, i):
    return struct.unpack_from("!H", b, i)[0]


def u32(b, i):
    return struct.unpack_from("!I", b, i)[0]


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def pad60(frame):
    return frame + bytes(max(0, 60 - len(frame)))


def is_admin():
    """Windows: elevated. Linux: root, or CAP_NET_RAW + CAP_NET_ADMIN (see install-linux.sh)."""
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    if IS_LINUX:
        return has_net_caps()
    return True


def has_net_caps():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    m = re.search(r"^CapEff:\s*([0-9a-f]+)", _read("/proc/self/status", ""), re.M)
    if not m:
        return False
    caps = int(m.group(1), 16)
    return bool(caps & (1 << 12)) and bool(caps & (1 << 13))     # NET_ADMIN, NET_RAW


def _read(path, default=None):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return default


# ====================================================================== constants
CDP_DST = bytes.fromhex("01000ccccccc")
PVST_DST = bytes.fromhex("01000ccccccd")
STP_DST = bytes.fromhex("0180c2000000")
PAE_DST = bytes.fromhex("0180c2000003")
LLDP_DST = bytes.fromhex("0180c200000e")
BCAST = b"\xff" * 6
SNAP_CDP = bytes.fromhex("aaaa0300000c2000")
DHCP_MAGIC = b"\x63\x82\x53\x63"

# Everything the sniffer cares about. "vlan" must stay last (it shifts later offsets).
BPF = ("ether dst 01:00:0c:cc:cc:cc or ether dst 01:00:0c:cc:cc:cd or ether dst 01:80:c2:00:00:00"
       " or ether proto 0x88cc or ether proto 0x888e or arp"
       " or (udp and (port 67 or port 68 or port 5353))"
       " or (icmp6 and ip6[40] == 134) or vlan")

MAU = {10: "10BASE-T HD", 11: "10BASE-T FD", 15: "100BASE-TX HD", 16: "100BASE-TX FD",
       29: "1000BASE-T HD", 30: "1000BASE-T FD"}
EAP_TYPES = {1: "Identity", 4: "MD5", 13: "EAP-TLS", 21: "TTLS", 25: "PEAP", 43: "FAST"}
DHCP_MSG = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
            7: "RELEASE", 8: "INFORM"}


# ====================================================================== frame classifier
def classify(raw):
    """Decode one Ethernet frame into a list of (kind, info) events."""
    ev = []
    if len(raw) < 14:
        return ev
    dst, src = raw[0:6], raw[6:12]
    srcs = mac_str(src)
    et, off, vlan = u16(raw, 12), 14, None
    if et in (0x8100, 0x88A8) and len(raw) >= 18:
        vlan = u16(raw, 14) & 0x0FFF
        et, off = u16(raw, 16), 18
        ev.append(("VLAN", {"vlan": vlan, "src": srcs}))
    p = raw[off:]

    def add(kind, info):
        if info is not None:
            info["src"] = srcs
            info["dst"] = mac_str(dst)
            info["vlan_tag"] = vlan
            ev.append((kind, info))

    if et == 0x88CC:
        add("LLDP", parse_lldp(p))
    elif et == 0x888E:
        add("EAPOL", parse_eapol(p))
    elif et == 0x0806:
        add("ARP", parse_arp(p))
    elif et == 0x0800:
        for k, i in parse_ipv4(p):
            add(k, i)
    elif et == 0x86DD:
        for k, i in parse_ipv6(p):
            add(k, i)
    elif et <= 1500:
        if p[:3] == b"\xaa\xaa\x03" and p[3:6] == b"\x00\x00\x0c" and len(p) >= 8:
            pid, body = u16(p, 6), p[8:]
            if pid == 0x2000:
                add("CDP", parse_cdp(body))
            elif pid == 0x2004:
                add("DTP", parse_dtp(body))
            elif pid == 0x010B:
                add("STP", parse_bpdu(body, pvst=True))
        elif p[:3] == b"\x42\x42\x03":
            add("STP", parse_bpdu(p[3:]))
    return ev


# ---------------------------------------------------------------------- CDP
def _cdp_addrs(v):
    out = []
    if len(v) < 4:
        return out
    n, j = u32(v, 0), 4
    for _ in range(min(n, 16)):
        if j + 2 > len(v):
            break
        ptype, plen = v[j], v[j + 1]
        j += 2
        proto = v[j:j + plen]
        j += plen
        if j + 2 > len(v):
            break
        alen = u16(v, j)
        j += 2
        addr = v[j:j + alen]
        j += alen
        if ptype == 1 and proto == b"\xcc" and alen == 4:
            out.append(socket.inet_ntoa(addr))
    return out


def parse_cdp(p):
    d = {}
    i = 4  # version, ttl, checksum
    while i + 4 <= len(p):
        t, ln = struct.unpack_from("!HH", p, i)
        if ln < 4:
            break
        v = p[i + 4:i + ln]
        if t == 0x0001:
            d["name"] = txt(v)
        elif t == 0x0002:
            ips = _cdp_addrs(v)
            if ips:
                d["addr"] = ips[0]
        elif t == 0x0003:
            d["port"] = txt(v)
        elif t == 0x0005 and v:
            d["software"] = txt(v).splitlines()[0]
        elif t == 0x0006:
            d["platform"] = txt(v)
        elif t == 0x0009:
            d["vtp"] = txt(v)
        elif t == 0x000A and len(v) >= 2:
            d["vlan"] = u16(v, 0)
        elif t == 0x000B and v:
            d["duplex"] = "full" if v[0] else "half"
        elif t == 0x000E and len(v) >= 3:
            d["voice_vlan"] = u16(v, 1)
        elif t == 0x0010 and len(v) >= 2:
            d["poe"] = f"{u16(v, 0) / 1000:.1f} W"
        elif t == 0x0016:
            ips = _cdp_addrs(v)
            if ips:
                d["mgmt_ip"] = ips[0]
        i += ln
    if "mgmt_ip" not in d and "addr" in d:
        d["mgmt_ip"] = d["addr"]
    return d


def build_cdp(mac, device_id, port_id, ip=None, platform_name="PorkChopCheck",
              software="PorkChopCheck switch-port tester"):
    def tlv(t, v):
        return struct.pack("!HH", t, len(v) + 4) + v

    def body(sw):
        b = tlv(1, device_id.encode()[:200])
        if ip:
            b += tlv(2, struct.pack("!I", 1) + bytes([1, 1, 0xCC]) + struct.pack("!H", 4)
                     + socket.inet_aton(ip))
        b += tlv(3, port_id.encode()[:100])
        b += tlv(4, struct.pack("!I", 0x10))          # capabilities: host
        b += tlv(5, sw.encode())
        b += tlv(6, platform_name.encode())
        return b

    b = body(software)
    if (4 + len(b)) % 2:                              # keep the length even (Cisco odd-byte quirk)
        b = body(software + " ")
    hdr = bytes([2, 180, 0, 0])
    ck = checksum(hdr + b)
    cdp = bytes([2, 180]) + struct.pack("!H", ck) + b
    payload = SNAP_CDP + cdp
    return pad60(CDP_DST + mac_bytes(mac) + struct.pack("!H", len(payload)) + payload)


# ---------------------------------------------------------------------- LLDP
def _lldp_id(v):
    sub, val = v[0], v[1:]
    if sub in (3, 4) and len(val) == 6:
        return sub, mac_str(val)
    if sub == 5 and len(val) >= 5 and val[0] == 1:
        return sub, socket.inet_ntoa(val[1:5])
    return sub, txt(val)


def parse_lldp(p):
    d = {}
    i = 0
    while i + 2 <= len(p):
        h = u16(p, i)
        t, ln = h >> 9, h & 0x1FF
        v = p[i + 2:i + 2 + ln]
        i += 2 + ln
        if t == 0:
            break
        if t == 1 and v:
            d["chassis"] = _lldp_id(v)[1]
        elif t == 2 and v:
            sub, val = _lldp_id(v)
            d["port"] = val
            d["port_is_mac"] = sub == 3
        elif t == 4:
            d["port_desc"] = txt(v)
        elif t == 5:
            d["name"] = txt(v)
        elif t == 6 and v:
            d["platform"] = txt(v).splitlines()[0]
        elif t == 8 and len(v) >= 6:
            if v[1] == 1 and v[0] == 5:
                d["mgmt_ip"] = socket.inet_ntoa(v[2:6])
        elif t == 127 and len(v) >= 4:
            oui, st, b = v[:3], v[3], v[4:]
            if oui == b"\x00\x80\xc2" and st == 1 and len(b) >= 2:
                d["vlan"] = u16(b, 0)
            elif oui == b"\x00\x80\xc2" and st == 3 and len(b) >= 3:
                d.setdefault("vlan_names", {})[u16(b, 0)] = txt(b[3:3 + b[2]])
            elif oui == b"\x00\x12\x0f" and st == 1 and len(b) >= 5:
                d["autoneg"] = "Auto" if b[0] & 0x02 else "Forced"
                mau = u16(b, 3)
                d["mau"] = MAU.get(mau, f"MAU {mau}")
            elif oui == b"\x00\x12\xbb" and st == 2 and len(b) >= 4:
                if b[0] == 1:
                    d["voice_vlan"] = (int.from_bytes(b[1:4], "big") >> 9) & 0xFFF
            elif oui == b"\x00\x12\xbb" and st == 4 and len(b) >= 3:
                d["poe"] = f"{u16(b, 1) / 10:.1f} W"
            elif oui == b"\x00\x12\x0f" and st == 2 and "poe" not in d:
                d["poe"] = "Yes"
    return d


def build_lldp(mac, port_name, sysname, sysdesc="PorkChopCheck switch-port tester", ip=None):
    def tl(t, v):
        return struct.pack("!H", (t << 9) | len(v)) + v

    mb = mac_bytes(mac)
    p = tl(1, b"\x04" + mb)
    p += tl(2, b"\x05" + port_name.encode()[:250])
    p += tl(3, struct.pack("!H", 120))
    p += tl(4, port_name.encode()[:250])
    p += tl(5, sysname.encode()[:250])
    p += tl(6, sysdesc.encode()[:250])
    p += tl(7, struct.pack("!HH", 0x0080, 0x0080))   # station only
    if ip:
        p += tl(8, bytes([5, 1]) + socket.inet_aton(ip) + bytes([2]) + struct.pack("!I", 0) + b"\x00")
    p += tl(0, b"")
    return pad60(LLDP_DST + mb + b"\x88\xcc" + p)


def merge_neighbors(nb):
    """CDP wins where both have a value; LLDP fills the gaps."""
    lldp = dict(nb.get("LLDP", ({}, 0))[0])
    cdp = nb.get("CDP", ({}, 0))[0]
    if lldp.get("port_is_mac") and lldp.get("port_desc"):
        lldp["port"] = lldp["port_desc"]
    names = lldp.get("vlan_names", {})
    if "vlan" in lldp and lldp["vlan"] in names:
        lldp["vlan_name"] = names[lldp["vlan"]]
    out = dict(lldp)
    out.update({k: v for k, v in cdp.items() if v not in (None, "")})
    return out


# ---------------------------------------------------------------------- DTP / STP / EAPOL
def parse_dtp(b):
    if not b:
        return None
    d, i = {}, 1
    while i + 4 <= len(b):
        t, ln = u16(b, i), u16(b, i + 2)
        if ln < 4:
            break
        v = b[i + 4:i + ln]
        if t == 1:
            d["domain"] = txt(v)
        elif t == 2 and v:
            st = v[0]
            d["admin"] = {1: "on", 2: "off", 3: "desirable", 4: "auto"}.get(st & 0x07, f"0x{st:02x}")
            d["oper"] = "trunk" if st & 0x80 else "access"
        elif t == 4 and len(v) >= 6:
            d["neighbor"] = mac_str(v[:6])
        i += ln
    return d


def parse_bpdu(b, pvst=False):
    if len(b) < 4 or u16(b, 0) != 0:
        return None
    ver, typ = b[2], b[3]
    d = {"proto": {0: "STP", 2: "RSTP", 3: "MSTP"}.get(ver, f"v{ver}"), "tcn": typ == 0x80}
    if pvst:
        d["proto"] = "Rapid-PVST" if ver >= 2 else "PVST+"
    if typ == 0x80 or len(b) < 35:
        return d
    flags, rp, bp = b[4], u16(b, 5), u16(b, 17)
    d.update(tc=bool(flags & 1), root_prio=rp & 0xF000, root_mac=mac_str(b[7:13]),
             cost=u32(b, 13), bridge_prio=bp & 0xF000, bridge_mac=mac_str(b[19:25]),
             vlan=bp & 0x0FFF, port_id=u16(b, 25), hello=u16(b, 31) / 256)
    if ver >= 2:
        d["role"] = {0: "Unknown", 1: "Alt/Backup", 2: "Root", 3: "Designated"}[(flags >> 2) & 3]
    return d


def parse_eapol(p):
    if len(p) < 4:
        return None
    d = {"ptype": p[1]}
    if p[1] == 0 and len(p) >= 8:
        code = p[4]
        d["code"] = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}.get(code, str(code))
        if code in (1, 2) and len(p) >= 9:
            d["eap_type"] = EAP_TYPES.get(p[8], str(p[8]))
    elif p[1] == 1:
        d["code"] = "Start"
    return d


def build_eapol_start(mac):
    return pad60(PAE_DST + mac_bytes(mac) + b"\x88\x8e" + bytes([1, 1, 0, 0]))


# ---------------------------------------------------------------------- ARP
def parse_arp(p):
    if len(p) < 28 or u16(p, 0) != 1 or u16(p, 2) != 0x0800:
        return None
    return {"op": u16(p, 6), "sha": mac_str(p[8:14]), "spa": socket.inet_ntoa(p[14:18]),
            "tha": mac_str(p[18:24]), "tpa": socket.inet_ntoa(p[24:28])}


def build_arp_request(mac, sender_ip, target_ip):
    """sender_ip=None builds an RFC 5227 probe (sender 0.0.0.0) for duplicate-address checks."""
    mb = mac_bytes(mac)
    spa = socket.inet_aton(sender_ip) if sender_ip else bytes(4)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mb + spa + bytes(6) + socket.inet_aton(target_ip)
    return pad60(BCAST + mb + b"\x08\x06" + arp)


# ---------------------------------------------------------------------- IPv4 / IPv6 / UDP
def parse_ipv4(p):
    if len(p) < 20 or p[0] >> 4 != 4:
        return []
    ihl = (p[0] & 0x0F) * 4
    if p[9] != 17 or len(p) < ihl + 8:
        return []
    return parse_udp(p[ihl:], socket.inet_ntoa(p[12:16]), socket.inet_ntoa(p[16:20]))


def parse_ipv6(p):
    if len(p) < 40:
        return []
    nh = p[6]
    src = socket.inet_ntop(socket.AF_INET6, p[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, p[24:40])
    body = p[40:]
    if nh == 58 and body and body[0] == 134:
        return [("RA", parse_ra(body, src))]
    if nh == 17 and len(body) >= 8:
        return parse_udp(body, src, dst)
    return []


def parse_udp(u, src, dst):
    sport, dport, ln = struct.unpack_from("!HHH", u, 0)
    data = u[8:ln] if ln >= 8 else u[8:]
    out = []
    if sport in (67, 68) and dport in (67, 68):
        d = parse_bootp(data)
        if d:
            d["ip_src"] = src
            out.append(("DHCP", d))
    elif sport == 5353 or dport == 5353:
        try:
            m = parse_dns(data)
        except Exception:  # noqa: BLE001
            m = None
        if m and m["qr"]:
            m["ip_src"], m["ip_dst"] = src, dst
            out.append(("MDNS", m))
    return out


def ipv4_udp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, random.randint(0, 0xFFFF), 0, 64, 17, 0,
                      socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return pad60(dst_mac + mac_bytes(src_mac) + b"\x08\x00" + hdr + udp)


def parse_ra(b, src):
    d = {"router": src, "m": bool(b[5] & 0x80), "o": bool(b[5] & 0x40), "prefixes": []}
    if len(b) >= 8:
        d["lifetime"] = u16(b, 6)
    i = 16
    while i + 2 <= len(b):
        t, ln = b[i], b[i + 1] * 8
        if ln == 0:
            break
        o = b[i:i + ln]
        if t == 3 and len(o) >= 32:
            d["prefixes"].append(f"{socket.inet_ntop(socket.AF_INET6, o[16:32])}/{o[2]}")
        elif t == 1 and len(o) >= 8:
            d["router_mac"] = mac_str(o[2:8])
        elif t == 5 and len(o) >= 8:
            d["mtu"] = u32(o, 4)
        i += ln
    return d


# ---------------------------------------------------------------------- DHCP
def _ips(v):
    return [socket.inet_ntoa(v[i:i + 4]) for i in range(0, len(v) - 3, 4)]


def parse_bootp(b):
    if len(b) < 240 or b[236:240] != DHCP_MAGIC:
        return None
    opts, i = {}, 240
    while i < len(b):
        c = b[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        ln = b[i + 1]
        opts[c] = b[i + 2:i + 2 + ln]
        i += 2 + ln
    d = {"op": b[0], "xid": u32(b, 4), "yiaddr": socket.inet_ntoa(b[16:20]),
         "siaddr": socket.inet_ntoa(b[20:24]), "chaddr": mac_str(b[28:34]),
         "msg": DHCP_MSG.get((opts.get(53) or b"\x00")[0], "?")}
    if len(opts.get(54, b"")) == 4:
        d["server"] = socket.inet_ntoa(opts[54])
    if len(opts.get(1, b"")) == 4:
        d["mask"] = socket.inet_ntoa(opts[1])
    if 3 in opts:
        d["routers"] = _ips(opts[3])
    if 6 in opts:
        d["dns"] = _ips(opts[6])
    if 15 in opts:
        d["domain"] = txt(opts[15])
    if len(opts.get(51, b"")) == 4:
        d["lease"] = u32(opts[51], 0)
    if 66 in opts:
        d["tftp_name"] = txt(opts[66])
    if 150 in opts:
        d["tftp_ips"] = _ips(opts[150])
    if 43 in opts:
        d["opt43"] = opts[43].hex()
    if 42 in opts:
        d["ntp"] = _ips(opts[42])
    sname = txt(b[44:108])
    if sname:
        d["sname"] = sname
    return d


def build_dhcp_discover(mac, xid):
    mb = mac_bytes(mac)
    bootp = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, 0x8000) + bytes(16) + mb + bytes(10)
    bootp += bytes(64) + bytes(128) + DHCP_MAGIC
    prl = [1, 3, 6, 15, 42, 43, 51, 54, 66, 150]
    bootp += bytes([53, 1, 1]) + bytes([61, 7, 1]) + mb + bytes([55, len(prl)]) + bytes(prl) + b"\xff"
    return ipv4_udp_frame(mac, BCAST, "0.0.0.0", "255.255.255.255", 68, 67, bootp)


# ---------------------------------------------------------------------- DNS / mDNS
def read_name(b, i):
    """Return (labels, next_index), following compression pointers."""
    labels, end, hops = [], None, 0
    while True:
        if i >= len(b):
            raise ValueError("name runs past end")
        ln = b[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            if i + 1 >= len(b):
                raise ValueError("bad pointer")
            if end is None:
                end = i + 2
            i = ((ln & 0x3F) << 8) | b[i + 1]
            hops += 1
            if hops > 30:
                raise ValueError("pointer loop")
            continue
        labels.append(b[i + 1:i + 1 + ln].decode("utf-8", "replace"))
        i += 1 + ln
    return labels, (end if end is not None else i)


def parse_dns(b):
    qid, flags, qd, an, ns, ar = struct.unpack_from("!6H", b, 0)
    i = 12
    for _ in range(qd):
        _, i = read_name(b, i)
        i += 4
    recs = []
    for _ in range(an + ns + ar):
        labels, i = read_name(b, i)
        typ, _cls, ttl, rdl = struct.unpack_from("!HHIH", b, i)
        i += 10
        start, rdata = i, b[i:i + rdl]
        i += rdl
        r = {"labels": labels, "name": ".".join(labels), "type": typ, "ttl": ttl}
        if typ == 12:
            r["ptr_labels"] = read_name(b, start)[0]
            r["ptr"] = ".".join(r["ptr_labels"])
        elif typ == 33 and rdl >= 6:
            r["port"] = u16(rdata, 4)
            r["target"] = ".".join(read_name(b, start + 6)[0])
        elif typ == 1 and rdl == 4:
            r["a"] = socket.inet_ntoa(rdata)
        elif typ == 28 and rdl == 16:
            r["aaaa"] = socket.inet_ntop(socket.AF_INET6, rdata)
        elif typ == 16:
            out, j = [], 0
            while j < len(rdata):
                ln = rdata[j]
                out.append(rdata[j + 1:j + 1 + ln].decode("utf-8", "replace"))
                j += 1 + ln
            r["txt"] = [t for t in out if t]
        recs.append(r)
    return {"id": qid, "qr": bool(flags & 0x8000), "records": recs}


def encode_labels(labels):
    out = b""
    for part in labels:
        e = part.encode()[:63]
        out += bytes([len(e)]) + e
    return out + b"\x00"


def encode_name(name):
    return encode_labels([p for p in name.rstrip(".").split(".") if p])


def build_dns_query(questions, qid=None):
    """questions: list of (encoded_name_bytes, qtype)."""
    qid = qid if qid is not None else random.randint(1, 0xFFFF)
    h = struct.pack("!6H", qid, 0, len(questions), 0, 0, 0)
    return h + b"".join(n + struct.pack("!HH", t, 1) for n, t in questions)


SERVICES = "_services._dns-sd._udp.local"
FRIENDLY = {
    "_airplay._tcp.local": "AirPlay", "_raop._tcp.local": "AirPlay audio",
    "_googlecast._tcp.local": "Chromecast / Google", "_spotify-connect._tcp.local": "Spotify Connect",
    "_ipp._tcp.local": "Printer (IPP)", "_ipps._tcp.local": "Printer (IPPS)",
    "_printer._tcp.local": "Printer (LPD)", "_pdl-datastream._tcp.local": "Printer (raw 9100)",
    "_uscan._tcp.local": "Scanner", "_scanner._tcp.local": "Scanner",
    "_hap._tcp.local": "HomeKit", "_homekit._tcp.local": "HomeKit", "_matter._tcp.local": "Matter",
    "_matterc._udp.local": "Matter (commissioning)", "_sonos._tcp.local": "Sonos",
    "_smb._tcp.local": "SMB file share", "_afpovertcp._tcp.local": "AFP file share",
    "_http._tcp.local": "Web UI", "_https._tcp.local": "Web UI (https)",
    "_ssh._tcp.local": "SSH", "_sftp-ssh._tcp.local": "SFTP",
    "_workstation._tcp.local": "Workstation", "_device-info._tcp.local": "Device info",
    "_companion-link._tcp.local": "Apple device", "_airport._tcp.local": "AirPort",
    "_sleep-proxy._udp.local": "Sleep proxy", "_mqtt._tcp.local": "MQTT",
    "_amzn-wplay._tcp.local": "Amazon Fire/Echo", "_androidtvremote2._tcp.local": "Android TV",
    "_rdlink._tcp.local": "Apple remote", "_touch-able._tcp.local": "Apple remote",
    "_esphomelib._tcp.local": "ESPHome", "_hue._tcp.local": "Philips Hue",
    "_wled._tcp.local": "WLED", "_nanoleafapi._tcp.local": "Nanoleaf", "_elg._tcp.local": "Elgato light",
    "_shelly._tcp.local": "Shelly", "_tuya._tcp.local": "Tuya",
}
COMMON_TYPES = sorted(FRIENDLY)


class MdnsBrowser:
    """Collects mDNS answers (active legacy-unicast queries + passive sniffing)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.types = set()
            self.inst = {}          # (instance_label, type) -> {"host", "port", "txt"}
            self.hosts = {}         # hostname -> set(ips)
            self.responders = set()
            self.multicast_seen = 0
            self.unicast_replies = 0
            self.running = False
            self.last_scan = None
            self.error = None

    def ingest(self, msg, src_ip, multicast):
        with self.lock:
            if src_ip:
                self.responders.add(src_ip)
            if multicast:
                self.multicast_seen += 1
            else:
                self.unicast_replies += 1
            for r in msg["records"]:
                t = r["type"]
                if t == 12:
                    pl = r["ptr_labels"]
                    if r["name"].lower() == SERVICES:
                        self.types.add(".".join(pl).lower())
                    elif len(pl) >= 4 and pl[-2].lower() in ("_tcp", "_udp"):
                        stype = ".".join(pl[1:]).lower()
                        self.types.add(stype)
                        self.inst.setdefault((pl[0], stype), {})
                elif t in (33, 16):
                    lb = r["labels"]
                    if len(lb) >= 4 and lb[-2].lower() in ("_tcp", "_udp"):
                        key = (lb[0], ".".join(lb[1:]).lower())
                        e = self.inst.setdefault(key, {})
                        self.types.add(key[1])
                        if t == 33:
                            e["host"], e["port"] = r["target"].lower(), r["port"]
                        else:
                            e["txt"] = r.get("txt", [])
                elif t in (1, 28):
                    ip = r.get("a") or r.get("aaaa")
                    if ip:
                        self.hosts.setdefault(r["name"].lower(), set()).add(ip)

    def _questions(self, first):
        with self.lock:
            if first:
                qs = [(encode_name(SERVICES), 12)] + [(encode_name(t), 12) for t in COMMON_TYPES]
            else:
                qs = [(encode_name(t), 12) for t in self.types]
                for (label, stype), e in self.inst.items():
                    if "host" not in e:
                        n = encode_labels([label] + stype.split("."))
                        qs += [(n, 33), (n, 16)]
                for e in self.inst.values():
                    h = e.get("host")
                    if h and h not in self.hosts:
                        qs.append((encode_name(h), 1))
            qs = [q for q in dict.fromkeys(qs) if q not in self._asked]
            self._asked.update(qs)
            return qs

    def scan(self, src_ip, rounds=4, wait=1.5):
        """Legacy unicast queries from an ephemeral port: replies come straight back to us."""
        with self.lock:
            self.running, self.error, self._asked = True, None, set()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((src_ip or "0.0.0.0", 0))
            if src_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.settimeout(0.25)
            for rnd in range(rounds):
                qs = self._questions(rnd == 0)
                if not qs and rnd > 0:
                    break
                for k in range(0, len(qs), 6):
                    sock.sendto(build_dns_query(qs[k:k + 6]), ("224.0.0.251", 5353))
                    time.sleep(0.02)
                end = time.time() + wait
                while time.time() < end:
                    try:
                        data, (ip, _port) = sock.recvfrom(9000)
                    except socket.timeout:
                        continue
                    try:
                        m = parse_dns(data)
                    except Exception:  # noqa: BLE001
                        continue
                    if m["qr"]:
                        self.ingest(m, ip, multicast=False)
        except OSError as e:
            with self.lock:
                self.error = str(e)
        finally:
            sock.close()
            with self.lock:
                self.running = False
                self.last_scan = time.time()

    def snapshot(self):
        with self.lock:
            return {"types": set(self.types), "inst": {k: dict(v) for k, v in self.inst.items()},
                    "hosts": {k: set(v) for k, v in self.hosts.items()},
                    "responders": set(self.responders), "multicast_seen": self.multicast_seen,
                    "unicast_replies": self.unicast_replies, "running": self.running,
                    "last_scan": self.last_scan, "error": self.error}


def mdns_rows(snap):
    """[(text, kind)] grouped by service type. kind: 'hdr' or 'row'."""
    by_type = {}
    for (label, stype), e in snap["inst"].items():
        by_type.setdefault(stype, []).append((label, e))
    out = []
    for stype in sorted(by_type, key=lambda t: FRIENDLY.get(t, t).lower()):
        items = sorted(by_type[stype], key=lambda x: x[0].lower())
        short = stype.replace(".local", "")
        out.append((f"{FRIENDLY.get(stype, short)}   {short}   ×{len(items)}", "hdr"))
        for label, e in items:
            host = e.get("host", "")
            ips = sorted(snap["hosts"].get(host, ()), key=lambda ip: (":" in ip, ip))
            addr = ips[0] if ips else (host.replace(".local", "") or "?")
            if e.get("port"):
                addr += f":{e['port']}"
            out.append((f"{label}  ·  {addr}", "row"))
    empty = sorted(t for t in snap["types"] if t not in by_type and t.endswith(".local"))
    if empty:
        out.append(("Types advertised (no instances answered)", "hdr"))
        out.append((", ".join(t.replace(".local", "") for t in empty), "row"))
    return out


# ====================================================================== ICMP (ping / traceroute)
class _IPOPT(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


_ipl = None


def _ip2ul(ip):
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def _ul2ip(v):
    return socket.inet_ntoa(struct.pack("<I", v))


def _win_echo(dst, src, ttl, timeout_ms, size):
    global _ipl
    if _ipl is None:
        lib = ctypes.WinDLL("iphlpapi", use_last_error=True)
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        lib.IcmpSendEcho2Ex.argtypes = [ctypes.c_void_p] * 4 + [
            ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        lib.IcmpSendEcho2Ex.restype = ctypes.c_ulong
        _ipl = lib
    h = _ipl.IcmpCreateFile()
    try:
        data = ctypes.create_string_buffer((b"PorkChopCheck-ping-" * 8)[:size], size)
        reply = ctypes.create_string_buffer(256 + size)
        opt = _IPOPT(ttl, 0, 0, 0, None)
        t = time.perf_counter()
        n = _ipl.IcmpSendEcho2Ex(h, None, None, None, _ip2ul(src) if src else 0, _ip2ul(dst),
                                 data, size, ctypes.byref(opt), reply, len(reply), timeout_ms)
        elapsed = (time.perf_counter() - t) * 1000
        addr, status, rtt = struct.unpack_from("<III", reply.raw, 0)
        if n == 0:
            return ("timeout", None, None)
        if status == 0:
            return ("ok", _ul2ip(addr), float(rtt))
        if status == 11013:
            return ("ttl", _ul2ip(addr), float(rtt) if rtt else elapsed)
        if status in (11002, 11003, 11004, 11005):
            return ("unreach", _ul2ip(addr), None)
        if status == 11010:
            return ("timeout", None, None)
        return ("error", None, None)
    finally:
        _ipl.IcmpCloseHandle(h)


def _sub_echo(dst, src, ttl, timeout_ms):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), "-i", str(ttl)] + (["-S", src] if src else [])
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), "-t", str(ttl)]
        cmd += ["-I", src] if src else []
    t = time.perf_counter()
    _, out, _ = run(cmd + [dst], timeout=5)
    return parse_ping_output(out, dst, (time.perf_counter() - t) * 1000)


def parse_ping_output(out, dst, elapsed_ms=None):
    """Turn Windows or Linux ping text into (status, responder_ip, rtt_ms)."""
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out, re.I)
    if "ttl=" in out.lower() and m:
        return ("ok", dst, float(m.group(1)))
    m = re.search(r"from\s+([\d.]+)\S*\s.*?(time to live exceeded|ttl expired)", out, re.I)
    if m:
        return ("ttl", m.group(1), elapsed_ms)
    m = re.search(r"from\s+([\d.]+)\S*\s.*?unreachable", out, re.I)
    if m:
        return ("unreach", m.group(1), None)
    return ("timeout", None, None)


def icmp_echo(dst, src=None, ttl=128, timeout_ms=1000, size=32):
    """Returns (status, responder_ip, rtt_ms). status: ok | ttl | timeout | unreach | error."""
    if IS_WIN:
        try:
            return _win_echo(dst, src, ttl, timeout_ms, size)
        except Exception:  # noqa: BLE001
            pass
    return _sub_echo(dst, src, ttl, timeout_ms)


def ping_ms(dst, src=None, timeout_ms=1000):
    st, _, rtt = icmp_echo(dst, src, timeout_ms=timeout_ms)
    return rtt if st == "ok" else None


# ====================================================================== other probes
def dns_probe(server, src, name="www.google.com", timeout=2.0):
    """Query a DNS server directly, sourced from the Ethernet IP. Returns ms or None."""
    q = build_dns_query([(encode_name(name), 1)], qid=random.randint(1, 0xFFFF))
    qid = u16(q, 0)
    q = q[:2] + b"\x01\x00" + q[4:]          # recursion desired
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        if src:
            s.bind((src, 0))
        t = time.perf_counter()
        s.sendto(q, (server, 53))
        while True:
            data, _ = s.recvfrom(2048)
            if len(data) >= 12 and u16(data, 0) == qid:
                break
        ms = (time.perf_counter() - t) * 1000
        return ms if (data[3] & 0x0F) == 0 and u16(data, 6) > 0 else None
    except OSError:
        return None
    finally:
        s.close()


def tcp_probe(host, port, src, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if src:
            s.bind((src, 0))
        t = time.perf_counter()
        s.connect((host, port))
        return (time.perf_counter() - t) * 1000
    except OSError:
        return None
    finally:
        s.close()


def parse_trace_ip(text):
    """The ip= line of a Cloudflare /cdn-cgi/trace reply, checked to be an address."""
    m = re.search(r"^ip=(\S+)$", text, re.M)
    try:
        return str(ipaddress.ip_address(m.group(1))) if m else None
    except ValueError:
        return None


def public_ip(src=None, timeout=4.0):
    """The address the internet sees this port as, or None. Asks Cloudflare by IP address, so it
    still answers when DNS on this port is broken, and goes out through `src` like every other
    probe."""
    for host in ("1.1.1.1", "1.0.0.1"):
        try:
            c = http.client.HTTPSConnection(host, 443, timeout=timeout,
                                            source_address=(src, 0) if src else None)
            try:
                c.request("GET", "/cdn-cgi/trace", headers={"User-Agent": "PorkChopCheck"})
                r = c.getresponse()
                ip = parse_trace_ip(r.read(4096).decode("ascii", "replace")) if r.status == 200 else None
                if ip:
                    return ip
            finally:
                c.close()
        except (OSError, http.client.HTTPException, ValueError):
            continue
    return None


def scan_hosts(ip, mask, cap=1024):
    """Hosts to ARP-scan. Subnets bigger than `cap` are limited to the /24 around us."""
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    limited = False
    if net.num_addresses > cap + 2:
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        limited = True
    return net, [str(h) for h in net.hosts() if str(h) != ip], limited


# ====================================================================== speed tests
def find_iperf(extra_dirs=()):
    for d in extra_dirs:
        for name in ("iperf3.exe", "iperf3"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return shutil.which("iperf3")


def run_iperf(exe, server, src=None, reverse=False, secs=5, port=5201):
    """Returns (bits_per_second, retransmits, error)."""
    cmd = [exe, "-c", server, "-p", str(port), "-t", str(secs), "-J"]
    if src:
        cmd += ["-B", src]
    if reverse:
        cmd.append("-R")
    _, out, err = run(cmd, timeout=secs + 25)
    try:
        j = json.loads(out)
    except ValueError:
        return None, None, (err or out or "no output").strip()[:120]
    if j.get("error"):
        return None, None, j["error"][:120]
    end = j.get("end", {})
    bps = end.get("sum_received", {}).get("bits_per_second")
    retr = end.get("sum_sent", {}).get("retransmits")
    return bps, retr, None


SPEED_HOST = "speed.cloudflare.com"


def http_download(src=None, nbytes=25_000_000, timeout=30):
    c = http.client.HTTPSConnection(SPEED_HOST, 443, timeout=timeout,
                                    source_address=(src, 0) if src else None)
    try:
        c.connect()
        c.request("GET", f"/__down?bytes={nbytes}")
        r = c.getresponse()
        got, t1 = 0, None
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            if t1 is None:
                t1 = time.perf_counter()
            got += len(chunk)
        t2 = time.perf_counter()
        return got * 8 / max(t2 - (t1 or t2 - 1), 1e-3)
    finally:
        c.close()


def http_upload(src=None, nbytes=10_000_000, timeout=30):
    c = http.client.HTTPSConnection(SPEED_HOST, 443, timeout=timeout,
                                    source_address=(src, 0) if src else None)
    try:
        c.connect()
        body = b"0" * nbytes
        t0 = time.perf_counter()
        c.request("POST", "/__up", body=body, headers={"Content-Type": "application/octet-stream"})
        c.getresponse().read()
        return nbytes * 8 / max(time.perf_counter() - t0, 1e-3)
    finally:
        c.close()


# ====================================================================== MAC vendors
def mac_kind(mac):
    m = norm_mac(mac)
    if len(m) != 17:
        return None
    if m.startswith("00:00:0c:07:ac:"):
        return f"HSRPv1 group {int(m[-2:], 16)}"
    if m.startswith("00:00:0c:9f:f"):
        return f"HSRPv2 group {int(m[-5:].replace(':', ''), 16) & 0xFFF}"
    if m.startswith("00:00:5e:00:01:"):
        return f"VRRP VRID {int(m[-2:], 16)}"
    if m.startswith("00:07:b4:00:"):
        return "GLBP virtual MAC"
    if int(m[1], 16) & 0x2:
        return "Private / random MAC"
    return None


class Oui:
    URL = "https://www.wireshark.org/download/automated/data/manuf"

    def __init__(self, path):
        self.path = path
        self.map = {}
        self.load()

    def load(self):
        m, longm = {}, {}
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line or line[0] == "#":
                        continue
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 2 and len(parts[0]) == 8:
                        m[parts[0].lower()] = parts[1].strip()
                        if len(parts) >= 3 and parts[2].strip():
                            longm[parts[0].lower()] = parts[2].strip()
        except OSError:
            pass
        self.map, self.long = m, longm

    def available(self):
        return bool(self.map)

    def vendor(self, mac):
        return self.map.get(norm_mac(mac)[:8], "")

    def vendor_long(self, mac):
        k = norm_mac(mac)[:8]
        return self.long.get(k) or self.map.get(k, "")

    def lookup(self, mac):
        bits = [b for b in (self.vendor(mac), mac_kind(mac)) if b]
        return " · ".join(bits)

    def download(self):
        req = urllib.request.Request(self.URL, headers={"User-Agent": "PorkChopCheck"})
        data = urllib.request.urlopen(req, timeout=30).read()
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, self.path)
        self.load()
        return len(self.map)


# ====================================================================== settings + port log
class Settings:
    DEFAULTS = {"announce": True, "autolog": True, "hostname": "", "iperf_server": "",
                "iperf_port": 5201, "smart_services": False}

    def __init__(self, folder):
        self.path = os.path.join(folder, "settings.json")
        self.data = dict(self.DEFAULTS)
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    def get(self, k):
        return self.data.get(k, self.DEFAULTS.get(k))

    def set(self, k, v):
        self.data[k] = v
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except OSError:
            pass


LOG_FIELDS = ["last_seen", "label", "switch", "port", "vlan", "voice_vlan", "mgmt_ip", "model",
              "poe", "speed", "duplex", "ip", "gateway", "gw_ms", "gw_mac", "dhcp_server",
              "dhcp_servers", "dns", "internet", "time_to_ip", "dot1x", "stp", "dtp",
              "tagged_vlans", "ipv6", "pc_mac", "adapter", "first_seen", "saves"]
HIST_FIELDS = ["time", "source"] + [f for f in LOG_FIELDS
                                    if f not in ("last_seen", "first_seen", "saves")]


# ====================================================================== multicast
# Well-known groups, by address or by range, with the name a network person would use.
MCAST_NAMES = {
    "224.0.0.1": "All hosts", "224.0.0.2": "All routers", "224.0.0.5": "OSPF", "224.0.0.6": "OSPF DR",
    "224.0.0.9": "RIPv2", "224.0.0.10": "EIGRP", "224.0.0.13": "PIM", "224.0.0.18": "VRRP",
    "224.0.0.22": "IGMPv3 reports", "224.0.0.102": "HSRPv2", "224.0.0.251": "mDNS",
    "224.0.0.252": "LLMNR", "224.0.1.1": "NTP", "224.0.1.39": "Cisco RP announce",
    "224.0.1.40": "Cisco RP discovery", "224.0.1.129": "PTP", "224.0.1.130": "PTP",
    "224.0.1.131": "PTP", "224.0.1.132": "PTP", "224.0.0.107": "PTP peer delay",
    "224.0.23.12": "KNX", "239.255.255.250": "SSDP / UPnP", "239.255.255.253": "SLP",
    "224.2.127.254": "SAP announcements",
}
MCAST_RANGES = [("224.0.0.230", "224.0.0.233", "Dante control"), ("239.69.0.0", "239.69.255.255", "Dante / AES67 audio"),
                ("239.255.0.0", "239.255.249.255", "sACN lighting"), ("232.0.0.0", "232.255.255.255", "Source-specific (SSM)")]
MCAST_BPF = "ip multicast or (vlan and ip multicast)"


def mcast_name(group):
    if group in MCAST_NAMES:
        return MCAST_NAMES[group]
    try:
        g = int(ipaddress.IPv4Address(group))
    except ValueError:
        return ""
    for lo, hi, name in MCAST_RANGES:
        if int(ipaddress.IPv4Address(lo)) <= g <= int(ipaddress.IPv4Address(hi)):
            return name
    return ""


def mcast_is_link_local(group):
    """224.0.0.x never leaves the subnet and switches flood it even with IGMP snooping on."""
    return group.startswith("224.0.0.")


def parse_mcast_target(text):
    """"239.1.2.3", "239.1.2.3:5004" or "239.1.2.3 5004" -> (group, port or None); None if it is
    not a multicast group. A space or slash works for the port because the on-screen keyboard
    has no colon."""
    m = re.fullmatch(r"\s*(\d+\.\d+\.\d+\.\d+)(?:\s*[:/ ]\s*(\d{1,5}))?\s*", text or "")
    if not m:
        return None
    try:
        addr = ipaddress.IPv4Address(m.group(1))
    except ValueError:
        return None
    port = int(m.group(2)) if m.group(2) else None
    if not addr.is_multicast or (port is not None and not 0 < port < 65536):
        return None
    return str(addr), port


def mcast_mac(group):
    """The Ethernet address a multicast group is sent to: 01:00:5e plus its low 23 bits."""
    b = socket.inet_aton(group)
    return bytes([0x01, 0x00, 0x5E, b[1] & 0x7F, b[2], b[3]])


def mcast_frame(src_mac, src_ip, group, proto, payload, ttl=1, dst_ip=None, vlan=None):
    """An Ethernet + IPv4 frame to a multicast group. Used by the tests and the demo."""
    dst_ip = dst_ip or group
    ra = b"\x94\x04\x00\x00" if proto == 2 else b""          # IGMP carries Router Alert
    ihl = 5 + len(ra) // 4
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0xC0 if proto == 2 else 0, 20 + len(ra) + len(payload),
                      0, 0, ttl, proto, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip)) + ra
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return mcast_mac(dst_ip) + bytes.fromhex(norm_mac(src_mac).replace(":", "")) + tag + b"\x08\x00" + hdr + payload


def igmp_payload(kind, group="0.0.0.0", max_resp=100, version=2, qqic=125):
    """kind: query | report | leave | report3 | leave3."""
    g = socket.inet_aton(group)
    if kind == "query":
        body = struct.pack("!BBH4s", 0x11, 0 if version == 1 else max_resp, 0, g)
        if version == 3:
            body += struct.pack("!BBH", 2, qqic, 0)
    elif kind == "report":
        body = struct.pack("!BBH4s", 0x12 if version == 1 else 0x16, 0, 0, g)
    elif kind == "leave":
        body = struct.pack("!BBH4s", 0x17, 0, 0, g)
    else:                                   # v3 report with one record: join = TO_EX {}, leave = TO_IN {}
        body = struct.pack("!BBHHHBBH4s", 0x22, 0, 0, 0, 1, 4 if kind == "report3" else 3, 0, 0, g)
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def parse_mcast(raw):
    """One frame -> {"src", "group", "proto", "len", "vlan", "port", "igmp"} or None if it is not
    IPv4 multicast. "igmp" is a list of (what, group, detail) with what in query/join/leave."""
    if len(raw) < 34:
        return None
    off, vlan, et = 14, None, u16(raw, 12)
    if et == 0x8100 and len(raw) >= 38:
        vlan, et, off = u16(raw, 14) & 0x0FFF, u16(raw, 16), 18
    if et != 0x0800 or raw[off] >> 4 != 4:
        return None
    ihl = (raw[off] & 0x0F) * 4
    if ihl < 20 or len(raw) < off + ihl or raw[off + 16] & 0xF0 != 0xE0:
        return None
    proto = raw[off + 9]
    out = {"src": socket.inet_ntoa(raw[off + 12:off + 16]), "group": socket.inet_ntoa(raw[off + 16:off + 20]),
           "proto": proto, "len": len(raw), "vlan": vlan, "port": None, "igmp": []}
    body = raw[off + ihl:off + max(ihl, u16(raw, off + 2))]
    if proto == 17 and len(body) >= 4:
        out["port"] = u16(body, 2)
    elif proto == 2 and len(body) >= 8:
        out["igmp"] = parse_igmp(body)
    return out


def igmp_code(v):
    """IGMPv3 packs times of 128 and up as a small float: 1eeemmmm -> (mmmm | 0x10) << (eee + 3)."""
    return v if v < 128 else ((v & 0x0F) | 0x10) << (((v >> 4) & 0x07) + 3)


def mcast_join_socket(group, src):
    """Join a group the ordinary way, through the operating system, on the interface that owns
    `src`. The OS sends the IGMP reports and answers queries for as long as the socket is open;
    closing it leaves the group."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((src, 0))                 # Windows refuses a membership on an unbound socket
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     socket.inet_aton(group) + socket.inet_aton(src))
    except OSError:
        s.close()
        raise
    return s


def parse_igmp(b):
    """IGMP message -> [(what, group, detail)]."""
    t, grp = b[0], socket.inet_ntoa(b[4:8])
    if t == 0x11:
        if len(b) >= 12:
            ver, detail = 3, {"qqic": igmp_code(b[9]), "max_resp": igmp_code(b[1]) / 10}
        elif b[1] == 0:
            ver, detail = 1, {"max_resp": 10.0}
        else:
            ver, detail = 2, {"max_resp": b[1] / 10}
        return [("query", grp, dict(detail, version=ver, general=grp == "0.0.0.0"))]
    if t in (0x12, 0x16):
        return [("join", grp, {"version": 1 if t == 0x12 else 2})]
    if t == 0x17:
        return [("leave", grp, {"version": 2})]
    if t == 0x22:
        out, off = [], 8
        for _ in range(min(u16(b, 6), 64)):
            if len(b) < off + 8:
                break
            rtype, aux, nsrc = b[off], b[off + 1], u16(b, off + 2)
            g = socket.inet_ntoa(b[off + 4:off + 8])
            if rtype in (2, 4) or (rtype in (1, 5) and nsrc):
                out.append(("join", g, {"version": 3}))
            elif rtype == 6 or (rtype == 3 and not nsrc):
                out.append(("leave", g, {"version": 3}))
            elif rtype == 3:
                out.append(("join", g, {"version": 3}))
            off += 8 + 4 * nsrc + 4 * aux
        return out
    return []


class McastTracker:
    """Counts what multicast crosses the port and remembers who is asking about it."""

    MAX_GROUPS, MAX_SOURCES, MAX_MEMBERS = 2000, 16, 32

    def __init__(self, now=None):
        self.lock = threading.Lock()
        self.reset(now)

    def reset(self, now=None):
        with self.lock:
            self.started = time.time() if now is None else now
            self.groups = {}             # group -> counters
            self.queriers = {}           # ip -> what its queries said
            self.frames = 0

    def feed(self, raw, ts):
        p = parse_mcast(raw)
        if not p:
            return
        with self.lock:
            self.frames += 1
            for what, grp, det in p["igmp"]:
                if what == "query":
                    q = self.queriers.setdefault(p["src"], {"ip": p["src"], "general": 0, "specific": 0,
                                                            "first": ts, "times": []})
                    q.update(version=det["version"], max_resp=det["max_resp"], last=ts)
                    if det.get("qqic") is not None:
                        q["qqic"] = det["qqic"]
                    if det["general"]:
                        q["general"] += 1
                        q["times"] = (q["times"] + [ts])[-4:]
                    else:
                        q["specific"] += 1
                else:
                    g = self._group(grp, ts)
                    if g is not None:
                        if what == "join":
                            if len(g["members"]) < self.MAX_MEMBERS or p["src"] in g["members"]:
                                g["members"][p["src"]] = ts
                        else:
                            g["members"].pop(p["src"], None)
                            g["left"] = ts
            if p["proto"] == 2:
                return                   # IGMP is bookkeeping, not traffic for the group it is sent to
            g = self._group(p["group"], ts)
            if g is None:
                return
            g["pkts"] += 1
            g["bytes"] += p["len"]
            g["last"] = ts
            if p["port"]:
                g["port"] = p["port"]
            if p["vlan"] is not None:
                g["vlan"] = p["vlan"]
            if p["src"] in g["sources"] or len(g["sources"]) < self.MAX_SOURCES:
                g["sources"][p["src"]] = g["sources"].get(p["src"], 0) + 1

    def _group(self, grp, ts):
        g = self.groups.get(grp)
        if g is None:
            if len(self.groups) >= self.MAX_GROUPS:
                return None
            g = self.groups[grp] = {"group": grp, "pkts": 0, "bytes": 0, "first": ts, "last": None,
                                    "sources": {}, "members": {}, "port": None, "vlan": None, "left": None,
                                    "pps": 0.0, "bps": 0.0, "_at": ts, "_pkts": 0, "_bytes": 0}
        return g

    def tick(self, now):
        """Work out each group's rate since the last tick. Call about once a second."""
        with self.lock:
            for g in self.groups.values():
                dt = now - g["_at"]
                if dt >= 0.5:
                    g["pps"] = (g["pkts"] - g["_pkts"]) / dt
                    g["bps"] = (g["bytes"] - g["_bytes"]) * 8 / dt
                    g["_at"], g["_pkts"], g["_bytes"] = now, g["pkts"], g["bytes"]

    def snapshot(self, now):
        with self.lock:
            groups = []
            for g in self.groups.values():
                row = {k: v for k, v in g.items() if not k.startswith("_")}
                row["sources"] = [ip for ip, _ in sorted(g["sources"].items(), key=lambda kv: -kv[1])]
                row["members"] = sorted(g["members"])
                row["name"] = mcast_name(g["group"])
                groups.append(row)
            groups.sort(key=lambda r: (-r["bps"], -r["pkts"], socket.inet_aton(r["group"])))
            queriers = []
            for q in self.queriers.values():
                t = q["times"]
                gaps = [b - a for a, b in zip(t, t[1:])]
                queriers.append(dict({k: v for k, v in q.items() if k != "times"},
                                     interval=sum(gaps) / len(gaps) if gaps else None))
            # The lowest address wins the querier election.
            queriers.sort(key=lambda q: socket.inet_aton(q["ip"]))
            return {"groups": groups, "queriers": queriers, "elapsed": now - self.started,
                    "frames": self.frames, "bps": sum(g["bps"] for g in groups)}


def querier_verdict(snap, probed=False):
    """(text, level, note) for the IGMP querier line. level: ok | wait | warn."""
    qs = [q for q in snap["queriers"] if q["general"] or q["specific"]]
    el = snap["elapsed"]
    if qs:
        q = qs[0]
        every = q.get("interval") or q.get("qqic")
        note = f"IGMPv{q['version']}" + (f" · asks every {every:.0f} s" if every else "")
        if len(qs) > 1:
            note += f" · {len(qs)} queriers seen, lowest address wins"
        return (f"Querier: {q['ip']}", "ok", note)
    if el < 130 and not (probed and el > 5):
        return ("No querier heard yet", "wait",
                f"listening {el:.0f} s — a querier normally asks every 125 s. Tap Querier to prompt one.")
    return ("No IGMP querier found", "warn",
            "With IGMP snooping on and no querier, streams, AirPlay and mDNS work for a few minutes and then stop.")


class PcapWriter:
    """A classic .pcap file (libpcap 2.4, Ethernet, microsecond stamps) that Wireshark opens.
    Written here and not with scapy so it works the same on every platform."""

    SNAPLEN = 262144

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.frames = 0
        self.bytes = 24
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, self.SNAPLEN, 1))

    def add(self, raw, ts):
        sec = int(ts)
        cap = raw[:self.SNAPLEN]
        with self.lock:
            if self.f is None:
                return
            self.f.write(struct.pack("<IIII", sec & 0xFFFFFFFF, int((ts - sec) * 1_000_000),
                                     len(cap), len(raw)) + cap)
            self.frames += 1
            self.bytes += 16 + len(cap)

    def close(self):
        with self.lock:
            if self.f is not None:
                self.f.close()
                self.f = None


def read_pcap(path):
    """[(timestamp, frame bytes)] from a file PcapWriter made."""
    out = []
    with open(path, "rb") as f:
        magic, _maj, _min, _tz, _sig, _snap, link = struct.unpack("<IHHiIII", f.read(24))
        if magic != 0xA1B2C3D4 or link != 1:
            raise ValueError("not an Ethernet .pcap file")
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return out
            sec, usec, caplen, _orig = struct.unpack("<IIII", hdr)
            out.append((sec + usec / 1_000_000, f.read(caplen)))


def capture_name(now, tag=""):
    """capture-20261010-015500-SW01-Gi1_0_14.pcap; the tag is cut down to safe characters."""
    tag = re.sub(r"[^A-Za-z0-9.]+", "_", tag or "").strip("_.")[:40]
    return time.strftime("capture-%Y%m%d-%H%M%S", time.localtime(now)) + (f"-{tag}" if tag else "") + ".pcap"


def list_captures(folder, limit=20):
    """[(name, size, mtime)] newest first."""
    rows = []
    try:
        for n in os.listdir(folder):
            if n.endswith(".pcap"):
                st = os.stat(os.path.join(folder, n))
                rows.append((n, st.st_size, st.st_mtime))
    except OSError:
        pass
    return sorted(rows, key=lambda r: r[2], reverse=True)[:limit]


def fmt_bytes(n):
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("kB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


def csv_safe(row):
    """A copy of a row that is safe to open in Excel or LibreOffice. Names, labels and models
    come from whatever is on the network, and a cell that starts with = + - or @ is run as a
    formula. A leading apostrophe makes the spreadsheet treat it as plain text."""
    return {k: ("'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v) for k, v in row.items()}


class PortLog:
    """ports.csv = one row per switch+port (latest result). history.csv = every save.
    ports.json is what gets read back; the CSV files are only ever written."""

    def __init__(self, folder):
        self.folder = folder
        self.json_path = os.path.join(folder, "ports.json")
        self.csv_path = os.path.join(folder, "ports.csv")
        self.hist_path = os.path.join(folder, "history.csv")
        self.lock = threading.Lock()
        try:
            with open(self.json_path, encoding="utf-8") as f:
                self.ports = json.load(f)
        except (OSError, ValueError):
            self.ports = {}

    @staticmethod
    def key(rec):
        if rec.get("switch") and rec.get("port"):
            return f"{rec['switch']}|{rec['port']}".lower()
        return None

    def label_for(self, rec):
        with self.lock:
            return self.ports.get(self.key(rec) or "", {}).get("label", "")

    def upsert(self, rec, manual=False):
        """Returns (is_new_port, error_or_None)."""
        with self.lock:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            rec = {k: ("" if v is None else v) for k, v in rec.items()}
            rec["last_seen"] = now
            k, new, err = self.key(rec), False, None
            if k:
                old = self.ports.get(k, {})
                new = not old
                rec["first_seen"] = old.get("first_seen", now)
                if not rec.get("label"):
                    rec["label"] = old.get("label", "")
                rec["saves"] = int(old.get("saves", 0) or 0) + (1 if manual else 0)
                self.ports[k] = rec
                err = self._write_json() or self._write_csv()
            if manual or new:
                err = self._append_hist(rec, "manual" if manual else "auto") or err
            return new, err

    def rows(self):
        with self.lock:
            return sorted(self.ports.values(), key=lambda r: r.get("last_seen", ""), reverse=True)

    def _write_json(self):
        try:
            tmp = self.json_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.ports, f, indent=1)
            os.replace(tmp, self.json_path)
        except OSError as e:
            return f"Couldn't save log: {e}"
        return None

    def _write_csv(self):
        rows = sorted(self.ports.values(), key=lambda r: (str(r.get("switch", "")).lower(),
                                                          _port_sort(r.get("port", ""))))
        try:
            tmp = self.csv_path + ".tmp"
            with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=LOG_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerows(csv_safe(r) for r in rows)
            os.replace(tmp, self.csv_path)
        except PermissionError:
            return "ports.csv is open (Excel?) — will update next time"
        except OSError as e:
            return f"Couldn't write ports.csv: {e}"
        return None

    def _append_hist(self, rec, source):
        try:
            new_file = not os.path.exists(self.hist_path)
            with open(self.hist_path, "a", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=HIST_FIELDS, extrasaction="ignore")
                if new_file:
                    w.writeheader()
                w.writerow(csv_safe(dict(rec, time=rec.get("last_seen"), source=source)))
        except PermissionError:
            return "history.csv is open (Excel?)"
        except OSError as e:
            return f"Couldn't write history.csv: {e}"
        return None


def _port_sort(port):
    """Gi1/0/10 sorts after Gi1/0/9."""
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", str(port))]


# ====================================================================== Linux platform layer
# Everything Windows gets from PowerShell, Linux gets from /sys, `ip -j`, NetworkManager and ethtool.
SYS_NET = "/sys/class/net"


def _json_cmd(cmd, timeout=5):
    _, out, _ = run(cmd, timeout)
    try:
        return json.loads(out) if out.strip() else []
    except ValueError:
        return []


def linux_l3_iface(n):
    """Bridge / bond members carry no IP: the address lives on their master (br0, bond0...)."""
    m = os.path.join(SYS_NET, n, "master")
    return os.path.basename(os.path.realpath(m)) if os.path.exists(m) else n


def linux_adapters():
    """Physical wired NICs only: no loopback, Wi-Fi, bridges, veth, docker or VPN interfaces."""
    out = []
    try:
        names = sorted(os.listdir(SYS_NET))
    except OSError:
        return out
    for n in names:
        p = os.path.join(SYS_NET, n)
        if _read(p + "/type") != "1" or not os.path.exists(p + "/device"):
            continue
        if os.path.exists(p + "/wireless") or os.path.exists(p + "/phy80211"):
            continue
        desc = linux_describe(n)
        l3 = linux_l3_iface(n)
        if l3 != n:
            desc = f"{desc} · IP on {l3}"
        out.append({"name": n, "desc": desc, "mac": norm_mac(_read(p + "/address", "")),
                    "up": _read(p + "/carrier") == "1"})
    return out


def linux_describe(n):
    p = os.path.join(SYS_NET, n)
    props = {}
    if shutil.which("udevadm"):
        _, out, _ = run(["udevadm", "info", "-q", "property", "-p", p], 5)
        props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    desc = " ".join(x for x in (props.get("ID_VENDOR_FROM_DATABASE", ""),
                                props.get("ID_MODEL_FROM_DATABASE", "")) if x)
    if not desc:
        drv = p + "/device/driver"
        desc = os.path.basename(os.path.realpath(drv)) if os.path.exists(drv) else n
    if "/usb" in os.path.realpath(p + "/device"):
        desc += " (USB)"
    return desc[:80]


def linux_link(n):
    """(link_up, speed_mbps). carrier is the real cable state; psutil's isup is only admin-up."""
    p = os.path.join(SYS_NET, n)
    up = _read(p + "/carrier") == "1"
    try:
        speed = int(_read(p + "/speed", "0") or 0)
    except ValueError:
        speed = 0
    return up, max(speed, 0) if up else 0


def parse_nmcli(text):
    """Parse `nmcli -t -f GENERAL.CONNECTION,IP4.GATEWAY,IP4.DNS,IP4.DOMAIN,DHCP4 device show IF`."""
    d = {"dns": [], "domain": [], "dhcp": {}}
    for line in text.splitlines():
        key, sep, val = line.partition(":")
        if not sep:
            continue
        val = val.replace("\\:", ":").replace("\\\\", "\\").strip()
        k = key.split("[")[0]
        if k == "GENERAL.CONNECTION":
            d["connection"] = val
        elif k == "IP4.GATEWAY" and val and val != "--":
            d["gateway"] = val
        elif k == "IP4.DNS" and val:
            d["dns"].append(val)
        elif k == "IP4.DOMAIN" and val:
            d["domain"].append(val)
        elif k == "DHCP4.OPTION" and "=" in val:
            ok, _, ov = val.partition("=")
            d["dhcp"][ok.strip()] = ov.strip()
    return d


def parse_ip_gateways(js):
    return [r["gateway"] for r in as_list(js) if isinstance(r, dict) and is_ipv4(r.get("gateway"))]


def parse_ip_neigh(js):
    rows = []
    for r in as_list(js):
        if not isinstance(r, dict):
            continue
        ip, mac = r.get("dst"), r.get("lladdr")
        state = (r.get("state") or [""])[0]
        if is_ipv4(ip) and mac and state not in ("FAILED", "INCOMPLETE"):
            rows.append((ip, norm_mac(mac), state.title()))
    return rows


def parse_ip6(js):
    out = []
    for link in as_list(js):
        for a in (link.get("addr_info", []) if isinstance(link, dict) else []):
            if a.get("family") != "inet6" or a.get("temporary"):
                continue
            if a.get("scope") == "link":
                origin = "WellKnown"
            elif a.get("mngtmpaddr") or a.get("dynamic"):
                origin = "RouterAdvertisement"
            else:
                origin = "Manual"
            out.append({"IPAddress": a.get("local"), "Origin": origin})
    return out


def parse_ethtool_bcast(text):
    for line in text.splitlines():
        name, _, v = line.strip().partition(":")
        if name.strip() in ("rx_broadcast", "rx_bcast", "rx_broadcast_packets", "rx_bcast_packets",
                            "rx_broadcast_pkts"):
            try:
                return int(v.strip())
            except ValueError:
                return None
    return None


def parse_resolvectl(text):
    _, _, rest = text.partition("):")
    return [x for x in rest.split() if is_ipv4(x)]


def linux_dns(name):
    if shutil.which("resolvectl"):
        _, out, _ = run(["resolvectl", "dns", name], 5)
        dns = parse_resolvectl(out)
        if dns:
            return dns
    dns = re.findall(r"^\s*nameserver\s+(\S+)", _read("/etc/resolv.conf", ""), re.M)
    return [x for x in dns if is_ipv4(x) and not x.startswith("127.")]


def fmt_epoch(ts):
    s = time.strftime("%b %d %I:%M %p", time.localtime(int(ts)))
    return re.sub(r"\b0(\d)", r"\1", s)


def linux_detail(name):
    """Same keys the Windows PowerShell query returns, so the UI doesn't care which OS it's on."""
    p = os.path.join(SYS_NET, name)
    l3 = linux_l3_iface(name)                 # e.g. br0 when the NIC is bridged for VMs
    d = {"FullDuplex": {"full": True, "half": False}.get(_read(p + "/duplex")),
         "Mac": _read(p + "/address"), "L3Iface": l3}
    d["Gateway"] = parse_ip_gateways(_json_cmd(["ip", "-j", "-4", "route", "show", "default", "dev", l3]))
    nm = {}
    if shutil.which("nmcli"):
        _, out, _ = run(["nmcli", "-t", "-f", "GENERAL.CONNECTION,IP4.GATEWAY,IP4.DNS,IP4.DOMAIN,DHCP4",
                         "device", "show", l3], 5)
        nm = parse_nmcli(out)
    dhcp = nm.get("dhcp", {})
    if not d["Gateway"] and nm.get("gateway"):
        d["Gateway"] = [nm["gateway"]]
    d["Dns"] = nm.get("dns") or linux_dns(l3)
    d["Domain"] = (nm.get("domain") or [""])[0]
    d["DhcpServer"] = dhcp.get("dhcp_server_identifier")
    if str(dhcp.get("expiry", "")).isdigit():
        d["LeaseExpires"] = fmt_epoch(dhcp["expiry"])
    if dhcp:
        d["DhcpEnabled"] = True
    elif nm.get("connection") and nm["connection"] != "--":
        _, m, _ = run(["nmcli", "-g", "ipv4.method", "connection", "show", nm["connection"]], 5)
        d["DhcpEnabled"] = {"auto": True, "manual": False}.get(m.strip())
    gw = first_v4(d["Gateway"])
    if gw:
        rows = parse_ip_neigh(_json_cmd(["ip", "-j", "-4", "neigh", "show", gw, "dev", l3]))
        if rows:
            d["GwMac"] = rows[0][1]
    try:
        d["RxMcast"] = int(_read(p + "/statistics/multicast", "0") or 0)
    except ValueError:
        pass
    if shutil.which("ethtool"):
        _, out, _ = run(["ethtool", "-S", name], 5)
        b = parse_ethtool_bcast(out)
        if b is not None:
            d["RxBcast"] = b
    d["V6"] = parse_ip6(_json_cmd(["ip", "-j", "-6", "addr", "show", "dev", l3]))
    return d


def linux_neigh(name):
    return parse_ip_neigh(_json_cmd(["ip", "-j", "-4", "neigh", "show", "dev", linux_l3_iface(name)]))


def linux_set_link(name, up):
    """Bring an interface up or down from this process. It has to be done here and not by
    running `ip link set`: the link capability belongs to this process and is deliberately not
    passed on to the programs it starts."""
    import fcntl
    ifname = name.encode()[:15]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            flags = linux_link_flags(name, s)
            flags = flags | IFF_UP if up else flags & ~IFF_UP
            fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", ifname, flags, b""))
        return True
    except OSError:
        return False


SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1


def linux_link_flags(name, sock=None):
    """The interface's IFF_* flags. Raises OSError if there is no such interface."""
    import fcntl
    s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH14s", name.encode()[:15], 0, b""))
        return struct.unpack("16sH14s", ifr)[1]
    finally:
        if not sock:
            s.close()


def linux_renew(name):
    """Drop and re-request the DHCP lease. Returns (ok, error_text)."""
    name = linux_l3_iface(name)
    if shutil.which("nmcli"):
        run(["nmcli", "device", "disconnect", name], 20)
        code, out, err = run(["nmcli", "device", "connect", name], 60)
        return code == 0, (err or out).strip()[:80]
    if shutil.which("dhclient"):
        run(["dhclient", "-r", name], 20)
        code, out, err = run(["dhclient", "-1", name], 60)
        return code == 0, (err or out).strip()[:80]
    if shutil.which("networkctl"):
        code, out, err = run(["networkctl", "renew", name], 20)
        return code == 0, (err or out).strip()[:80]
    return False, "no DHCP client tool (nmcli / dhclient / networkctl)"
