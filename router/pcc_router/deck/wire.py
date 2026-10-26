"""What the wire says: one listener feeding the wire report (Watchdog), Port details (Overview),
the mDNS browser and the multicast page. The decoding is PorkChopCheck's (pc_net.py, unchanged).

It hears broadcast and multicast, and any unicast the switch floods to this port (frames for other
machines). A separate ICMP socket catches redirects and "fragmentation needed" sent to the probe.
"""
import ctypes
import re
import socket
import struct
import subprocess
import threading
import time

import pc_net as N
from appbase import App

SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4
FLOOD_PAUSE = 5000           # frames a second for other machines: a mirror port or a bad flood; stop for 30 s
HSRP = re.compile(r"^00:00:0c:07:ac:([0-9a-f]{2})$")
HSRP2 = re.compile(r"^00:00:0c:9f:f([0-9a-f]):([0-9a-f]{2})$")
VRRP = re.compile(r"^00:00:5e:00:01:([0-9a-f]{2})$")
GLBP = re.compile(r"^00:07:b4:00:")


def compile_bpf(iface, expr):
    """tcpdump turns the filter into BPF instructions for the kernel."""
    out = subprocess.run(["tcpdump", "-i", iface, "-dd", expr], capture_output=True, text=True, timeout=10).stdout
    ins = re.findall(r"\{\s*(0x[0-9a-f]+),\s*(\d+),\s*(\d+),\s*(0x[0-9a-f]+)\s*\}", out)
    if not ins:
        raise OSError(f"tcpdump couldn't compile '{expr}'")
    return [(int(a, 16), int(b), int(c), int(d, 16)) for a, b, c, d in ins]


def gateway_kind(mac):
    if not mac:
        return None
    m = mac.lower()
    if HSRP.match(m):
        return f"HSRP v1 virtual MAC (group {int(HSRP.match(m).group(1), 16)})"
    if HSRP2.match(m):
        return "HSRP v2 virtual MAC"
    if VRRP.match(m):
        return f"VRRP virtual MAC (group {int(VRRP.match(m).group(1), 16)})"
    if GLBP.match(m):
        return "GLBP virtual MAC"
    return None


class Wire(App):
    name = "wire"
    SETTINGS = {"on": True}

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.w = N.new_wire()
        self.ww = None
        self.mdns = N.MdnsBrowser()
        self.mcast = N.McastTracker()
        self.sock = self.icmp = None
        self.error = None
        self.my = None
        self.cdp = self.lldp = self.dot1x = None
        self.offers = {}          # DHCP server -> its latest offer, with the phone and boot options
        self.nic_base = None
        self.flood_count, self.flood_sec = 0, 0
        self.paused_until = 0

    def iface(self):
        return self.p.watch.iface

    # ---------- listening ----------
    def open(self):
        iface = self.iface()
        self.my = N.norm_mac(open(f"/sys/class/net/{iface}/address").read().strip())
        prog = compile_bpf(iface, N.wire_bpf(self.my))
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        buf = ctypes.create_string_buffer(b"".join(struct.pack("HBBI", *i) for i in prog))
        s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, struct.pack("HL", len(prog), ctypes.addressof(buf)))
        s.bind((iface, 0))
        self._bpf = buf
        s.settimeout(1)
        self.ww = N.WireWatch(N.linux_local_macs(iface) | {self.my})
        return s

    def start(self):
        threading.Thread(target=self.icmp_loop, daemon=True).start()
        threading.Thread(target=self.tick_loop, daemon=True).start()
        while True:
            if not self.conf["on"] or time.time() < self.paused_until:
                if self.sock:
                    self.sock.close()
                    self.sock = None
                time.sleep(2)
                continue
            if not self.sock:
                try:
                    self.sock = self.open()
                    self.error = None
                    self.w["paused"] = False
                except OSError as e:
                    self.error = f"can't listen: {e.strerror or e}"
                    time.sleep(10)
                    continue
            try:
                raw, addr = self.sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                self.sock = None
                continue
            if addr[2] == PACKET_OUTGOING:
                continue
            try:
                self.on_frame(raw)
            except Exception:  # a frame that won't decode is just skipped
                pass

    def on_frame(self, raw):
        now = time.time()
        if not raw[0] & 1:                      # unicast for someone else: the switch is flooding
            sec = int(now)
            if sec != self.flood_sec:
                self.flood_sec, self.flood_count = sec, 0
            self.flood_count += 1
            if self.flood_count > FLOOD_PAUSE:
                self.w["paused"] = True
                self.paused_until = now + 30
                return
        self.ww.feed(raw)
        if raw[0] & 1:
            self.mcast.feed(raw, now)
        for kind, info in N.classify(raw):
            self.handle(kind, info, now)

    def handle(self, kind, info, now):
        src, w = info.get("src"), self.w
        if src == self.my:
            return
        if kind in ("LACP", "UDLD", "VTP", "PAGP", "LOOP"):
            w[kind.lower()] = dict(info, ts=now)
        elif kind == "PAUSE":
            w["pause_frames"] += 1
            w["pause_at"] = now
        elif kind == "RA":
            if src and src not in w["routers"] and len(w["routers"]) < 16:
                w["routers"][src] = {"ts": now, "prefix": (info.get("prefixes") or [""])[0]}
        elif kind == "CDP":
            self.cdp = dict(info, ts=now)
        elif kind == "LLDP":
            self.lldp = dict(info, ts=now)
        elif kind == "EAPOL":
            if info.get("code") in ("Request", "Success", "Failure"):
                self.dot1x = dict(info, ts=now)
        elif kind == "DHCP" and info.get("op") == 2 and info.get("msg") in ("OFFER", "ACK"):
            srv = info.get("server") or info.get("ip_src")
            if srv and (srv in self.offers or len(self.offers) < 16):
                self.offers[srv] = dict(info, ts=now)
        elif kind == "MDNS":
            self.mdns.ingest(info, info.get("ip_src"), multicast=info.get("ip_dst") in ("224.0.0.251", "ff02::fb"))

    def icmp_loop(self):
        while True:
            try:
                if not self.icmp:
                    self.icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    self.icmp.settimeout(2)
                data, _ = self.icmp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                self.icmp = None
                time.sleep(10)
                continue
            if len(data) < 28:
                continue
            ihl = (data[0] & 0x0F) * 4
            for _, info in N.parse_icmp_notice(data, ihl, socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])):
                self.w["icmp"] = (self.w["icmp"] + [dict(info, ts=time.time())])[-12:]

    def tick_loop(self):
        last_nic = 0
        while True:
            time.sleep(1)
            now = time.time()
            if self.ww:
                self.ww.tick(now)
            self.mcast.tick(now)
            if now - last_nic > 30:
                last_nic = now
                try:
                    nic = N.linux_nic_report(self.iface())
                except Exception:
                    nic = None
                if nic:
                    self.w["nic"] = nic
                    pause, errors = nic.get("stats") or ({}, {})
                    stats = dict(pause, **errors)          # ethtool -S: the pause and error counters
                    if self.nic_base is None:
                        self.nic_base = stats
                    self.w["rises"] = N.counter_rises(self.nic_base, stats)

    # ---------- what it found ----------
    def wire_now(self):
        w = dict(self.w)
        w["talk"] = self.ww.snapshot() if self.ww else None
        wd = self.p.watch
        if wd:
            with wd.lock:
                w["conflicts"] = [{"ip": c["ip"], "macs": c["macs"], "ts": c["t"]} for c in list(wd.conflicts.values())[-12:]]
        return w

    def vendor(self, mac):
        hs = self.p.apps.get("hosts")
        try:
            return (hs.vendor(mac) if hs and mac else "") or ""
        except Exception:
            return ""

    def findings(self):
        return [{"section": s, "level": lv, "text": t} for s, lv, t in N.wire_findings(self.wire_now(), self.vendor, True)]

    def port_details(self):
        now = time.time()
        cdp, lldp = self.cdp, self.lldp
        nb = cdp if cdp and now - cdp["ts"] < 300 else lldp if lldp and now - lldp["ts"] < 300 else None
        gw_mac = self.p.watch.gw_mac if self.p.watch else None
        lease = (self.p.net.get("dhcp") or {}).get("server")
        offer = self.offers.get(lease) or next(iter(sorted(self.offers.values(), key=lambda o: -o["ts"])), None)
        d1 = self.dot1x if self.dot1x and now - self.dot1x["ts"] < 600 else None
        return {
            "via": "CDP" if nb is cdp and cdp else "LLDP" if nb else None,
            "data_vlan": nb and nb.get("vlan"), "voice_vlan": nb and nb.get("voice_vlan"), "poe": nb and nb.get("poe"),
            "duplex": nb and nb.get("duplex"), "vtp": nb and nb.get("vtp"),
            "dot1x": {"code": d1["code"], "eap": d1.get("eap_type"), "ago": round(now - d1["ts"])} if d1 else None,
            "gateway": {"mac": gw_mac, "kind": gateway_kind(gw_mac), "vendor": self.vendor(gw_mac)} if gw_mac else None,
            "dhcp": {k: offer.get(k) for k in ("server", "tftp_ips", "tftp_name", "opt43", "ntp", "domain", "sname")} if offer else None,
            "dtp": self.p.watch.dtp if self.p.watch else None,
        }

    def status(self):
        return None

    def get(self, sub, arg, q, user):
        f = self.findings()
        bad = sum(1 for x in f if x["level"] in ("warn", "bad"))
        return {"on": self.conf["on"], "listening": bool(self.sock), "error": self.error, "paused": self.w.get("paused"),
                "findings": f, "headline": N.wire_headline([(x["section"], x["level"], x["text"]) for x in f]), "issues": bad,
                "port": self.port_details(), "since": self.w["since"], "now": time.time()}

    def post(self, action, body, user):
        if action == "restart":
            self.w = N.new_wire()
            self.nic_base = None
            if self.ww:
                self.ww = N.WireWatch(self.ww.local)
            return {}
        return super().post(action, body, user)


class Mdns(App):
    """The mDNS browser: services announced on the LAN, by type."""
    name = "mdns"

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.busy = False

    def browser(self):
        return self.p.apps["wire"].mdns

    def start(self):
        time.sleep(40)  # after a boot: let DHCP settle
        while True:
            if self.p.net.get("ip"):
                self.scan()
            time.sleep(600)

    def scan(self):
        if self.busy:
            return
        self.busy = True
        try:
            self.browser().scan(self.p.net.get("ip"))
        finally:
            self.busy = False

    def get(self, sub, arg, q, user):
        s = self.browser().snapshot()
        by_type = {}
        for (label, stype), e in s["inst"].items():
            host = e.get("host", "")
            ips = sorted(s["hosts"].get(host, ()), key=lambda ip: (":" in ip, ip))
            by_type.setdefault(stype, []).append({"name": label, "host": host.replace(".local", ""), "ips": ips, "port": e.get("port"),
                                                  "txt": [t for t in (e.get("txt") or [])][:12]})
        types = [{"type": t, "friendly": N.FRIENDLY.get(t, t.replace(".local", "")), "items": sorted(v, key=lambda x: x["name"].lower())}
                 for t, v in by_type.items()]
        types.sort(key=lambda x: x["friendly"].lower())
        empty = sorted(t.replace(".local", "") for t in s["types"] if t not in by_type and t.endswith(".local"))
        return {"types": types, "empty": empty, "responders": len(s["responders"]), "multicast_seen": s["multicast_seen"],
                "running": s["running"] or self.busy, "last_scan": s["last_scan"], "error": s["error"], "now": time.time()}

    def post(self, action, body, user):
        if action == "scan":
            if not self.p.net.get("ip"):
                raise ValueError("The probe has no address")
            threading.Thread(target=self.scan, daemon=True).start()
            return {}
        if action == "reset":
            self.browser().reset()
            return {}
        return super().post(action, body, user)


class Multicast(App):
    """Multicast on this port: groups and their traffic, IGMP queriers, and a join test."""
    name = "mcast"
    PROBE_GROUP = "239.192.137.251"      # joined for a moment to make a querier speak up (PorkChopCheck's)

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.join = None
        self.sock = None
        self.probed = None

    def tracker(self):
        return self.p.apps["wire"].mcast

    def get(self, sub, arg, q, user):
        now = time.time()
        snap = self.tracker().snapshot(now)
        qtext, level, note = N.querier_verdict(snap, probed=bool(self.probed) and now - self.probed > 3)
        jg = None
        if self.join:
            g = next((x for x in snap["groups"] if x["group"] == self.join["group"]), None)
            jg = dict(self.join, pkts=g["pkts"] if g else 0, bps=g["bps"] if g else 0, sources=g["sources"] if g else [])
        return {"groups": snap["groups"][:200], "queriers": snap["queriers"], "elapsed": snap["elapsed"], "bps": snap["bps"],
                "querier": {"text": qtext, "level": level, "note": note}, "join": jg, "now": now}

    def leave(self):
        s, self.sock = self.sock, None
        if s:
            try:
                s.close()
            except OSError:
                pass
        self.join = None

    def post(self, action, body, user):
        src = self.p.net.get("ip")
        if action in ("join", "probe") and not src:
            raise ValueError("The probe has no address")
        if action == "join":
            t = N.parse_mcast_target(str(body.get("group") or ""))
            if not t:
                raise ValueError("Not a multicast group: try something like 239.1.2.3")
            self.leave()
            try:
                self.sock = N.mcast_join_socket(t[0], src)
            except OSError as e:
                raise ValueError(f"Couldn't join {t[0]}: {e}") from None
            self.join = {"group": t[0], "port": t[1], "since": time.time()}
            return {}
        if action == "leave":
            self.leave()
            return {}
        if action == "probe":
            def work():
                try:
                    s = N.mcast_join_socket(self.PROBE_GROUP, src)
                    time.sleep(1.5)
                    s.close()
                    self.probed = time.time()
                except OSError:
                    pass
            threading.Thread(target=work, daemon=True).start()
            return {}
        if action == "reset":
            self.tracker().reset()
            return {}
        return super().post(action, body, user)
