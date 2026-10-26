"""Host scan: who is on this subnet.

A sweep sends one small UDP packet to every address (that makes the kernel ARP for it), then
reads the neighbor table: every address that answered ARP is a host, even with its firewall up.
For each host: the maker from its MAC (IEEE lists in /usr/share/ieee-data), names from reverse
DNS, NetBIOS (Windows PCs) and mDNS, and a few open TCP ports. Hosts are remembered by MAC with
first and last seen, so new machines stand out.
"""
import csv
import ipaddress
import json
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from appbase import App, load_json, save_json

IEEE = "/usr/share/ieee-data"
MAX_HOSTS = 1024
KEEP_HOSTS = 2000
PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 139: "netbios", 443: "https", 445: "smb", 515: "lpd",
              631: "ipp", 3389: "rdp", 5201: "iperf3", 5900: "vnc", 8080: "http-alt", 8443: "https-alt", 9100: "printer",
              27015: "game", 3128: "proxy", 1883: "mqtt", 554: "rtsp", 161: "snmp"}


def load_ouis():
    """MAC prefix (hex, 6/7/9 digits) -> organisation."""
    out = {}
    for name in ("oui.csv", "mam.csv", "oui36.csv"):
        try:
            with open(f"{IEEE}/{name}", newline="", encoding="utf-8", errors="replace") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and row[0] != "Registry":
                        out[row[1].strip().upper()] = row[2].strip()
        except OSError:
            pass
    return out


def nbstat_query(tid):
    name = b"*" + b"\0" * 15
    enc = bytes(c for b in name for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack("!HH", 0x21, 1)


def nbstat_name(data):
    """The machine's own NetBIOS name from a node status answer."""
    try:
        i = 12
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i]:
                i += data[i] + 1
            i += 1
        i += 8   # type, class, ttl
        i += 2   # rdlength
        n = data[i]
        i += 1
        for _ in range(n):
            nm, suffix, flags = data[i:i + 15], data[i + 15], struct.unpack("!H", data[i + 16:i + 18])[0]
            i += 18
            if suffix == 0 and not flags & 0x8000:
                return nm.decode("ascii", "replace").strip() or None
    except (IndexError, struct.error):
        pass
    return None


class HostScan(App):
    name = "hosts"
    SETTINGS = {"every": 15, "ports": "22,80,443,445,3389,5201,8080,9100,27015", "names": True, "smart": True}
    LIMITS = {"every": (0, 1440)}

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.file = self.dir / "hosts.json"
        saved = load_json(self.file, {})
        self.hosts = saved.get("hosts", {}) if isinstance(saved, dict) else {}
        self.base_t = saved.get("base_t") if isinstance(saved, dict) else None
        self.ouis = None
        self.scan = {"running": False, "step": None, "last": saved.get("last") if isinstance(saved, dict) else None, "error": None}
        self.wake_ev = threading.Event()
        self.pool = ThreadPoolExecutor(48)

    def check(self, k, v):
        if k == "ports":
            ps = sorted({int(x) for x in str(v).replace(" ", "").split(",") if x})
            if len(ps) > 24 or any(not 0 < p < 65536 for p in ps):
                raise ValueError("Up to 24 ports, 1-65535")
            return ",".join(map(str, ps))
        return super().check(k, v)

    def ports(self):
        return [int(x) for x in self.conf["ports"].split(",") if x]

    def vendor(self, mac):
        if int(mac[:2], 16) & 2:
            return "Private (random) MAC"
        if self.ouis is None:
            self.ouis = load_ouis()
        h = mac.replace(":", "").upper()
        return self.ouis.get(h[:9]) or self.ouis.get(h[:7]) or self.ouis.get(h[:6])

    # ---------- the sweep ----------
    def start(self):
        self.wake_ev.wait(40)  # after a boot: let DHCP and the watchdog settle (Scan now cuts it short)
        while True:
            every = int(self.conf["every"])
            due = every and (not self.scan["last"] or time.time() - self.scan["last"]["t"] > every * 60)
            if (due or self.wake_ev.is_set()) and self.p.link["up"] and self.p.net.get("ip"):
                self.wake_ev.clear()
                self.run_scan()
            self.wake_ev.wait(20)

    def subnet(self):
        net = ipaddress.ip_network(f"{self.p.net['ip']}/{self.p.net.get('prefix') or 24}", strict=False)
        if net.num_addresses > MAX_HOSTS:
            net = ipaddress.ip_network(f"{self.p.net['ip']}/22", strict=False)
        return net

    def run_scan(self):
        with self.lock:
            if self.scan["running"]:
                return
            self.scan.update(running=True, step="sweeping", error=None)
        t0 = time.time()
        try:
            iface = self.p_iface()
            net = self.subnet()
            me = self.p.net.get("ip")
            addrs = [str(a) for a in net.hosts() if str(a) != me]
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            for rnd in range(2):
                for a in addrs:
                    try:
                        s.sendto(b"probe-deck", (a, 9))
                    except OSError:
                        pass
                    if len(addrs) > 256:
                        time.sleep(0.001)
                time.sleep(1.5)
            s.close()
            time.sleep(1)
            found = {}
            for n in json.loads(subprocess.run(["ip", "-j", "-4", "neigh", "show", "dev", iface], capture_output=True, text=True, timeout=5).stdout or "[]"):
                mac, st = n.get("lladdr"), n.get("state") or []
                if mac and n.get("dst") and any(x in st for x in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT")):
                    if ipaddress.ip_address(n["dst"]) in net:
                        found[n["dst"]] = mac.lower()
            # the watchdog's ARP sightings fill in hosts that went quiet in the last 10 minutes
            if self.p.watch:
                for h in self.p.watch.seen_hosts(500):
                    if h["ip"] and time.time() - h["t"] < 600 and h["ip"] != me and ipaddress.ip_address(h["ip"]) in net:
                        found.setdefault(h["ip"], h["mac"])
            with self.lock:
                self.scan["step"] = f"looking at {len(found)} hosts"
            names = self.lookup_names(list(found)) if self.conf["names"] else {}
            ports = self.scan_ports(list(found))
            smart = {}
            if self.conf["smart"]:
                with self.lock:
                    self.scan["step"] = "identifying devices (SSDP, mDNS, Kasa, Hue, Roku…)"
                smart = self.smart_scan(net, found)
            now = time.time()
            with self.lock:
                if self.base_t is None:
                    self.base_t = now
                for ip, mac in found.items():
                    h = self.hosts.get(mac) or {"mac": mac, "first": now}
                    h.update(ip=ip, last=now, vendor=self.vendor(mac), ports=ports.get(ip, []))
                    nm = names.get(ip) or {}
                    h["names"] = {**(h.get("names") or {}), **{k: v for k, v in nm.items() if v}}
                    sd = smart.get(ip)
                    if sd:
                        h["smart"] = sd
                    self.hosts[mac] = h
                if len(self.hosts) > KEEP_HOSTS:
                    for mac in sorted(self.hosts, key=lambda m: self.hosts[m]["last"])[:len(self.hosts) - KEEP_HOSTS]:
                        del self.hosts[mac]
                self.scan["last"] = {"t": now, "took": round(now - t0, 1), "found": len(found), "net": str(net)}
            self.save()
        except Exception as e:
            self.scan["error"] = str(e)[:160]
        finally:
            with self.lock:
                self.scan.update(running=False, step=None)

    def smart_scan(self, net, found):
        """PorkChopCheck's smart-device discovery (pc_smart.py): type, brand, model, serial."""
        import pc_smart

        class Oui:
            def __init__(s, fn):
                s.fn = fn

            def vendor_long(s, mac):
                return s.fn(mac) or ""

            vendor = vendor_long

        def mdns_fn():
            m = self.p.apps.get("mdns")
            if not m:
                return {"types": set(), "inst": {}, "hosts": {}, "responders": set()}
            m.scan()
            return m.browser().snapshot()

        try:
            my = open(f"/sys/class/net/{self.p_iface()}/address").read().strip()
            sc = pc_smart.SmartScan(self.p.net["ip"], str(net.netmask), my, Oui(self.vendor),
                                    lambda: [(ip, mac, "REACHABLE") for ip, mac in found.items()], mdns_fn)
            devs = sc.run()
        except Exception as e:
            print(f"smart scan: {e}", flush=True)
            return {}
        out = {}
        for d in devs:
            if d.get("category") == "unknown" and not d.get("model") and not d.get("serial"):
                continue
            out[d["ip"]] = {k: d.get(k) for k in ("category", "brand", "model", "serial", "name", "smart")}
            out[d["ip"]]["sources"] = list(d.get("sources") or [])[:6]
        return out

    def p_iface(self):
        return self.p.watch.iface  # the interface the probe was started on

    def save(self):
        with self.lock:
            data = {"hosts": self.hosts, "base_t": self.base_t, "last": self.scan["last"]}
        save_json(self.file, data)

    def lookup_names(self, ips):
        out = {ip: {} for ip in ips}

        def rdns(ip):
            try:
                return socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                return None

        def mdns(ip):
            try:
                r = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=3).stdout.split()
                return r[1].removesuffix(".local") if len(r) >= 2 else None
            except (OSError, subprocess.TimeoutExpired):
                return None

        futs = {(ip, "dns"): self.pool.submit(rdns, ip) for ip in ips}
        futs.update({(ip, "mdns"): self.pool.submit(mdns, ip) for ip in ips})
        # NetBIOS: one socket, every host at once
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            for i, ip in enumerate(ips):
                try:
                    s.sendto(nbstat_query(0x4000 + i), (ip, 137))
                except OSError:
                    pass
            end = time.time() + 2
            while time.time() < end:
                try:
                    data, (ip, _) = s.recvfrom(2048)
                except socket.timeout:
                    continue
                if ip in out:
                    out[ip]["netbios"] = nbstat_name(data)
            s.close()
        except OSError:
            pass
        for (ip, kind), f in futs.items():
            try:
                v = f.result(timeout=8)
            except Exception:
                v = None
            if v and v != ip:
                out[ip][kind] = v[:80]
        return out

    def scan_ports(self, ips):
        ports = self.ports()

        def probe(ip, port):
            try:
                with socket.create_connection((ip, port), timeout=0.6):
                    return True
            except OSError:
                return False

        futs = {(ip, port): self.pool.submit(probe, ip, port) for ip in ips for port in ports}
        out = {}
        for (ip, port), f in futs.items():
            try:
                if f.result(timeout=20):
                    out.setdefault(ip, []).append(port)
            except Exception:
                pass
        return out

    # ---------- for the page ----------
    def status(self):
        if self.scan["running"]:
            return {"dot": "live"}
        return {"dot": "on" if self.scan["last"] and time.time() - self.scan["last"]["t"] < 3600 else ""}

    def labels(self):
        """Names the probe already knows: Wake machines, Perf-Deck stations, managed switches, the gateway."""
        by_mac, by_ip = {}, {}
        if self.p.wake:
            for h in self.p.wake.hosts:
                by_mac[h["mac"]] = h.get("name")
        for pr in list(self.p.peers.values()):
            by_ip[pr.get("ip")] = f"Perf-Deck: {pr.get('name')}"
        nm = self.p.netmap
        if nm:
            with nm.lock:
                for d in nm.devices:
                    by_ip[d["host"]] = (nm.state.get(d["id"], {}).get("name") or d.get("name") or d["host"]).split(".")[0]
        gw = self.p.net.get("gateway")
        if gw:
            by_ip.setdefault(gw, "Gateway")
        return by_mac, by_ip

    def get(self, sub, arg, q, user):
        now = time.time()
        by_mac, by_ip = self.labels()
        last = self.scan["last"]
        with self.lock:
            hosts = [dict(h) for h in self.hosts.values()]
        out = []
        for h in hosts:
            names = h.get("names") or {}
            out.append({
                **h, "label": by_mac.get(h["mac"]) or by_ip.get(h["ip"]),
                "name": names.get("netbios") or names.get("mdns") or names.get("dns"),
                "up": bool(last and h["last"] >= last["t"] - 5),
                "new": bool(self.base_t and h["first"] > self.base_t + 60 and now - h["first"] < 86400),
                "ports": [{"port": p, "name": PORT_NAMES.get(p, "")} for p in h.get("ports") or []],
            })
        out.sort(key=lambda h: (not h["up"], tuple(int(x) for x in h["ip"].split("."))))
        return {"scan": dict(self.scan), "hosts": out, "every": self.conf["every"], "ports": self.conf["ports"],
                "names": self.conf["names"], "smart": self.conf["smart"], "now": now, "subnet": str(self.subnet()) if self.p.net.get("ip") else None}

    def post(self, action, body, user):
        if action == "scan":
            if not self.p.net.get("ip"):
                raise ValueError("The probe has no address")
            self.wake_ev.set()
            return {}
        if action == "forget":
            with self.lock:
                if body.get("all"):
                    self.hosts, self.base_t = {}, None
                else:
                    self.hosts.pop(str(body.get("mac")), None)
            self.save()
            return {}
        return super().post(action, body, user)
