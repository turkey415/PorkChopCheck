"""LAN cache checker (lancache.net and friends).

1. DNS: the game CDNs' names must resolve to the cache, through every DNS server the probe got.
2. The cache answers: lancache answers GET /lancache-heartbeat (Host lancache.steamcontent.com) with 204
   and an X-LanCache-Processed-By header; port 443 should be open too (HTTPS passes straight through).
3. Optional: a test file (a URL you copy from the cache's access log) is fetched through the cache twice.
   The X-Upstream-Cache-Status header says MISS then HIT, and the second fetch shows the cache's speed.
"""
import http.client
import ipaddress
import re
import socket
import subprocess
import threading
import time
from collections import Counter
from urllib.parse import urlsplit

from appbase import App

# Names on the uklans cache-domains lists (github.com/uklans/cache-domains), which lancache-dns points at the cache.
# Each one is on its service's list as written or under a wildcard; checked against the lists 2026-10-24.
# Steam's list is the single name lancache.steamcontent.com: the Steam client looks it up and, when it is a
# LAN address, downloads through it. Other Steam CDN names are meant to stay public.
SERVICES = [
    ("Steam", ["lancache.steamcontent.com"]),
    ("Battle.net", ["level3.blizzard.com", "blzddist1-a.akamaihd.net"]),
    ("Epic Games", ["epicgames-download1.akamaized.net", "fastly-download.epicgames.com"]),
    ("Riot", ["lol.dyn.riotcdn.net", "riotgamespatcher-a.akamaihd.net"]),
    ("EA / Origin", ["origin-a.akamaihd.net"]),
    ("Ubisoft", ["uplaypc-s-ubisoft.cdn.ubi.com"]),
    ("Xbox / Microsoft Store", ["assets1.xboxlive.com", "xvcf1.xboxlive.com"]),
    ("Windows Update", ["download.windowsupdate.com", "dl.delivery.mp.microsoft.com"]),
]


def private(ip):
    """A LAN address (not 0.0.0.0 or loopback, which is what DNS blockers answer)."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_unspecified and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


def dig(server, name):
    out = subprocess.run(["dig", "+time=2", "+tries=1", f"@{server}", name, "A"], capture_output=True, text=True, timeout=6).stdout
    st = re.search(r"status: (\w+)", out)
    return {"status": st.group(1) if st else "no answer", "ips": re.findall(r"\sIN\s+A\s+([\d.]+)", out)}


class LanCache(App):
    name = "cache"
    HTTP_PORT = 80   # lancache listens on 80 (tests change it)
    SETTINGS = {"cache_ip": "", "every": 10, "test_url": "", "dns_extra": "", "dns_dhcp": True}
    LIMITS = {"every": (0, 1440)}

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.result = None
        self.running = False
        self.wake_ev = threading.Event()
        self.trial = None     # a DNS server typed for one check, not saved

    @staticmethod
    def parse_dns(text):
        out = []
        for part in re.split(r"[,\s]+", str(text or "").strip()):
            if not part:
                continue
            try:
                ipaddress.ip_address(part)
            except ValueError:
                raise ValueError(f"Not a DNS server address: {part[:40]}") from None
            if part not in out:
                out.append(part)
        if len(out) > 6:
            raise ValueError("Up to 6 DNS servers")
        return out

    def check(self, k, v):
        if k == "dns_extra":
            return ", ".join(self.parse_dns(v))
        if k == "cache_ip":
            v = str(v or "").strip()
            if v and not private(v):
                raise ValueError("The cache's address must be a LAN IPv4 address")
            return v
        if k == "test_url":
            v = str(v or "").strip()
            if v and not re.fullmatch(r"http://[\w.\-]+(:\d+)?/\S{1,500}", v):
                raise ValueError("The test file must be an http:// URL with a path")
            return v
        return super().check(k, v)

    def on_conf(self):
        self.wake_ev.set()

    def start(self):
        self.wake_ev.wait(30)
        while True:
            every = int(self.conf["every"])
            due = every and (not self.result or time.time() - self.result["t"] > every * 60)
            if (due or self.wake_ev.is_set()) and self.p.link["up"] and self.p.net.get("ip"):
                self.wake_ev.clear()
                self.run()
            self.wake_ev.wait(15)

    # ---------- the checks ----------
    def run(self):
        if self.running:
            return
        self.running = True
        t0 = time.time()
        trial, self.trial = self.trial, None
        if trial:
            servers = [(x, "trial") for x in trial]
        else:
            servers = [(x, "DHCP") for x in (self.p.net.get("dns") or [])[:3]] if self.conf["dns_dhcp"] else []
            servers += [(x, "added") for x in self.parse_dns(self.conf["dns_extra"]) if x not in [y for y, _ in servers]]
        res = {"t": t0, "dns_servers": [x for x, _ in servers], "dns_from": [w for _, w in servers], "trial": bool(trial),
               "services": [], "error": None}
        try:
            servers = res["dns_servers"]
            if not servers:
                raise RuntimeError("No DNS servers to ask: DHCP gave none and none are added")
            jobs = [(svc, name, srv) for svc, names in SERVICES for name in names for srv in servers]
            answers = {}
            ths = []
            for job in jobs:
                def one(j=job):
                    try:
                        answers[j] = dig(j[2], j[1])
                    except (OSError, subprocess.TimeoutExpired):
                        answers[j] = {"status": "timeout", "ips": []}
                th = threading.Thread(target=one, daemon=True)
                th.start()
                ths.append(th)
            for th in ths:
                th.join(10)
            # the cache: as set, or the private address most of the names point at
            cache = self.conf["cache_ip"]
            if not cache:
                votes = Counter(ip for a in answers.values() for ip in a["ips"][:1] if private(ip))
                top = votes.most_common(1)
                cache = top[0][0] if top and top[0][1] >= 2 else ""
            res["cache_ip"], res["cache_auto"] = cache or None, not self.conf["cache_ip"]
            for svc, names in SERVICES:
                rows = []
                for name in names:
                    per = []
                    for srv in servers:
                        a = answers.get((svc, name, srv)) or {"status": "timeout", "ips": []}
                        ip = a["ips"][0] if a["ips"] else None
                        per.append({"server": srv, "ip": ip, "status": a["status"], "cached": bool(cache and ip == cache), "lan": bool(ip and private(ip))})
                    rows.append({"name": name, "per": per, "cached": all(x["cached"] for x in per)})
                res["services"].append({"name": svc, "names": rows, "cached": all(r["cached"] for r in rows)})
            res["names_total"] = sum(len(s["names"]) for s in res["services"])
            res["names_cached"] = sum(r["cached"] for s in res["services"] for r in s["names"])
            if cache:
                res["heartbeat"] = self.heartbeat(cache)
                res["https"] = self.port_open(cache, 443)
                if self.conf["test_url"]:
                    res["test"] = self.test_file(cache, self.conf["test_url"])
        except Exception as e:
            res["error"] = str(e)[:160]
        res["took"] = round(time.time() - t0, 1)
        self.result = res
        self.running = False

    def heartbeat(self, cache):
        t0 = time.perf_counter()
        try:
            c = http.client.HTTPConnection(cache, self.HTTP_PORT, timeout=4)
            c.request("GET", "/lancache-heartbeat", headers={"Host": "lancache.steamcontent.com", "User-Agent": "probe-deck"})
            r = c.getresponse()
            r.read()
            h = {k.lower(): v for k, v in r.getheaders()}
            c.close()
            return {"ok": r.status == 204 or "x-lancache-processed-by" in h, "code": r.status, "by": h.get("x-lancache-processed-by"),
                    "ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as e:
            return {"ok": False, "error": str(e)[:100] or type(e).__name__}

    @staticmethod
    def port_open(ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2):
                return True
        except OSError:
            return False

    def test_file(self, cache, url):
        u = urlsplit(url)
        path = u.path + (f"?{u.query}" if u.query else "")
        out = []
        for _ in range(2):
            t0 = time.perf_counter()
            try:
                c = http.client.HTTPConnection(cache, self.HTTP_PORT, timeout=15)
                c.request("GET", path, headers={"Host": u.netloc, "User-Agent": "Valve/Steam HTTP Client 1.0"})
                r = c.getresponse()
                n = 0
                while True:
                    b = r.read(65536)
                    if not b:
                        break
                    n += len(b)
                    if n > 200_000_000:
                        break
                secs = time.perf_counter() - t0
                h = {k.lower(): v for k, v in r.getheaders()}
                c.close()
                out.append({"code": r.status, "bytes": n, "secs": round(secs, 3), "bps": round(n * 8 / secs) if secs > 0 else None,
                            "cache": h.get("x-upstream-cache-status") or h.get("x-cache-status") or h.get("x-cache"),
                            "by": h.get("x-lancache-processed-by")})
            except Exception as e:
                out.append({"error": str(e)[:100] or type(e).__name__})
        return out

    # ---------- for the page ----------
    def status(self):
        r = self.result
        if self.running:
            return {"dot": "live"}
        if not r or not r.get("cache_ip"):
            return {"dot": ""}
        hb = r.get("heartbeat") or {}
        if not hb.get("ok"):
            return {"dot": "err"}
        return {"dot": "on" if r["names_cached"] == r["names_total"] else "warn"}

    def get(self, sub, arg, q, user):
        return {"result": self.result, "running": self.running, "cache_ip": self.conf["cache_ip"], "every": self.conf["every"],
                "test_url": self.conf["test_url"], "dns_extra": self.conf["dns_extra"], "dns_dhcp": self.conf["dns_dhcp"],
                "dhcp_dns": list(self.p.net.get("dns") or [])[:3], "now": time.time()}

    def post(self, action, body, user):
        if action == "run":
            if body.get("dns"):
                if self.running:
                    raise ValueError("A check is running: try again in a moment")
                self.trial = self.parse_dns(body["dns"])
            self.wake_ev.set()
            return {}
        return super().post(action, body, user)
