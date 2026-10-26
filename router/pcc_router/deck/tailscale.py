"""Tailscale on the probe: status, peers, settings, on/off, log in and out.

Talks to tailscaled's local API on its unix socket (what the `tailscale` command uses), so no output parsing.
The page reads it on the Tailscale tab; only admins can change anything.
"""
import http.client
import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

SOCK = "/var/run/tailscale/tailscaled.sock"
SYSCTL = Path("/etc/sysctl.d/99-tailscale.conf")
EXIT_ROUTES = ("0.0.0.0/0", "::/0")
TS_V4 = ipaddress.ip_network("100.64.0.0/10")
TS_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
DEFAULT_CONTROL = "https://controlplane.tailscale.com"
URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]{1,253}(:\d{1,5})?(/[\w.\-/~%]*)?")
KEY_RE = re.compile(r"[\w\-:]{8,200}")
PROFILE_RE = re.compile(r"[0-9a-f]{1,16}")
# Tailscale's relay (DERP) regions: a device's "home" relay is the one nearest to it, so it places the device
# roughly on the map without any lookup. lat, lon, city.
DERP = {
    "sea": (47.61, -122.33, "Seattle"), "sfo": (37.77, -122.42, "San Francisco"), "lax": (34.05, -118.24, "Los Angeles"),
    "den": (39.74, -104.99, "Denver"), "dfw": (32.78, -96.80, "Dallas"), "ord": (41.88, -87.63, "Chicago"),
    "mia": (25.76, -80.19, "Miami"), "iad": (39.04, -77.49, "Ashburn"), "nyc": (40.71, -74.01, "New York City"),
    "tor": (43.65, -79.38, "Toronto"), "hnl": (21.31, -157.86, "Honolulu"), "atl": (33.75, -84.39, "Atlanta"),
    "lhr": (51.51, -0.13, "London"), "ams": (52.37, 4.90, "Amsterdam"), "fra": (50.11, 8.68, "Frankfurt"), "par": (48.86, 2.35, "Paris"),
    "mad": (40.42, -3.70, "Madrid"), "waw": (52.23, 21.01, "Warsaw"), "hel": (60.17, 24.94, "Helsinki"), "tok": (35.68, 139.69, "Tokyo"),
    "sin": (1.35, 103.82, "Singapore"), "syd": (-33.87, 151.21, "Sydney"), "sao": (-23.55, -46.63, "São Paulo"), "blr": (12.97, 77.59, "Bangalore"),
    "hkg": (22.32, 114.17, "Hong Kong"), "jnb": (-26.20, 28.05, "Johannesburg"), "dbi": (25.20, 55.27, "Dubai"), "nai": (-1.29, 36.82, "Nairobi"),
}
GEO_URL = "http://ip-api.com/batch?fields=status,lat,lon,city,regionName,countryCode,query"
GEO_TTL = 86400


def public_ip(addr):
    """'1.2.3.4:41641' -> '1.2.3.4' when it's a public address, else None."""
    host = (addr or "").rsplit(":", 1)[0].strip("[]")
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return None
    return host if a.is_global and a not in TS_V4 else None


HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?")


class _Conn(http.client.HTTPConnection):
    def __init__(self, timeout):
        super().__init__("local-tailscaled.sock", timeout=timeout)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCK)


def api(method, path, body=None, timeout=5):
    c = _Conn(timeout)
    try:
        c.request(method, "/localapi/v0/" + path, body=json.dumps(body) if body is not None else None,
                  headers={"Sec-Tailscale": "localapi", "Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        if r.status >= 400:
            raise ValueError("tailscale: " + data.decode(errors="replace").strip()[:200])
        return json.loads(data) if data.strip() else None
    except OSError as e:
        raise ValueError(f"tailscaled isn't answering ({e.strerror or e})")
    finally:
        c.close()


def systemctl(*args):
    return subprocess.run(["systemctl", *args, "tailscaled"], capture_output=True, text=True, timeout=30)


def in_tailnet(ip):
    try:
        a = ipaddress.ip_address(ip.removeprefix("::ffff:"))
        return a in TS_V4 if a.version == 4 else a in TS_V6
    except ValueError:
        return False


def parse_routes(text):
    out = []
    for part in re.split(r"[,\s]+", str(text or "")):
        if not part:
            continue
        try:
            n = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise ValueError(f"Not a subnet: {part[:40]} (use e.g. 192.168.1.0/24)")
        if str(n) in EXIT_ROUTES:
            raise ValueError("Use the exit node switch for 0.0.0.0/0")
        out.append(str(n))
    if len(out) > 16:
        raise ValueError("At most 16 subnets")
    return list(dict.fromkeys(out))


class Tailscale:
    def __init__(self, probe):
        self.p = probe
        self.geo = {}              # ip -> (fetched, {lat, lon, city, region, cc} or None)
        self.geo_want = set()
        self.geo_lock = threading.Lock()
        self.derp_names = {}
        threading.Thread(target=self.geo_loop, daemon=True).start()

    # ---------- where devices are ----------
    def geo_on(self):
        return bool(self.p.conf.get("ts_geoip"))

    def locate(self, ip):
        """City-level location of a public IP, when the lookup is turned on (looked up in the background)."""
        if not ip or not self.geo_on():
            return None
        with self.geo_lock:
            hit = self.geo.get(ip)
            if hit and time.time() - hit[0] < GEO_TTL:
                return hit[1]
            self.geo_want.add(ip)
        return hit[1] if hit else None

    def geo_loop(self):
        while True:
            time.sleep(5)
            with self.geo_lock:
                want, self.geo_want = list(self.geo_want)[:100], set()
            if not want or not self.geo_on():
                continue
            try:
                req = urllib.request.Request(GEO_URL, data=json.dumps(want).encode(), headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    rows = json.loads(r.read())
            except (OSError, ValueError):
                continue
            now = time.time()
            with self.geo_lock:
                for row in rows if isinstance(rows, list) else []:
                    ok = row.get("status") == "success" and isinstance(row.get("lat"), (int, float))
                    self.geo[str(row.get("query"))] = (now, {"lat": row["lat"], "lon": row["lon"], "city": str(row.get("city") or "")[:40],
                                                             "region": str(row.get("regionName") or "")[:40], "cc": str(row.get("countryCode") or "")[:2]} if ok else None)

    def relay(self, code):
        if not code:
            return None
        if code not in self.derp_names:
            try:
                dm = api("GET", "derpmap") or {}
                for r in (dm.get("Regions") or {}).values():
                    self.derp_names[r.get("RegionCode")] = r.get("RegionName")
            except ValueError:
                pass
            self.derp_names.setdefault(code, None)
        known = DERP.get(code)
        return {"code": code, "name": (known[2] if known else None) or self.derp_names.get(code) or code.upper(),
                "lat": known[0] if known else None, "lon": known[1] if known else None}

    def installed(self):
        return Path("/usr/bin/tailscale").exists() or Path("/usr/sbin/tailscaled").exists()

    def service(self):
        en = systemctl("is-enabled").stdout.strip()
        act = systemctl("is-active").stdout.strip()
        return {"enabled": en == "enabled", "active": act == "active", "state": act}

    def lan_cidr(self):
        n = self.p.net
        if n.get("ip") and n.get("prefix"):
            return str(ipaddress.ip_network(f"{n['ip']}/{n['prefix']}", strict=False))
        return None

    def snapshot(self, client_ip=""):
        out = {"installed": self.installed(), "client_tailnet": in_tailnet(client_ip), "lan": self.lan_cidr(), "now": time.time()}
        if not out["installed"]:
            return out
        out["service"] = self.service()
        if not out["service"]["active"]:
            return out
        try:
            st = api("GET", "status")
            pr = api("GET", "prefs")
        except ValueError as e:
            out["error"] = str(e)
            return out
        me = st.get("Self") or {}
        tn = st.get("CurrentTailnet") or {}
        adv = pr.get("AdvertiseRoutes") or []
        au = pr.get("AutoUpdate") or {}
        out.update({
            "version": (st.get("Version") or "").split("-")[0], "state": st.get("BackendState"), "auth_url": st.get("AuthURL") or "",
            "ips": st.get("TailscaleIPs") or [], "dns": (me.get("DNSName") or "").rstrip("."), "online": me.get("Online"),
            "tailnet": tn.get("Name"), "magic_dns": tn.get("MagicDNSEnabled"), "relay": me.get("Relay"),
            "health": [h for h in (st.get("Health") or []) if isinstance(h, str)][:6],
            "prefs": {"want_running": pr.get("WantRunning"), "logged_out": pr.get("LoggedOut"), "hostname": pr.get("Hostname") or socket.gethostname(),
                      "route_all": pr.get("RouteAll"), "corp_dns": pr.get("CorpDNS"), "run_ssh": pr.get("RunSSH"), "shields_up": pr.get("ShieldsUp"),
                      "routes": [r for r in adv if r not in EXIT_ROUTES], "exit_node": any(r in EXIT_ROUTES for r in adv),
                      "auto_update": bool(au.get("Apply"))},
            "approved": [str(r) for r in (me.get("PrimaryRoutes") or [])],
            "geoip": self.geo_on(), "home": self.relay(me.get("Relay")),
            "public_ip": next((ip for ip in map(public_ip, me.get("Addrs") or []) if ip), None),
            "forwarding": Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1",
        })
        peers = []
        for p in (st.get("Peer") or {}).values():
            dip = public_ip(p.get("CurAddr"))
            peers.append({"id": str(p.get("ID") or p.get("PublicKey") or "")[-16:], "home": self.relay(p.get("Relay")),
                          "geo": self.locate(dip), "name": p.get("HostName") or "?", "dns": (p.get("DNSName") or "").split(".")[0], "ip": (p.get("TailscaleIPs") or [None])[0],
                          "os": p.get("OS"), "online": bool(p.get("Online")), "active": bool(p.get("Active")),
                          "direct": p.get("CurAddr") or "", "relay": p.get("Relay") or "", "last_seen": p.get("LastSeen"),
                          "exit": bool(p.get("ExitNodeOption")), "rx": p.get("RxBytes") or 0, "tx": p.get("TxBytes") or 0})
        out["geo"] = self.locate(out["public_ip"])
        out["control_url"] = pr.get("ControlURL") or DEFAULT_CONTROL
        out["profiles"] = self.profiles()
        if not any(p["current"] for p in out["profiles"]):
            # a new connection isn't saved by Tailscale until its login finishes
            out["profiles"].insert(0, {"id": None, "name": "", "user": "", "dns": "", "control": out["control_url"],
                                       "headscale": out["control_url"].rstrip("/") != DEFAULT_CONTROL, "current": True, "pending": True})
        out["peers"] = sorted(peers, key=lambda x: (not x["online"], x["name"].lower()))[:200]
        return out

    @staticmethod
    def profiles():
        """Saved logins: your tailnet, Headscale servers. One is in use at a time."""
        try:
            cur = (api("GET", "profiles/current") or {}).get("ID")
            lst = api("GET", "profiles/") or []
        except ValueError:
            return []
        out = []
        for p in lst:
            url = p.get("ControlURL") or DEFAULT_CONTROL
            out.append({"id": p.get("ID"), "name": (p.get("NetworkProfile") or {}).get("DisplayName") or p.get("Name") or "",
                        "user": (p.get("UserProfile") or {}).get("LoginName") or "", "dns": (p.get("NetworkProfile") or {}).get("MagicDNSName") or "",
                        "control": url, "headscale": url.rstrip("/") != DEFAULT_CONTROL, "current": p.get("ID") == cur})
        return out

    def add_server(self, url, key):
        """Log in to another control server (Headscale) as a new saved profile, and switch to it."""
        url = str(url or "").strip().rstrip("/")
        if not URL_RE.fullmatch(url):
            raise ValueError("Server: a URL like https://headscale.example.com")
        key = str(key or "").strip()
        if key and not KEY_RE.fullmatch(key):
            raise ValueError("That doesn't look like a pre-auth key")
        host = (api("GET", "prefs") or {}).get("Hostname") or socket.gethostname()
        api("PUT", "profiles/")                      # a fresh, empty profile becomes the current one
        prefs = api("GET", "prefs") or {}
        prefs.update(ControlURL=url, WantRunning=True, Hostname=host, LoggedOut=False)
        prefs.pop("Config", None)
        opts = {"UpdatePrefs": prefs}
        if key:
            opts["AuthKey"] = key
        api("POST", "start", opts, timeout=20)
        if not key:
            api("POST", "login-interactive")

    # ---------- changes (admin only) ----------
    def action(self, body):
        a = body.get("action")
        if a == "service":
            on = bool(body.get("on"))
            r = systemctl("enable" if on else "disable", "--now")
            if r.returncode:
                raise ValueError((r.stderr.strip().splitlines() or ["systemctl failed"])[-1][:200])
            return
        if a == "up":
            api("PATCH", "prefs", {"WantRunning": True, "WantRunningSet": True})
            st = api("GET", "status")
            if st.get("BackendState") in ("NeedsLogin", "NoState"):
                api("POST", "login-interactive")
            return
        if a == "down":
            api("PATCH", "prefs", {"WantRunning": False, "WantRunningSet": True})
            return
        if a == "login":
            api("PATCH", "prefs", {"WantRunning": True, "WantRunningSet": True})
            api("POST", "login-interactive")
            return
        if a == "logout":
            api("POST", "logout", timeout=15)
            return
        if a == "settings":
            return self.settings(body)
        if a == "add_server":
            return self.add_server(body.get("url"), body.get("key"))
        if a in ("switch", "remove"):
            pid = str(body.get("id") or "")
            if not PROFILE_RE.fullmatch(pid):
                raise ValueError("Bad profile")
            if a == "switch":
                api("POST", "profiles/" + pid, timeout=15)
            else:
                if any(p["current"] and p["id"] == pid for p in self.profiles()):
                    raise ValueError("Switch to another connection before removing this one")
                api("DELETE", "profiles/" + pid)
            return
        raise ValueError("Unknown action")

    def settings(self, b):
        m = {}
        if "hostname" in b:
            h = str(b["hostname"]).strip().lower()
            if not HOST_RE.fullmatch(h):
                raise ValueError("Tailscale name: letters, digits and dashes")
            m.update(Hostname=h, HostnameSet=True)
        for key, pref in (("route_all", "RouteAll"), ("corp_dns", "CorpDNS"), ("run_ssh", "RunSSH"), ("shields_up", "ShieldsUp")):
            if key in b:
                m.update({pref: bool(b[key]), pref + "Set": True})
        if "routes" in b or "exit_node" in b:
            cur = api("GET", "prefs").get("AdvertiseRoutes") or []
            routes = parse_routes(b["routes"]) if "routes" in b else [r for r in cur if r not in EXIT_ROUTES]
            exit_on = bool(b["exit_node"]) if "exit_node" in b else any(r in EXIT_ROUTES for r in cur)
            routes += list(EXIT_ROUTES) if exit_on else []
            m.update(AdvertiseRoutes=routes, AdvertiseRoutesSet=True)
            if routes:
                self.forwarding()
        if "geoip" in b:
            self.p.save_conf({"ts_geoip": bool(b["geoip"])})
        if "auto_update" in b:
            on = bool(b["auto_update"])
            m.update(AutoUpdate={"Check": True, "Apply": on}, AutoUpdateSet={"CheckSet": True, "ApplySet": True})
        if m:
            api("PATCH", "prefs", m)

    @staticmethod
    def forwarding():
        """Subnet routes and exit nodes need IP forwarding; Tailscale's own docs set it this way."""
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1":
            return
        SYSCTL.write_text("# Probe Deck: Tailscale subnet router / exit node\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n")
        subprocess.run(["sysctl", "-p", str(SYSCTL)], capture_output=True, timeout=10)

    def cert_names(self, tls):
        """The certificate's names plus this probe's Tailscale name and IP."""
        snap = self.snapshot()
        if not snap.get("dns"):
            raise ValueError("Tailscale isn't logged in yet")
        info = tls.info() or {}
        names = list(info.get("names") or tls.default_names())
        for n in [snap["dns"], snap["dns"].split(".")[0]] + [i for i in snap.get("ips", []) if "." in i]:
            if n not in names:
                names.append(n)
        return ", ".join(names)
