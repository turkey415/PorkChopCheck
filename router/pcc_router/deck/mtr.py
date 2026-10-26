"""Traceroute that keeps watching (like mtr): every hop to a target is probed once a second, and
each hop keeps its loss, latency and the last 40 results. A slow or lossy hop in the middle that
the hops after it don't share is a router that limits its replies, not a fault; loss or delay that
carries on to the last hop is real.
"""
import random
import socket
import struct
import threading
import time

from appbase import App, load_json, save_json

MAX_HOPS = 30
TIMEOUT = 2.0
KEEP = 40
RUN_MAX = 3600


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def echo(ident, seq):
    payload = b"probe-deck-mtr".ljust(36, b"\0")
    h = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    return struct.pack("!BBHHH", 8, 0, checksum(h + payload), ident, seq) + payload


class Mtr(App):
    name = "mtr"
    SETTINGS = {"target": "1.1.1.1"}

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.run = None
        self.stop_ev = threading.Event()
        self.names = {}
        self.recent = load_json(self.dir / "recent.json", [])

    def check(self, k, v):
        if k == "target":
            v = str(v or "").strip()
            if not v or len(v) > 253 or not all(c.isalnum() or c in ".-:" for c in v):
                raise ValueError("Type an address or a name, e.g. 1.1.1.1 or steamcommunity.com")
            return v
        return super().check(k, v)

    def begin(self, target, user):
        if self.run and self.run["running"]:
            self.stop_ev.set()
            time.sleep(1.2)
        self.save_conf({"target": target})
        try:
            dst = socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
        except OSError:
            raise ValueError(f"Can't find {target}") from None
        self.stop_ev = threading.Event()
        self.run = {"running": True, "target": target, "ip": dst, "started": time.time(), "by": user, "hops": {}, "last_hop": None, "rounds": 0}
        if target not in self.recent:
            self.recent = ([target] + self.recent)[:10]
            save_json(self.dir / "recent.json", self.recent)
        threading.Thread(target=self.go, args=(self.run, self.stop_ev), daemon=True).start()

    def hop(self, r, ttl):
        return r["hops"].setdefault(ttl, {"ttl": ttl, "ip": None, "ips": [], "sent": 0, "recv": 0, "last": None, "best": None, "worst": None,
                                          "sum": 0.0, "hist": []})

    def go(self, r, stop):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError as e:
            r.update(running=False, error=f"Can't open a raw socket: {e.strerror or e}")
            return
        s.settimeout(0.2)
        ident = random.getrandbits(16)
        out = {}                                   # seq -> (ttl, sent)
        lock = threading.Lock()

        def receive():
            while not stop.is_set():
                try:
                    data, (src, _) = s.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    return
                now = time.time()
                ihl = (data[0] & 0x0F) * 4
                icmp = data[ihl:]
                if len(icmp) < 8:
                    continue
                typ = icmp[0]
                if typ == 0:
                    rid, seq = struct.unpack("!HH", icmp[4:8])
                elif typ in (11, 3) and len(icmp) >= 8 + 20 + 8:
                    inner = icmp[8:]
                    iihl = (inner[0] & 0x0F) * 4
                    if inner[9] != 1 or len(inner) < iihl + 8:
                        continue
                    rid, seq = struct.unpack("!HH", inner[iihl + 4:iihl + 8])
                else:
                    continue
                if rid != ident:
                    continue
                with lock:
                    sent = out.pop(seq, None)
                if not sent:
                    continue
                ttl, t0 = sent
                ms = (now - t0) * 1000
                h = self.hop(r, ttl)
                h["recv"] += 1
                h["last"] = round(ms, 2)
                h["sum"] += ms
                h["best"] = ms if h["best"] is None else min(h["best"], ms)
                h["worst"] = ms if h["worst"] is None else max(h["worst"], ms)
                h["hist"] = (h["hist"] + [round(ms, 2)])[-KEEP:]
                if src not in h["ips"]:
                    h["ips"].append(src)
                    if len(h["ips"]) > 4:
                        h["ips"].pop(0)
                h["ip"] = src
                if typ == 0 or src == r["ip"]:
                    if r["last_hop"] is None or ttl < r["last_hop"]:
                        r["last_hop"] = ttl
                if src not in self.names:
                    self.names[src] = None
                    threading.Thread(target=self.lookup, args=(src,), daemon=True).start()

        threading.Thread(target=receive, daemon=True).start()
        rnd = 0
        try:
            while not stop.is_set() and time.time() - r["started"] < RUN_MAX:
                top = r["last_hop"] or MAX_HOPS
                for ttl in range(1, top + 1):
                    seq = (rnd * 64 + ttl) & 0xFFFF
                    try:
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                        with lock:
                            out[seq] = (ttl, time.time())
                        s.sendto(echo(ident, seq), (r["ip"], 0))
                    except OSError as e:
                        r["error"] = str(e)[:100]
                    h = self.hop(r, ttl)
                    h["sent"] += 1
                    time.sleep(0.01)
                stop.wait(1.0)
                # probes past their timeout are lost
                now = time.time()
                with lock:
                    gone = [(q, v) for q, v in out.items() if now - v[1] > TIMEOUT]
                    for q, _ in gone:
                        out.pop(q, None)
                for _, (ttl, _) in gone:
                    h = self.hop(r, ttl)
                    h["lost"] = h.get("lost", 0) + 1
                    h["hist"] = (h["hist"] + [None])[-KEEP:]
                # hops past the target are noise once it has answered
                if r["last_hop"]:
                    for t in [t for t in r["hops"] if t > r["last_hop"]]:
                        r["hops"].pop(t, None)
                rnd += 1
                r["rounds"] = rnd
        finally:
            stop.set()
            s.close()
            r["running"] = False

    def lookup(self, ip):
        try:
            self.names[ip] = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            self.names[ip] = ""

    def status(self):
        return {"dot": "live"} if self.run and self.run["running"] else None

    def get(self, sub, arg, q, user):
        r = None
        if self.run:
            r = {k: v for k, v in self.run.items() if k != "hops"}
            hops = []
            for ttl in sorted(self.run["hops"]):
                h = self.run["hops"][ttl]
                lost = h.get("lost", 0)
                hops.append({"ttl": ttl, "ip": h["ip"], "ips": h["ips"], "name": self.names.get(h["ip"]) if h["ip"] else None,
                             "sent": h["sent"], "recv": h["recv"], "loss": round(100 * lost / (h["recv"] + lost), 1) if h["recv"] + lost else 0,
                             "last": h["last"], "avg": round(h["sum"] / h["recv"], 2) if h["recv"] else None,
                             "best": round(h["best"], 2) if h["best"] is not None else None, "worst": round(h["worst"], 2) if h["worst"] is not None else None,
                             "hist": h["hist"]})
            r["hops"] = hops
        return {"run": r, "target": self.conf["target"], "recent": self.recent, "gateway": self.p.net.get("gateway"), "now": time.time()}

    def post(self, action, body, user):
        if action == "start":
            self.begin(self.check("target", body.get("target")), user["name"])
            return {}
        if action == "stop":
            self.stop_ev.set()
            return {}
        return super().post(action, body, user)
