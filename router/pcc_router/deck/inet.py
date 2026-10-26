"""Internet speed test against Cloudflare (speed.cloudflare.com), for the event's uplink.

Download: several streams pull big files for N seconds. Upload: they push. Latency is measured
idle (small requests) and loaded (ping to 1.1.1.1 while the streams run): the difference is
bufferbloat. A gigabit test moves about 1-2 GB, so it only runs when someone presses Start.
"""
import http.client
import re
import ssl
import statistics
import subprocess
import threading
import time

from appbase import App, load_json, save_json

HOST = "speed.cloudflare.com"
CHUNK = 64 * 1024
HIST_MAX = 40
SIZES = [25_000_000, 10_000_000, 5_000_000, 2_000_000, 1_000_000]  # Cloudflare limits each size per IP: step down on a 429


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Inet(App):
    name = "speed"
    SETTINGS = {"secs": 10, "streams": 4}
    LIMITS = {"secs": (3, 30), "streams": (1, 8)}

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.ctx = ssl.create_default_context()
        self.run = {"running": False, "phase": None, "points": [], "error": None}
        self.hist_file = self.dir / "history.json"
        self.history = load_json(self.hist_file, [])[-HIST_MAX:]
        self.stop = False

    def conn(self, timeout=10):
        return http.client.HTTPSConnection(HOST, timeout=timeout, context=self.ctx)

    # ---------- pieces ----------
    def meta(self):
        """Cloudflare puts who-and-where in the headers of any test response."""
        try:
            c = self.conn(5)
            c.request("GET", "/__down?bytes=0", headers={"User-Agent": "probe-deck"})
            r = c.getresponse()
            r.read()
            h = {k.lower(): v for k, v in r.getheaders()}
            c.close()
            return {"ip": h.get("cf-meta-ip"), "asn": h.get("asn"), "colo": h.get("colo"), "city": h.get("city"), "country": h.get("country")}
        except Exception:
            return {}

    def idle_latency(self, n=12):
        """Ping 1.1.1.1 before any load, the same way the loaded latency is measured."""
        out = subprocess.run(["ping", "-n", "-c", str(n), "-i", "0.2", "-W", "2", "1.1.1.1"], capture_output=True, text=True, timeout=n + 5).stdout
        ms = [float(x) for x in re.findall(r"time=([\d.]+)", out)]
        if not ms:
            raise RuntimeError("1.1.1.1 doesn't answer ping")
        return ms

    def pinger(self, out, stop, phase=None, t0=None):
        """ICMP to 1.1.1.1 every 0.25 s while the streams run: the loaded latency."""
        p = subprocess.Popen(["ping", "-n", "-i", "0.25", "-W", "2", "1.1.1.1"], stdout=subprocess.PIPE, text=True)
        try:
            for line in p.stdout:
                m = re.search(r"time=([\d.]+)", line)
                if m:
                    out.append(float(m.group(1)))
                    if phase:
                        with self.lock:
                            self.run.setdefault("lat", []).append([phase, round(time.time() - t0, 2), float(m.group(1))])
                if stop.is_set():
                    break
        finally:
            p.kill()

    def streams(self, phase, secs, n):
        """Run n streams for secs; returns (bps after the first second, loaded latencies, per-0.5 s points)."""
        moved = [0] * n
        stop = threading.Event()
        errs = []
        refused = []
        level = [0]
        step = threading.Lock()

        def down(i):
            while not stop.is_set():
                c = self.conn(10)
                lv = level[0]
                try:
                    c.request("GET", f"/__down?bytes={SIZES[lv]}", headers={"User-Agent": "probe-deck"})
                    r = c.getresponse()
                    if r.status != 200:
                        raise Refused(r.status)
                    while not stop.is_set():
                        b = r.read1(CHUNK) if hasattr(r, "read1") else r.read(CHUNK)
                        if not b:
                            break
                        moved[i] += len(b)
                except Refused as e:
                    with step:
                        if e.code == 429 and lv < level[0]:
                            pass            # another stream already stepped down
                        elif e.code == 429 and level[0] < len(SIZES) - 1:
                            level[0] += 1   # smaller requests are still allowed
                        else:
                            refused.append(e.code)
                            stop.set()
                except Exception as e:
                    errs.append(str(e)[:100])
                    time.sleep(0.3)
                finally:
                    c.close()

        def up(i):
            blob = b"0" * CHUNK
            while not stop.is_set():
                c = self.conn(10)
                lv = level[0]
                try:
                    c.putrequest("POST", "/__up")
                    c.putheader("User-Agent", "probe-deck")
                    c.putheader("Content-Type", "application/octet-stream")
                    size = SIZES[lv]
                    c.putheader("Content-Length", str(size))
                    c.endheaders()
                    sent = 0
                    while sent < size and not stop.is_set():
                        c.send(blob)
                        sent += len(blob)
                        moved[i] += len(blob)
                    if sent >= size:
                        r = c.getresponse()
                        r.read()
                        if r.status != 200:
                            raise Refused(r.status)
                except Refused as e:
                    with step:
                        if e.code == 429 and lv < level[0]:
                            pass            # another stream already stepped down
                        elif e.code == 429 and level[0] < len(SIZES) - 1:
                            level[0] += 1   # smaller requests are still allowed
                        else:
                            refused.append(e.code)
                            stop.set()
                except Exception as e:
                    errs.append(str(e)[:100])
                    time.sleep(0.3)
                finally:
                    c.close()

        lat = []
        threads = [threading.Thread(target=down if phase == "down" else up, args=(i,), daemon=True) for i in range(n)]
        t0 = time.time()
        pt = threading.Thread(target=self.pinger, args=(lat, stop, phase, t0), daemon=True)
        for t in threads:
            t.start()
        pt.start()
        last_b, last_t, base = 0, t0, None
        while time.time() - t0 < secs and not self.stop and not refused:
            time.sleep(0.5)
            now, b = time.time(), sum(moved)
            bps = (b - last_b) * 8 / max(0.01, now - last_t)
            last_b, last_t = b, now
            with self.lock:
                self.run["points"].append([phase, round(now - t0, 2), round(bps)])
                self.run["live"] = {"phase": phase, "bps": round(bps)}
            if base is None and now - t0 >= 1.0:
                base = (now, b)       # skip the first second: TCP slow start
        stop.set()
        if refused:
            raise RuntimeError("Cloudflare is limiting tests from this public IP (429): wait a few minutes" if 429 in refused
                               else f"Cloudflare refused the test ({refused[0]})")
        end_t, end_b = time.time(), sum(moved)
        if base is None or end_b == 0:
            raise RuntimeError(errs[-1] if errs else "nothing moved")
        return (end_b - base[1]) * 8 / max(0.1, end_t - base[0]), lat, end_b

    # ---------- the whole test ----------
    def start(self):
        pass

    def begin(self, user):
        with self.lock:
            if self.run["running"]:
                raise ValueError("A test is already running")
            if self.p.speed.get("running"):
                raise ValueError("A LAN speed test is running")
            if not self.p.link["up"]:
                raise ValueError("No link")
            self.stop = False
            self.run = {"running": True, "phase": "meta", "points": [], "lat": [], "error": None, "started": time.time(), "live": None, "result": None}
        threading.Thread(target=self.go, args=(user,), daemon=True).start()

    def go(self, user):
        secs, n = int(self.conf["secs"]), int(self.conf["streams"])
        res = {"t": time.time(), "by": user, "secs": secs, "streams": n,
               "port": (self.p.neighbor or {}).get("port"), "switch": (self.p.neighbor or {}).get("switch")}
        try:
            res.update(self.meta())
            with self.lock:
                self.run["phase"] = "latency"
            ms = self.idle_latency()
            res["idle_pts"] = ms
            res["idle_ms"] = round(statistics.median(ms), 1)
            res["jitter_ms"] = round(statistics.mean(abs(a - b) for a, b in zip(ms[1:], ms[:-1])), 1) if len(ms) > 2 else None
            for phase in ("down", "up"):
                if self.stop:
                    raise RuntimeError("stopped")
                with self.lock:
                    self.run["phase"] = phase
                bps, lat, moved = self.streams(phase, secs, n)
                res[phase] = round(bps)
                res[f"{phase}_ms"] = round(statistics.median(lat), 1) if lat else None
                res[f"{phase}_bytes"] = moved
            res["ok"] = True
            with self.lock:
                res["pts"], res["lat"] = list(self.run["points"]), list(self.run["lat"])[:600]
        except Exception as e:
            res.update(ok=False, error=str(e)[:160])
        with self.lock:
            self.run.update(running=False, phase=None, result=res, error=res.get("error"), live=None)
            self.history = (self.history + [res])[-HIST_MAX:]
        save_json(self.hist_file, self.history)

    # ---------- for the page ----------
    def status(self):
        return {"dot": "live" if self.run["running"] else ""}

    def get(self, sub, arg, q, user):
        with self.lock:
            return {"run": dict(self.run), "history": self.history[::-1], "secs": self.conf["secs"], "streams": self.conf["streams"]}

    def post(self, action, body, user):
        if action == "start":
            if body:
                self.save_conf({k: body[k] for k in ("secs", "streams") if k in body})
            self.begin(user["name"])
            return {}
        if action == "stop":
            self.stop = True
            return {}
        if action == "clear":
            with self.lock:
                self.history = []
            save_json(self.hist_file, [])
            return {}
        return super().post(action, body, user)
