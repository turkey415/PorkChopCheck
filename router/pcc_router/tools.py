"""The router's tools, from the desktop app's Tools page: ping with the event timeline, the tick test,
the reflector, the speed test (iperf3), the port finder and the port log.

Each tool is a small object the service owns; the phone page starts and stops them and reads
state(). They use the same pc_net code as the desktop app: TickTest, Reflector, tick_summary and
its grades, run_iperf, event_impact, bucket_samples.
"""

import collections
import csv
import io
import os
import random
import socket
import struct
import subprocess
import threading
import time

import pc_net as N

PING_RATE = 4  # a second, as on the desktop
PING_KEEP = 30 * 60  # seconds of samples kept: the longest graph
SPANS = (30, 300, 1800)


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


# ---------- ping ----------
def icmp_checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def echo_request(ident, seq, payload=b"PorkChopCheck-ping"):
    head = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    return struct.pack("!BBHHH", 8, 0, icmp_checksum(head + payload), ident, seq) + payload


def parse_echo_reply(packet):
    """(ident, seq) from an IPv4 packet carrying an ICMP echo reply, else None."""
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    icmp = packet[ihl:]
    if len(icmp) < 8 or icmp[0] != 0:
        return None
    _, _, _, ident, seq = struct.unpack("!BBHHH", icmp[:8])
    return ident, seq


class Pinger:
    """Pings one target four times a second, from the WAN's address, and keeps half an hour."""

    def __init__(self, src_fn, target_fn):
        self.src_fn, self.target_fn = src_fn, target_fn  # functions: the WAN address, the target now
        self.samples = collections.deque()  # (time sent, rtt in ms or None)
        self.lock = threading.Lock()
        self.ident = random.randint(1, 0xFFFF)
        self.target = None

    def run(self, stop):
        seq, pending = 0, {}  # seq -> perf time sent, wall time sent
        sock, bound = None, None
        while not stop.is_set():
            target, src = self.target_fn(), self.src_fn()
            if target != self.target:
                with self.lock:
                    self.samples.clear()
                    self.target = target
                pending.clear()
            if not target or not src:
                time.sleep(1)
                continue
            if sock is None or bound != src:  # a new socket whenever the WAN's address changes
                if sock:
                    sock.close()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.settimeout(0.05)
                    sock.bind((src, 0))
                    bound = src
                except OSError:
                    sock = None
                    time.sleep(5)
                    continue
            seq = (seq + 1) & 0xFFFF
            sent = time.perf_counter()
            pending[seq] = (sent, time.time())
            try:
                sock.sendto(echo_request(self.ident, seq), (target, 0))
            except OSError:
                pass
            end = sent + 1.0 / PING_RATE
            while time.perf_counter() < end:
                try:
                    got = parse_echo_reply(sock.recv(2048))
                except (TimeoutError, OSError):
                    got = None
                if got and got[0] == self.ident and got[1] in pending:
                    t_perf, t_wall = pending.pop(got[1])
                    self._add(t_wall, (time.perf_counter() - t_perf) * 1000)
            for s in [s for s, (t, _) in pending.items() if time.perf_counter() - t > 1.0]:
                self._add(pending.pop(s)[1], None)  # no reply within a second: lost
        if sock:
            sock.close()

    def _add(self, t, rtt):
        with self.lock:
            self.samples.append((t, rtt))
            while self.samples and self.samples[0][0] < time.time() - PING_KEEP:
                self.samples.popleft()

    def state(self, span, events, cols=120):
        now = time.time()
        with self.lock:
            samples = sorted(self.samples)
        recent = [s for s in samples if s[0] >= now - span]
        rtts = [r for _, r in recent if r is not None]
        lost = len(recent) - len(rtts)
        jitter = sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1) if len(rtts) > 1 else None
        marks = []
        for e in events:
            if e["t"] >= now - span:
                imp = N.event_impact(samples, e["t"])
                marks.append({**e, "impact": N.impact_text(imp), "hit": bool(imp and imp["hit"])})
        return {
            "target": self.target, "span": span, "sent": len(recent), "lost": lost,
            "loss_pct": round(100 * lost / len(recent), 2) if recent else None,
            "avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
            "p99": N.percentile(rtts, 99), "jitter": round(jitter, 2) if jitter is not None else None,
            "last": recent[-1][1] if recent else None,
            "cols": N.bucket_samples(recent, now, span, cols), "events": marks,
        }  # fmt: skip


# ---------- tick test and reflector ----------
class Tick:
    """One tick test at a time: game-rate UDP to a reflector, graded for Counter-Strike."""

    def __init__(self):
        self.test, self.info, self.lock = None, {}, threading.Lock()

    def start(self, src, server, rate=64, secs=30):
        host, port = N.parse_tick_server(server)
        self.stop()
        self.warm_up(src, host, port)
        test = N.TickTest(src, host, port, rate)
        test.start()
        with self.lock:
            self.test = test
            self.info = {"server": f"{host}:{port}", "rate": rate, "secs": secs, "started": time.time(), "running": True}
        threading.Timer(secs, self.finish, args=(test,)).start()

    @staticmethod
    def warm_up(src, host, port):
        """One packet the reflector ignores (no test marker), and a moment's wait, so the first test
        packets are not lost while the two ends look up each other's MAC address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                if src:
                    s.bind((src, 0))
                s.sendto(b"PorkChopCheck warm-up", (host, port))
        except OSError:
            pass
        time.sleep(0.3)

    def finish(self, test):
        if test is self.test:
            self.stop()

    def stop(self):
        with self.lock:
            if self.test:
                self.test.stop()
                self.info["running"] = False
                self.info["ended"] = time.time()

    def state(self):
        with self.lock:
            test, info = self.test, dict(self.info)
        if not test:
            return {"running": False}
        rate = info["rate"]
        end = info.get("ended") or time.time()
        s = N.tick_summary(test.buf.samples(end), rate)
        head, grade = N.tick_verdict(s, rate)
        holds = N.hold_summary(test.buf.holds(info["started"]), rate)
        lost_at = [round(ts - info["started"], 2) for ts, rtt in test.buf.samples(end) if rtt is None][:20]
        return {
            **info, "summary": s, "headline": head, "grade": grade, "error": test.error,
            "ratings": [{"key": k, "label": N.TICK_LABELS[k], "value": v, "grade": g} for k, v, g in N.tick_ratings(s, rate)],
            "holds": holds, "hold_mode": test.buf.hold_mode, "counters": test.buf.counters(),
            "pace_ms": round(test.pace_err, 2), "lost_at": lost_at,
        }  # fmt: skip


class ReflectorTool:
    """The far end of a tick test, on the router: one router at the game server, another at a seat.
    The WAN firewall is opened for its UDP port only while it runs."""

    RULE = "pcc_reflector"

    def __init__(self, port=N.TICK_PORT):
        self.port, self.ref = port, None

    def _firewall(self, open_):
        if open_:
            for cmd in (f"set firewall.{self.RULE}=rule", f"set firewall.{self.RULE}.name=PorkChopCheck-reflector",
                        f"set firewall.{self.RULE}.src=wan", f"set firewall.{self.RULE}.proto=udp",
                        f"set firewall.{self.RULE}.dest_port={self.port}", f"set firewall.{self.RULE}.target=ACCEPT"):  # fmt: skip
                run(["uci"] + cmd.split(" ", 1))
        else:
            run(["uci", "-q", "delete", f"firewall.{self.RULE}"])
        run(["uci", "commit", "firewall"])
        run(["/etc/init.d/firewall", "reload"], timeout=30)

    def set(self, on):
        if on and not self.ref:
            self.ref = N.Reflector(self.port)
            self.ref.start()
            self._firewall(True)
        elif not on and self.ref:
            self.ref.stop()
            self.ref = None
            self._firewall(False)

    def tidy(self):
        """At start: no rule left open from a run that ended badly."""
        if not self.ref:
            out = run(["uci", "-q", "get", f"firewall.{self.RULE}"])
            if out and out.returncode == 0:
                self._firewall(False)

    def state(self):
        if not self.ref:
            return {"on": False, "port": self.port}
        now = time.time()
        return {"on": True, "port": self.port, "answered": self.ref.count,
                "peers": sorted(ip for ip, t in self.ref.peers.items() if now - t < 60)}  # fmt: skip


# ---------- speed test ----------
class Speed:
    def __init__(self):
        self.info, self.lock = {"running": False}, threading.Lock()

    def start(self, src, server, port=5201, secs=5):
        with self.lock:
            if self.info.get("running"):
                return
            self.info = {"running": True, "server": f"{server}:{port}", "started": time.time()}
        threading.Thread(target=self._run, args=(src, server, port, secs), daemon=True).start()

    def _run(self, src, server, port, secs):
        up, up_retr, err = N.run_iperf("iperf3", server, src, reverse=False, secs=secs, port=port)
        down, _, err2 = (None, None, err) if err else N.run_iperf("iperf3", server, src, reverse=True, secs=secs, port=port)
        with self.lock:
            self.info.update(running=False, ended=time.time(), error=err or err2,
                             up_mbps=round(up / 1e6, 1) if up else None,
                             down_mbps=round(down / 1e6, 1) if down else None, retransmits=up_retr)  # fmt: skip

    def state(self):
        with self.lock:
            return dict(self.info)


# ---------- port finder ----------
class Blink:
    """Blinks the switch port's link LED: the WAN link down for 1.5 s, then up until the link is
    really back (about 3 s on the Slate 7, which is longer than the desktop's fixed 3 s) and for 2 s
    after, until stopped. Like a toner, but for switch ports. The tester ignores these link changes."""

    UP_FOR = 2.0  # seconds the link stays up once it is back, so the LED is plainly on
    UP_WAIT = 10.0  # most to wait for the link to come back

    def __init__(self, iface, tester):
        self.iface, self.tester = iface, tester
        self.stop_ev, self.cycles, self.running = threading.Event(), 0, False

    def set(self, on):
        if on and not self.running:
            self.stop_ev = threading.Event()
            self.running, self.cycles = True, 0
            self.tester.blinking = True
            threading.Thread(target=self._run, args=(self.stop_ev,), daemon=True).start()
        elif not on:
            self.stop_ev.set()

    def _run(self, stop):
        try:
            while not stop.is_set():
                run(["ip", "link", "set", self.iface, "down"])
                stop.wait(1.5)
                run(["ip", "link", "set", self.iface, "up"])
                back = time.monotonic() + self.UP_WAIT
                while not self.carrier() and time.monotonic() < back and not stop.is_set():
                    stop.wait(0.1)
                self.cycles += 1
                stop.wait(self.UP_FOR)
        finally:
            run(["ip", "link", "set", self.iface, "up"])
            self.running = False
            threading.Timer(8, self._done).start()  # let the link and DHCP settle first

    def carrier(self):
        try:
            with open(f"/sys/class/net/{self.iface}/carrier") as f:
                return f.read().strip() == "1"
        except OSError:
            return False

    def _done(self):
        if not self.running:
            self.tester.blinking = False

    def state(self):
        return {"running": self.running, "cycles": self.cycles}


# ---------- port log ----------
LOG_FIELDS = ["time", "switch", "port", "vlan", "voice_vlan", "speed", "duplex", "address", "gateway_ms",
              "internet", "verdict", "findings", "label"]  # fmt: skip


class PortLog:
    """One row per switch + port, updated whenever CDP/LLDP names it (data/ports.csv on the desktop),
    and history.csv with every save. Kept in /etc/pcc-router so it survives a reboot."""

    def __init__(self, folder):
        self.ports_path = os.path.join(folder, "ports.csv")
        self.history_path = os.path.join(folder, "history.csv")
        self.lock = threading.Lock()
        self.rows = self._read()
        self.last_key = None

    def _read(self):
        try:
            with open(self.ports_path, newline="") as f:
                return {(r["switch"], r["port"]): r for r in csv.DictReader(f)}
        except OSError:
            return {}

    def _write(self):
        tmp = self.ports_path + ".tmp"
        with open(tmp, "w", newline="") as f:
            w = csv.DictWriter(f, LOG_FIELDS)
            w.writeheader()
            for r in sorted(self.rows.values(), key=lambda r: r["time"], reverse=True):
                w.writerow({k: r.get(k, "") for k in LOG_FIELDS})
        os.replace(tmp, self.ports_path)

    @staticmethod
    def row(snap, label=""):
        sw, link, wan, gw = snap["switch"], snap["link"], snap["wan"], snap["checks"].get("gateway") or {}
        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"), "switch": sw.get("name") or "", "port": sw.get("port") or "",
            "vlan": "" if sw.get("vlan") is None else str(sw["vlan"]),
            "voice_vlan": "" if sw.get("voice_vlan") is None else str(sw["voice_vlan"]),
            "speed": str(link.get("speed") or ""), "duplex": link.get("duplex") or "", "address": wan.get("address") or "",
            "gateway_ms": f"{gw['ms']:.1f}" if gw.get("ok") and gw.get("ms") is not None else "",
            "internet": "yes" if (snap["checks"].get("internet") or {}).get("ok") else "no",
            "verdict": snap["verdict"], "findings": "; ".join(t for _, t in snap["findings"]), "label": label,
        }  # fmt: skip

    def auto(self, snap):
        """Log the port when CDP/LLDP first names it, keeping any label saved before."""
        sw = snap["switch"]
        if not sw.get("heard") or not sw.get("port"):
            return
        key = (sw.get("name") or "", sw["port"])
        if key == self.last_key:
            return
        with self.lock:
            self.last_key = key
            old = self.rows.get(key, {})
            self.rows[key] = {**self.row(snap), "label": old.get("label", "")}
            self._write()

    def save(self, snap, label):
        """The port now, with a label, in both files. Without CDP/LLDP it is logged by address."""
        with self.lock:
            r = self.row(snap, label.strip()[:120])
            key = (r["switch"] or "(no CDP/LLDP)", r["port"] or r["address"] or "?")
            r["switch"], r["port"] = key
            self.rows[key] = r
            self._write()
            new = not os.path.exists(self.history_path)
            with open(self.history_path, "a", newline="") as f:
                w = csv.DictWriter(f, LOG_FIELDS)
                if new:
                    w.writeheader()
                w.writerow(r)
            return r

    def list(self):
        with self.lock:
            return sorted(self.rows.values(), key=lambda r: r["time"], reverse=True)

    def csv_text(self):
        out = io.StringIO()
        w = csv.DictWriter(out, LOG_FIELDS)
        w.writeheader()
        for r in self.list():
            w.writerow({k: r.get(k, "") for k in LOG_FIELDS})
        return out.getvalue()
