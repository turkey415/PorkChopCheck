"""Wake-on-LAN panel: saved machines, magic packets, staggered "wake all", and who's up.

A machine is "up" when it answers ping. With no IP saved, the Watchdog's ARP table supplies one.
Waking many at once is staggered so 30 gaming PCs don't hit the breakers in the same second.
"""
import json
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

MAX_HOSTS = 256
DEFAULTS = {"wol_stagger": 2.0}
MAC_RE = re.compile(r"([0-9a-f]{2})[:\-.]?([0-9a-f]{2})[:\-.]?([0-9a-f]{2})[:\-.]?([0-9a-f]{2})[:\-.]?([0-9a-f]{2})[:\-.]?([0-9a-f]{2})")
IP_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")


def norm_mac(text):
    m = MAC_RE.fullmatch(str(text).strip().lower())
    if not m:
        raise ValueError(f"Not a MAC address: {str(text)[:30]}")
    mac = ":".join(m.groups())
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or int(mac[:2], 16) & 1:
        raise ValueError(f"{mac} can't be a computer's MAC")
    return mac


def norm_ip(text):
    v = str(text or "").strip()
    if v and not (IP_RE.fullmatch(v) and all(int(x) < 256 for x in v.split("."))):
        raise ValueError(f"Not an IPv4 address: {v[:30]}")
    return v or None


class Wake:
    def __init__(self, probe, iface, data_dir, watchdog=None):
        self.p = probe
        self.iface = iface
        self.file = os.path.join(data_dir, "wol.json")
        self.watch = watchdog
        self.lock = threading.Lock()
        self.hosts = []
        try:
            with open(self.file) as f:
                self.hosts = [h for h in json.load(f) if isinstance(h, dict) and "mac" in h][:MAX_HOSTS]
        except (OSError, ValueError):
            pass
        self.state = {}       # id -> {"up", "ms", "seen", "ip", "learned"}
        self.waking = {}      # id -> {"t", "up_in"}
        self.job = None
        self.pool = ThreadPoolExecutor(32)
        threading.Thread(target=self.ping_loop, daemon=True).start()

    def save(self):
        tmp = self.file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.hosts, f, indent=1)
        os.replace(tmp, self.file)

    # ---------- the list ----------
    def upsert(self, body):
        name = re.sub(r"[^\w .\-#()]", "", str(body.get("name") or ""))[:32].strip()
        mac = norm_mac(body.get("mac"))
        ip = norm_ip(body.get("ip"))
        group = re.sub(r"[^\w .\-#]", "", str(body.get("group") or ""))[:20].strip() or None
        bcast = norm_ip(body.get("bcast"))
        hid = str(body.get("id") or "")
        with self.lock:
            other = next((h for h in self.hosts if h["mac"] == mac and h["id"] != hid), None)
            if other:
                raise ValueError(f"{mac} is already saved as {other['name']}")
            h = next((h for h in self.hosts if h["id"] == hid), None) if hid else None
            if not h:
                if len(self.hosts) >= MAX_HOSTS:
                    raise ValueError(f"At most {MAX_HOSTS} machines")
                h = {"id": uuid.uuid4().hex[:10]}
                self.hosts.append(h)
            h.update(name=name or mac, mac=mac, ip=ip, group=group, bcast=bcast)
            self.save()
        return h["id"]

    def delete(self, hid):
        with self.lock:
            self.hosts = [h for h in self.hosts if h["id"] != hid]
            self.state.pop(hid, None)
            self.save()

    def import_text(self, text):
        """One machine per line: name, MAC[, IP][, group]. Also takes "MAC name" and CSV with a header."""
        added, errors = 0, []
        for n, line in enumerate(str(text).splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in re.split(r"[,;\t]", line)] if re.search(r"[,;\t]", line) else line.split()
            mac_i = next((i for i, x in enumerate(parts) if MAC_RE.fullmatch(x.lower())), None)
            if mac_i is None:
                if n == 1:
                    continue  # header row
                errors.append(f"line {n}: no MAC")
                continue
            rest = parts[:mac_i] + parts[mac_i + 1:]
            ip = next((x for x in rest if IP_RE.fullmatch(x)), None)
            others = [x for x in rest if x and x != ip]
            try:
                mac = norm_mac(parts[mac_i])
                with self.lock:
                    have = next((h for h in self.hosts if h["mac"] == mac), None)
                self.upsert({"id": have and have["id"], "name": others[0] if others else (have or {}).get("name", ""),
                             "mac": mac, "ip": ip or (have or {}).get("ip"),
                             "group": others[1] if len(others) > 1 else (have or {}).get("group")})
                added += 1
            except ValueError as e:
                errors.append(f"line {n}: {e}")
            if len(errors) > 20:
                break
        return {"added": added, "errors": errors[:20]}

    # ---------- magic packets ----------
    def targets(self, h):
        out = {"255.255.255.255"}
        bc = self.p.net.get("broadcast")
        if bc:
            out.add(bc)
        if h.get("bcast"):
            out.add(h["bcast"])  # another subnet: needs 'ip directed-broadcast' on that VLAN's interface
        return out

    def magic(self, h):
        mac = bytes.fromhex(h["mac"].replace(":", ""))
        pkt = b"\xff" * 6 + mac * 16
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface.encode())
            except OSError:
                pass  # not root (testing on a PC): the default route will do
            sent = 0
            for _ in range(3):
                for dst in self.targets(h):
                    for port in (9, 7):
                        try:
                            s.sendto(pkt, (dst, port))
                            sent += 1
                        except OSError:
                            pass
                time.sleep(0.05)
            return sent
        finally:
            s.close()

    def wake(self, ids=None, mac=None):
        if mac:  # a one-off MAC that isn't saved
            h = {"id": "adhoc", "name": norm_mac(mac), "mac": norm_mac(mac)}
            if not self.magic(h):
                raise ValueError("Couldn't send the magic packet")
            return
        with self.lock:
            hosts = [h for h in self.hosts if not ids or h["id"] in ids]
            if self.job and not self.job.get("done_at"):
                raise ValueError("A wake run is going already")
        if not hosts:
            raise ValueError("Nothing to wake")
        if len(hosts) == 1:
            self.wake_one(hosts[0])
            return
        self.job = {"total": len(hosts), "done": 0, "cancel": False, "done_at": None, "started": time.time(),
                    "stagger": float(self.p.conf.get("wol_stagger", 2))}
        threading.Thread(target=self.wake_run, args=(hosts, self.job), daemon=True).start()

    def wake_one(self, h):
        if not self.magic(h):
            raise ValueError("Couldn't send the magic packet")
        st = self.state.get(h["id"]) or {}
        with self.lock:
            # Boot time only counts if the machine was seen down: one that was already on didn't boot.
            self.waking[h["id"]] = {"t": time.time(), "up_in": None, "down": st.get("up") is False}

    def wake_run(self, hosts, job):
        for i, h in enumerate(hosts):
            if job["cancel"]:
                break
            try:
                self.wake_one(h)
            except ValueError:
                pass
            job["done"] = i + 1
            if i < len(hosts) - 1:
                t0 = time.time()
                while time.time() - t0 < job["stagger"] and not job["cancel"]:
                    time.sleep(0.1)
        job["done_at"] = time.time()

    def stop(self):
        if self.job:
            self.job["cancel"] = True

    # ---------- who's up ----------
    def ip_of(self, h):
        if h.get("ip"):
            return h["ip"], False
        learned = self.watch.ip_for(h["mac"]) if self.watch else None
        return learned, bool(learned)

    def ping(self, ip):
        out = subprocess.run(["ping", "-n", "-c1", "-W1", ip], capture_output=True, text=True).stdout
        m = re.search(r"time[=<]([\d.]+) ms", out)
        return float(m.group(1)) if m else None

    def check(self, h):
        ip, learned = self.ip_of(h)
        st = {"ip": ip, "learned": learned, "up": None, "ms": None}
        if ip and self.p.link["up"]:
            ms = self.ping(ip)
            st.update(up=ms is not None, ms=ms)
        now = time.time()
        with self.lock:
            prev = self.state.get(h["id"], {})
            st["seen"] = now if st["up"] else prev.get("seen")
            self.state[h["id"]] = st
            w = self.waking.get(h["id"])
            if w and st["up"] is False:
                w["down"] = True
            if w and st["up"] and w["up_in"] is None and w["down"]:
                w["up_in"] = round(now - w["t"])
            if w and now - w["t"] > 600:
                self.waking.pop(h["id"], None)

    def ping_loop(self):
        n = 0
        while True:
            with self.lock:
                hosts = list(self.hosts)
                waking = set(self.waking)
            # Machines being woken get checked every 2 s (to time the boot), the rest every 10 s.
            due = [h for h in hosts if h["id"] in waking or n % 5 == 0]
            list(self.pool.map(self.check, due))
            n += 1
            time.sleep(2)

    def snapshot(self):
        now = time.time()
        with self.lock:
            hosts = []
            for h in self.hosts:
                st = self.state.get(h["id"], {})
                w = self.waking.get(h["id"])
                hosts.append({**h, **{k: st.get(k) for k in ("up", "ms", "seen", "learned")}, "cur_ip": st.get("ip"),
                              "waking": {"ago": round(now - w["t"]), "up_in": w["up_in"]} if w else None})
            saved = {h["mac"] for h in self.hosts}
        seen = [s for s in (self.watch.seen_hosts() if self.watch else []) if s["mac"] not in saved][:60]
        job = self.job
        return {"hosts": hosts, "job": {k: job[k] for k in ("total", "done", "done_at", "stagger")} if job else None,
                "stagger": self.p.conf.get("wol_stagger", 2), "seen": seen}
