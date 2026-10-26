"""System stats: what the probe itself is doing. CPU per core, clocks and throttling, every temperature
sensor with its trip points, memory and swap, the SD card, every network interface, and the busiest
processes. Read straight from /proc and /sys every 2 s; the last 10 minutes are kept for the charts.

Nothing here touches the network.
"""
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from appbase import App

STEP = 2.0                  # seconds between samples
KEEP = 300                  # samples kept: 10 minutes
PAGE = os.sysconf("SC_PAGE_SIZE")
HZ = os.sysconf("SC_CLK_TCK")
SYS = Path("/sys")


def rd(path, default=None):
    try:
        return Path(path).read_text().strip()
    except (OSError, ValueError):
        return default


def num(path, scale=1, default=None):
    v = rd(path)
    try:
        return int(v) / scale
    except (TypeError, ValueError):
        return default


def cpu_times():
    """{'cpu': (busy, total, iowait), 'cpu0': …} from /proc/stat."""
    out = {}
    for line in (rd("/proc/stat", "") or "").splitlines():
        if not line.startswith("cpu"):
            continue
        f = line.split()
        v = [int(x) for x in f[1:9]]
        idle = v[3] + v[4]
        out[f[0]] = (sum(v) - idle, sum(v), v[4])
    return out


def meminfo():
    return {k: int(v) * 1024 for k, v in re.findall(r"(\w+):\s+(\d+) kB", rd("/proc/meminfo", "") or "")}


def netdev():
    out = {}
    for line in (rd("/proc/net/dev", "") or "").splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 16:
            out[name.strip()] = {"rx": int(f[0]), "rxp": int(f[1]), "rxe": int(f[2]), "rxd": int(f[3]),
                                 "tx": int(f[8]), "txp": int(f[9]), "txe": int(f[10]), "txd": int(f[11])}
    return out


def diskstats():
    """Bytes read and written per whole disk (mmcblk0, sda…), skipping partitions and ram/loop/zram."""
    out = {}
    for line in (rd("/proc/diskstats", "") or "").splitlines():
        f = line.split()
        if len(f) < 10:
            continue
        name = f[2]
        if re.match(r"(loop|ram|zram|dm-)", name) or re.search(r"(mmcblk\d+p\d+|[a-z]d[a-z]\d+|nvme\d+n\d+p\d+)$", name):
            continue
        if not (SYS / "block" / name).exists():
            continue
        out[name] = {"r": int(f[5]) * 512, "w": int(f[9]) * 512, "busy_ms": int(f[12]) if len(f) > 12 else 0}
    return out


def proc_list():
    """{pid: (name, cpu_ticks, rss_bytes, threads)} for every process."""
    out = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                s = f.read()
            name = s[s.index("(") + 1:s.rindex(")")]
            rest = s[s.rindex(")") + 2:].split()
            ticks = int(rest[11]) + int(rest[12])
            threads = int(rest[17])
            rss = int(rest[21]) * PAGE
        except (OSError, ValueError, IndexError):
            continue
        out[int(d)] = (name, ticks, rss, threads)
    return out


def proc_label(pid, name):
    """A friendlier name: python scripts show the script, not 'python3'."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            args = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
    except OSError:
        return name
    if args and re.match(r"python", os.path.basename(args[0])):
        for a in args[1:]:
            if a in ("-c", "-m"):
                return f"{name} {a}"
            if not a.startswith("-"):
                return os.path.basename(a)
    return name


class Stats(App):
    name = "stats"

    def __init__(self, probe, conf_dir, data_dir):
        super().__init__(probe, conf_dir, data_dir)
        self.hist = []           # [t, cpu%, temp, mem_used, rx_bps, tx_bps, disk_r_bps, disk_w_bps]
        self.cur = {}
        self.static = self.read_static()
        self.watched = 0         # last time the page asked; processes are only tracked while someone looks
        self.prev = None
        self.prev_procs = None
        self.ntp = None
        self.ntp_at = 0

    # ---------- things that don't change ----------
    def read_static(self):
        osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', rd("/etc/os-release", "") or "", re.M))
        cores = sorted((int(m.group(1)) for p in (SYS / "devices/system/cpu").glob("cpu[0-9]*") if (m := re.match(r"cpu(\d+)$", p.name))))
        parts = {"0xd03": "Cortex-A53", "0xd04": "Cortex-A35", "0xd05": "Cortex-A55", "0xd07": "Cortex-A57", "0xd08": "Cortex-A72", "0xd0b": "Cortex-A76"}
        cpuinfo = rd("/proc/cpuinfo", "") or ""
        m = re.search(r"CPU part\s*:\s*(0x[0-9a-f]+)", cpuinfo)
        mn = re.search(r"model name\s*:\s*(.+)", cpuinfo)
        cpu = parts.get(m.group(1), m.group(1)) if m else (mn.group(1).strip() if mn else "?")
        f0 = SYS / "devices/system/cpu/cpu0/cpufreq"
        sd = {}
        for dev in sorted((SYS / "block").glob("mmcblk[0-9]")):
            sd[dev.name] = {"name": rd(dev / "device/name"), "type": rd(dev / "device/type"), "date": rd(dev / "device/date"),
                            "size": (num(dev / "size") or 0) * 512}
        un = os.uname()
        return {"model": (rd("/proc/device-tree/model") or "").strip("\0 ") or None, "cpu": cpu, "cores": len(cores),
                "os": osr.get("PRETTY_NAME"), "kernel": un.release, "arch": un.machine,
                "freq_min": num(f0 / "cpuinfo_min_freq", 1000), "freq_max": num(f0 / "cpuinfo_max_freq", 1000),
                "governor": rd(f0 / "scaling_governor"), "cards": sd}

    # ---------- sampling ----------
    def start(self):
        while True:
            t0 = time.monotonic()
            try:
                self.sample()
            except Exception as e:  # keep sampling whatever one reading does
                print(f"stats: {e}", flush=True)
            time.sleep(max(0.2, STEP - (time.monotonic() - t0)))

    def temps(self):
        out = []
        for z in sorted(SYS.glob("class/thermal/thermal_zone*")):
            c = num(z / "temp", 1000)
            if c is None:
                continue
            trips = []
            for tp in sorted(z.glob("trip_point_*_temp")):
                tt = num(tp, 1000)
                kind = rd(str(tp).replace("_temp", "_type"))
                if tt and tt > 0 and kind in ("passive", "hot", "critical"):
                    trips.append({"c": tt, "type": kind})
            name = (rd(z / "type") or z.name).replace("-thermal", "").replace("_thermal", "")
            out.append({"name": name, "c": round(c, 1), "trips": trips})
        return out

    def fans(self):
        out = []
        for h in SYS.glob("class/hwmon/hwmon*"):
            for f in sorted(h.glob("fan*_input")):
                out.append({"name": f"{rd(h / 'name')} {f.name[:-6]}", "rpm": num(f)})
            for f in sorted(h.glob("pwm[0-9]")):
                v = num(f)
                if v is not None:
                    out.append({"name": f"{rd(h / 'name')} {f.name}", "pwm": round(v / 255 * 100)})
        return out

    def cooling(self):
        out = []
        for c in sorted(SYS.glob("class/thermal/cooling_device*")):
            cur, mx = num(c / "cur_state"), num(c / "max_state")
            if mx:
                out.append({"name": rd(c / "type"), "cur": int(cur or 0), "max": int(mx)})
        return out

    def sample(self):
        now = time.time()
        ct, nd, ds = cpu_times(), netdev(), diskstats()
        mem = meminfo()
        cores = sorted((k for k in ct if k != "cpu"), key=lambda k: int(k[3:]))
        freqs = [num(SYS / f"devices/system/cpu/{c}/cpufreq/scaling_cur_freq", 1000) for c in cores]
        temps = self.temps()
        cpu_temp = next((t["c"] for t in temps if "cpu" in t["name"].lower()), temps[0]["c"] if temps else None)
        cur = {"t": now, "temps": temps, "fans": self.fans(), "cooling": self.cooling(), "freqs": freqs}
        prev = self.prev
        dt = now - prev["t"] if prev else 0
        if prev and dt > 0:
            def pct(k):
                a, b = ct.get(k), prev["ct"].get(k)
                if not a or not b or a[1] == b[1]:
                    return None
                return round(100 * (a[0] - b[0]) / (a[1] - b[1]), 1)
            cur["cpu"] = pct("cpu")
            a, b = ct.get("cpu"), prev["ct"].get("cpu")
            cur["iowait"] = round(100 * (a[2] - b[2]) / (a[1] - b[1]), 1) if a and b and a[1] != b[1] else None
            cur["cores"] = [pct(c) for c in cores]
            ifs = []
            for name, v in nd.items():
                p = prev["nd"].get(name)
                if not p:
                    continue
                d = SYS / "class/net" / name
                spd = num(d / "speed")
                ifs.append({"name": name, "state": rd(d / "operstate"), "speed": spd if spd and spd > 0 else None,
                            "mac": rd(d / "address"), "mtu": num(d / "mtu"),
                            "rx_bps": max(0, (v["rx"] - p["rx"]) * 8 / dt), "tx_bps": max(0, (v["tx"] - p["tx"]) * 8 / dt),
                            "rx_pps": max(0, (v["rxp"] - p["rxp"]) / dt), "tx_pps": max(0, (v["txp"] - p["txp"]) / dt),
                            "rx": v["rx"], "tx": v["tx"], "errors": v["rxe"] + v["txe"], "drops": v["rxd"] + v["txd"]})
            cur["ifaces"] = ifs
            disks = []
            for name, v in ds.items():
                p = prev["ds"].get(name)
                if p:
                    disks.append({"name": name, "r_bps": max(0, (v["r"] - p["r"]) / dt), "w_bps": max(0, (v["w"] - p["w"]) / dt),
                                  "busy": min(100, round((v["busy_ms"] - p["busy_ms"]) / (dt * 10), 1)), "r": v["r"], "w": v["w"]})
            cur["disks"] = disks
        total, avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
        cur["mem"] = {"total": total, "avail": avail, "used": total - avail, "free": mem.get("MemFree", 0),
                      "cache": mem.get("Cached", 0) + mem.get("Buffers", 0) + mem.get("SReclaimable", 0), "shmem": mem.get("Shmem", 0),
                      "swap_total": mem.get("SwapTotal", 0), "swap_used": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)}
        if self.watched and now - self.watched < 30:
            procs = proc_list()
            if self.prev_procs and dt > 0:
                pp = self.prev_procs
                top = []
                for pid, (name, ticks, rss, thr) in procs.items():
                    was = pp.get(pid)
                    used = (ticks - was[1]) / HZ / dt * 100 if was and was[0] == name else 0
                    top.append((used, rss, pid, name, thr))
                cur["procs"] = {"count": len(procs), "threads": sum(p[3] for p in procs.values()),
                                "top": [{"pid": pid, "name": proc_label(pid, name), "cpu": round(c, 1), "rss": rss, "threads": thr}
                                        for c, rss, pid, name, thr in sorted(top, reverse=True)[:8]]}
            self.prev_procs = procs
        else:
            self.prev_procs = None
        with self.lock:
            self.prev = {"t": now, "ct": ct, "nd": nd, "ds": ds}
            if "cpu" in cur:
                eth = next((i for i in cur["ifaces"] if i["name"] == getattr(self.p, "iface", "eth0")), None) \
                    or next((i for i in cur["ifaces"] if i["name"] != "lo"), None)
                dk = cur["disks"][0] if cur["disks"] else {}
                self.hist.append([now, cur["cpu"], cpu_temp, cur["mem"]["used"], eth["rx_bps"] if eth else 0, eth["tx_bps"] if eth else 0,
                                  dk.get("r_bps", 0), dk.get("w_bps", 0)])
                del self.hist[:-KEEP]
            if "procs" not in cur and "procs" in self.cur and self.prev_procs is not None:
                cur["procs"] = self.cur["procs"]
            self.cur = cur

    # ---------- slow readings ----------
    def ntp_state(self):
        if time.time() - self.ntp_at > 60:
            self.ntp_at = time.time()
            try:
                out = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone"], capture_output=True, text=True, timeout=5).stdout
                d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
                self.ntp = {"synced": d.get("NTPSynchronized") == "yes", "tz": d.get("Timezone")}
            except (OSError, subprocess.SubprocessError):
                self.ntp = None
        return self.ntp

    def filesystems(self):
        out, seen = [], set()
        for line in (rd("/proc/mounts", "") or "").splitlines():
            f = line.split()
            if len(f) < 3 or not f[0].startswith("/dev/") or f[0].startswith("/dev/loop") or f[2] in ("squashfs", "iso9660") or f[0] in seen:
                continue
            seen.add(f[0])
            try:
                st = os.statvfs(f[1])
            except OSError:
                continue
            total = st.f_blocks * st.f_frsize
            if total:
                out.append({"dev": f[0], "mount": f[1], "fs": f[2], "total": total, "free": st.f_bavail * st.f_frsize,
                            "used": (st.f_blocks - st.f_bfree) * st.f_frsize, "ro": "ro" in f[3].split(",")})
        return out

    def zram(self):
        out = []
        for z in sorted(SYS.glob("block/zram*")):
            size = num(z / "disksize") or 0
            if size:
                mm = (rd(z / "mm_stat") or "").split()
                out.append({"name": z.name, "size": size, "data": int(mm[0]) if mm else None, "compressed": int(mm[1]) if len(mm) > 1 else None})
        return out

    def swaps(self):
        out = []
        for line in (rd("/proc/swaps", "") or "").splitlines()[1:]:
            f = line.split()
            if len(f) >= 4:
                out.append({"name": f[0], "type": f[1], "size": int(f[2]) * 1024, "used": int(f[3]) * 1024})
        return out

    # ---------- for the page ----------
    def status(self):
        c = self.cur
        if not c:
            return None
        worst = 0
        for t in c.get("temps", []):
            passive = min((x["c"] for x in t["trips"] if x["type"] == "passive"), default=70)
            worst = max(worst, 2 if t["c"] >= passive + 10 else 1 if t["c"] >= passive - 5 else 0)
        m = c.get("mem", {})
        if m.get("total"):
            u = m["used"] / m["total"]
            worst = max(worst, 2 if u > .95 else 1 if u > .85 else 0)
        if any(d["cur"] for d in c.get("cooling", [])):
            worst = max(worst, 1)
        return {"dot": ["on", "warn", "err"][worst]}

    def get(self, sub, arg, query, user):
        if sub:
            raise ValueError("not found")
        now = time.time()
        first = not self.watched or now - self.watched > 30
        self.watched = now
        with self.lock:
            cur, hist = dict(self.cur), list(self.hist)
        try:
            up = float(rd("/proc/uptime", "0").split()[0])
            load = [float(x) for x in rd("/proc/loadavg", "0 0 0").split()[:3]]
        except (ValueError, AttributeError):
            up, load = None, []
        return {"now": now, "first": first, "static": self.static, "cur": cur, "hist": hist, "step": STEP,
                "uptime": up, "load": load, "boot": now - up if up else None, "ntp": self.ntp_state(),
                "fs": self.filesystems(), "swaps": self.swaps(), "zram": self.zram()}
