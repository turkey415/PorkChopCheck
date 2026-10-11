#!/usr/bin/env python3
"""
PorkChopCheck - a big-text, touch-friendly switch-port tester for Windows and Linux (Nobara/Fedora).

Pages:  PORT    link, speed/duplex, IP, gateway, DHCP, DNS, time-to-IP, internet
        SWITCH  CDP/LLDP neighbor: switch, port, VLAN, voice VLAN, mgmt IP, model, PoE
        L2      802.1X, spanning tree, trunk/DTP, DHCP servers, phone options, gateway MAC,
                IPv6, broadcast rate
        SMART   every smart-home device on the network: brand, type, model, serial, IP, MAC
        STATS   MAC, adapter, errors, discards, throughput, link drops
        TOOLS   ping, traceroute, speed test (iperf3 / internet), ARP table, ARP scan,
                mDNS browser, switches (SNMP), port finder, port log, re-run checks, settings
        SAVE    log this port (with an optional label) to data/ports.csv

Run:   Windows: double-click porkchopcheck.py (asks for admin once, opens fullscreen)
       Linux:   ./install-linux.sh once, then launch "PorkChopCheck" from the app menu
       python porkchopcheck.py --windowed --size 800x480   |   --fullscreen
       python porkchopcheck.py --demo      (fake data, to preview the screens)
Keys:  1-5 pages  S save  R renew  A next adapter  F11 fullscreen  Esc back  Q quit
Needs: Python 3.10+, psutil, scapy (+ Npcap on Windows). pc_net.py, pc_smart.py and pc_snmp.py
       must sit next to this file.
"""

import collections
import copy
import ipaddress
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time

FROZEN = getattr(sys, "frozen", False)          # running as the PyInstaller .exe
SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))


def _crash_log(text):
    """Append to crash.log next to the app, or under ~/Documents/PorkChopCheck when the app
    folder is read-only (the Linux install in /opt)."""
    for d in (SCRIPT_DIR, os.path.join(os.path.expanduser("~"), "Documents", "PorkChopCheck")):
        try:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "crash.log"), "a", encoding="utf-8") as f:
                f.write(text)
            return
        except OSError:
            continue


def _fatal(msg):
    """Show a startup error even without a console (pythonw / .exe), and keep it in crash.log."""
    _crash_log(time.strftime("%Y-%m-%d %H:%M:%S  ") + msg + "\n\n")
    print(msg, file=sys.stderr)
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, msg[:1500], "PorkChopCheck", 0x10)
        except Exception:  # noqa: BLE001
            pass
    sys.exit(1)


def _use_private_python():
    """Linux: an installed copy always runs through pcc-launch, which is the only thing holding
    the capture permission (see linux/pcc-launch.c). Starting the file directly, e.g. by
    double-clicking it, hands over to the launcher. A source checkout with a .venv next to it
    runs under that Python instead, for scapy; it gets no capture permission that way."""
    if not sys.platform.startswith("linux") or FROZEN or "--no-venv" in sys.argv:
        return
    if os.environ.get("PCC_LAUNCHED"):
        return
    launcher = os.path.join(SCRIPT_DIR, "pcc-launch")
    if os.access(launcher, os.X_OK):
        try:
            os.execv(launcher, [launcher] + sys.argv[1:])
        except OSError:
            pass                      # fall through and run as-is; the L2 page will explain
    vpy = os.path.join(SCRIPT_DIR, ".venv", "bin", "python3")
    if os.path.exists(vpy) and os.path.realpath(sys.executable) != os.path.realpath(vpy):
        try:
            os.execv(vpy, [vpy, os.path.abspath(__file__)] + sys.argv[1:])
        except OSError:
            pass


def _drop_ambient_caps():
    """Linux: keep the capture and link capabilities in this process only. pcc-launch passes
    them as ambient capabilities, which every program we start would otherwise inherit."""
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(47, 4, 0, 0, 0)   # PR_CAP_AMBIENT, CLEAR_ALL
    except Exception:  # noqa: BLE001
        pass


_use_private_python()
_drop_ambient_caps()

if "--reflector" in sys.argv:
    # The far end of the tick test, with no window: needs nothing but Python itself.
    import pc_net
    sys.exit(pc_net.reflector_main(sys.argv))


def log_error(what):
    """Append the current exception to crash.log without stopping the app."""
    import traceback
    _crash_log(time.strftime("%Y-%m-%d %H:%M:%S  ") + what + f"  [python: {sys.executable}]\n"
               + traceback.format_exc() + "\n")


try:
    import tkinter as tk
    import tkinter.font as tkfont
except ImportError as e:
    _fatal("Tkinter is missing.\nNobara/Fedora: sudo dnf install python3-tkinter\n\n" + repr(e))

try:
    import psutil
except ImportError:
    psutil = None

try:
    import pc_net as N
    import pc_smart as S
    import pc_snmp as SN
except Exception as e:  # noqa: BLE001
    _fatal("PorkChopCheck couldn't load pc_net.py / pc_smart.py / pc_snmp.py. Keep them in the same folder as "
           "porkchopcheck.py.\n\n" + repr(e))

IS_WIN = N.IS_WIN
IS_LINUX = N.IS_LINUX
DEMO = "--demo" in sys.argv
WINDOWED = ("--windowed" in sys.argv or (DEMO and not IS_WIN)
            or (IS_LINUX and "--fullscreen" not in sys.argv))
ADMIN_HINT = "run ./install-linux.sh" if IS_LINUX else "needs admin"
# The release workflow writes the real version here (tools/stamp_version.py).
VERSION = "2.0.0-dev"


def pick_data_dir():
    sub = "data_demo" if DEMO else "data"
    for d in (os.path.join(SCRIPT_DIR, sub),
              os.path.join(os.path.expanduser("~"), "Documents", "PorkChopCheck", sub)):
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".write_test")
            with open(probe, "w") as f:
                f.write("x")
            os.remove(probe)
            return d
        except OSError:
            continue
    return SCRIPT_DIR


DATA_DIR = pick_data_dir()

# ---------------------------------------------------------------- colors
BG = "#0b0f14"
PANEL = "#161b22"
FG = "#e6edf3"
DIM = "#8b949e"
GREEN = "#238636"
AMBER = "#9e6a03"
RED = "#b62324"
BLUE = "#1f6feb"
GREY = "#30363d"
OK = "#3fb950"
WARN = "#e3b341"
BAD = "#f85149"
HDR = "#79c0ff"

PENDING = "pending"
SW_COLORS = {SN.GOOD: OK, SN.WARN: WARN, SN.BAD: BAD, SN.DOWN: "#3d444d", SN.OFF: "#21262d"}
SW_POLL_SECS = 15       # how often the Switches page re-reads each switch
SW_SCAN_MAX = 64        # devices a scan will question before it gives up

PING_TARGETS = [("gateway", "Gateway"), ("dns", "DNS server"), ("switch", "Switch mgmt"),
                ("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google DNS")]
TRACE_TARGETS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google DNS"), ("gateway", "Gateway"),
                 ("dns", "DNS server")]

# ---------------------------------------------------------------- PowerShell
ADAPTERS_PS = r"""$ErrorActionPreference='SilentlyContinue'
ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -Physical |
  Where-Object { $_.PhysicalMediaType -eq '802.3' -or $_.MediaType -eq '802.3' } |
  Select-Object Name, InterfaceDescription, @{n='Status';e={[string]$_.Status}}, MacAddress)"""

DETAIL_PS = r"""$ErrorActionPreference='SilentlyContinue'
$a = Get-NetAdapter -Name __NAME__
$c = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex=" + $a.ifIndex)
$exp = $null; if ($c.DHCPLeaseExpires) { $exp = $c.DHCPLeaseExpires.ToString('MMM d h:mm tt') }
$gw = @($c.DefaultIPGateway) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
$gwmac = $null; if ($gw) { $gwmac = (Get-NetNeighbor -InterfaceIndex $a.ifIndex -IPAddress $gw).LinkLayerAddress }
$s = Get-NetAdapterStatistics -Name __NAME__
$v6 = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 |
        Select-Object IPAddress, @{n='Origin';e={[string]$_.PrefixOrigin}})
$v4s = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | ForEach-Object { [string]$_.AddressState })
[pscustomobject]@{
  Status = [string]$a.Status
  FullDuplex = $a.FullDuplex
  Mac = $a.MacAddress
  Desc = $a.InterfaceDescription
  DhcpEnabled = $c.DHCPEnabled
  DhcpServer = $c.DHCPServer
  LeaseExpires = $exp
  Gateway = @($c.DefaultIPGateway)
  Dns = @($c.DNSServerSearchOrder)
  Domain = $c.DNSDomain
  GwMac = $gwmac
  RxBcast = $s.ReceivedBroadcastPackets
  RxMcast = $s.ReceivedMulticastPackets
  V6 = $v6
  V4State = $v4s
} | ConvertTo-Json -Compress -Depth 4"""

NEIGH_PS = r"""$ErrorActionPreference='SilentlyContinue'
ConvertTo-Json -Compress -InputObject @(Get-NetNeighbor -InterfaceAlias __NAME__ -AddressFamily IPv4 |
  Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and [string]$_.State -ne 'Unreachable' } |
  Select-Object IPAddress, LinkLayerAddress, @{n='State';e={[string]$_.State}})"""


# ================================================================ shared state
def new_switch(ip, name="", model=""):
    return {"ip": ip, "name": name, "model": model, "ok": None, "msg": "", "fails": 0, "polled": None,
            "ports": [], "sum": None}


def switch_level(x):
    """The colour of a switch's icon: red if it stopped answering or any port is red."""
    if x["ok"] is False:
        return SN.BAD
    return x["sum"]["level"] if x["sum"] else None


def new_ping():
    return {"running": False, "kind": "gateway", "label": "Gateway", "target": None,
            "samples": collections.deque(maxlen=7200),    # (time, rtt or None); 30 min at 4 a second
            "log": collections.deque(maxlen=40), "span": 30,
            "sent": 0, "recv": 0, "min": None, "max": None, "sum": 0.0, "jit": 0.0, "jn": 0,
            "last": None}


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.adapters = []
        self.sel = None
        self.toast = None
        self.toast_until = 0.0
        self.ping = new_ping()
        self.trace = {"running": False, "kind": "1.1.1.1", "label": "Cloudflare", "target": None,
                      "hops": []}
        self.speed = {"running": False, "mode": "", "down": None, "up": None, "lines": []}
        self.arp_table = {"running": False, "rows": [], "ts": None}
        self.arp_scan = {"running": False, "net": None, "range": None, "found": {}, "sent": 0,
                         "total": 0, "limited": False}
        self.blink = {"running": False, "cycles": 0}
        self.tick = {"running": False, "rate": 64, "span": 30, "msg": "", "target": "", "sum": None,
                     "cols": [], "t_end": 0.0, "normal": 0.0, "counters": {}, "pace": 0.0,
                     "impacts": {}, "hold": None, "reflecting": False, "reflected": 0, "peers": []}
        self.events = collections.deque(maxlen=300)       # the timeline: link, STP, gateway, storms…
        self.bc_storm = False
        self.mcast = {"running": False, "msg": "", "snap": None, "join": None, "probed": None,
                      "last_join": "239."}
        self.capture = {"running": False, "secs": 30, "left": 0, "frames": 0, "bytes": 0,
                        "file": "", "msg": "", "ok": True, "files": []}
        self.smart = {"running": False, "stage": "", "devices": [], "ts": None, "counts": {}}
        self.switches = {"running": False, "stage": "", "list": []}
        self.reset_adapter()

    def reset_adapter(self):
        now = time.time()
        self.link = None
        self.speed_mbps = 0
        self.ipv4 = None
        self.mask = None
        self.mac = ""
        self.d = {}
        self.io = None
        self.io_base = None
        self.io_prev = None
        self.rx_bps = 0.0
        self.tx_bps = 0.0
        self.drops = 0
        self.link_up_at = None
        self.ip_wait_from = None
        self.time_to_ip = None
        self.gw_ms = self.dns_ms = self.net_ms = PENDING
        self.public_ip = None
        self.nb = {}
        self.sniff_msg = "Starting…"
        self.reset_l2(now)

    def reset_l2(self, now):
        self.l2_since = now
        self.dot1x = None
        self.stp = None
        self.stp_tc_at = None
        self.dtp = None
        self.tagged = set()
        self.dhcp_scan = None
        self.dhcp_seen = {}
        self.dhcp_ack = None
        self.dup_mac = None
        self.gw_mac = None
        self.ra = None
        self.bc_pps = None
        self.mc_pps = None
        self.bc_prev = None
        self.eapol_sent = False
        self.dhcp_done = False
        self.dup_done = False
        self.gw_arp_sent = False
        self.last_announce = 0.0
        self.wire = N.new_wire()

    def add_event(self, kind, text, sev, now, quiet=0.0):
        """Call with self.lock held."""
        N.add_event(self.events, kind, text, sev, now, quiet)

    def snapshot(self):
        with self.lock:
            return copy.deepcopy({k: v for k, v in self.__dict__.items() if k != "lock"})

    def say(self, msg, secs=4):
        with self.lock:
            self.toast = msg
            self.toast_until = time.time() + secs


# ================================================================ summaries (UI + log)
def good_ip(s):
    ip = s["ipv4"]
    return bool(ip) and not ip.startswith("169.254.")


def sniff_ok(s):
    return s["sniff_msg"] == "listening"


def fmt_ms(v):
    if v == PENDING or v is None:
        return ""
    return "<1 ms" if v < 1 else f"{v:.0f} ms"


def sum_dot1x(s, now):
    if not s["link"]:
        return ("—", FG, "")
    if not sniff_ok(s):
        return ("Needs Npcap", WARN, "")
    x = s["dot1x"]
    el = now - s["l2_since"]
    if x:
        code, et = x.get("code"), x.get("eap_type", "")
        if code == "Success":
            return ("Authorized", OK, "EAP success")
        if code == "Failure":
            return ("AUTH FAILED", BAD, "EAP failure")
        return ("ENABLED", WARN, f"EAP {code}" + (f" / {et}" if et else ""))
    if el > 35:
        return ("Not detected", OK, f"no EAP in {el:.0f}s")
    return ("Listening…", DIM, f"{el:.0f}s")


def sum_stp(s, now):
    if not s["link"]:
        return ("—", FG, "")
    if not sniff_ok(s):
        return ("Needs Npcap", WARN, "")
    x = s["stp"]
    el = now - s["l2_since"]
    if x:
        val = x.get("proto", "STP") + (f" · VLAN {x['vlan']}" if x.get("vlan") else "")
        if s["stp_tc_at"] and now - s["stp_tc_at"] < 60:
            return (val, WARN, "TOPOLOGY CHANGE")
        if "root_mac" in x:
            if x.get("cost") == 0:
                return (val, FG, "this switch is root")
            return (val, FG, f"root {x['root_prio']}·{x['root_mac'][-8:]}")
        return (val, FG, "")
    if el > 10:
        return ("No BPDUs", DIM, "filtered?")
    return ("Listening…", DIM, "")


def sum_trunk(s, now):
    if not s["link"]:
        return ("—", FG, "")
    if not sniff_ok(s):
        return ("Needs Npcap", WARN, "")
    tags = sorted(s["tagged"])
    dtp = s["dtp"]
    el = now - s["l2_since"]
    if tags:
        more = "…" if len(tags) > 6 else ""
        return ("Tagged " + ",".join(map(str, tags[:6])) + more, BAD, "TRUNK PORT?")
    if dtp:
        if dtp.get("oper") == "trunk":
            return ("TRUNK (DTP)", BAD, f"mode {dtp.get('admin')}")
        return (f"DTP {dtp.get('admin')}", WARN, "nonegotiate off")
    if el > 65:
        return ("Access", OK, "no tags / DTP")
    return ("Listening…", DIM, f"{el:.0f}s")


def dhcp_servers(s):
    servers = set()
    sc = s["dhcp_scan"]
    if sc:
        servers |= set(sc["offers"])
    servers |= {k for k, v in s["dhcp_seen"].items() if v.get("msg") in ("OFFER", "ACK")}
    return sorted(servers)


def sum_dhcp(s, now):
    if not s["link"]:
        return ("—", FG, "")
    sc = s["dhcp_scan"]
    servers = dhcp_servers(s)
    if len(servers) > 1:
        return (f"{len(servers)} SERVERS!", BAD, ", ".join(servers[:3]))
    if not good_ip(s) and not sc:
        return ("—", FG, "")
    if not sc:
        return ("Needs Npcap", WARN, "") if not sniff_ok(s) else ("Pending…", DIM, "")
    if sc["status"] == "running":
        return ("Testing…", DIM, "")
    if len(servers) == 1:
        return ("1 server", OK, servers[0])
    return ("No offers", WARN, "server silent?")


def phone_opts(s):
    sc = s["dhcp_scan"]
    if sc and sc["offers"]:
        return next(iter(sc["offers"].values()))
    return s["dhcp_ack"]


def sum_phone(s):
    o = phone_opts(s)
    if not s["link"] or not o:
        return ("—", FG, "")
    if o.get("tftp_ips"):
        return ("TFTP " + ", ".join(o["tftp_ips"][:2]), OK, "option 150")
    if o.get("tftp_name"):
        return ("TFTP " + o["tftp_name"], OK, "option 66")
    if o.get("opt43"):
        return ("Option 43 set", FG, o["opt43"][:16])
    return ("None", DIM, "no 66 / 150 / 43")


def gw_mac_of(s):
    return N.norm_mac(s["gw_mac"] or s["d"].get("GwMac") or "")


def sum_gw(s, oui):
    mac = gw_mac_of(s)
    if not s["link"] or not mac:
        return ("—", FG, "")
    return (mac, FG, oui.lookup(mac) if oui else "")


def sum_v6(s, now):
    if not s["link"]:
        return ("—", FG, "")
    v6 = [a for a in N.as_list(s["d"].get("V6")) if isinstance(a, dict) and a.get("IPAddress")]
    glob = [a for a in v6 if not str(a["IPAddress"]).lower().startswith("fe80")]
    ra = s["ra"]
    if ra:
        flags = "".join(f for f, on in (("M", ra.get("m")), ("O", ra.get("o"))) if on)
        note = "RA" + (f" {flags}" if flags else "") + (f" {ra['prefixes'][0]}" if ra.get("prefixes") else "")
    else:
        note = "no RA" if now - s["l2_since"] > 30 else ""
    if glob:
        origin = {"RouterAdvertisement": "SLAAC", "Dhcp": "DHCPv6"}.get(glob[0].get("Origin"), "")
        return (glob[0]["IPAddress"], OK, note or origin)
    if v6:
        return ("Link-local only", DIM, note)
    return ("—", FG, note)


def sum_bcast(s):
    bc, mc = s["bc_pps"], s["mc_pps"]
    if not s["link"] or (bc is None and mc is None):
        return ("—", FG, "")
    if bc is None:
        return (f"{mc:.0f} mcast/s", WARN if mc > 1000 else OK, "bcast n/a on this NIC")
    color = BAD if bc > 500 else WARN if bc > 100 else OK
    return (f"{bc:.0f} bcast/s", color, f"{mc or 0:.0f} mcast/s")


def build_record(s, oui, label=""):
    now = time.time()
    nb = N.merge_neighbors(s["nb"])
    d = s["d"]
    pl = N.prefix_len(s["mask"]) if s["mask"] else None
    srv = d.get("DhcpServer")
    srv = srv if N.is_ipv4(srv) and srv != "255.255.255.255" else ""
    net = s["net_ms"]
    adapter = next((a for a in s["adapters"] if a["name"] == s["sel"]), {})
    sc = s["dhcp_scan"]
    return {
        "label": label,
        "switch": nb.get("name") or nb.get("chassis") or "",
        "port": nb.get("port", ""),
        "vlan": nb.get("vlan", ""),
        "voice_vlan": nb.get("voice_vlan", ""),
        "mgmt_ip": nb.get("mgmt_ip", ""),
        "model": nb.get("platform", ""),
        "poe": nb.get("poe", ""),
        "speed": N.fmt_speed(s["speed_mbps"]) if s["link"] else "no link",
        "duplex": {True: "full", False: "half"}.get(d.get("FullDuplex"), ""),
        "ip": (f"{s['ipv4']}/{pl}" if pl else s["ipv4"]) if s["ipv4"] else "",
        "gateway": N.first_v4(d.get("Gateway")) or "",
        "gw_ms": fmt_ms(s["gw_ms"]),
        "gw_mac": gw_mac_of(s),
        "dhcp_server": srv,
        "dhcp_servers": len(dhcp_servers(s)) if sc and sc["status"] == "done" else "",
        "dns": ", ".join(x for x in N.as_list(d.get("Dns")) if N.is_ipv4(x)),
        "internet": "" if net == PENDING else ("ok" if net is not None else "fail"),
        "time_to_ip": f"{s['time_to_ip']:.1f}" if s["time_to_ip"] is not None else "",
        "dot1x": sum_dot1x(s, now)[0],
        "stp": " ".join(x for x in sum_stp(s, now)[::2] if x),
        "dtp": sum_trunk(s, now)[0],
        "tagged_vlans": ",".join(map(str, sorted(s["tagged"]))),
        "ipv6": sum_v6(s, now)[0],
        "pc_mac": s["mac"],
        "adapter": adapter.get("desc") or s["sel"] or "",
    }


SIG_FIELDS = ("switch", "port", "vlan", "voice_vlan", "speed", "duplex", "ip", "dhcp_server",
              "internet", "dot1x", "dtp", "dhcp_servers", "poe")


# ================================================================ backend
class Backend:
    def __init__(self, st, settings, portlog, oui, mdns):
        self.st, self.settings, self.portlog, self.oui, self.mdns = st, settings, portlog, oui, mdns
        self.kick = threading.Event()
        self.sniffer = None
        self.sniff_gen = 0
        self.sniff_iface = None         # what the sniffer is listening on; captures reuse it
        self.l2sock = None
        self.send_lock = threading.Lock()
        self.stops = {}
        self.last_sig = None
        self.last_log = 0.0
        self.oui_tried = False
        self.pubip_at = 0.0             # last time the public IP was asked for
        self.arpwatch = N.ArpWatch()    # kept here, not in State: it can hold thousands of entries
        self.wirewatch = None
        self.wire_sniffer = None
        self.nic_base = None            # the adapter's counters when the wire report started
        self.pubip_for = None           # (adapter, local IP) it was asked from
        self.devstore = S.DeviceStore(DATA_DIR)
        self.swwatch = {}               # each switch's memory between SNMP readings
        self.sw_kick = threading.Event()
        self.sw_poll_lock = threading.Lock()
        with st.lock:
            st.switches["list"] = [new_switch(x["ip"], x.get("name", ""), x.get("model", ""))
                                   for x in settings.get("switches") or [] if isinstance(x, dict) and x.get("ip")]

    # ---------------------------------------------------------- lifecycle
    def start(self):
        self.recover_blink()
        self.load_adapters()
        for fn in (self.fast_loop, self.detail_loop, self.health_loop, self.probe_loop, self.wire_loop):
            threading.Thread(target=fn, daemon=True).start()
        self.restart_sniffer()

    def shutdown(self):
        ev = self.stops.get("blink")
        if ev and not ev.is_set():
            ev.set()
            with self.st.lock:
                name = self.st.sel
            if name:
                self._set_admin(name, True)
        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception:  # noqa: BLE001
            pass

    def recover_blink(self):
        lock = os.path.join(DATA_DIR, "blink.lock")
        if os.path.exists(lock):
            try:
                with open(lock, encoding="utf-8") as f:
                    name = f.read().strip()
                if name:
                    self._set_admin(name, True)
                os.remove(lock)
            except OSError:
                pass

    def load_adapters(self):
        lst = []
        if IS_WIN:
            for a in N.as_list(N.ps_json(ADAPTERS_PS)):
                if a and a.get("Name"):
                    lst.append({"name": a["Name"], "desc": a.get("InterfaceDescription") or "",
                                "mac": N.norm_mac(a.get("MacAddress")), "up": a.get("Status") == "Up"})
        elif IS_LINUX:
            lst = N.linux_adapters()
        if not lst and psutil:
            for n, s in psutil.net_if_stats().items():
                if n.startswith(("Ethernet", "eth", "en")):
                    lst.append({"name": n, "desc": "", "mac": "", "up": s.isup})
        lst.sort(key=lambda a: (not a["up"], a["name"]))
        st = self.st
        with st.lock:
            st.adapters = lst
            names = [a["name"] for a in lst]
            changed = st.sel not in names
            if changed:
                st.sel = names[0] if names else None
                st.reset_adapter()
        if changed:
            self.restart_sniffer()

    def my_mac(self):
        """Call with st.lock held."""
        st = self.st
        for a in st.adapters:
            if a["name"] == st.sel and a["mac"]:
                return a["mac"]
        return st.mac

    # ---------------------------------------------------------- fast loop (psutil, 1 s)
    def fast_loop(self):
        while True:
            try:
                self.fast_tick()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)

    def fast_tick(self):
        st = self.st
        name = st.sel
        if not name or not psutil:
            return
        stats = psutil.net_if_stats().get(name)
        up = bool(stats and stats.isup)
        speed = stats.speed if stats else 0
        if IS_LINUX:
            up, speed = N.linux_link(name)
        ip = mask = mac = None
        addrs = psutil.net_if_addrs()
        l3 = N.linux_l3_iface(name) if IS_LINUX else name      # bridged NIC: IP lives on br0
        for a in addrs.get(l3, []):
            if a.family == socket.AF_INET and (ip is None or ip.startswith("169.254.")):
                ip, mask = a.address, a.netmask
        for a in addrs.get(name, []):
            if a.family == psutil.AF_LINK:
                mac = N.norm_mac(a.address)
        io = psutil.net_io_counters(pernic=True).get(name)
        now = time.time()
        came_up = changed = False
        with st.lock:
            if name != st.sel:
                return
            if st.link is not None and up != st.link:
                changed = True
                if up:
                    came_up = True
                    st.link_up_at = st.ip_wait_from = now
                    st.time_to_ip = None
                    st.add_event("link", f"Link up at {N.fmt_speed(speed)}" if speed else "Link up", "info", now)
                elif not st.blink["running"]:
                    st.drops += 1
                    st.add_event("link", "Link down", "bad", now)
            elif up and st.link and speed and st.speed_mbps and speed != st.speed_mbps:
                st.add_event("link", f"Speed changed: {N.fmt_speed(st.speed_mbps)} to {N.fmt_speed(speed)}",
                             "bad" if speed < st.speed_mbps else "info", now)
            new_ip = ip if up else None
            if st.link is not None and new_ip != st.ipv4 and not changed:
                if new_ip and st.ipv4:
                    st.add_event("ip", f"IP address changed: {st.ipv4} to {new_ip}", "warn", now)
                elif new_ip and new_ip.startswith("169.254."):
                    st.add_event("ip", f"Self-assigned address {new_ip}: no DHCP answer", "warn", now)
                elif new_ip:
                    st.add_event("ip", f"Got IP address {new_ip}", "info", now)
                else:
                    st.add_event("ip", f"Lost IP address {st.ipv4}", "bad", now)
                st.nb = {}
                st.gw_ms = st.dns_ms = st.net_ms = PENDING
                st.public_ip = None
                st.reset_l2(now)
            st.link = up
            st.speed_mbps = speed if up else 0
            st.ipv4 = ip if up else None
            st.mask = mask if up else None
            if mac:
                st.mac = mac
            if (up and ip and not ip.startswith("169.254.")
                    and st.ip_wait_from and st.time_to_ip is None):
                st.time_to_ip = now - st.ip_wait_from
                st.ip_wait_from = None
            if io:
                if st.io_base is None:
                    st.io_base = io
                if st.io_prev:
                    pio, pt = st.io_prev
                    dt = max(now - pt, 0.1)
                    st.rx_bps = max(io.bytes_recv - pio.bytes_recv, 0) * 8 / dt
                    st.tx_bps = max(io.bytes_sent - pio.bytes_sent, 0) * 8 / dt
                st.io_prev = (io, now)
                st.io = io
        if changed:
            self.kick.set()
        if came_up:
            self.restart_sniffer()

    # ---------------------------------------------------------- detail loop (PowerShell, ~3 s)
    def detail_loop(self):
        n = 0
        while True:
            self.kick.wait(3)
            self.kick.clear()
            n += 1
            try:
                if n % 10 == 0:
                    self.load_adapters()
                self.detail_tick()
            except Exception:  # noqa: BLE001
                pass

    def detail_tick(self):
        if not (IS_WIN or IS_LINUX):
            return
        name = self.st.sel
        if not name:
            return
        if IS_LINUX:
            data = N.linux_detail(name)
        else:
            data = N.ps_json(DETAIL_PS.replace("__NAME__", N.psq(name)))
        if not isinstance(data, dict):
            return
        now = time.time()
        st = self.st
        with st.lock:
            if st.sel != name:
                return
            st.d = data
            bc, mc = data.get("RxBcast"), data.get("RxMcast")
            num = (int, float)
            if isinstance(mc, num):
                if st.bc_prev:
                    pbc, pmc, pt = st.bc_prev
                    dt = max(now - pt, 0.5)
                    st.bc_pps = (max(bc - pbc, 0) / dt) if isinstance(bc, num) and isinstance(pbc, num) else None
                    st.mc_pps = max(mc - pmc, 0) / dt
                st.bc_prev = (bc, mc, now)
                rate = st.bc_pps
                if rate is not None and rate > 500 and not st.bc_storm:
                    st.bc_storm = True
                    st.add_event("bcast", f"Broadcast storm: {rate:,.0f} a second", "bad", now)
                elif rate is not None and rate < 100 and st.bc_storm:
                    st.bc_storm = False
                    st.add_event("bcast", f"Broadcast back to {rate:,.0f} a second", "info", now)
            if "Duplicate" in N.as_list(data.get("V4State")) and not st.dup_mac:
                st.dup_mac = "(flagged by Windows)"

    # ---------------------------------------------------------- health loop (gateway / DNS / internet)
    def health_loop(self):
        while True:
            try:
                self.health_tick()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(4)

    def health_tick(self):
        st = self.st
        with st.lock:
            name, up, ip = st.sel, st.link, st.ipv4
            gw = N.first_v4(st.d.get("Gateway"))
            dns = N.first_v4(st.d.get("Dns"))
        sn = self.sniffer
        if sn is not None and not getattr(sn, "running", True):
            with st.lock:
                st.add_event("capture", "Packet capture stopped", "warn", time.time(), quiet=3600)
                st.sniff_msg = ("Capture stopped — run ./install-linux.sh" if IS_LINUX
                                else "Capture stopped — is Npcap installed?")
        if not up or not ip or ip.startswith("169.254."):
            return
        gw_ms = self.echo_ms(gw, ip) if gw else PENDING
        dns_ms = N.dns_probe(dns, ip) if dns else PENDING
        net_ms = N.tcp_probe("1.1.1.1", 443, ip)
        if net_ms is None:
            net_ms = N.tcp_probe("8.8.8.8", 443, ip)
        with st.lock:
            have_pub = st.public_ip
            if st.sel == name and st.link:
                st.gw_ms, st.dns_ms, st.net_ms = gw_ms, dns_ms, net_ms
                if net_ms is None:
                    st.public_ip = have_pub = None
        # Ask for the public IP as soon as the internet answers on a new port or address, then
        # every five minutes; while there is none yet, try again every 20 s.
        now = time.time()
        if net_ms is not None and ((name, ip) != self.pubip_for
                                   or now - self.pubip_at > (300 if have_pub else 20)):
            self.pubip_at, self.pubip_for = now, (name, ip)
            pub = N.public_ip(ip)
            with st.lock:
                if st.sel == name and st.link and st.ipv4 == ip:
                    st.public_ip = pub or st.public_ip
        if net_ms is not None and not self.oui.available() and not self.oui_tried:
            self.oui_tried = True
            threading.Thread(target=self.update_oui, args=(True,), daemon=True).start()

    # ---------------------------------------------------------- active probes + auto-log (2 s)
    def probe_loop(self):
        while True:
            try:
                self.probe_tick()
            except Exception:  # noqa: BLE001
                pass
            try:
                self.maybe_autolog()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(2)

    def probe_tick(self):
        st = self.st
        now = time.time()
        actions = []
        with st.lock:
            if not st.link or self.l2sock is None or st.blink["running"]:
                return
            mac, ip, sel = self.my_mac(), st.ipv4, st.sel
            ok_ip = bool(ip) and not ip.startswith("169.254.")
            gw = N.first_v4(st.d.get("Gateway"))
            if not mac:
                return
            if not st.eapol_sent and now - st.l2_since > 2:
                st.eapol_sent = True
                actions.append(("eapol",))
            if ok_ip and not st.dhcp_done:
                st.dhcp_done = True
                actions.append(("dhcp",))
            if ok_ip and not st.dup_done:
                st.dup_done = True
                actions.append(("dup",))
            if ok_ip and gw and not st.gw_mac and not st.gw_arp_sent:
                st.gw_arp_sent = True
                actions.append(("gwarp", gw))
            if self.settings.get("announce") and now - st.last_announce > 30:
                st.last_announce = now
                actions.append(("announce",))
        for a in actions:
            if a[0] == "eapol":
                self.send(N.build_eapol_start(mac))
            elif a[0] == "dhcp":
                threading.Thread(target=self.run_dhcp_check, daemon=True).start()
            elif a[0] == "dup":
                self.send(N.build_arp_request(mac, None, ip))
                time.sleep(0.3)
                self.send(N.build_arp_request(mac, None, ip))
            elif a[0] == "gwarp":
                self.send(N.build_arp_request(mac, ip, a[1]))
            elif a[0] == "announce":
                host = self.hostname()
                self.send(N.build_lldp(mac, sel, host, ip=ip if ok_ip else None))
                self.send(N.build_cdp(mac, host, sel, ip if ok_ip else None))

    def hostname(self):
        return self.settings.get("hostname") or f"PorkChopCheck-{socket.gethostname()}"

    def run_dhcp_check(self):
        st = self.st
        with st.lock:
            mac = self.my_mac()
            xid = random.getrandbits(32)
            st.dhcp_scan = {"xid": xid, "status": "running", "offers": {}, "ts": time.time()}
        frame = N.build_dhcp_discover(mac, xid)
        self.send(frame)
        time.sleep(1.5)
        self.send(frame)
        time.sleep(3.5)
        with st.lock:
            if st.dhcp_scan and st.dhcp_scan["xid"] == xid:
                st.dhcp_scan["status"] = "done"

    def rerun_checks(self):
        with self.st.lock:
            self.st.reset_l2(time.time())
            self.st.nb = {}
        self.restart_sniffer()
        self.st.say("Re-running L2 checks…", 3)

    def maybe_autolog(self):
        if not self.settings.get("autolog"):
            return
        s = self.st.snapshot()
        now = time.time()
        if not s["link"] or s["blink"]["running"]:
            return
        if s["gw_ms"] == PENDING and now - s["l2_since"] < 25:
            return
        rec = build_record(s, self.oui)
        if not rec["switch"] or not rec["port"]:
            return
        sig = tuple(rec[k] for k in SIG_FIELDS)
        if sig == self.last_sig and now - self.last_log < 600:
            return
        if sig != self.last_sig and now - self.last_log < 10:
            return
        self.last_sig, self.last_log = sig, now
        new, err = self.portlog.upsert(rec)
        if err:
            self.st.say(err, 5)
        elif new:
            self.st.say(f"Logged new port: {rec['switch']} {rec['port']}", 4)

    def save(self, label):
        s = self.st.snapshot()
        rec = build_record(s, self.oui, label)
        _, err = self.portlog.upsert(rec, manual=True)
        where = f"{rec['switch']} {rec['port']}".strip() or "this port"
        self.st.say(err or f"Saved {where}" + (f" — {label}" if label else ""), 4)

    # ---------------------------------------------------------- capture (scapy + Npcap)
    def restart_sniffer(self):
        self.sniff_gen += 1
        old, oldsock = self.sniffer, self.l2sock
        self.sniffer = self.l2sock = self.sniff_iface = None
        self._wire_stop()
        threading.Thread(target=self._sniff_start, args=(self.sniff_gen, old, oldsock),
                         daemon=True).start()

    def _set_sniff(self, gen, msg):
        with self.st.lock:
            if gen == self.sniff_gen:
                self.st.sniff_msg = msg

    def _sniff_start(self, gen, old, oldsock):
        for obj, meth in ((old, "stop"), (oldsock, "close")):
            if obj is not None:
                try:
                    getattr(obj, meth)()
                except Exception:  # noqa: BLE001
                    pass
        try:
            from scapy.all import AsyncSniffer, conf
            from scapy.layers.l2 import Ether
        except Exception as e:  # noqa: BLE001
            log_error("Packet capture library (scapy) failed to load")
            if isinstance(e, ImportError) and "scapy" in str(e):
                hint = "run ./install-linux.sh" if IS_LINUX else "run: py -m pip install scapy"
                self._set_sniff(gen, f"Capture off — scapy not installed for {sys.executable} — {hint}"[:110])
            else:
                self._set_sniff(gen, f"Capture off — scapy error: {type(e).__name__}: {e} (details in crash.log)"[:110])
            return
        if IS_LINUX and not N.has_net_caps():
            self._set_sniff(gen, "No capture permission — run ./install-linux.sh")
            return
        if IS_WIN and not getattr(conf, "use_pcap", False):
            self._set_sniff(gen, "Capture off — install Npcap (npcap.com)")
            return
        try:
            conf.layers.filter([Ether])      # we decode raw bytes ourselves; keeps scapy fast
        except Exception:  # noqa: BLE001
            pass
        with self.st.lock:
            name, mac = self.st.sel, self.my_mac()
        if not name:
            return
        iface = None
        try:
            for i in conf.ifaces.values():
                if mac and N.norm_mac(getattr(i, "mac", "")) == mac:
                    iface = i
                    break
        except Exception:  # noqa: BLE001
            pass
        if iface is None or IS_LINUX:
            iface = name
        try:
            sn = AsyncSniffer(iface=iface, filter=N.BPF, store=False,
                              prn=lambda pkt, g=gen: self._on_frame(g, bytes(pkt)))
            sn.start()
        except Exception as e:  # noqa: BLE001
            self._set_sniff(gen, f"Capture error: {e}"[:80])
            return
        sock = None
        try:
            sock = conf.L2socket(iface=iface)
        except Exception:  # noqa: BLE001
            pass
        if gen != self.sniff_gen:
            for obj, meth in ((sn, "stop"), (sock, "close")):
                try:
                    if obj is not None:
                        getattr(obj, meth)()
                except Exception:  # noqa: BLE001
                    pass
            return
        self.sniffer, self.l2sock, self.sniff_iface = sn, sock, iface
        self._set_sniff(gen, "listening")
        self._wire_start(gen, iface, name, mac)

    def send(self, frame):
        sock = self.l2sock
        if sock is None:
            return False
        try:
            from scapy.packet import Raw
            with self.send_lock:
                sock.send(Raw(load=frame))
            return True
        except Exception:  # noqa: BLE001
            return False

    def _on_frame(self, gen, raw):
        try:
            evs = N.classify(raw)
        except Exception:  # noqa: BLE001
            return
        if not evs:
            return
        now = time.time()
        st = self.st
        mdns_msgs = []
        with st.lock:
            if gen != self.sniff_gen:
                return
            my = self.my_mac()
            for kind, info in evs:
                if kind == "MDNS":
                    mdns_msgs.append(info)
                else:
                    try:
                        self._handle(kind, info, now, my)
                    except Exception:  # noqa: BLE001
                        pass
        for m in mdns_msgs:
            self.mdns.ingest(m, m.get("ip_src"), multicast=m.get("ip_dst") in ("224.0.0.251", "ff02::fb"))

    def _handle(self, kind, info, now, my):
        """Runs with st.lock held."""
        st = self.st
        src = info.get("src")
        if kind == "VLAN":
            if src != my:
                st.tagged.add(info["vlan"])
            return
        if src == my and kind in ("CDP", "LLDP", "EAPOL", "DTP", "STP", "LACP", "PAUSE", "UDLD",
                                  "PAGP", "VTP", "LOOP", "ICMP"):
            return                                      # our own announcements / probes
        w = st.wire
        if kind in ("LACP", "UDLD", "VTP", "PAGP", "LOOP"):
            key = kind.lower()
            if not w[key]:
                text = {"LACP": "LACP heard: the switch port is set up for a port-channel",
                        "PAGP": "PAgP heard: the switch port is trying to form a port-channel",
                        "UDLD": "UDLD heard on this port", "VTP": "VTP heard: this is a trunk-capable port",
                        "LOOP": "Loopback keepalive heard"}[kind]
                st.add_event("proto", text, "warn" if kind in ("LACP", "PAGP") else "info", now, quiet=3600)
            w[key] = dict(info, ts=now)
            return
        if kind == "PAUSE":
            w["pause_frames"] += 1
            w["pause_at"] = now
            st.add_event("pause", "PAUSE frame: the link was told to stop sending", "warn", now, quiet=10)
            return
        if kind == "ICMP":
            w["icmp"] = (w["icmp"] + [dict(info, ts=now)])[-12:]
            if info["what"] == "redirect":
                st.add_event("icmp", f"ICMP redirect from {info['from']}: use {info['use']}", "warn", now, quiet=60)
            else:
                st.add_event("icmp", f"Packet too big: {info['from']} reports a path MTU of {info['mtu']}", "warn",
                             now, quiet=60)
            return
        if kind in ("CDP", "LLDP"):
            st.nb[kind] = (info, now)
        elif kind == "DTP":
            st.dtp = dict(info, ts=now)
        elif kind == "STP":
            if not info.get("tcn") or not st.stp:
                st.stp = dict(info, ts=now)
            if info.get("tc") or info.get("tcn"):
                st.stp_tc_at = now
                vlan = info.get("vlan")
                st.add_event("stp", "Spanning-tree topology change" + (f" (VLAN {vlan})" if vlan else ""),
                             "warn", now, quiet=30)
        elif kind == "EAPOL":
            if info.get("code") in ("Request", "Success", "Failure"):
                st.dot1x = dict(info, ts=now)
        elif kind == "ARP":
            self._on_arp(info, now, my)
        elif kind == "DHCP":
            self._on_dhcp(info, now, my)
        elif kind == "RA":
            st.ra = dict(info, ts=now)
            if src and src not in w["routers"] and len(w["routers"]) < 16:
                extra = bool(w["routers"])
                pfx = (info.get("prefixes") or [""])[0]
                w["routers"][src] = {"ts": now, "prefix": pfx}
                st.add_event("ra", ("Another machine is advertising itself as an IPv6 router: " if extra
                                    else "IPv6 router heard: ") + src, "bad" if extra else "info", now, quiet=3600)

    def _on_arp(self, a, now, my):
        st = self.st
        ip = st.ipv4
        moved = self.arpwatch.feed(a, now)
        st.wire["gratuitous"] = self.arpwatch.gratuitous
        if moved and moved[0] != ip and moved[0] != N.first_v4(st.d.get("Gateway")):
            st.wire["conflicts"] = [dict(c, ip=i) for i, c in list(self.arpwatch.conflicts.items())[-12:]]
            st.add_event("conflict", f"IP conflict: {moved[0]} answered from {moved[1]}, now {moved[2]}", "bad",
                         now, quiet=30)
        if (ip and a["spa"] == ip and a["sha"] != my and a["sha"] != "00:00:00:00:00:00"):
            if st.dup_mac != a["sha"]:
                st.add_event("dup", f"Duplicate IP: {a['sha']} also claims {ip}", "bad", now, quiet=60)
            st.dup_mac = a["sha"]
        gw = N.first_v4(st.d.get("Gateway"))
        if gw and a["spa"] == gw:
            if st.gw_mac and a["sha"] != st.gw_mac and a["sha"] != "00:00:00:00:00:00":
                st.add_event("gwmac", f"Gateway {gw} changed MAC: {st.gw_mac} to {a['sha']}", "bad", now, quiet=10)
            st.gw_mac = a["sha"]
        sc = st.arp_scan
        if sc["range"] and a["spa"] != "0.0.0.0":
            net, mask = sc["range"]
            try:
                v = N.u32(socket.inet_aton(a["spa"]), 0)
            except OSError:
                return
            if v & mask == net:
                macs = sc["found"].setdefault(a["spa"], [])
                if a["sha"] not in macs:
                    macs.append(a["sha"])

    def _on_dhcp(self, d, now, my):
        st = self.st
        if d["op"] != 2:
            return
        srv = d.get("server") or d.get("ip_src")
        if srv not in st.dhcp_seen and st.dhcp_seen:
            st.add_event("dhcp", f"Another DHCP server answered: {srv}", "bad", now, quiet=300)
        st.dhcp_seen[srv] = {"mac": d.get("src"), "ts": now, "msg": d.get("msg")}
        sc = st.dhcp_scan
        if sc and d["xid"] == sc["xid"] and d["msg"] == "OFFER":
            sc["offers"][srv] = d
        if d.get("chaddr") == my and d.get("msg") == "ACK":
            st.dhcp_ack = d

    # ---------------------------------------------------------- primitives (overridden in demo)
    def echo(self, dst, src, ttl=128, timeout_ms=1000):
        return N.icmp_echo(dst, src, ttl=ttl, timeout_ms=timeout_ms)

    def echo_ms(self, dst, src):
        status, _, rtt = self.echo(dst, src)
        return rtt if status == "ok" else None

    def _set_admin(self, name, enabled):
        if IS_WIN:
            N.run(f'netsh interface set interface name="{name}" admin={"enabled" if enabled else "disabled"}', 20)
        elif IS_LINUX:
            N.linux_set_link(name, enabled)

    def _arp_table(self, name):
        if IS_LINUX:
            return [r for r in N.linux_neigh(name) if not 224 <= int(r[0].split(".")[0]) <= 239]
        rows = []
        for r in N.as_list(N.ps_json(NEIGH_PS.replace("__NAME__", N.psq(name)))):
            ip = r.get("IPAddress", "")
            if not N.is_ipv4(ip) or 224 <= int(ip.split(".")[0]) <= 239:
                continue
            rows.append((ip, N.norm_mac(r.get("LinkLayerAddress")), r.get("State", "")))
        return rows

    def _iperf(self, exe, server, src, reverse):
        return N.run_iperf(exe, server, src, reverse=reverse, port=int(self.settings.get("iperf_port") or 5201))

    def _http(self, src, which):
        return N.http_download(src) if which == "down" else N.http_upload(src)

    def _mdns_scan(self, src):
        self.mdns.scan(src)

    # ---------------------------------------------------------- simple actions
    def next_adapter(self):
        st = self.st
        with st.lock:
            names = [a["name"] for a in st.adapters]
            if len(names) < 2:
                st.toast, st.toast_until = "Only one Ethernet adapter found", time.time() + 3
                return
            st.sel = names[(names.index(st.sel) + 1) % len(names)] if st.sel in names else names[0]
            st.reset_adapter()
            st.toast, st.toast_until = f"Switched to {st.sel}", time.time() + 3
        self.mdns.reset()
        self.kick.set()
        self.restart_sniffer()

    def reset_counters(self):
        with self.st.lock:
            self.st.io_base = self.st.io
            self.st.drops = 0
        self.st.say("Counters reset", 2)

    def renew(self):
        threading.Thread(target=self._renew, daemon=True).start()

    def _renew(self):
        name = self.st.sel
        if not name:
            return
        self.st.say("Releasing DHCP lease…", 30)
        if not IS_LINUX:
            N.run(["ipconfig", "/release", name], 30)
        with self.st.lock:
            self.st.ip_wait_from = time.time()
            self.st.time_to_ip = None
            self.st.gw_ms = self.st.dns_ms = self.st.net_ms = PENDING
            self.st.public_ip = None
            self.st.dhcp_done = False
        self.st.say("Requesting new address…", 60)
        if IS_LINUX:
            ok, err = N.linux_renew(name)
        else:
            ok, err = N.run(["ipconfig", "/renew", name], 45)[0] == 0, ""
        self.kick.set()
        if ok:
            self.st.say("DHCP renew done", 3)
        elif IS_LINUX:
            self.st.say(f"Renew failed — {err or 'no DHCP reply'}"[:70], 6)
        else:
            self.st.say("Renew failed — " + ("needs admin" if not N.is_admin() else "no DHCP reply"), 5)

    def bounce(self):
        threading.Thread(target=self._bounce, daemon=True).start()

    def _bounce(self):
        name = self.st.sel
        if not name:
            return
        if not N.is_admin():
            self.st.say(f"Bounce {ADMIN_HINT}", 5)
            return
        self.st.say("Bouncing link…", 15)
        if IS_LINUX:
            N.linux_set_link(name, False)
            time.sleep(2)
            N.linux_set_link(name, True)
        else:
            N.powershell(f"Restart-NetAdapter -Name {N.psq(name)} -Confirm:$false", 30)
        self.kick.set()

    def update_oui(self, quiet=False):
        try:
            n = self.oui.download()
            if not quiet:
                self.st.say(f"Vendor list updated ({n:,} vendors)", 4)
        except Exception as e:  # noqa: BLE001
            if not quiet:
                self.st.say(f"Vendor download failed: {e}"[:70], 5)

    # ---------------------------------------------------------- tool targets
    def resolve(self, kind):
        with self.st.lock:
            d = self.st.d
            src = self.st.ipv4
            if kind == "gateway":
                tgt = N.first_v4(d.get("Gateway"))
            elif kind == "dns":
                tgt = N.first_v4(d.get("Dns"))
            elif kind == "switch":
                tgt = N.merge_neighbors(self.st.nb).get("mgmt_ip")
            else:
                tgt = kind
        if src and src.startswith("169.254."):
            src = None
        return tgt, src

    def _new_stop(self, name):
        old = self.stops.get(name)
        if old:
            old.set()
        ev = threading.Event()
        self.stops[name] = ev
        return ev

    # ---------------------------------------------------------- switches (SNMP)
    def _sw_client(self, ip, **kw):
        return SN.Client(ip, self.settings.get("snmp_community") or "public",
                         self.settings.get("snmp_version"), **kw)

    def _sw_stage(self, text):
        with self.st.lock:
            self.st.switches["stage"] = text

    def _sw_merge(self, ip, info):
        """Add a switch to the list, or refresh the one already there. True if it was new."""
        with self.st.lock:
            lst = self.st.switches["list"]
            cur = next((x for x in lst if x["ip"] == ip), None)
            new = cur is None
            if new:
                cur = new_switch(ip)
                lst.append(cur)
                lst.sort(key=lambda x: tuple(int(n) for n in x["ip"].split(".")))
            cur["name"] = info.get("name") or cur["name"]
            cur["model"] = SN.model_of(info) or cur["model"]
        self._sw_save()
        return new

    def _sw_save(self):
        with self.st.lock:
            keep = [{"ip": x["ip"], "name": x["name"], "model": x["model"]} for x in self.st.switches["list"]]
        self.settings.set("switches", keep)

    def sw_scan_toggle(self):
        with self.st.lock:
            running = self.st.switches["running"]
            ip, mask = self.st.ipv4, self.st.mask
            mgmt = N.merge_neighbors(self.st.nb).get("mgmt_ip")
        if running:
            self.stops["switches_scan"].set()
            return
        if not ip or not mask or ip.startswith("169.254."):
            self.st.say("Need an IP address to scan", 3)
            return
        ev = self._new_stop("switches_scan")
        threading.Thread(target=self._sw_scan, args=(ev, ip, mask, mgmt), daemon=True).start()

    def _sw_scan(self, ev, ip, mask, mgmt):
        """Ask the whole subnet, then follow CDP from each Cisco switch to the ones beyond it."""
        community, version = self.settings.get("snmp_community") or "public", self.settings.get("snmp_version")
        with self.st.lock:
            self.st.switches.update(running=True, stage="Starting…")
        new = answered = 0
        try:
            net, hosts, _ = N.scan_hosts(ip, mask)
            self._sw_stage(f"Asking {len(hosts)} addresses on {net}…")
            queue = list(SN.sweep(hosts, community, version, stop=ev))
            if mgmt and mgmt not in queue and SN.private_ip(mgmt):
                queue.append(mgmt)                  # the switch this port is on, even on another subnet
            tried, boots = set(), []
            while queue and not ev.is_set() and len(tried) < SW_SCAN_MAX:
                host = queue.pop(0)
                if host in tried:
                    continue
                tried.add(host)
                self._sw_stage(f"Checking {host}…")
                try:
                    with self._sw_client(host, timeout=1.0, retries=0) as c:   # most CDP neighbors are not switches
                        info = SN.identify(c)
                        answered += 1
                        if not SN.is_switch(info):
                            continue
                        boot = time.monotonic() - (info["uptime"] or 0) / 100
                        if any(n == info["name"] and abs(b - boot) < 5 for n, b in boots):
                            continue                # the same switch answering on another of its addresses
                        boots.append((info["name"], boot))
                        new += self._sw_merge(host, info)
                        if SN.is_cisco(info):
                            queue += [n for n in SN.cdp_neighbors(c) if n not in tried]
                except SN.SnmpError:
                    continue
            with self.st.lock:
                total = len(self.st.switches["list"])
            if ev.is_set():
                self.st.say("Scan stopped", 3)
            elif new:
                self.st.say(f"Found {new} new switch{'es' if new != 1 else ''} ({total} listed)", 5)
            elif total:
                self.st.say("No new switches", 4)
            else:
                self.st.say("Nothing answered SNMP: check the community and version" if not answered
                            else "Devices answered, but none is a switch", 6)
        except Exception as e:  # noqa: BLE001
            self.st.say(f"Scan error: {e}"[:70], 6)
        finally:
            with self.st.lock:
                self.st.switches["running"] = False
            self.sw_kick.set()

    def sw_add(self, text):
        try:
            ip = str(ipaddress.IPv4Address(text.strip()))
        except ValueError:
            self.st.say("That is not an IP address", 4)
            return
        threading.Thread(target=self._sw_add, args=(ip,), daemon=True).start()

    def _sw_add(self, ip):
        self.st.say(f"Asking {ip}…", 3)
        try:
            with self._sw_client(ip) as c:
                info = SN.identify(c)
        except SN.SnmpError:
            self.st.say(f"No SNMP answer from {ip}: check the address, community and version", 6)
            return
        new = self._sw_merge(ip, info)
        self.st.say(f"{'Added' if new else 'Already listed:'} {info.get('name') or ip}", 4)
        self.sw_kick.set()

    def sw_remove(self, ip):
        with self.st.lock:
            lst = self.st.switches["list"]
            lst[:] = [x for x in lst if x["ip"] != ip]
        self.swwatch.pop(ip, None)
        self._sw_save()

    def sw_clear(self, ip, index=None, name=""):
        """Forget the errors seen on one port, or on every port of a switch, and watch afresh."""
        with self.sw_poll_lock:
            watch = self.swwatch.get(ip)
            if watch:
                watch.clear(index)
        self.st.say(f"Cleared {name or 'every port'}: watching for new errors from now", 4)
        self.sw_kick.set()

    def sw_set_community(self, v):
        if v:
            self.settings.set("snmp_community", v)
            self.sw_kick.set()

    def sw_next_version(self):
        self.settings.set("snmp_version", 2 if self.settings.get("snmp_version") == 1 else 1)
        self.sw_kick.set()

    def sw_watch_start(self):
        ev = self._new_stop("switches")
        threading.Thread(target=self._sw_watch, args=(ev,), daemon=True).start()

    def sw_watch_stop(self):
        ev = self.stops.get("switches")
        if ev:
            ev.set()
        self.sw_kick.set()

    def _sw_watch(self, ev):
        """Re-read every listed switch while the Switches page is open."""
        while not ev.is_set():
            with self.st.lock:
                ips = [x["ip"] for x in self.st.switches["list"]]
            workers = [threading.Thread(target=self._sw_poll, args=(ip,), daemon=True) for ip in ips]
            for w in workers:
                w.start()
            for w in workers:
                w.join(30)
            self.sw_kick.wait(SW_POLL_SECS)
            self.sw_kick.clear()

    def _sw_read(self, ip):
        with self._sw_client(ip) as c:
            got = c.get([SN.SYS_UPTIME, SN.SYS_NAME])
            return SN.read_ports(c), got.get(SN.SYS_UPTIME), SN.text(got.get(SN.SYS_NAME))

    def _sw_poll(self, ip):
        ports, err = None, ""
        try:
            ports, uptime, name = self._sw_read(ip)
        except SN.SnmpError as e:
            err = str(e)
        except Exception:  # noqa: BLE001
            log_error(f"reading switch {ip}")
            err = "Could not read this switch"
        now = time.time()
        with self.sw_poll_lock:
            if ports is not None:
                ports = self.swwatch.setdefault(ip, SN.SwitchWatch()).update(ports, uptime, now)
            with self.st.lock:
                x = next((x for x in self.st.switches["list"] if x["ip"] == ip), None)
                if x is None:
                    return
                if ports is None:
                    x.update(ok=False, msg=err, fails=x["fails"] + 1)
                else:
                    x.update(ok=True, msg="", fails=0, ports=ports, sum=SN.summarize(ports), polled=now,
                             name=name or x["name"])

    # ---------------------------------------------------------- ping
    def ping_toggle(self):
        with self.st.lock:
            running = self.st.ping["running"]
        if running:
            self.stops["ping"].set()
            return
        ev = self._new_stop("ping")
        threading.Thread(target=self._ping_loop, args=(ev,), daemon=True).start()

    def ping_next_target(self):
        with self.st.lock:
            p = self.st.ping
            kinds = [k for k, _ in PING_TARGETS]
            i = (kinds.index(p["kind"]) + 1) % len(kinds) if p["kind"] in kinds else 0
            running = p["running"]
            fresh = new_ping()
            fresh["kind"], fresh["label"], fresh["running"] = PING_TARGETS[i][0], PING_TARGETS[i][1], running
            fresh["span"] = p["span"]
            self.st.ping = fresh

    PING_SPANS = (30, 300, 1800)

    def ping_next_span(self):
        with self.st.lock:
            p, opts = self.st.ping, self.PING_SPANS
            p["span"] = opts[(opts.index(p["span"]) + 1) % len(opts)] if p["span"] in opts else opts[0]

    def event(self, kind, text, sev="warn", quiet=0.0):
        """Put something on the event timeline. Use st.add_event when st.lock is already held."""
        with self.st.lock:
            self.st.add_event(kind, text, sev, time.time(), quiet)

    def _ping_loop(self, ev):
        st = self.st
        with st.lock:
            st.ping["running"] = True
        try:
            while not ev.is_set():
                t0 = time.time()
                with st.lock:
                    kind = st.ping["kind"]
                tgt, src = self.resolve(kind)
                if not tgt:
                    with st.lock:
                        st.ping["target"] = None
                    ev.wait(1)
                    continue
                status, _, rtt = self.echo(tgt, src, timeout_ms=1000)
                with st.lock:
                    p = st.ping
                    if p["kind"] != kind:
                        continue
                    p["target"] = tgt
                    p["sent"] += 1
                    if status == "ok":
                        p["recv"] += 1
                        p["samples"].append((t0, rtt))
                        p["min"] = rtt if p["min"] is None else min(p["min"], rtt)
                        p["max"] = rtt if p["max"] is None else max(p["max"], rtt)
                        p["sum"] += rtt
                        if p["last"] is not None:
                            p["jit"] += abs(rtt - p["last"])
                            p["jn"] += 1
                        p["last"] = rtt
                        p["log"].appendleft((f"#{p['sent']}  reply  {fmt_ms(rtt)}", OK))
                    else:
                        p["samples"].append((t0, None))
                        p["log"].appendleft((f"#{p['sent']}  {status}", BAD))
                ev.wait(max(0.0, 0.25 - (time.time() - t0)))
        finally:
            with st.lock:
                st.ping["running"] = False

    # ---------------------------------------------------------- traceroute
    def trace_next_target(self):
        with self.st.lock:
            t = self.st.trace
            if t["running"]:
                return
            kinds = [k for k, _ in TRACE_TARGETS]
            i = (kinds.index(t["kind"]) + 1) % len(kinds) if t["kind"] in kinds else 0
            t["kind"], t["label"], t["hops"], t["target"] = TRACE_TARGETS[i][0], TRACE_TARGETS[i][1], [], None

    def trace_toggle(self):
        with self.st.lock:
            running = self.st.trace["running"]
        if running:
            self.stops["trace"].set()
            return
        ev = self._new_stop("trace")
        threading.Thread(target=self._trace, args=(ev,), daemon=True).start()

    def _trace(self, ev):
        st = self.st
        with st.lock:
            kind = st.trace["kind"]
            st.trace.update(running=True, hops=[])
        tgt, src = self.resolve(kind)
        try:
            if not tgt:
                with st.lock:
                    st.trace["hops"] = [(0, None, None, "no target yet")]
                return
            with st.lock:
                st.trace["target"] = tgt
            for ttl in range(1, 21):
                if ev.is_set():
                    break
                status, ip, rtt = self.echo(tgt, src, ttl=ttl, timeout_ms=1000)
                with st.lock:
                    st.trace["hops"] = st.trace["hops"] + [(ttl, ip, rtt, status)]
                if status in ("ok", "unreach"):
                    break
        finally:
            with st.lock:
                st.trace["running"] = False

    # ---------------------------------------------------------- speed tests
    def speed_iperf(self):
        server = (self.settings.get("iperf_server") or "").strip()
        if not server:
            self.st.say("Set the iperf3 server in Tools › Settings first", 5)
            return
        exe = N.find_iperf([SCRIPT_DIR, DATA_DIR])
        if not exe and not DEMO:
            with self.st.lock:
                self.st.speed = {"running": False, "mode": "iperf3", "down": None, "up": None,
                                 "lines": [("iperf3.exe not found.", BAD),
                                           ("Download iperf3 for Windows and put iperf3.exe in:", FG),
                                           (SCRIPT_DIR, HDR)]}
            return
        self._speed_run("iperf3", lambda src, rev: self._iperf(exe, server, src, rev), server)

    def speed_http(self):
        def one(src, rev):
            try:
                return self._http(src, "down" if rev else "up"), None, None
            except Exception as e:  # noqa: BLE001
                return None, None, str(e)[:90]
        self._speed_run("internet", one, N.SPEED_HOST)

    def _speed_run(self, mode, fn, server):
        with self.st.lock:
            if self.st.speed["running"]:
                return
            self.st.speed = {"running": True, "mode": mode, "down": None, "up": None,
                             "lines": [(f"{mode} test against {server}", HDR)]}

        def work():
            _, src = self.resolve("gateway")
            for rev, key, label in ((True, "down", "Download"), (False, "up", "Upload")):
                with self.st.lock:
                    self.st.speed["lines"].append((f"{label}…", DIM))
                bps, retr, err = fn(src, rev)
                with self.st.lock:
                    sp = self.st.speed
                    if err:
                        sp["lines"].append((f"{label} failed: {err}", BAD))
                    else:
                        sp[key] = bps
                        extra = f"  ({retr} retransmits)" if retr else ""
                        sp["lines"].append((f"{label}: {N.fmt_mbps(bps)}{extra}", OK))
            with self.st.lock:
                self.st.speed["running"] = False
        threading.Thread(target=work, daemon=True).start()

    # ---------------------------------------------------------- ARP
    def arp_refresh(self):
        with self.st.lock:
            name = self.st.sel
            if self.st.arp_table["running"] or not name:
                return
            self.st.arp_table["running"] = True

        def work():
            rows = []
            try:
                rows = self._arp_table(name)
            finally:
                rows.sort(key=lambda r: N.u32(socket.inet_aton(r[0]), 0))
                with self.st.lock:
                    self.st.arp_table = {"running": False, "rows": rows, "ts": time.time()}
        threading.Thread(target=work, daemon=True).start()

    def arp_scan_toggle(self):
        with self.st.lock:
            sc = self.st.arp_scan
            if sc["running"]:
                self.stops["arpscan"].set()
                return
            ip, mask, mac = self.st.ipv4, self.st.mask, self.my_mac()
        if not ip or not mask or ip.startswith("169.254."):
            self.st.say("Need an IP address to scan", 3)
            return
        if self.l2sock is None:
            self.st.say("ARP scan needs Npcap", 4)
            return
        ev = self._new_stop("arpscan")
        threading.Thread(target=self._arp_scan, args=(ev, ip, mask, mac), daemon=True).start()

    def _arp_scan(self, ev, ip, mask, mac):
        net, hosts, limited = N.scan_hosts(ip, mask)
        with self.st.lock:
            self.st.arp_scan = {"running": True, "net": str(net), "limited": limited,
                                "range": (int(net.network_address), int(net.netmask)),
                                "found": {ip: [mac]}, "sent": 0, "total": len(hosts)}
        try:
            for rnd in range(2):
                for i, h in enumerate(hosts):
                    if ev.is_set():
                        return
                    if rnd == 1:
                        with self.st.lock:
                            if h in self.st.arp_scan["found"]:
                                continue
                    self.send(N.build_arp_request(mac, ip, h))
                    if i % 16 == 0:
                        with self.st.lock:
                            self.st.arp_scan["sent"] = i + rnd * len(hosts)
                    time.sleep(0.004)
                ev.wait(1.5)
            ev.wait(1.5)
        finally:
            with self.st.lock:
                self.st.arp_scan["running"] = False
                self.st.arp_scan["sent"] = self.st.arp_scan["total"]

    # ---------------------------------------------------------- mDNS
    def mdns_scan(self):
        if self.mdns.snapshot()["running"]:
            return
        _, src = self.resolve("gateway")
        if not src:
            self.st.say("Need an IP address for mDNS", 3)
            return
        threading.Thread(target=self._mdns_scan, args=(src,), daemon=True).start()

    # ---------------------------------------------------------- smart-home discovery
    def smart_scan_toggle(self):
        with self.st.lock:
            running = self.st.smart["running"]
            ip, mask, mac, name = self.st.ipv4, self.st.mask, self.my_mac(), self.st.sel
        if running:
            self.stops["smart"].set()
            return
        if not ip or not mask or ip.startswith("169.254."):
            self.st.say("Need an IP address to scan", 3)
            return
        ev = self._new_stop("smart")
        threading.Thread(target=self._smart_scan, args=(ev, ip, mask, mac, name), daemon=True).start()

    def _smart_progress(self, text):
        with self.st.lock:
            self.st.smart["stage"] = text

    def _smart_scan(self, ev, ip, mask, mac, name):
        with self.st.lock:
            self.st.smart.update(running=True, stage="Starting…")
        try:
            def mdns_fn():
                self._mdns_scan(ip)
                return self.mdns.snapshot()
            scan = S.SmartScan(ip, mask, mac, self.oui, lambda: self._arp_table(name), mdns_fn,
                               self._smart_progress, services=bool(self.settings.get("smart_services")))
            devs = scan.run(ev)
            self._smart_store(devs, scan.counts)
        except Exception as e:  # noqa: BLE001
            self.st.say(f"Scan error: {e}"[:70], 6)
        finally:
            with self.st.lock:
                self.st.smart["running"] = False

    def _smart_store(self, devs, counts):
        for d in devs:
            d["key"] = S.DeviceStore.key(d)
        _, err = self.devstore.merge(devs)
        for d in devs:
            d["label"] = self.devstore.label(d["key"])
            d["ports"] = self.devstore.ports(d["key"])      # includes what an earlier full check found
        with self.st.lock:
            self.st.smart.update(devices=devs, ts=time.time(), counts=dict(counts))
        n = sum(1 for d in devs if d.get("smart"))
        self.st.say(err or f"Found {n} smart devices ({len(devs)} hosts) — saved to devices.csv", 5)

    def set_device_label(self, key, label):
        err = self.devstore.set_label(key, label)
        with self.st.lock:
            for d in self.st.smart["devices"]:
                if d.get("key") == key:
                    d["label"] = label
        self.st.say(err or (f"Labelled: {label}" if label else "Label cleared"), 3)

    def device_ports_scan(self, key):
        """Check every common service port on one device (the Ports button on its detail card)."""
        with self.st.lock:
            d = next((x for x in self.st.smart["devices"] if x.get("key") == key), None)
            src = self.st.ipv4
            if not d or d.get("port_scan") == "running":
                return
            d["port_scan"] = "running"
            ip = d["ip"]
        threading.Thread(target=self._device_ports_scan, args=(key, ip, src), daemon=True).start()

    def _probe_device(self, ip, src):
        return S.probe_ports(ip, S.ALL_PORTS, src)

    def _device_ports_scan(self, key, ip, src):
        try:
            ports = self._probe_device(ip, src)
        except Exception:  # noqa: BLE001
            log_error("Port check failed")
            ports = None
        err = self.devstore.set_ports(key, ports) if ports is not None else "Port check failed"
        with self.st.lock:
            for d in self.st.smart["devices"]:
                if d.get("key") == key:
                    d["port_scan"] = "done" if ports is not None else ""
                    if ports is not None:
                        d["ports"], d["services_checked"] = ports, True
        self.st.say(err or f"{ip}: {len(ports)} of {len(S.ALL_PORTS)} common services answer", 4)

    # ---------------------------------------------------------- wire report
    WIRE_BUSY = 5000                # frames a second at which counting is paused to protect the CPU

    def wire_reset(self):
        """Start the report again from now."""
        with self.st.lock:
            keep_nic = self.st.wire["nic"]
            self.st.wire = N.new_wire()
            self.st.wire["nic"] = keep_nic
        self.arpwatch = N.ArpWatch()
        self.nic_base = None
        ww = self.wirewatch
        if ww is not None:
            self.wirewatch = N.WireWatch(ww.local)
        self.st.say("Wire report restarted", 3)

    def _wire_stop(self):
        sn, self.wire_sniffer, self.wirewatch = self.wire_sniffer, None, None
        if sn is not None:
            try:
                sn.stop()
            except Exception:  # noqa: BLE001
                pass

    def _wire_local_macs(self, name, mac):
        return (N.linux_local_macs(name) if IS_LINUX else set()) | {mac}

    def _wire_start(self, gen, iface, name, mac):
        """A second, count-only listener for everything not addressed to this box."""
        try:
            from scapy.all import AsyncSniffer
            self.wirewatch = N.WireWatch(self._wire_local_macs(name, mac))
            sn = AsyncSniffer(iface=iface, filter=N.wire_bpf(mac), store=False,
                              prn=lambda pkt: self._wire_feed(bytes(pkt)))
            sn.start()
            self.wire_sniffer = sn
        except Exception:  # noqa: BLE001
            log_error("Wire report listener failed to start")
            self.wirewatch = None

    def _wire_feed(self, raw):
        ww = self.wirewatch
        if ww is not None:
            ww.feed(raw)

    def wire_loop(self):
        """Every second: flooding and talker rates. Every five: the adapter's own settings and
        counters. Runs for the life of the app."""
        n = 0
        resume_at = 0.0
        while True:
            time.sleep(1)
            n += 1
            try:
                now = time.time()
                ww = self.wirewatch
                st = self.st
                with st.lock:
                    name, up, mac = st.sel, st.link, self.my_mac()
                if ww is None and resume_at and now >= resume_at and self.sniff_iface is not None:
                    resume_at = 0.0
                    self._wire_start(self.sniff_gen, self.sniff_iface, name, mac)
                    with st.lock:
                        st.wire["paused"] = False
                elif ww is not None:
                    ww.tick(now)
                    snap = ww.snapshot()
                    with st.lock:
                        was = (st.wire["talk"] or {}).get("flood_pps", 0)
                        st.wire["talk"] = snap
                        if snap["flood_pps"] >= 20 > was:
                            st.add_event("flood", f"Flooding: {snap['flood_pps']:,.0f} frames a second for other "
                                         "machines are reaching this port", "warn", now, quiet=20)
                    if snap["pps"] > self.WIRE_BUSY:
                        self._wire_stop()
                        resume_at = now + 30
                        with st.lock:
                            st.wire["paused"] = True
                            st.add_event("flood", f"Over {self.WIRE_BUSY:,} frames a second not addressed to this "
                                         "box: a mirror port, a hub, or a severe flood", "warn", now, quiet=120)
                if n % 5 == 0 and name and up:
                    self._nic_poll(name)
            except Exception:  # noqa: BLE001
                pass

    def _nic_report(self, name):
        return N.linux_nic_report(name) if IS_LINUX else None

    def _nic_poll(self, name):
        rep = self._nic_report(name)
        st = self.st
        now = time.time()
        if rep is None:
            return
        pause, errors = rep["stats"]
        cur = dict(pause, **errors)
        with st.lock:
            if st.sel != name:
                return
            old_eee = ((st.wire["nic"] or {}).get("eee") or {}).get("active")
            st.wire["nic"] = rep
            if self.nic_base is None or self.nic_base[0] != name:
                self.nic_base = (name, cur, cur)
            _, base, last = self.nic_base
            st.wire["rises"] = N.counter_rises(base, cur)
            step = N.counter_rises(last, cur)
            self.nic_base = (name, base, cur)
            for k, v in sorted(step.items()):
                if N.PAUSE_STAT.search(k):
                    st.add_event("pause", f"PAUSE frames counted by the adapter ({k})", "warn", now, quiet=15)
                else:
                    st.add_event("errors", f"Adapter error counter rising: {k} +{v:,}", "bad", now, quiet=15)
            if rep["eee"].get("active") and not old_eee:
                st.add_event("eee", "Energy Efficient Ethernet is active on this link", "warn", now, quiet=3600)
            best = N.downshift(rep["link"])
            if best:
                st.add_event("link", f"Linked at {N.fmt_speed(rep['link']['speed'])} although both ends offer "
                             f"{N.fmt_speed(best)}: suspect the cable", "bad", now, quiet=3600)

    # ---------------------------------------------------------- tick-rate test
    TICK_SPANS = (30, 300)
    TICK_COLS = 240

    def tick_toggle(self):
        with self.st.lock:
            running, rate, src = self.st.tick["running"], self.st.tick["rate"], self.st.ipv4
        if running:
            self.stops["tick"].set()
            return
        target = N.parse_tick_server(self.settings.get("tick_server"))
        if not target:
            self.st.say("Set the reflector's address first (the Server button)", 5)
            return
        if not src:
            self.st.say("Need an IP address", 3)
            return
        ev = self._new_stop("tick")
        with self.st.lock:
            self.st.tick.update(running=True, msg="", sum=None, cols=[], counters={},
                                target=f"{target[0]}:{target[1]}", impacts={})
        threading.Thread(target=self._tick_run, args=(ev, src, target, rate), daemon=True).start()

    def tick_next_rate(self):
        with self.st.lock:
            t, opts = self.st.tick, N.TICK_RATES
            if not t["running"]:
                t["rate"] = opts[(opts.index(t["rate"]) + 1) % len(opts)] if t["rate"] in opts else opts[0]

    def tick_next_span(self):
        with self.st.lock:
            t, opts = self.st.tick, self.TICK_SPANS
            t["span"] = opts[(opts.index(t["span"]) + 1) % len(opts)] if t["span"] in opts else opts[0]

    def tick_set_server(self, text):
        text = (text or "").strip()
        if text and not N.parse_tick_server(text):
            self.st.say("Enter an address like 10.1.2.3, optionally followed by a port", 5)
            return
        self.settings.set("tick_server", text)

    def _tick_open(self, src, target, rate):
        t = N.TickTest(src, target[0], target[1], rate)
        t.start()
        return t.buf, t

    def _tick_run(self, ev, src, target, rate):
        st = self.st
        try:
            buf, test = self._tick_open(src, target, rate)
        except OSError as e:
            with st.lock:
                st.tick.update(running=False, msg=f"Couldn't start: {e}"[:80])
            return
        t0 = time.time()
        while not ev.wait(0.5):
            self._tick_publish(buf, rate, getattr(test, "pace_err", 0.0), t0)
        if test is not None:
            test.stop()
        self._tick_publish(buf, rate, getattr(test, "pace_err", 0.0), t0)
        with st.lock:
            st.tick["running"] = False

    def _tick_publish(self, buf, rate, pace, t0):
        """Twice a second: boil the run down to what the screen needs. The packets themselves
        stay here; copying tens of thousands of them into the UI each refresh would be slow."""
        st = self.st
        now = time.time()
        with st.lock:
            span, events = st.tick["span"], list(st.events)
        samples = buf.samples(now)
        recent = [x for x in samples if x[0] >= now - span]
        summ = N.tick_summary(recent, rate)
        c = buf.counters()
        hold = dict(N.hold_summary(buf.holds(now - span), rate), mode=buf.hold_mode)
        msg = ""
        if c["sent"] > rate * 2 and c["recv"] == 0 and now - t0 > 2:
            msg = "No replies. Is the reflector running there, and is its firewall open?"
        impacts = {e["ts"]: N.impact_text(N.event_impact(samples, e["ts"], before=10, after=3),
                                          "the test", "packet")
                   for e in events[-25:]}
        with st.lock:
            st.tick.update(sum=summ, counters=c, pace=pace, t_end=now, msg=msg, impacts=impacts, hold=hold,
                           cols=N.bucket_samples(samples, now, span, self.TICK_COLS),
                           normal=summ["p50"] or 0.0)

    def tick_reflect_toggle(self):
        r = getattr(self, "reflector", None)
        if r is not None:
            r.stop()
            self.reflector = None
            with self.st.lock:
                self.st.tick.update(reflecting=False)
            self.st.say("Reflector stopped", 3)
            return
        try:
            r = N.Reflector(N.TICK_PORT)
        except OSError as e:
            self.st.say(f"Can't listen on UDP {N.TICK_PORT}: {e}"[:70], 5)
            return
        r.start()
        self.reflector = r
        with self.st.lock:
            self.st.tick.update(reflecting=True, reflected=0, peers=[])
        self.st.say(f"Reflecting on UDP port {N.TICK_PORT}", 4)

        def watch():
            while self.reflector is r:
                with self.st.lock:
                    self.st.tick.update(reflected=r.count, peers=sorted(r.peers))
                time.sleep(1)
        threading.Thread(target=watch, daemon=True).start()

    # ---------------------------------------------------------- multicast browser
    MCAST_PROBE_GROUP = "239.192.137.251"       # joined for a moment to make a querier speak up

    def mcast_toggle(self):
        with self.st.lock:
            running = self.st.mcast["running"]
        if running:
            self.mcast_stop()
        else:
            self.mcast_start()

    def mcast_start(self):
        with self.st.lock:
            if self.st.mcast["running"]:
                return
            name = self.st.sel
        iface = self.sniff_iface
        if not name or self.sniffer is None or iface is None:
            with self.st.lock:
                self.st.mcast["msg"] = "Capture isn't running on this adapter — see the L2 page"
            return
        ev = self._new_stop("mcast")
        with self.st.lock:
            self.st.mcast.update(running=True, msg="", snap=None, probed=None)
        threading.Thread(target=self._mcast_run, args=(ev, iface), daemon=True).start()

    def mcast_stop(self):
        ev = self.stops.get("mcast")
        if ev:
            ev.set()
        self.mcast_leave(quiet=True)

    def _mcast_run(self, ev, iface):
        tr = N.McastTracker()
        sn = None
        try:
            from scapy.all import AsyncSniffer
            sn = AsyncSniffer(iface=iface, filter=N.MCAST_BPF, store=False,
                              prn=lambda pkt: tr.feed(bytes(pkt), float(pkt.time)))
            sn.start()
        except Exception as e:  # noqa: BLE001
            log_error("Multicast browser failed to start")
            with self.st.lock:
                self.st.mcast.update(running=False, msg=f"Couldn't start: {e}"[:80])
            return
        self._mcast_publish(ev, tr)
        try:
            sn.stop()
        except Exception:  # noqa: BLE001
            pass

    def _mcast_publish(self, ev, tr):
        """Once a second: work out the rates and hand the UI a fresh picture."""
        while True:
            now = time.time()
            tr.tick(now)
            snap = tr.snapshot(now)
            with self.st.lock:
                self.st.mcast["snap"] = snap
            if ev.wait(1.0):
                break
        with self.st.lock:
            self.st.mcast["running"] = False

    def mcast_join(self, text):
        target = N.parse_mcast_target(text)
        with self.st.lock:
            src = self.st.ipv4
            self.st.mcast["last_join"] = (text or "").strip() or "239."
        if not target:
            self.st.say("Not a multicast group — try something like 239.1.2.3", 5)
            return
        if not src:
            self.st.say("Need an IP address to join a group", 4)
            return
        self.mcast_leave(quiet=True)
        group, port = target
        try:
            sock = N.mcast_join_socket(group, src)
        except OSError as e:
            self.st.say(f"Couldn't join {group}: {e}"[:70], 5)
            return
        self.mcast_sock = sock
        with self.st.lock:
            self.st.mcast["join"] = {"group": group, "port": port, "since": time.time()}
        self.mcast_start()
        self.st.say(f"Joined {group}", 3)

    def mcast_leave(self, quiet=False):
        sock, self.mcast_sock = getattr(self, "mcast_sock", None), None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        with self.st.lock:
            j, self.st.mcast["join"] = self.st.mcast["join"], None
        if j and not quiet:
            self.st.say(f"Left {j['group']}", 3)

    def mcast_probe(self):
        """Join a scratch group for a moment and leave it. A querier answers a leave with a
        group-specific query within about a second, which saves waiting two minutes for its
        next general one."""
        with self.st.lock:
            src, running = self.st.ipv4, self.st.mcast["running"]
        if not src or not running:
            self.st.say("Start the browser first" if src else "Need an IP address", 3)
            return

        def work():
            try:
                s = N.mcast_join_socket(self.MCAST_PROBE_GROUP, src)
                time.sleep(1.5)
                s.close()
            except OSError as e:
                self.st.say(f"Couldn't send the probe: {e}"[:70], 5)
                return
            with self.st.lock:
                self.st.mcast["probed"] = time.time()
        self.st.say("Asking for a querier…", 3)
        threading.Thread(target=work, daemon=True).start()

    # ---------------------------------------------------------- capture to file
    CAPTURE_SECS = (30, 60, 300)
    CAPTURE_MAX = 200 * 1024 * 1024         # stop early instead of filling the disk on a busy port

    @staticmethod
    def capture_dir():
        return os.path.join(DATA_DIR, "captures")

    def capture_refresh(self):
        files = N.list_captures(self.capture_dir())
        with self.st.lock:
            self.st.capture["files"] = files

    def capture_next_secs(self):
        with self.st.lock:
            c = self.st.capture
            if not c["running"]:
                opts = self.CAPTURE_SECS
                c["secs"] = opts[(opts.index(c["secs"]) + 1) % len(opts)] if c["secs"] in opts else opts[0]

    def capture_toggle(self):
        with self.st.lock:
            c = self.st.capture
            running, secs, name = c["running"], c["secs"], self.st.sel
            nb = N.merge_neighbors(self.st.nb)
        if running:
            self.stops["capture"].set()
            return
        iface = self.sniff_iface
        if not name or self.sniffer is None or iface is None:
            self.st.say("Capture isn't running on this adapter — see the L2 page", 5)
            return
        tag = "-".join(str(x) for x in (nb.get("name") or nb.get("chassis"), nb.get("port")) if x)
        ev = self._new_stop("capture")
        with self.st.lock:
            self.st.capture.update(running=True, left=secs, frames=0, bytes=0, file="", msg="", ok=True)
        threading.Thread(target=self._capture, args=(ev, iface, secs, tag), daemon=True).start()

    def _capture(self, ev, iface, secs, tag):
        """Record everything this adapter sees, unfiltered, for `secs` seconds."""
        st = self.st

        def finish(msg, ok):
            with st.lock:
                st.capture.update(running=False, left=0, msg=msg, ok=ok)
            self.capture_refresh()

        w = sn = None
        try:
            from scapy.all import AsyncSniffer
            os.makedirs(self.capture_dir(), exist_ok=True)
            path = os.path.join(self.capture_dir(), N.capture_name(time.time(), tag))
            w = N.PcapWriter(path)
            sn = AsyncSniffer(iface=iface, store=False,
                              prn=lambda pkt: w.add(bytes(pkt), float(pkt.time)))
            sn.start()
        except Exception as e:  # noqa: BLE001
            log_error("Capture to file failed to start")
            if w is not None:
                w.close()
            finish(f"Couldn't start: {e}"[:80], False)
            return
        with st.lock:
            st.capture["file"] = os.path.basename(path)
        t0, why = time.time(), ""
        while True:
            left = secs - (time.time() - t0)
            with st.lock:
                st.capture.update(left=max(0.0, left), frames=w.frames, bytes=w.bytes)
            if left <= 0:
                break
            if w.bytes >= self.CAPTURE_MAX:
                why = " · stopped at the 200 MB limit"
                break
            if time.time() - t0 > 1 and not getattr(sn, "running", True):
                why = " · the capture stopped early"
                break
            if ev.wait(0.25):
                why = " · stopped"
                break
        try:
            sn.stop()
        except Exception:  # noqa: BLE001
            pass
        w.close()
        with st.lock:
            st.capture.update(frames=w.frames, bytes=w.bytes)
        finish(f"Saved {w.frames:,} frames · {N.fmt_bytes(w.bytes)}{why}", True)

    # ---------------------------------------------------------- port finder
    def blink_toggle(self):
        with self.st.lock:
            running, name = self.st.blink["running"], self.st.sel
        if running:
            self.stops["blink"].set()
            return
        if not name:
            return
        if not N.is_admin():
            self.st.say(f"Port finder {ADMIN_HINT}", 4)
            return
        ev = self._new_stop("blink")
        threading.Thread(target=self._blink, args=(ev, name), daemon=True).start()

    def _blink(self, ev, name):
        lock = os.path.join(DATA_DIR, "blink.lock")
        try:
            with open(lock, "w", encoding="utf-8") as f:
                f.write(name)
        except OSError:
            pass
        with self.st.lock:
            self.st.blink = {"running": True, "cycles": 0}
        try:
            while not ev.is_set():
                self._set_admin(name, False)
                ev.wait(1.5)
                self._set_admin(name, True)
                with self.st.lock:
                    self.st.blink["cycles"] += 1
                ev.wait(3.0)
        finally:
            self._set_admin(name, True)
            try:
                os.remove(lock)
            except OSError:
                pass
            with self.st.lock:
                self.st.blink["running"] = False


# ================================================================ demo backend
class DemoBackend(Backend):
    """Fake data so every screen can be previewed without a switch."""

    def start(self):
        st = self.st
        with st.lock:
            st.adapters = [{"name": "Ethernet", "desc": "Realtek PCIe GbE Family Controller",
                            "mac": "00:e0:4c:68:12:9a", "up": True},
                           {"name": "Ethernet 2", "desc": "ASIX USB 2.5G Ethernet",
                            "mac": "00:0e:c6:aa:41:07", "up": False}]
            st.sel = "Ethernet"
            st.mac = "00:e0:4c:68:12:9a"
            st.sniff_msg = "listening"
        self.l2sock = object()
        threading.Thread(target=self.loop, daemon=True).start()
        threading.Thread(target=self.probe_loop, daemon=True).start()
        threading.Thread(target=self._demo_wire, daemon=True).start()

    # Pretend switches for the Switches page: name, port prefix, access ports, uplinks, what is wrong.
    DEMO_SWITCHES = {
        "10.20.0.1": ("CORE-SW", "Gi", 48, 4, {"Gi0/3": "crc", "Gi0/9": "flap", "Gi0/20": "slow10",
                                               "Gi0/31": "full", "Gi0/40": "drops"}),
        "10.20.0.11": ("TABLE-A-SW", "Fa", 24, 2, {"Fa0/7": "crc", "Gi0/1": "busy", "Fa0/22": "shut"}),
        "10.20.0.12": ("TABLE-B-SW", "Gi", 24, 4, {"Gi0/14": "slow100"}),
        "10.20.0.13": ("TABLE-C-SW", "Fa", 24, 2, {}),
    }

    def _sw_scan(self, ev, ip, mask, mgmt):
        with self.st.lock:
            self.st.switches.update(running=True, stage="Asking 254 addresses on 10.20.30.0/24…")
        time.sleep(0.8)
        for host, spec in self.DEMO_SWITCHES.items():
            self._sw_stage(f"Checking {host}…")
            time.sleep(0.25)
            self._sw_merge(host, {"name": spec[0], "descr": "Cisco IOS Software, C3560 Software"})
        with self.st.lock:
            self.st.switches["running"] = False
        self.st.say(f"Found {len(self.DEMO_SWITCHES)} switches", 4)
        self.sw_kick.set()

    def _sw_add(self, ip):
        self._sw_merge(ip, {"name": "SW-" + ip.rpartition(".")[2], "descr": "Cisco IOS Software, C3560 Software"})
        self.sw_kick.set()

    def _sw_read(self, ip):
        name, kind, n, up, wrong = self.DEMO_SWITCHES.get(ip, ("SW-" + ip.rpartition(".")[2], "Fa", 24, 2, {}))
        self.demo_sw_t0 = getattr(self, "demo_sw_t0", time.time())
        t = time.time() - self.demo_sw_t0
        speed = 1000 if kind == "Gi" else 100
        names = [(f"{kind}0/{i}", speed) for i in range(1, n + 1)]
        names += [(f"Gi0/{i + (n if kind == 'Gi' else 0)}", 1000) for i in range(1, up + 1)]
        ports = []
        for i, (pname, spd) in enumerate(names):
            what = wrong.get(pname, "")
            linked = i % 7 != 5 or bool(what)
            c = dict(in_err=0, out_err=0, in_disc=0, out_disc=0, fcs=0, align=0, late=0, excess=0,
                     in_oct=int(t * spd * 2500 * (1 + i % 5)), out_oct=int(t * spd * 900 * (1 + i % 3)))
            p = dict(index=10001 + i, name=pname, descr=pname, alias=f"Seat {i + 1:02d}" if i < n else "Uplink",
                     admin=what != "shut", oper=linked and what != "shut", speed=spd, duplex="full",
                     last_change=4000, wide=True, c=c)
            if what == "crc":                       # one cable keeps erroring, the other stops after a minute
                c["fcs"] = c["in_err"] = int((t if pname.startswith("Gi") else min(t, 60)) * 2.4)
            elif what == "drops":
                c["out_disc"] = int(t * 31)
            elif what in ("busy", "full"):
                c["out_oct"] = int(t * spd * 125000 * (0.78 if what == "busy" else 0.96))
            elif what == "slow10":
                p["speed"] = 10
                c["in_oct"] = c["out_oct"] = int(t * 40000)
            elif what == "slow100":
                p["speed"] = 100
                c["in_oct"] = c["out_oct"] = int(t * 400000)
            elif what == "flap":
                p["oper"] = int(t // 40) % 3 != 1
                p["last_change"] = 4000 + int(t // 40)
            ports.append(p)
        return ports, 8640000 + int(t * 100), name

    def wire_reset(self):
        self._demo_wire(once=True)
        self.st.say("Wire report restarted", 3)

    def _demo_wire(self, once=False):
        """A port with a few things wrong on it, so the wire report has something to show."""
        while True:
            if not once:
                time.sleep(6)
            now = time.time()
            with self.st.lock:
                w = self.st.wire
                if once:
                    w = self.st.wire = N.new_wire()
                w["nic"] = {"pause": {"autoneg": True, "rx": True, "tx": False},
                            "eee": {"supported": True, "enabled": True, "active": True, "partner": True},
                            "link": {"speed": 1000, "duplex": "Full", "ours": [10, 100, 1000, 2500],
                                     "partner": [10, 100, 1000]},
                            "stats": ({"rx_pause": 1840}, {"rx_crc_errors": 0, "align_errors": 0})}
                w["rises"] = {"rx_pause": int(now - w["since"]) // 4 + 3}
                w["talk"] = {"talkers": [
                    {"mac": "9c:76:13:aa:01:02", "bc": 5120, "mc": 240, "bytes": 0, "bc_pps": 84.0, "mc_pps": 3.0},
                    {"mac": "48:a6:b8:c1:d2:e3", "bc": 310, "mc": 4100, "bytes": 0, "bc_pps": 1.0, "mc_pps": 22.0},
                    {"mac": "d8:31:34:aa:bb:cc", "bc": 120, "mc": 980, "bytes": 0, "bc_pps": 0.0, "mc_pps": 6.0}],
                    "n_talkers": 14, "flood": 412, "flood_pps": 0.0, "pps": 140.0, "flood_dst": ["ec:b5:fa:12:34:56"]}
                w["conflicts"] = [{"ip": "10.20.30.88", "macs": ["3c:22:fb:10:20:30", "a4:83:e7:44:55:66"], "ts": now}]
                w["routers"] = {"70:db:98:1a:00:01": {"ts": now, "prefix": "2001:db8:30::/64"},
                                "a4:83:e7:44:55:66": {"ts": now, "prefix": "fd00:1234::/64"}}
                w["udld"] = {"op": "probe", "device": "FOC2145Z0AB", "port": "Gi1/0/23", "ts": now}
                w["icmp"] = [{"what": "fragneeded", "from": "10.20.0.1", "to": "10.20.30.147", "mtu": 1400,
                              "about": "172.16.9.20", "ts": now}]
            if once:
                return

    def send(self, frame):
        return True

    def loop(self):
        t0 = time.time()
        while True:
            t = time.time() - t0
            st = self.st
            with st.lock:
                if t < 2:
                    st.link = False
                elif t < 5:
                    if not st.link:
                        st.link_up_at = st.ip_wait_from = time.time()
                        st.l2_since = time.time() - 70
                    st.link, st.speed_mbps = True, 1000
                    st.d = {"FullDuplex": True, "DhcpEnabled": True}
                else:
                    st.link, st.speed_mbps = True, 1000
                    st.ipv4, st.mask = "10.20.30.147", "255.255.255.0"
                    if st.time_to_ip is None:
                        st.time_to_ip, st.ip_wait_from = 2.8, None
                    st.d = {"FullDuplex": True, "DhcpEnabled": True, "DhcpServer": "10.20.1.10",
                            "LeaseExpires": "Oct 10 4:52 PM", "Gateway": ["10.20.30.1"],
                            "Dns": ["10.20.1.10", "10.20.1.11"], "GwMac": "00-00-0C-07-AC-1E",
                            "V6": [{"IPAddress": "fe80::1c4a:9e2f:6d01:7a3b", "Origin": "WellKnown"},
                                   {"IPAddress": "2001:db8:30::1c4a:9e2f", "Origin": "RouterAdvertisement"}]}
                    st.gw_ms, st.dns_ms, st.net_ms = 0.9, 4.2, 18.6
                    st.public_ip = "203.0.113.47"
                    st.stp = {"proto": "Rapid-PVST", "vlan": 30, "root_prio": 24576,
                              "root_mac": "70:db:98:1a:00:01", "cost": 4}
                    st.dhcp_scan = {"xid": 1, "status": "done", "ts": time.time(), "offers": {
                        "10.20.1.10": {"tftp_ips": ["10.1.1.5", "10.1.1.6"]}}}
                    st.ra = {"router": "fe80::1", "m": False, "o": True, "prefixes": ["2001:db8:30::/64"]}
                    st.bc_pps, st.mc_pps = random.uniform(8, 20), random.uniform(30, 60)
                    st.mac = "00:e0:4c:68:12:9a"
                if t > 7:
                    st.nb["CDP"] = ({"name": "IDF2-ACC-SW01.lab.local", "port": "GigabitEthernet1/0/23",
                                     "vlan": 30, "voice_vlan": 130, "mgmt_ip": "10.20.0.12",
                                     "platform": "cisco C9200L-48P-4G", "duplex": "full",
                                     "poe": "15.4 W"}, time.time() - 12)
                    st.nb["LLDP"] = ({"name": "IDF2-ACC-SW01", "port": "Gi1/0/23",
                                      "autoneg": "Auto", "mau": "1000BASE-T FD"}, time.time() - 4)
                st.rx_bps = random.uniform(0.2e6, 1.8e6)
                st.tx_bps = random.uniform(0.05e6, 0.4e6)
            time.sleep(1)

    def echo(self, dst, src, ttl=128, timeout_ms=1000):
        time.sleep(0.05)
        if ttl < 6:
            hops = ["10.20.30.2", "10.20.0.1", "172.16.1.1", "68.85.10.1", "162.158.4.1"]
            return ("ttl", hops[ttl - 1], random.uniform(1, 4) * ttl)
        # Every 23 s the demo network has a spanning-tree change that costs a second of lag, and
        # once in between a gateway MAC change that costs nothing.
        phase = time.time() % 23
        if phase < 1.2:
            self.event("stp", "Spanning-tree topology change (VLAN 30)", "warn", quiet=10)
            return ("timeout", None, None) if random.random() < 0.45 else ("ok", dst, random.uniform(60, 220))
        if 11 < phase < 12:
            self.event("gwmac", "Gateway 10.20.30.1 changed MAC: 00:00:0c:07:ac:1e to 70:db:98:1a:00:01",
                       "bad", quiet=10)
        if random.random() < 0.004:
            return ("timeout", None, None)
        return ("ok", dst, random.uniform(0.4, 2.5))

    def _arp_table(self, name):
        return [("10.20.30.1", "00:00:0c:07:ac:1e", "Reachable"),
                ("10.20.30.2", "70:db:98:1a:00:41", "Stale"),
                ("10.20.30.3", "70:db:98:1a:00:42", "Stale"),
                ("10.20.30.55", "f0:b3:ec:12:9a:01", "Reachable")]

    def arp_scan_toggle(self):
        def work():
            with self.st.lock:
                self.st.arp_scan = {"running": True, "net": "10.20.30.0/24", "limited": False,
                                    "range": (0, 0), "found": {}, "sent": 0, "total": 253}
            fake = {"10.20.30.1": ["00:00:0c:07:ac:1e"], "10.20.30.2": ["70:db:98:1a:00:41"],
                    "10.20.30.3": ["70:db:98:1a:00:42"], "10.20.30.20": ["3c:22:fb:01:02:03"],
                    "10.20.30.55": ["f0:b3:ec:12:9a:01"], "10.20.30.88": ["00:1b:a9:44:55:66", "b8:27:eb:01:02:03"],
                    "10.20.30.147": ["00:e0:4c:68:12:9a"]}
            for i, (ip, macs) in enumerate(fake.items()):
                time.sleep(0.3)
                with self.st.lock:
                    self.st.arp_scan["found"][ip] = macs
                    self.st.arp_scan["sent"] = (i + 1) * 36
            with self.st.lock:
                self.st.arp_scan.update(running=False, sent=253)
        threading.Thread(target=work, daemon=True).start()

    def _mdns_scan(self, src):
        m = self.mdns
        with m.lock:
            m.running = True
        time.sleep(1.5)
        with m.lock:
            m.inst.update({("Living Room TV", "_airplay._tcp.local"): {"host": "lr-tv.local", "port": 7000},
                           ("Conf Room Display", "_googlecast._tcp.local"): {"host": "cast-1.local", "port": 8009},
                           ("HP LaserJet 4th Floor", "_ipp._tcp.local"): {"host": "hp-4f.local", "port": 631},
                           ("HP LaserJet 4th Floor", "_uscan._tcp.local"): {"host": "hp-4f.local", "port": 8080},
                           ("Sonos Lobby", "_sonos._tcp.local"): {"host": "sonos-lobby.local", "port": 1443}})
            m.hosts.update({"lr-tv.local": {"10.20.30.55"}, "cast-1.local": {"10.20.30.61"},
                            "hp-4f.local": {"10.20.30.20"}, "sonos-lobby.local": {"10.20.30.70"}})
            m.responders |= {"10.20.30.55", "10.20.30.61", "10.20.30.20", "10.20.30.70"}
            m.unicast_replies += 9
            m.multicast_seen += 3
            m.running = False
            m.last_scan = time.time()

    def _iperf(self, exe, server, src, reverse):
        time.sleep(1.2)
        return (941e6 if reverse else 936e6), (0 if reverse else 12), None

    def _http(self, src, which):
        time.sleep(1.2)
        return 482e6 if which == "down" else 41e6

    def _set_admin(self, name, enabled):
        pass

    def renew(self):
        self.st.say("DHCP renew (demo)", 2)

    def bounce(self):
        self.st.say("Bounce link (demo)", 2)

    def blink_toggle(self):
        with self.st.lock:
            self.st.blink["running"] = not self.st.blink["running"]

    def update_oui(self, quiet=False):
        self.st.say("Vendor list updated (demo)", 2)

    def _tick_open(self, src, target, rate):
        """A made-up path: steady 1.2 ms, with the demo network's spanning-tree glitch in it."""
        buf = N.TickBuffer()
        stop = self.stops["tick"]

        def feed():
            due = time.time()
            while not stop.is_set():
                now = time.time()
                while due <= now:
                    seq = buf.add_sent(due)
                    phase = due % 23
                    if phase < 1.2:
                        self.event("stp", "Spanning-tree topology change (VLAN 30)", "warn", quiet=10)
                        if random.random() < 0.5:
                            buf.add_reply(seq, random.uniform(20, 90))
                    elif random.random() > 0.0008:
                        buf.add_reply(seq, max(0.3, random.gauss(1.2, 0.12)),
                                      random.choice((0.2, 0.3, 0.3, 0.4, 19.0 if random.random() < 0.02 else 0.3)), True)
                    due += 1.0 / rate
                time.sleep(0.05)
        threading.Thread(target=feed, daemon=True).start()
        return buf, None

    def tick_toggle(self):
        if not self.settings.get("tick_server"):
            self.settings.data["tick_server"] = "10.20.30.200"
        super().tick_toggle()

    def tick_reflect_toggle(self):
        with self.st.lock:
            on = not self.st.tick["reflecting"]
            self.st.tick.update(reflecting=on, reflected=18240 if on else 0, peers=["10.20.30.61"] if on else [])

    def mcast_start(self):
        with self.st.lock:
            if self.st.mcast["running"]:
                return
            self.st.mcast.update(running=True, msg="", snap=None, probed=None)
        ev = self._new_stop("mcast")
        threading.Thread(target=self._mcast_run, args=(ev, None), daemon=True).start()

    def _mcast_run(self, ev, iface):
        tr = N.McastTracker()
        mac, t0 = "70:db:98:1a:00:01", time.time()
        F = N.mcast_frame
        for ago in (250, 125, 0):
            tr.feed(F(mac, "10.20.30.1", "224.0.0.1", 2, N.igmp_payload("query")), t0 - ago)
        tr.feed(F(mac, "10.20.30.21", "224.0.0.22", 2, N.igmp_payload("report3", "239.1.1.10")), t0)
        tr.feed(F(mac, "10.20.30.44", "224.0.0.22", 2, N.igmp_payload("report3", "239.69.12.7")), t0)

        def feed():
            udp = lambda port, n: struct.pack("!HHHH", 40000, port, 8 + n, 0) + bytes(n)  # noqa: E731
            while not ev.wait(0.1):
                now = time.time()
                with self.st.lock:
                    j = self.st.mcast["join"]
                for _ in range(40):
                    tr.feed(F(mac, "10.1.1.5", "239.1.1.10", 17, udp(5004, 1316), ttl=16), now)
                for _ in range(10):
                    tr.feed(F(mac, "10.20.30.44", "239.69.12.7", 17, udp(5004, 288), ttl=8), now)
                if random.random() < 0.3:
                    tr.feed(F(mac, f"10.20.30.{random.choice((15, 21, 70))}", "239.255.255.250", 17, udp(1900, 300)), now)
                if random.random() < 0.5:
                    tr.feed(F(mac, f"10.20.30.{random.choice((21, 34, 147))}", "224.0.0.251", 17, udp(5353, 120)), now)
                if random.random() < 0.1:
                    tr.feed(F(mac, "10.20.30.2", "224.0.0.18", 112, bytes(20)), now)
                if j and now - j["since"] > 1.5:
                    for _ in range(25):
                        tr.feed(F(mac, "10.1.1.9", j["group"], 17, udp(j["port"] or 5004, 1316), ttl=16), now)
        threading.Thread(target=feed, daemon=True).start()
        self._mcast_publish(ev, tr)

    def mcast_join(self, text):
        target = N.parse_mcast_target(text)
        if not target:
            self.st.say("Not a multicast group — try something like 239.1.2.3", 5)
            return
        with self.st.lock:
            self.st.mcast["join"] = {"group": target[0], "port": target[1], "since": time.time()}
            self.st.mcast["last_join"] = text.strip()
        self.mcast_start()

    def mcast_probe(self):
        with self.st.lock:
            self.st.mcast["probed"] = time.time()
        self.st.say("Asking for a querier…", 3)

    def _probe_device(self, ip, src):
        time.sleep(1.2)
        with self.st.lock:
            d = next((x for x in self.st.smart["devices"] if x.get("ip") == ip), {})
        extra = {"camera": [80, 443, 554, 8554], "tv": [7000, 8008, 8009, 8060], "printer": [80, 443, 515, 631, 9100],
                 "speaker": [1400, 7000], "hub": [80, 443, 8080]}.get(d.get("category"), [80])
        return sorted(set(d.get("ports", [])) | set(extra))

    def capture_refresh(self):
        with self.st.lock:
            self.st.capture["files"] = [("capture-20261010-101502-SW-IDF2-03-Gi1_0_14.pcap", 4_812_330, 0),
                                        ("capture-20261009-164455-SW-IDF2-03-Gi1_0_14.pcap", 918_204, 0)]

    def capture_toggle(self):
        with self.st.lock:
            c = self.st.capture
            if c["running"]:
                self.stops["capture"].set()
                return
            secs = c["secs"]
            c.update(running=True, left=secs, frames=0, bytes=24, msg="", ok=True,
                     file="capture-demo.pcap")
        ev = self._new_stop("capture")

        def work():
            t0 = time.time()
            while not ev.wait(0.25) and time.time() - t0 < secs:
                with self.st.lock:
                    c = self.st.capture
                    c["left"] = secs - (time.time() - t0)
                    c["frames"] += random.randint(8, 40)
                    c["bytes"] += random.randint(2_000, 30_000)
            with self.st.lock:
                c = self.st.capture
                c.update(running=False, left=0, ok=True,
                         msg=f"Saved {c['frames']:,} frames · {N.fmt_bytes(c['bytes'])} (demo: nothing written)")
        threading.Thread(target=work, daemon=True).start()

    def smart_scan_toggle(self):
        def work():
            with self.st.lock:
                self.st.smart.update(running=True)
            for stage in ("Waking up every host on the subnet…", "Asking devices to identify themselves…",
                          "Fetching device details (Roku, Hue, Shelly, Cast)…"):
                self._smart_progress(stage)
                time.sleep(0.4)
            raw = [
                dict(ip="10.20.30.21", mac="d8:31:34:aa:bb:cc", name="Den TV", model="Roku Ultra",
                     serial="YH00AB123456", serial_source="Roku ECP", brand="Roku", category="tv", sources=["SSDP", "Roku"]),
                dict(ip="10.20.30.70", mac="48:a6:b8:c1:d2:e3", name="Lobby", model="Sonos Era 100 S39",
                     serial="48-A6-B8-C1-D2-E3:A", serial_source="UPnP", brand_hint="Sonos, Inc.", sources=["SSDP", "UPnP"]),
                dict(ip="10.20.30.15", mac="ec:b5:fa:12:34:56", name="Hue Bridge", model="Hue Bridge BSB002",
                     serial="ECB5FAFFFE123456", serial_source="Hue bridge ID", brand="Philips Hue", category="hub",
                     sources=["SSDP", "Hue"]),
                dict(ip="10.20.30.40", mac="1c:3b:f3:11:22:33", name="Coffee maker", model="HS103(US)",
                     serial="8006ABCDEF0123456789", serial_source="Kasa device ID", brand="TP-Link Kasa / Tapo",
                     category="plug", sources=["Kasa"]),
                dict(ip="10.20.30.81", mac="5c:62:8b:aa:bb:cc", model="L530E(US)", serial="802A1B2C",
                     serial_source="TP-Link device ID", brand="TP-Link Kasa / Tapo", category="light", sources=["Kasa"]),
                dict(ip="10.20.30.33", mac="44:00:49:11:22:33", hostname="echo-dot-kitchen",
                     vendor="Amazon Technologies Inc.", sources=["ARP", "DNS"]),
                dict(ip="10.20.30.34", mac="9c:76:13:aa:01:02", hostname="ring-front-door", vendor="Ring LLC",
                     sources=["ARP", "DNS"]),
                dict(ip="10.20.30.50", mac="18:b4:30:12:ab:cd", name="Hallway thermostat", vendor="Nest Labs Inc.",
                     sources=["ARP", "mDNS"]),
                dict(ip="10.20.30.61", mac="f4:f5:d8:01:02:03", name="Conf Room Display", model="Chromecast",
                     brand_hint="Google", mdns_types=["_googlecast._tcp.local"], sources=["mDNS", "Cast"]),
                dict(ip="10.20.30.90", name="Office lights", model="Govee H6163", serial="1F:80:C5:32:32:36:72:4E",
                     serial_source="Govee device ID", brand="Govee", category="light", sources=["Govee"]),
                dict(ip="10.20.30.44", mac="44:17:93:a1:b2:c3", model="Shelly Plus1PM",
                     serial="shellyplus1pm-441793a1b2c3", serial_source="Shelly ID", brand="Shelly", category="plug",
                     sources=["Shelly"]),
                dict(ip="10.20.30.55", mac="2c:aa:8e:01:02:03", hostname="wyze-cam-garage", vendor="Wyze Labs Inc",
                     ports=[554], sources=["ARP", "Ports"]),
                dict(ip="10.20.30.20", mac="a0:d3:c1:44:55:66", name="HP LaserJet 4th Floor", model="HP LaserJet M404",
                     mdns_types=["_ipp._tcp.local"], vendor="Hewlett Packard", sources=["mDNS"]),
                dict(ip="10.20.30.9", mac="f8:bc:12:9a:8b:7c", hostname="desktop-7h2k", vendor="Dell Inc.",
                     sources=["ARP", "DNS"]),
            ]
            devs = [S.classify(d) for d in raw]
            self._smart_store(devs, {"SSDP": 3, "UPnP": 1, "Kasa": 2, "mDNS": 3, "Govee": 1, "Shelly": 1,
                                     "Roku": 1, "Hue": 1, "ARP": 6, "DNS": 4})
            self._smart_progress("Done in 18s")
            with self.st.lock:
                self.st.smart["running"] = False
        threading.Thread(target=work, daemon=True).start()


# ================================================================ UI widgets
CAT_COLORS = {"light": "#e3b341", "plug": "#3fb950", "speaker": "#a371f7", "tv": "#58a6ff",
              "camera": "#f85149", "thermostat": "#ff9e64", "hub": "#79c0ff", "lock": "#d29922",
              "sensor": "#56d4dd", "appliance": "#db61a2", "iot": "#7ee787", "printer": "#8b949e",
              "console": "#bc8cff", "computer": "#8b949e", "phone": "#8b949e", "network": "#2f81f7",
              "unknown": "#6e7681"}


def draw_icon(c, cat, x, y, s):
    """Generic device-type icons drawn from simple shapes (no brand logos)."""
    col = CAT_COLORS.get(cat, CAT_COLORS["unknown"])
    w = max(2, int(s / 16))
    c.create_rectangle(x, y, x + s, y + s, fill="#0d1117", outline="#30363d")

    def P(*pts):
        return [x + v * s if i % 2 == 0 else y + v * s for i, v in enumerate(pts)]
    line = dict(fill=col, width=w, capstyle="round")
    shape = dict(outline=col, width=w)
    if cat == "light":
        c.create_oval(*P(.28, .12, .72, .56), **shape)
        c.create_rectangle(*P(.4, .56, .6, .72), **shape)
        c.create_line(*P(.42, .8, .58, .8), **line)
    elif cat == "plug":
        c.create_rectangle(*P(.22, .18, .78, .82), **shape)
        c.create_line(*P(.4, .36, .4, .5), **line)
        c.create_line(*P(.6, .36, .6, .5), **line)
        c.create_oval(*P(.45, .6, .55, .7), **shape)
    elif cat == "speaker":
        c.create_rectangle(*P(.26, .1, .74, .9), **shape)
        c.create_oval(*P(.35, .45, .65, .75), **shape)
        c.create_oval(*P(.44, .2, .56, .32), **shape)
    elif cat == "tv":
        c.create_rectangle(*P(.1, .2, .9, .7), **shape)
        c.create_line(*P(.5, .7, .5, .82), **line)
        c.create_line(*P(.32, .84, .68, .84), **line)
    elif cat == "camera":
        c.create_rectangle(*P(.12, .32, .66, .7), **shape)
        c.create_polygon(*P(.66, .44, .88, .32, .88, .7, .66, .58), fill="", **shape)
        c.create_oval(*P(.26, .42, .42, .58), **shape)
    elif cat == "thermostat":
        c.create_oval(*P(.14, .14, .86, .86), **shape)
        c.create_arc(*P(.28, .28, .72, .72), start=220, extent=-260, style="arc", **shape)
        c.create_oval(*P(.46, .46, .54, .54), fill=col, outline=col)
    elif cat == "hub":
        c.create_rectangle(*P(.2, .52, .8, .84), **shape)
        for r in (.14, .26):
            c.create_arc(*P(.5 - r, .5 - r, .5 + r, .5 + r), start=45, extent=90, style="arc", **shape)
    elif cat == "lock":
        c.create_rectangle(*P(.24, .46, .76, .86), **shape)
        c.create_arc(*P(.33, .16, .67, .62), start=0, extent=180, style="arc", **shape)
        c.create_oval(*P(.46, .58, .54, .66), fill=col, outline=col)
    elif cat == "sensor":
        c.create_oval(*P(.4, .4, .6, .6), fill=col, outline=col)
        for r in (.2, .32):
            c.create_arc(*P(.5 - r, .5 - r, .5 + r, .5 + r), start=-40, extent=80, style="arc", **shape)
            c.create_arc(*P(.5 - r, .5 - r, .5 + r, .5 + r), start=140, extent=80, style="arc", **shape)
    elif cat == "appliance":
        c.create_oval(*P(.14, .14, .86, .86), **shape)
        c.create_oval(*P(.38, .38, .62, .62), **shape)
    elif cat == "printer":
        c.create_rectangle(*P(.12, .38, .88, .7), **shape)
        c.create_rectangle(*P(.3, .14, .7, .38), **shape)
        c.create_rectangle(*P(.3, .62, .7, .86), **shape)
    elif cat == "console":
        c.create_rectangle(*P(.1, .34, .9, .7), **shape)
        c.create_line(*P(.24, .52, .4, .52), **line)
        c.create_line(*P(.32, .44, .32, .6), **line)
        c.create_oval(*P(.62, .44, .7, .52), fill=col, outline=col)
        c.create_oval(*P(.72, .52, .8, .6), fill=col, outline=col)
    elif cat == "computer":
        c.create_rectangle(*P(.12, .16, .88, .64), **shape)
        c.create_line(*P(.5, .64, .5, .8), **line)
        c.create_line(*P(.3, .82, .7, .82), **line)
    elif cat == "phone":
        c.create_rectangle(*P(.32, .1, .68, .9), **shape)
        c.create_line(*P(.45, .8, .55, .8), **line)
    elif cat == "network":
        c.create_rectangle(*P(.12, .52, .88, .8), **shape)
        c.create_line(*P(.28, .52, .2, .2), **line)
        c.create_line(*P(.72, .52, .8, .2), **line)
        for fx in (.3, .45, .6):
            c.create_oval(*P(fx, .63, fx + .06, .69), fill=col, outline=col)
    else:                                                      # iot / unknown: a chip
        c.create_rectangle(*P(.28, .28, .72, .72), **shape)
        for f in (.38, .5, .62):
            c.create_line(*P(f, .14, f, .28), **line)
            c.create_line(*P(f, .72, f, .86), **line)
            c.create_line(*P(.14, f, .28, f), **line)
            c.create_line(*P(.72, f, .86, f), **line)


def device_title(d):
    return d.get("label") or d.get("name") or d.get("hostname") or d.get("model") or d.get("ip", "")


class DeviceList(tk.Canvas):
    """Scrollable list of devices with icons. Drag to scroll, tap a row for details."""

    def __init__(self, master, ui, on_tap):
        super().__init__(master, bg=PANEL, highlightthickness=0, yscrollincrement=8)
        self.ui, self.on_tap = ui, on_tap
        self.items, self._sig, self._empty, self._py = [], None, "", 0
        self.row_h = ui.sz["row"] + 2 * ui.sz["rowsm"] + 14 + 2 * ui.pad
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", lambda e: self.scan_dragto(0, e.y, gain=1))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<MouseWheel>", lambda e: self.yview_scroll(int(-e.delta / 120) * 4, "units"))
        self.bind("<Configure>", lambda e: self.redraw())

    def _press(self, e):
        self._py = e.y
        self.scan_mark(0, e.y)

    def _release(self, e):
        if abs(e.y - self._py) < 10 and self.ui._moved(e) < self.ui.W * 0.04:
            i = int(self.canvasy(e.y) // self.row_h)
            if 0 <= i < len(self.items):
                self.on_tap(self.items[i])

    def set_items(self, items, empty=""):
        sig = tuple((d.get("key"), d.get("label"), d.get("name"), d.get("model"), d.get("serial"), d.get("ip"),
                     d.get("mac"), d.get("brand"), d.get("category")) for d in items)
        if sig == self._sig and empty == self._empty:
            return
        self.items, self._sig, self._empty = items, sig, empty
        self.redraw()

    def redraw(self):
        w = self.winfo_width()
        if w < 20:
            return
        top = self.yview()[0]
        self.delete("all")
        ui, pad, rh = self.ui, self.ui.pad, self.row_h
        ic = rh - 2 * pad
        if not self.items:
            self.create_text(pad, pad, anchor="nw", text=self._empty, fill=DIM,
                             font=ui.font(ui.sz["row"]), width=w - 2 * pad)
        for i, d in enumerate(self.items):
            y = i * rh
            if i:
                self.create_line(pad, y, w - pad, y, fill=BG, width=2)
            cat = d.get("category", "unknown")
            draw_icon(self, cat, pad, y + pad, ic)
            x = 2 * pad + ic
            brand = (d.get("brand") or "")[:24]
            self.create_text(w - pad, y + pad, anchor="ne", text=brand, fill=CAT_COLORS.get(cat, DIM),
                             font=ui.font(ui.sz["rowsm"], "bold"))
            room = max(10, (w - x - pad - ui.font(ui.sz["rowsm"], "bold").measure(brand) - pad)
                       // max(1, ui.font(ui.sz["row"], "bold").measure("M")))
            title = device_title(d)
            self.create_text(x, y + pad, anchor="nw", text=title[:room], fill=FG,
                             font=ui.font(ui.sz["row"], "bold"))
            line2 = "  ·  ".join(b for b in (S.CATEGORIES.get(cat, ""), d.get("model", ""),
                                             f"SN {d['serial']}" if d.get("serial") else "") if b)
            self.create_text(x, y + pad + ui.sz["row"] + 4, anchor="nw", text=line2, fill=DIM,
                             font=ui.font(ui.sz["rowsm"]))
            self.create_text(x, y + pad + ui.sz["row"] + ui.sz["rowsm"] + 9, anchor="nw",
                             text=f"{d.get('ip', ''):<16}{d.get('mac') or 'MAC not seen'}", fill=FG,
                             font=ui.mono(ui.sz["rowsm"]))
        h = max(len(self.items) * rh, self.winfo_height())
        self.configure(scrollregion=(0, 0, w, h))
        self.yview_moveto(top)


class DeviceDetail(tk.Frame):
    """Full-screen card with everything known about one device."""

    def __init__(self, ui, d):
        super().__init__(ui.root, bg=BG)
        self.ui, self.d = ui, d
        pad = ui.pad
        self.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.lift()
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=pad, pady=pad)
        isz = int(ui.H * 0.11)
        icon = tk.Canvas(hdr, width=isz, height=isz, bg=BG, highlightthickness=0)
        icon.pack(side="left")
        draw_icon(icon, d.get("category", "unknown"), 1, 1, isz - 2)
        ui.button(hdr, "Close", self.close, ui.sz["small"], bg=GREY, padx=pad * 2).pack(side="right")
        ui.button(hdr, "Label", self.relabel, ui.sz["small"], bg=BLUE, padx=pad * 2).pack(
            side="right", padx=(0, pad // 2))
        self.ports_btn = ui.button(hdr, "Ports", self.scan_ports, ui.sz["small"], bg=BLUE, padx=pad * 2)
        self.ports_btn.pack(side="right", padx=(0, pad // 2))
        titles = tk.Frame(hdr, bg=BG)
        titles.pack(side="left", fill="x", expand=True, padx=pad)
        tk.Label(titles, text=device_title(d), bg=BG, fg=FG, anchor="w",
                 font=ui.font(ui.sz["sub"], "bold")).pack(fill="x")
        tk.Label(titles, text=f"{d.get('brand', '')}  ·  {S.CATEGORIES.get(d.get('category', ''), '')}",
                 bg=BG, fg=CAT_COLORS.get(d.get("category"), DIM), anchor="w",
                 font=ui.font(ui.sz["small"], "bold")).pack(fill="x")
        self.lst = ListView(self, ui)
        self.lst.pack(fill="both", expand=True, padx=pad, pady=(0, pad))
        self.fill()
        ui.overlay = self
        self.after(500, self.poll)

    def poll(self):
        """Pick up the result of a port check, or a label change, while the card is open."""
        if self.ui.overlay is not self:
            return
        with self.ui.st.lock:
            cur = next((copy.deepcopy(x) for x in self.ui.st.smart["devices"]
                        if x.get("key") == self.d.get("key")), None)
        if cur is not None and cur != self.d:
            self.d = cur
            self.fill()
        self.after(500, self.poll)

    def scan_ports(self):
        self.ui.be.device_ports_scan(self.d.get("key"))

    def fill(self):
        d, ui = self.d, self.ui
        busy = d.get("port_scan") == "running"
        self.ports_btn.config(text="Checking…" if busy else "Ports", bg=GREY if busy else BLUE)
        ports = d.get("ports", [])
        if busy:
            svc = "Checking every common service…"
        elif ports:
            svc = "\n".join(S.describe_ports(ports))
        else:
            svc = "none answered"
        if not busy and not d.get("services_checked"):
            svc += "\n(quick check only: tap Ports to check all " + str(len(S.ALL_PORTS)) + " common services)"
        serial = d.get("serial") or ""
        rows = [
            ("Label", d.get("label") or "(tap Label to add one)"),
            ("Name", d.get("name", "")), ("Model", d.get("model", "")),
            ("Serial / ID", f"{serial}   ({d.get('serial_source', '')})" if serial else "not published by this device"),
            ("IP address", d.get("ip", "")), ("MAC address", d.get("mac") or "not seen"),
            ("MAC vendor", d.get("vendor", "")), ("Hostname", d.get("hostname", "")),
            ("Firmware", d.get("fw", "")),
            ("Open services", svc),
            ("Advertises (mDNS)", ", ".join(t.replace(".local", "") for t in d.get("mdns_types", []))),
            ("Found via", ", ".join(d.get("sources", []))),
            ("Smart home", "yes" if d.get("smart") else "no"),
        ]
        out = []
        for k, v in rows:
            if v:
                out.append((k.upper(), DIM, "dim"))
                out.append((str(v), FG, "row"))
        self.lst.set_rows(out)

    def relabel(self):
        key, d = self.d.get("key"), self.d
        self.close()
        Keyboard(self.ui, f"Label for {device_title(d)}", d.get("label", ""),
                 lambda v: self.ui.be.set_device_label(key, v),
                 "Saved to devices.csv, e.g. 'Garage camera' or 'Room 204 TV'. Leave empty to clear.")

    def close(self):
        self.ui.overlay = None
        self.destroy()

    def key(self, e):
        if e.keysym in ("Escape", "Return"):
            self.close()


class Tile(tk.Frame):
    def __init__(self, master, ui, title):
        super().__init__(master, bg=PANEL)
        self.ui = ui
        self.pack_propagate(False)
        pad = ui.pad
        top = tk.Frame(self, bg=PANEL)
        top.pack(fill="x", padx=pad, pady=(pad // 2 + 1, 0))
        self.t = tk.Label(top, text=title.upper(), bg=PANEL, fg=DIM, anchor="w",
                          font=ui.font(ui.sz["title"], "bold"))
        self.t.pack(side="left")
        self.n = tk.Label(top, text="", bg=PANEL, fg=DIM, anchor="e",
                          font=ui.font(ui.sz["title"], "bold"))
        self.n.pack(side="right")
        self.v = tk.Label(self, text="—", bg=PANEL, fg=FG, anchor="w",
                          font=ui.font(ui.sz["val"], "bold"))
        self.v.pack(fill="both", expand=True, padx=pad, pady=(0, pad // 2))
        self._last = None

    def set(self, value, color=FG, note="", note_color=None):
        value = str(value) if value not in (None, "") else "—"
        if note_color is None:
            note_color = color if color in (BAD, WARN) else DIM
        w = self.winfo_width()
        key = (value, color, note, note_color, w)
        if key == self._last:
            return
        self._last = key
        self.n.config(text=note, fg=note_color)
        self.ui.fit(self.v, value, self.ui.sz["val"], w - 2 * self.ui.pad, color)


class ListView(tk.Canvas):
    """Touch-scrollable list (drag to scroll)."""

    def __init__(self, master, ui):
        super().__init__(master, bg=PANEL, highlightthickness=0, yscrollincrement=8)
        self.ui = ui
        self._rows = None
        self._empty = ""
        self.bind("<ButtonPress-1>", lambda e: self.scan_mark(0, e.y))
        self.bind("<B1-Motion>", lambda e: self.scan_dragto(0, e.y, gain=1))
        self.bind("<MouseWheel>", lambda e: self.yview_scroll(int(-e.delta / 120) * 4, "units"))
        self.bind("<Configure>", lambda e: self.redraw())

    def set_rows(self, rows, empty=""):
        if rows == self._rows and empty == self._empty:
            return
        self._rows, self._empty = rows, empty
        self.redraw()

    def redraw(self):
        w = self.winfo_width()
        if w < 20:
            return
        top = self.yview()[0]
        self.delete("all")
        ui, pad = self.ui, self.ui.pad
        fonts = {"hdr": ui.font(ui.sz["row"], "bold"), "row": ui.font(ui.sz["row"]),
                 "mono": ui.mono(ui.sz["row"]), "dim": ui.font(ui.sz["rowsm"])}
        y = pad
        rows = self._rows or []
        if not rows:
            self.create_text(pad, y, anchor="nw", text=self._empty, fill=DIM, font=fonts["row"],
                             width=w - 2 * pad)
        for text, color, kind in rows:
            if kind == "hdr" and y > pad:
                y += pad // 2
            item = self.create_text(pad, y, anchor="nw", text=text, fill=color,
                                    font=fonts.get(kind, fonts["row"]), width=w - 2 * pad)
            bb = self.bbox(item)
            y = (bb[3] if bb else y + ui.sz["row"]) + max(2, pad // 3)
        self.configure(scrollregion=(0, 0, w, max(y + pad, self.winfo_height())))
        self.yview_moveto(top)


class ToolView(tk.Frame):
    def __init__(self, master, ui, title, actions, chart=False, back=None):
        super().__init__(master, bg=BG)
        self.ui = ui
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x")
        ui.button(hdr, "‹ Back", back or ui.show_tools, ui.sz["small"], bg=GREY, padx=ui.pad * 2).pack(side="left")
        self.title = tk.Label(hdr, text=title, bg=BG, fg=FG, font=ui.font(ui.sz["sub"], "bold"))
        self.title.pack(side="left", padx=ui.pad)
        self.act = []
        for text, cmd in reversed(actions):
            b = ui.button(hdr, text, cmd, ui.sz["small"], bg=BLUE, padx=ui.pad)
            b.pack(side="right", padx=(ui.pad // 2, 0))
            self.act.insert(0, b)
        self.summary = tk.Label(self, text="", bg=BG, fg=FG, anchor="w",
                                font=ui.font(ui.sz["val"], "bold"))
        self.summary.pack(fill="x", pady=(ui.pad // 2, 0))
        self.sub = tk.Label(self, text="", bg=BG, fg=DIM, anchor="w", font=ui.font(ui.sz["small"]))
        self.sub.pack(fill="x")
        self.chart = None
        if chart:
            frac = chart if isinstance(chart, float) else 0.15
            self.chart = tk.Canvas(self, bg=PANEL, highlightthickness=0, height=int(ui.H * frac))
            self.chart.pack(fill="x", pady=(ui.pad // 2, 0))
        self.list = ListView(self, ui)
        self.list.pack(fill="both", expand=True, pady=(ui.pad // 2, 0))
        self._sum = None

    def set_action(self, i, text, bg=BLUE):
        b = self.act[i]
        if b.cget("text") != text or b.cget("bg") != bg:
            b.config(text=text, bg=bg)

    def set_summary(self, text, color=FG, sub="", sub_color=DIM):
        key = (text, color, sub, sub_color, self.winfo_width())
        if key == self._sum:
            return
        self._sum = key
        self.ui.fit(self.summary, text, self.ui.sz["val"], self.winfo_width(), color)
        self.sub.config(text=sub, fg=sub_color)


class Keyboard(tk.Frame):
    """On-screen keyboard overlay for the touchscreen (physical keys work too)."""
    ROWS = ["1234567890", "qwertyuiop", "asdfghjkl-", "zxcvbnm._/"]

    def __init__(self, ui, title, initial, on_ok, info=""):
        super().__init__(ui.root, bg=BG)
        self.ui, self.on_ok, self.value, self.shift = ui, on_ok, initial or "", False
        pad = ui.pad
        self.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.lift()
        tk.Label(self, text=title, bg=BG, fg=FG, anchor="w", font=ui.font(ui.sz["sub"], "bold")).pack(
            fill="x", padx=pad, pady=(pad, 0))
        if info:
            tk.Label(self, text=info, bg=BG, fg=DIM, anchor="w", font=ui.font(ui.sz["small"]),
                     wraplength=ui.W - 2 * pad, justify="left").pack(fill="x", padx=pad)
        self.disp = tk.Label(self, text="", bg=PANEL, fg=FG, anchor="w",
                             font=ui.font(ui.sz["val"], "bold"), padx=pad, pady=pad // 2)
        self.disp.pack(fill="x", padx=pad, pady=pad // 2)
        grid = tk.Frame(self, bg=BG)
        grid.pack(fill="both", expand=True, padx=pad, pady=(0, pad))
        ks = ui.sz["key"]
        self.keys = []
        for r, row in enumerate(self.ROWS):
            for c, ch in enumerate(row):
                b = ui.button(grid, ch, lambda ch=ch: self.type(ch), ks, bg=PANEL)
                b.grid(row=r, column=c, sticky="nsew", padx=1, pady=1)
                self.keys.append((b, ch))
        specials = [(0, 2, "Shift", self.toggle_shift, GREY), (2, 5, "space", lambda: self.type(" "), PANEL),
                    (7, 3, "Delete", self.back, GREY)]
        for col, span, text, cmd, bg in specials:
            ui.button(grid, text, cmd, ks, bg=bg).grid(row=4, column=col, columnspan=span,
                                                       sticky="nsew", padx=1, pady=1)
        ui.button(grid, "Cancel", self.close, ks, bg=GREY).grid(row=5, column=0, columnspan=4,
                                                                sticky="nsew", padx=1, pady=(pad // 2, 1))
        ui.button(grid, "Clear", self.clear, ks, bg=GREY).grid(row=5, column=4, columnspan=2,
                                                               sticky="nsew", padx=1, pady=(pad // 2, 1))
        ui.button(grid, "OK", self.ok, ks, bg=GREEN).grid(row=5, column=6, columnspan=4,
                                                          sticky="nsew", padx=1, pady=(pad // 2, 1))
        for c in range(10):
            grid.columnconfigure(c, weight=1, uniform="k")
        for r in range(6):
            grid.rowconfigure(r, weight=1, uniform="r")
        ui.overlay = self
        self.render()

    def render(self):
        self.disp.config(text=self.value + "|")
        for b, ch in self.keys:
            b.config(text=ch.upper() if self.shift else ch)

    def type(self, ch):
        self.value += ch.upper() if self.shift else ch
        if self.shift:
            self.shift = False
        self.render()

    def toggle_shift(self):
        self.shift = not self.shift
        self.render()

    def back(self):
        self.value = self.value[:-1]
        self.render()

    def clear(self):
        self.value = ""
        self.render()

    def ok(self):
        v = self.value.strip()
        self.close()
        self.on_ok(v)

    def close(self):
        self.ui.overlay = None
        self.destroy()

    def key(self, e):
        if e.keysym == "BackSpace":
            self.back()
        elif e.keysym in ("Return", "KP_Enter"):
            self.ok()
        elif e.keysym == "Escape":
            self.close()
        elif e.char and e.char.isprintable():
            self.value += e.char
            self.render()


# ================================================================ UI
class UI:
    MAIN = ("PORT", "SWITCH", "L2", "SMART", "STATS", "TOOLS")

    def __init__(self, root, st, be, size):
        self.root, self.st, self.be = root, st, be
        self.W, self.H = size
        H = self.H
        fams = set(tkfont.families(root))
        self.fam = next((f for f in ("Segoe UI", "Noto Sans", "Inter", "Cantarell", "DejaVu Sans", "Helvetica") if f in fams),
                        "TkDefaultFont")
        self.mono_fam = next((f for f in ("Consolas", "Cascadia Mono", "Noto Sans Mono", "DejaVu Sans Mono", "Courier New")
                              if f in fams), "TkFixedFont")
        self._fonts = {}
        self.pad = max(6, int(H * 0.016))
        self.sz = {"big": int(H * 0.08), "sub": int(H * 0.04), "title": max(10, int(H * 0.028)),
                   "val": int(H * 0.058), "nav": int(H * 0.036), "small": max(11, int(H * 0.032)),
                   "row": max(12, int(H * 0.036)), "rowsm": max(10, int(H * 0.028)),
                   "key": int(H * 0.042), "toolbtn": int(H * 0.042)}
        self.overlay = None
        root.configure(bg=BG)

        # banner (tap = next adapter)
        self.banner = tk.Frame(root, bg=GREY)
        self.banner.pack(side="top", fill="x")
        self.b_big = tk.Label(self.banner, text="STARTING", bg=GREY, fg="white",
                              font=self.font(self.sz["big"], "bold"))
        self.b_big.pack(fill="x", pady=(self.pad // 2, 0))
        self.b_sub = tk.Label(self.banner, text="", bg=GREY, fg="white", font=self.font(self.sz["sub"]))
        self.b_sub.pack(fill="x", pady=(0, self.pad // 2))
        self._press = (0, 0)
        root.bind_all("<ButtonPress-1>", lambda e: setattr(self, "_press", (e.x_root, e.y_root)), add="+")
        root.bind_all("<ButtonRelease-1>", self._maybe_swipe, add="+")
        for w in (self.banner, self.b_big, self.b_sub):
            self.on_tap(w, self.be.next_adapter)

        # nav
        self.nav = tk.Frame(root, bg=BG)
        self.nav.pack(side="bottom", fill="x", padx=self.pad, pady=self.pad)
        self.nav_btns = {}
        for i, name in enumerate(self.MAIN + ("SAVE",)):
            self.nav.columnconfigure(i, weight=1, uniform="nav")
            cmd = self.open_save if name == "SAVE" else (lambda n=name: self.show(n))
            b = self.button(self.nav, name, cmd, self.sz["nav"])
            b.grid(row=0, column=i, sticky="nsew", padx=self.pad // 3)
            self.nav_btns[name] = b

        # body
        self.body = tk.Frame(root, bg=BG)
        self.body.pack(side="top", fill="both", expand=True, padx=self.pad, pady=(self.pad // 2, 0))
        self.views, self.tiles = {}, {}
        self.build_grid("PORT", ["Speed", "Duplex", "IP address", "Gateway",
                                 "DHCP server", "DNS", "Time to IP", "Internet"])
        self.build_grid("SWITCH", ["Switch", "Port", "Data VLAN", "Voice VLAN",
                                   "Mgmt IP", "Model", "PoE", "Negotiation"])
        self.sw_foot = tk.Label(self.views["SWITCH"], text="", bg=BG, fg=DIM, anchor="w",
                                font=self.font(self.sz["small"]))
        self.sw_foot.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(self.pad // 3, 0))
        self.build_grid("L2", ["802.1X", "Spanning tree", "Trunk / DTP", "DHCP servers",
                               "Phone options", "Gateway MAC", "IPv6", "Broadcast"])
        self.l2_foot = tk.Label(self.views["L2"], text="", bg=BG, fg=DIM, anchor="w",
                                font=self.font(self.sz["small"]))
        self.l2_foot.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(self.pad // 3, 0))
        self.build_grid("STATS", ["MAC", "Adapter", "RX errors", "TX errors",
                                  "RX discards", "TX discards", "Throughput", "Link drops"])
        actions = tk.Frame(self.views["STATS"], bg=BG)
        actions.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(self.pad // 3, 0))
        for i, (label, cmd) in enumerate((("Next adapter", self.be.next_adapter),
                                          ("Reset", self.be.reset_counters),
                                          ("Renew DHCP", self.be.renew),
                                          ("Bounce", self.be.bounce))):
            actions.columnconfigure(i, weight=1, uniform="act")
            self.button(actions, label, cmd, self.sz["small"], bg=GREY).grid(
                row=0, column=i, sticky="nsew", padx=self.pad // 3)
        self.build_smart()
        self.build_tools_grid()
        self.tools = {
            "ping": ToolView(self.body, self, "Ping", [("Start", self.be.ping_toggle),
                                                     ("Target ›", self.be.ping_next_target),
                                                     ("30 s", self.be.ping_next_span)], chart=0.24),
            "tick": ToolView(self.body, self, "Tick test", [("Start", self.be.tick_toggle),
                                                           ("64/s", self.be.tick_next_rate),
                                                           ("30 s", self.be.tick_next_span),
                                                           ("Server", self.tick_server_dialog),
                                                           ("Reflect", self.be.tick_reflect_toggle)], chart=0.24),
            "trace": ToolView(self.body, self, "Traceroute", [("Run", self.be.trace_toggle),
                                                             ("Target ›", self.be.trace_next_target)]),
            "speed": ToolView(self.body, self, "Speed test", [("iperf3", self.be.speed_iperf),
                                                             ("Internet", self.be.speed_http)]),
            "arp": ToolView(self.body, self, "ARP table", [("Refresh", self.be.arp_refresh)]),
            "arpscan": ToolView(self.body, self, "ARP scan", [("Scan", self.be.arp_scan_toggle)]),
            "mdns": ToolView(self.body, self, "mDNS browser", [("Scan", self.be.mdns_scan),
                                                              ("Clear", self.be.mdns.reset)]),
            "blink": ToolView(self.body, self, "Port finder", [("Start", self.be.blink_toggle)]),
            "wire": ToolView(self.body, self, "Wire report", [("Restart", self.be.wire_reset)]),
            "mcast": ToolView(self.body, self, "Multicast", [("Stop", self.be.mcast_toggle),
                                                           ("Join…", self.mcast_join_dialog),
                                                           ("Querier", self.be.mcast_probe)]),
            "capture": ToolView(self.body, self, "Capture", [("Start", self.be.capture_toggle),
                                                           ("30 s", self.be.capture_next_secs),
                                                           ("Folder", self.open_captures)]),
            "log": ToolView(self.body, self, "Port log", [("Open folder", self.open_data)]),
            "switches": ToolView(self.body, self, "Switches", [("Scan", self.be.sw_scan_toggle),
                                                              ("Add", self.sw_add_dialog),
                                                              ("Community", self.sw_community_dialog),
                                                              ("v2c", self.be.sw_next_version)], chart=0.5),
            "swports": ToolView(self.body, self, "Switch", [("Clear all", self.sw_clear_open),
                                                            ("Remove", self.sw_remove_open)], chart=0.42,
                                back=lambda: self.show("switches")),
        }
        self.sw_open = self.sw_port = self.sw_sig = self.swp_sig = None
        self.sw_hits, self.swp_hits = [], []
        self.tools["switches"].chart.bind("<ButtonRelease-1>", self._sw_tap)
        self.tools["swports"].chart.bind("<ButtonRelease-1>", self._swp_tap)
        self.views.update(self.tools)
        self.build_settings()

        root.bind("<Key>", self._on_key)
        self.cur = None
        self.show("PORT")
        self.refresh()

    # ---------------------------------------------------------- building blocks
    def font(self, px, weight="normal"):
        key = (self.fam, px, weight)
        if key not in self._fonts:
            self._fonts[key] = tkfont.Font(self.root, family=self.fam, size=-px, weight=weight)
        return self._fonts[key]

    def mono(self, px):
        key = (self.mono_fam, px, "normal")
        if key not in self._fonts:
            self._fonts[key] = tkfont.Font(self.root, family=self.mono_fam, size=-px)
        return self._fonts[key]

    def fit(self, label, text, max_px, width, color=FG):
        size = max_px
        if width > 40:
            while size > 9 and self.font(size, "bold").measure(text) > width:
                size -= 1
        label.config(text=text, fg=color, font=self.font(size, "bold"))

    def button(self, parent, text, cmd, px, bg=PANEL, padx=0):
        b = tk.Label(parent, text=text, bg=bg, fg=FG, font=self.font(px, "bold"),
                     pady=max(4, px // 3), padx=padx, cursor="hand2")
        self.on_tap(b, cmd)
        return b

    def _moved(self, e):
        return max(abs(e.x_root - self._press[0]), abs(e.y_root - self._press[1]))

    def on_tap(self, widget, cmd):
        """Fire on release, only if the finger didn't travel (so swipes don't press buttons)."""
        widget.bind("<ButtonRelease-1>", lambda e: cmd() if self._moved(e) < self.W * 0.04 else None)

    def _maybe_swipe(self, e):
        if self.overlay or self.cur not in self.MAIN:
            return
        dx = e.x_root - self._press[0]
        dy = e.y_root - self._press[1]
        if abs(dx) > self.W * 0.15 and abs(dx) > 1.5 * abs(dy):
            self.step(-1 if dx > 0 else 1)

    def build_grid(self, name, titles):
        page = tk.Frame(self.body, bg=BG)
        self.views[name] = page
        for c in range(2):
            page.columnconfigure(c, weight=1, uniform="c")
        for r in range(4):
            page.rowconfigure(r, weight=1, uniform="r")
        for i, title in enumerate(titles):
            t = Tile(page, self, title)
            t.grid(row=i // 2, column=i % 2, sticky="nsew",
                   padx=(0, self.pad // 3) if i % 2 == 0 else (self.pad // 3, 0), pady=self.pad // 3)
            self.tiles[(name, title)] = t

    def build_smart(self):
        page = tk.Frame(self.body, bg=BG)
        self.views["SMART"] = page
        self.sm_filter, self.sm_all = "", False
        hdr = tk.Frame(page, bg=BG)
        hdr.pack(fill="x")
        self.sm_summary = tk.Label(hdr, text="", bg=BG, fg=FG, anchor="w", font=self.font(self.sz["sub"], "bold"))
        self.sm_summary.pack(side="left", fill="x", expand=True)
        self.sm_btns = {}
        for key, text, cmd in (("scan", "Scan", self.be.smart_scan_toggle), ("search", "Search", self.smart_search),
                               ("all", "Smart only", self.smart_toggle_all), ("folder", "Folder", self.open_data)):
            b = self.button(hdr, text, cmd, self.sz["small"], bg=BLUE if key == "scan" else GREY, padx=self.pad)
            b.pack(side="left", padx=(self.pad // 2, 0))
            self.sm_btns[key] = b
        self.sm_sub = tk.Label(page, text="", bg=BG, fg=DIM, anchor="w", font=self.font(self.sz["small"]))
        self.sm_sub.pack(fill="x")
        self.sm_list = DeviceList(page, self, lambda d: DeviceDetail(self, d))
        self.sm_list.pack(fill="both", expand=True, pady=(self.pad // 3, 0))

    def smart_search(self):
        Keyboard(self, "Search devices", self.sm_filter, lambda v: setattr(self, "sm_filter", v),
                 "Matches label, name, brand, type, model, serial, IP or MAC. Leave empty to show everything.")

    def smart_toggle_all(self):
        self.sm_all = not self.sm_all

    def render_smart(self, s):
        sm = s["smart"]
        devs = sm["devices"]
        smart = [d for d in devs if d.get("smart")]
        shown = devs if self.sm_all else smart
        if self.sm_filter:
            q = self.sm_filter.lower()
            shown = [d for d in shown if q in " ".join(str(d.get(k, "")) for k in (
                "label", "name", "brand", "model", "serial", "ip", "mac", "hostname", "vendor")).lower()
                or q in S.CATEGORIES.get(d.get("category"), "").lower()]
        shown = sorted(shown, key=lambda d: (not d.get("smart"), d.get("category", ""), d.get("brand", "").lower(),
                                             device_title(d).lower()))
        b = self.sm_btns
        b["scan"].config(text="Stop" if sm["running"] else "Scan", bg=RED if sm["running"] else BLUE)
        b["all"].config(text="All hosts" if self.sm_all else "Smart only")
        b["search"].config(text=f"Search: {self.sm_filter[:10]}" if self.sm_filter else "Search",
                           bg=BLUE if self.sm_filter else GREY)
        if devs:
            brands = len({d.get("brand") for d in smart if d.get("brand")})
            summ = f"{len(smart)} smart devices · {brands} brands"
            if self.sm_all:
                summ += f" · {len(devs)} hosts"
        else:
            summ = "Smart home devices"
        self.fit(self.sm_summary, summ, self.sz["sub"], max(50, self.sm_summary.winfo_width()), FG)
        if sm["running"]:
            sub, col = sm["stage"], WARN
        elif sm["ts"]:
            top = sorted(sm["counts"].items(), key=lambda kv: -kv[1])[:5]
            via = ", ".join(f"{k} {v}" for k, v in top)
            sub = (f"Scanned {time.strftime('%H:%M', time.localtime(sm['ts']))} · showing {len(shown)}"
                   + (f" · via {via}" if via else "") + " · tap a device for details")
            col = DIM
        else:
            sub, col = "Tap Scan — takes about 20 seconds", DIM
        if self.sm_sub.cget("text") != sub:
            self.sm_sub.config(text=sub, fg=col)
        empty = ("No devices match that search." if devs else
                 "Tap Scan to find smart plugs, bulbs, speakers, TVs, cameras, thermostats and hubs.\n\n"
                 "Tips: Govee needs 'LAN Control' and WiZ needs 'Allow local communication' turned on in "
                 "their apps. Cloud-only gadgets still show up by brand, IP and MAC. Results are saved to "
                 "devices.csv.")
        self.sm_list.set_items(shown, empty)

    def build_tools_grid(self):
        page = tk.Frame(self.body, bg=BG)
        self.views["TOOLS"] = page
        items = [("Ping", lambda: self.show("ping")), ("Tick test", lambda: self.show("tick")),
                 ("Traceroute", lambda: self.show("trace")), ("Speed test", lambda: self.show("speed")),
                 ("Wire report", lambda: self.show("wire")), ("Switches", lambda: self.show("switches")),
                 ("Multicast", self.open_mcast),
                 ("ARP table", self.open_arp), ("ARP scan", lambda: self.show("arpscan")),
                 ("mDNS browser", self.open_mdns), ("Capture", self.open_capture),
                 ("Port finder", lambda: self.show("blink")), ("Port log", lambda: self.show("log")),
                 ("Re-run checks", self.be.rerun_checks), ("Settings", lambda: self.show("settings"))]
        for c in range(2):
            page.columnconfigure(c, weight=1, uniform="c")
        for r in range((len(items) + 1) // 2):
            page.rowconfigure(r, weight=1, uniform="r")
        for i, (label, cmd) in enumerate(items):
            self.button(page, label, cmd, self.sz["toolbtn"]).grid(
                row=i // 2, column=i % 2, sticky="nsew",
                padx=(0, self.pad // 3) if i % 2 == 0 else (self.pad // 3, 0), pady=self.pad // 3)

    def build_settings(self):
        page = tk.Frame(self.body, bg=BG)
        self.views["settings"] = page
        hdr = tk.Frame(page, bg=BG)
        hdr.pack(fill="x")
        self.button(hdr, "‹ Back", self.show_tools, self.sz["small"], bg=GREY, padx=self.pad * 2).pack(side="left")
        tk.Label(hdr, text="Settings", bg=BG, fg=FG, font=self.font(self.sz["sub"], "bold")).pack(
            side="left", padx=self.pad)
        tk.Label(hdr, text=f"v{VERSION}  ·  github.com/turkey415/porkchopcheck", bg=BG, fg=DIM,
                 font=self.font(self.sz["rowsm"])).pack(side="right", padx=self.pad)
        lst = tk.Frame(page, bg=BG)
        lst.pack(fill="both", expand=True, pady=(self.pad // 2, 0))
        self.set_btns = {}
        rows = [("announce", self.toggle("announce")), ("autolog", self.toggle("autolog")),
                ("smartsvc", self.toggle("smart_services")), ("tickclaude", self.toggle("tick_claude")),
                ("hostname", self.edit_hostname), ("iperf", self.edit_iperf),
                ("oui", lambda: threading.Thread(target=self.be.update_oui, daemon=True).start()),
                ("folder", self.open_data), ("exit", self.quit)]
        for r, (key, cmd) in enumerate(rows):
            lst.rowconfigure(r, weight=1, uniform="s")
            b = self.button(lst, "", cmd, self.sz["small"], bg=RED if key == "exit" else PANEL)
            b.config(anchor="w", padx=self.pad * 2)
            b.grid(row=r, column=0, sticky="nsew", pady=self.pad // 4)
            self.set_btns[key] = b
        lst.columnconfigure(0, weight=1)

    # ---------------------------------------------------------- navigation
    def show(self, name):
        if self.cur == name:
            return
        if self.cur == "mcast":
            self.be.mcast_stop()          # stop listening, and leave any group, when the view closes
        sw = ("switches", "swports")      # switches are only read while one of their pages is open
        if name in sw and self.cur not in sw:
            self.be.sw_watch_start()
        elif self.cur in sw and name not in sw:
            self.be.sw_watch_stop()
        if self.cur:
            self.views[self.cur].pack_forget()
        self.views[name].pack(fill="both", expand=True)
        self.cur = name
        active = name if name in self.MAIN else "TOOLS"
        for n, b in self.nav_btns.items():
            b.config(bg=BLUE if n == active else (GREEN if n == "SAVE" else PANEL))

    def show_tools(self):
        self.show("TOOLS")

    def step(self, d):
        i = self.MAIN.index(self.cur)
        self.show(self.MAIN[(i + d) % len(self.MAIN)])

    def open_arp(self):
        self.show("arp")
        self.be.arp_refresh()

    def open_mdns(self):
        self.show("mdns")
        if not self.be.mdns.snapshot()["last_scan"]:
            self.be.mdns_scan()

    def tick_server_dialog(self):
        Keyboard(self, "Reflector address for the tick test", self.be.settings.get("tick_server"),
                 self.be.tick_set_server,
                 f"The machine running 'porkchopcheck --reflector', or another PorkChopCheck with "
                 f"Reflect on. Port {N.TICK_PORT} unless you add another after a space.")

    def open_mcast(self):
        self.show("mcast")
        self.be.mcast_start()

    def mcast_join_dialog(self):
        with self.st.lock:
            joined, last = self.st.mcast["join"], self.st.mcast["last_join"]
        if joined:
            self.be.mcast_leave()
            return
        Keyboard(self, "Multicast group to join", last, self.be.mcast_join,
                 "e.g. 239.1.2.3. This box joins the group like a receiver would, then shows "
                 "whether the stream arrives.")

    def sw_add_dialog(self):
        Keyboard(self, "Switch address", "", self.be.sw_add,
                 "The switch's management IP, e.g. 10.2.1.2. It is asked with the community and SNMP "
                 "version set on this page.")

    def sw_community_dialog(self):
        Keyboard(self, "SNMP community string", self.be.settings.get("snmp_community"),
                 self.be.sw_set_community,
                 "The read-only community set on your switches. Use Shift for capitals, or a real "
                 "keyboard for other symbols. Saved in settings.json on this machine.")

    def sw_clear_open(self):
        """Clear the port that is picked, or the whole switch when none is."""
        with self.st.lock:
            x = next((x for x in self.st.switches["list"] if x["ip"] == self.sw_open), None)
            name = next((p["name"] for p in x["ports"] if p["index"] == self.sw_port), "") if x else ""
        if x:
            self.be.sw_clear(self.sw_open, self.sw_port if name else None, name)

    def sw_remove_open(self):
        if self.sw_open:
            self.be.sw_remove(self.sw_open)
        self.show("switches")

    def _sw_tap(self, e):
        if self._moved(e) >= self.W * 0.04:
            return
        for x1, y1, x2, y2, ip in self.sw_hits:
            if x1 <= e.x <= x2 and y1 <= e.y <= y2:
                self.sw_open, self.sw_port = ip, None
                self.show("swports")
                return

    def _swp_tap(self, e):
        if self._moved(e) >= self.W * 0.04:
            return
        self.sw_port = next((idx for x1, y1, x2, y2, idx in self.swp_hits
                             if x1 <= e.x <= x2 and y1 <= e.y <= y2), None)

    def open_capture(self):
        self.show("capture")
        self.be.capture_refresh()

    def open_captures(self):
        os.makedirs(self.be.capture_dir(), exist_ok=True)
        self.open_data(self.be.capture_dir())

    def open_data(self, folder=DATA_DIR):
        try:
            if IS_WIN:
                os.startfile(folder)  # noqa: S606
            elif IS_LINUX:
                subprocess.Popen(["xdg-open", folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                self.st.say(folder, 4)
        except OSError as e:
            self.st.say(str(e)[:60], 4)

    def open_save(self):
        if self.overlay:
            return
        s = self.st.snapshot()
        rec = build_record(s, self.be.oui)
        if rec["switch"]:
            info = f"{rec['switch']} · {rec['port']} · VLAN {rec['vlan'] or '?'} · {rec['speed']}"
        else:
            info = "No CDP/LLDP neighbor yet — saved to history.csv only"
        initial = self.be.portlog.label_for(rec)
        Keyboard(self, "Save this port — label (optional)", initial, self.be.save, info)

    def toggle(self, key):
        def f():
            self.be.settings.set(key, not self.be.settings.get(key))
            if key == "announce" and self.be.settings.get(key):
                with self.st.lock:
                    self.st.last_announce = 0
        return f

    def edit_hostname(self):
        Keyboard(self, "Name this box announces to the switch", self.be.hostname(),
                 lambda v: self.be.settings.set("hostname", v),
                 "Shows up in 'show cdp neighbors' / 'show lldp neighbors'.")

    def edit_iperf(self):
        Keyboard(self, "iperf3 server (IP or name, optional :port)",
                 self.be.settings.get("iperf_server"), self._set_iperf,
                 "Run 'iperf3 -s' on a PC or server, then enter its address here.")

    def _set_iperf(self, v):
        host, _, port = v.partition(":")
        self.be.settings.set("iperf_server", host.strip())
        if port.strip().isdigit():
            self.be.settings.set("iperf_port", int(port))

    def quit(self):
        try:
            self.be.shutdown()
        finally:
            self.root.destroy()

    def _on_key(self, e):
        if self.overlay:
            self.overlay.key(e)
            return "break"
        ch = (e.char or "").lower()
        if e.keysym == "F11":
            self.root.attributes("-fullscreen", not self.root.attributes("-fullscreen"))
        elif e.keysym == "Escape":
            if self.cur not in self.MAIN:
                self.show("TOOLS")
            else:
                self.root.attributes("-fullscreen", False)
        elif e.keysym in ("Left", "Right") and self.cur in self.MAIN:
            self.step(-1 if e.keysym == "Left" else 1)
        elif ch in "123456" and ch:
            self.show(self.MAIN[int(ch) - 1])
        elif ch == "s":
            self.open_save()
        elif ch == "r":
            self.be.renew()
        elif ch == "a":
            self.be.next_adapter()
        elif ch == "q":
            self.quit()

    # ---------------------------------------------------------- refresh
    def refresh(self):
        try:
            self.render(self.st.snapshot())
        except Exception as e:  # noqa: BLE001
            if DEMO:
                import traceback
                traceback.print_exc()
            _ = e
        self.root.after(500, self.refresh)

    def tile(self, page, title):
        return self.tiles[(page, title)]

    def render(self, s):
        now = time.time()
        self.render_banner(s, now)
        if self.cur == "PORT":
            self.render_port(s, now)
        elif self.cur == "SWITCH":
            self.render_switch(s, now)
        elif self.cur == "L2":
            self.render_l2(s, now)
        elif self.cur == "STATS":
            self.render_stats(s)
        elif self.cur == "SMART":
            self.render_smart(s)
        elif self.cur == "settings":
            self.render_settings()
        elif self.cur in self.tools:
            getattr(self, "render_" + self.cur)(s, self.tools[self.cur], now)

    def render_banner(self, s, now):
        d = s["d"]
        up, ip = s["link"], s["ipv4"]
        nb = N.merge_neighbors(s["nb"])
        gw = N.first_v4(d.get("Gateway"))
        x = s["dot1x"]
        if not s["sel"]:
            color, big, sub = GREY, "NO ETHERNET ADAPTER", "Plug in a USB NIC or check drivers"
        elif s["blink"]["running"]:
            color, big, sub = BLUE, "PORT FINDER ON", "Watch the switch for the blinking LED"
        elif up is None:
            color, big, sub = GREY, "CHECKING…", s["sel"]
        elif not up:
            color, big, sub = RED, "NO LINK", "Check cable · port shut / err-disabled?"
        elif s["dup_mac"]:
            color, big, sub = RED, "DUPLICATE IP", f"{ip} also used by {s['dup_mac']}"
        elif not good_ip(s):
            waited = now - s["ip_wait_from"] if s["ip_wait_from"] else None
            if x and x.get("code") in ("Request", "Failure"):
                color, big, sub = AMBER, "802.1X · NO ACCESS", "Port wants authentication (EAP)"
            elif ip:
                color, big = AMBER, "NO DHCP"
                sub = f"Self-assigned {ip} · link {N.fmt_speed(s['speed_mbps'])}"
            else:
                color, big = AMBER, "WAITING FOR IP"
                sub = f"Link {N.fmt_speed(s['speed_mbps'])}" + (f" · {waited:.0f}s" if waited else "")
        elif s["gw_ms"] == PENDING and gw:
            color, big, sub = BLUE, "TESTING…", f"{ip} · pinging gateway"
        elif gw and s["gw_ms"] is None:
            color, big, sub = AMBER, "GATEWAY NOT REPLYING", f"{ip} · wrong VLAN?"
        elif len(dhcp_servers(s)) > 1:
            color, big, sub = AMBER, "MULTIPLE DHCP SERVERS", ", ".join(dhcp_servers(s)[:3])
        elif s["net_ms"] is None:
            color, big, sub = AMBER, "NO INTERNET", f"{ip} · gateway OK"
        else:
            color, big = GREEN, "GOOD · " + (N.fmt_speed(s["speed_mbps"]) if s["speed_mbps"] else "link up")
            vlan = nb.get("vlan")
            sub = f"{ip}" + (f" · VLAN {vlan}" if vlan else "") + (
                f" · {nb['port']}" if nb.get("port") else "")
        if s["toast"] and now < s["toast_until"]:
            sub = s["toast"]
        elif len(s["adapters"]) > 1 and s["sel"]:
            sub = f"{sub}   [{s['sel']} ›]"
        for w in (self.banner, self.b_big, self.b_sub):
            if w.cget("bg") != color:
                w.config(bg=color)
        if self.b_big.cget("text") != big:
            self.b_big.config(text=big)
        if self.b_sub.cget("text") != sub:
            self.b_sub.config(text=sub)

    def render_port(self, s, now):
        T = lambda t: self.tile("PORT", t)  # noqa: E731
        d, up, ip = s["d"], s["link"], s["ipv4"]
        nb = N.merge_neighbors(s["nb"])
        spd = s["speed_mbps"]
        T("Speed").set(N.fmt_speed(spd) if up else "—",
                       OK if spd >= 1000 else WARN if spd >= 100 else BAD if spd else FG)
        full = d.get("FullDuplex")
        sw_duplex = nb.get("duplex")
        if not up or full is None:
            T("Duplex").set("—")
        elif full is False:
            T("Duplex").set("HALF", BAD)
        elif sw_duplex == "half":
            T("Duplex").set("Full", BAD, "SWITCH SAYS HALF")
        else:
            T("Duplex").set("Full", OK, "switch agrees" if sw_duplex else "")
        if ip and up:
            pl = N.prefix_len(s["mask"])
            apipa = ip.startswith("169.254.")
            if s["dup_mac"]:
                note, nc = "DUPLICATE!", BAD
            elif apipa:
                note, nc = "APIPA", WARN
            else:
                note = "DHCP" if d.get("DhcpEnabled") else ("STATIC" if d.get("DhcpEnabled") is False else "")
                nc = DIM
            T("IP address").set(f"{ip}/{pl}" if pl else ip, BAD if s["dup_mac"] else WARN if apipa else FG,
                                note, nc)
        else:
            T("IP address").set("—")
        gw = N.first_v4(d.get("Gateway"))
        T("Gateway").set(gw if up else "—", FG, *self.probe_note(s["gw_ms"], up and gw))
        srv = d.get("DhcpServer")
        srv = srv if N.is_ipv4(srv) and srv != "255.255.255.255" else None
        T("DHCP server").set(srv if up else "—", FG,
                             f"until {d['LeaseExpires']}" if up and srv and d.get("LeaseExpires") else "")
        dns_list = [x for x in N.as_list(d.get("Dns")) if N.is_ipv4(x)]
        T("DNS").set(", ".join(dns_list[:2]) if up and dns_list else "—", FG,
                     *self.probe_note(s["dns_ms"], up and dns_list))
        if s["time_to_ip"] is not None and up:
            tti = s["time_to_ip"]
            T("Time to IP").set(f"{tti:.1f} s", OK if tti < 8 else WARN if tti < 35 else BAD,
                                "portfast off?" if tti >= 25 else "since link up")
        elif up and s["ip_wait_from"] and not good_ip(s):
            T("Time to IP").set(f"{now - s['ip_wait_from']:.0f} s…", WARN, "waiting")
        else:
            T("Time to IP").set("—", FG, "plug in to time it" if not up else "")
        nm = s["net_ms"]
        if not good_ip(s):
            T("Internet").set("—")
        elif nm == PENDING:
            T("Internet").set("Testing…", DIM)
        elif nm is None:
            T("Internet").set("No route out", WARN)
        elif s["public_ip"]:
            T("Internet").set(s["public_ip"], OK, "online · " + fmt_ms(nm))
        else:
            T("Internet").set("Reachable", OK, fmt_ms(nm))

    def render_switch(self, s, now):
        T = lambda t: self.tile("SWITCH", t)  # noqa: E731
        nb = N.merge_neighbors(s["nb"])
        protos = [p for p in ("CDP", "LLDP") if p in s["nb"]]
        T("Switch").set(nb.get("name") or nb.get("chassis"), FG, "+".join(protos))
        T("Port").set(nb.get("port"))
        vlan = nb.get("vlan")
        T("Data VLAN").set(vlan, OK if vlan else FG, nb.get("vlan_name", ""))
        T("Voice VLAN").set(nb.get("voice_vlan"))
        T("Mgmt IP").set(nb.get("mgmt_ip"))
        T("Model").set((nb.get("platform") or "")[:60])
        T("PoE").set(nb.get("poe"))
        neg = " · ".join(x for x in (nb.get("autoneg"), nb.get("mau")) if x)
        if not neg and nb.get("duplex"):
            neg = f"{nb['duplex'].title()} duplex"
        T("Negotiation").set(neg)
        if not sniff_ok(s):
            self.sw_foot.config(text=s["sniff_msg"], fg=WARN)
        elif not s["link"]:
            self.sw_foot.config(text="Waiting for link…", fg=DIM)
        elif not protos:
            self.sw_foot.config(text=f"Listening {now - s['l2_since']:.0f}s — CDP every 60s, LLDP every 30s",
                                fg=DIM)
        else:
            parts = [f"{p} {now - s['nb'][p][1]:.0f}s ago" for p in protos]
            self.sw_foot.config(text="Heard: " + " · ".join(parts), fg=OK)

    def render_l2(self, s, now):
        T = lambda t: self.tile("L2", t)  # noqa: E731
        T("802.1X").set(*sum_dot1x(s, now))
        T("Spanning tree").set(*sum_stp(s, now))
        T("Trunk / DTP").set(*sum_trunk(s, now))
        T("DHCP servers").set(*sum_dhcp(s, now))
        T("Phone options").set(*sum_phone(s))
        T("Gateway MAC").set(*sum_gw(s, self.be.oui))
        T("IPv6").set(*sum_v6(s, now))
        T("Broadcast").set(*sum_bcast(s))
        if not sniff_ok(s):
            self.l2_foot.config(text=s["sniff_msg"], fg=WARN)
        else:
            ann = f"Announcing as {self.be.hostname()}" if self.be.settings.get("announce") else "Not announcing"
            self.l2_foot.config(text=f"{ann} · listening {now - s['l2_since']:.0f}s", fg=DIM)

    def render_stats(self, s):
        T = lambda t: self.tile("STATS", t)  # noqa: E731
        adapter = next((a for a in s["adapters"] if a["name"] == s["sel"]), {})
        mac = s["mac"] or adapter.get("mac")
        T("MAC").set(mac, FG, self.be.oui.vendor(mac) if mac else "")
        T("Adapter").set(adapter.get("desc") or s["sel"], FG, s["sel"] or "")
        io, base = s["io"], s["io_base"]
        for title, attr in (("RX errors", "errin"), ("TX errors", "errout"),
                            ("RX discards", "dropin"), ("TX discards", "dropout")):
            if io is not None and base is not None:
                n = getattr(io, attr) - getattr(base, attr)
                T(title).set(f"{n:,}", BAD if n > 0 else OK, "since reset")
            else:
                T(title).set("—")
        T("Throughput").set(f"↓ {N.fmt_rate(s['rx_bps'])}   ↑ {N.fmt_rate(s['tx_bps'])}" if s["link"] else "—")
        T("Link drops").set(s["drops"], BAD if s["drops"] else OK, "since reset")

    def render_settings(self):
        g = self.be.settings.get
        n_oui = len(self.be.oui.map)
        texts = {
            "announce": f"Announce to switch (LLDP + CDP):  {'ON' if g('announce') else 'OFF'}",
            "autolog": f"Auto-log every port to ports.csv:  {'ON' if g('autolog') else 'OFF'}",
            "smartsvc": f"Smart scan checks common services on every device:  {'ON' if g('smart_services') else 'OFF'}",
            "tickclaude": f"Claude recommended tick settings (stricter):  {'ON' if g('tick_claude') else 'OFF'}",
            "hostname": f"Name sent to switch:  {self.be.hostname()}",
            "iperf": "iperf3 server:  " + ((g('iperf_server') + (f":{g('iperf_port')}" if g('iperf_port') != 5201 else ""))
                                           if g("iperf_server") else "(tap to set)"),
            "oui": f"Update MAC vendor list  ({n_oui:,} vendors loaded)" if n_oui else "Download MAC vendor list",
            "folder": f"Open data folder  ({DATA_DIR})",
            "exit": "Exit PorkChopCheck",
        }
        for k, t in texts.items():
            b = self.set_btns[k]
            if b.cget("text") != t:
                b.config(text=t)

    @staticmethod
    def probe_note(v, active):
        if not active:
            return ("",)
        if v == PENDING:
            return ("testing…", DIM)
        if v is None:
            return ("NO REPLY", BAD)
        return (fmt_ms(v), OK)

    # ---------------------------------------------------------- tool renders
    SEV_COLOR = {"bad": BAD, "warn": WARN, "info": HDR}
    GRADE_COLOR = {"excellent": OK, "good": OK, "fair": WARN, "bad": BAD, "info": FG}

    def render_ping(self, s, v, now):
        p = s["ping"]
        samples, span = list(p["samples"]), p["span"]
        v.set_action(0, "Stop" if p["running"] else "Start", RED if p["running"] else BLUE)
        v.set_action(2, {30: "30 s", 300: "5 min", 1800: "30 min"}.get(span, f"{span} s"))
        tgt = p["target"] or "(no address yet)"
        if p["sent"]:
            loss = 100 * (p["sent"] - p["recv"]) / p["sent"]
            avg = p["sum"] / p["recv"] if p["recv"] else None
            jit = p["jit"] / p["jn"] if p["jn"] else 0
            color = OK if loss == 0 else WARN if loss < 5 else BAD
            summ = f"{loss:.1f}% loss · avg {fmt_ms(avg) or '—'} · jitter {jit:.1f} ms"
            rtts = [r for _, r in samples]
            p99 = N.percentile(rtts, 99)
            sub = (f"{p['label']} {tgt} · sent {p['sent']} · min {fmt_ms(p['min']) or '—'}"
                   f" · 99% under {fmt_ms(p99) or '—'} · max {fmt_ms(p['max']) or '—'}")
        else:
            color, summ = FG, f"{p['label']}: {tgt}"
            sub = "Tap Start — 4 pings a second. Port events are marked on the graph as they happen."
        v.set_summary(summ, color, sub)
        t_end = now if p["running"] or not samples else samples[-1][0]
        events = list(s["events"])
        ncol = 120 if span <= 30 else max(60, v.chart.winfo_width() // 3)
        normal = N.percentile([r for _, r in samples if r is not None], 50) or 0
        self.draw_timeline(v.chart, N.bucket_samples(samples, t_end, span, ncol), normal, events, t_end, span)
        rows = [("Port events, newest first", HDR, "hdr")]
        for e in reversed(events[-25:]):
            stamp = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
            went_on = e["last"] - e["ts"]
            lasted = f"  (kept up for {went_on:.0f} s)" if went_on >= 2 else ""
            rows.append((f"{stamp}  {e['text']}{lasted}", self.SEV_COLOR.get(e["sev"], FG), "row"))
            rows.append(("              " + N.impact_text(N.event_impact(samples, e["ts"])), DIM, "dim"))
        if not events:
            rows.append(("None yet. Link drops, speed changes, spanning-tree changes, gateway MAC changes, "
                         "broadcast storms, duplicate IPs and extra DHCP servers show up here and on the graph.",
                         DIM, "dim"))
        rows.append(("Last pings", HDR, "hdr"))
        rows += [(t, c, "mono") for t, c in list(p["log"])[:8]]
        v.list.set_rows(rows, "")

    def render_tick(self, s, v, now):
        t = s["tick"]
        run, rate, span, summ = t["running"], t["rate"], t["span"], t["sum"]
        v.set_action(0, "Stop" if run else "Start", RED if run else BLUE)
        v.set_action(1, f"{rate}/s", GREY if run else BLUE)
        v.set_action(2, {30: "30 s", 300: "5 min"}.get(span, f"{span} s"))
        v.set_action(4, "Reflecting" if t["reflecting"] else "Reflect", GREEN if t["reflecting"] else BLUE)
        server = self.be.settings.get("tick_server")
        claude = bool(self.be.settings.get("tick_claude"))
        tick_ms = 1000.0 / rate
        if summ and summ["n"]:
            head, grade = N.tick_verdict(summ, rate, claude)
            c = t["counters"]
            sub = t["msg"] or (f"{summ['loss_pct']:.2f}% loss · {summ['p50']:.1f} ms · "
                               f"jitter {summ['jitter'] or 0:.2f} ms · {t['target']} · {rate} a second"
                               f" · sent {c.get('sent', 0):,}")
            v.set_summary(head, self.GRADE_COLOR.get(grade, FG), sub, BAD if t["msg"] else DIM)
        elif run:
            v.set_summary("Waiting for replies…", FG, t["msg"] or t["target"], BAD if t["msg"] else DIM)
        else:
            v.set_summary("Game-rate UDP test", FG, t["msg"] or (
                f"Reflector: {server}. Tap Start." if server else
                "Tap Server to set where the reflector is, then Start."), BAD if t["msg"] else DIM)
        events = list(s["events"])
        # A reply that takes one tick longer than usual arrives a tick late: that is the amber line.
        self.draw_timeline(v.chart, t["cols"], t["normal"], events, t["t_end"] or now, span,
                           slow=t["normal"] + tick_ms, cap=max(t["normal"] + 3 * tick_ms, 3 * t["normal"] + 5))
        rows = []
        if summ and summ["n"]:
            rows.append(("How it rates for Counter-Strike"
                         + (" (Claude recommended tick settings)" if claude else ""), HDR, "hdr"))
            for key, value, grade in N.tick_ratings(summ, rate, claude):
                word = "Not graded" if grade == "info" else grade.capitalize()
                rows.append((f"{N.TICK_LABELS[key]:<15}{value:>10}   {word}",
                             self.GRADE_COLOR[grade], "mono"))
                if grade in ("fair", "bad"):
                    rows.append((N.TICK_FELT[key], DIM, "dim"))
        if summ and summ["n"] and summ["min"] is not None:
            rows += [("Reply times over the " + ("last 30 s" if span == 30 else "last 5 min"), HDR, "hdr"),
                     (f"fastest {summ['min']:.1f} · typical {summ['p50']:.1f} · 95% under {summ['p95']:.1f} · "
                      f"99% under {summ['p99']:.1f} · slowest {summ['max']:.1f} ms", FG, "row"),
                     (f"{summ['lost']} of {summ['n']:,} lost · longest run of lost packets {summ['burst']} · "
                      f"{summ['late']} replies over a tick ({tick_ms:.1f} ms) late · "
                      f"{t['counters'].get('reorder', 0)} out of order · "
                      f"{t['counters'].get('dup', 0)} duplicated · this box's own send timing is within "
                      f"{t['pace']:.2f} ms", DIM, "dim")]
            hold = t.get("hold") or {}
            if hold.get("mode") == "none":
                rows.append(("The reflector is an older PorkChopCheck that does not report how long it holds each "
                             "packet, so its own delays are counted as late replies. Update it to match this one.",
                             WARN, "dim"))
            elif hold.get("n"):
                rows.append((f"Reflector's own delay, already taken out: typical {hold['p50']:.2f} ms · longest "
                             f"{hold['max']:.1f} ms · {hold['over']} over a tick. What is left is the network.",
                             DIM, "dim"))
                if hold["mode"] == "timed":
                    rows.append(("The reflector's system cannot stamp packets as they arrive (Windows), so time it "
                                 "spent waiting to run still counts as network delay.", WARN, "dim"))
        if t["reflecting"]:
            rows += [("Reflector", HDR, "hdr"),
                     (f"Answering on UDP port {N.TICK_PORT}: {t['reflected']:,} packets returned"
                      + (f" to {', '.join(t['peers'][:3])}" if t["peers"] else ""), OK, "row")]
        rows.append(("Port events, newest first", HDR, "hdr"))
        for e in reversed(events[-25:]):
            stamp = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
            rows.append((f"{stamp}  {e['text']}", self.SEV_COLOR.get(e["sev"], FG), "row"))
            imp = t["impacts"].get(e["ts"])
            if imp:
                rows.append(("              " + imp, DIM, "dim"))
        if not events:
            rows.append(("None yet.", DIM, "dim"))
        rows.append(("How to use it", HDR, "hdr"))
        rows.append((f"Run 'porkchopcheck --reflector' on the game server or any machine at the far end, or tap "
                     f"Reflect on a second PorkChopCheck. Then set its address with Server and tap Start. "
                     f"This sends {N.TICK_SIZE}-byte UDP packets at the game's rate and times each one.", FG, "row"))
        v.list.set_rows(rows, "")

    def draw_timeline(self, c, cols, normal, events, t_end, span, slow=None, cap=None):
        """Latency bars with lost packets in red, and under them a lane marking each port event.
        `cols` is N.bucket_samples output; `normal` the usual reply time, for colouring. With
        `cap`, the scale stops there so one huge spike doesn't flatten everything else; bars
        that go past it are drawn full height and the scale label gets a plus."""
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 20 or not cols:
            return
        lane = max(10, int(h * 0.2))
        ph = h - lane
        ncol = len(cols)
        bw = w / ncol
        vals = [r for r, _, _ in cols if r is not None]
        slow = slow if slow is not None else max(20, 3 * normal)
        top = max(max(vals) if vals else 1, 2) * 1.15
        clipped = cap is not None and top > cap
        if clipped:
            top = cap
        for i, (r, lost, n) in enumerate(cols):
            x = i * bw
            if not n:
                continue
            if r is None:
                c.create_rectangle(x, 0, x + bw - 1, ph, fill=BAD, width=0)
                continue
            bh = min(ph, max(2, ph * r / top))
            c.create_rectangle(x, ph - bh, x + max(1, bw - 1), ph, fill=OK if r < slow else WARN, width=0)
            if lost:
                c.create_rectangle(x, 0, x + bw - 1, max(3, ph * 0.12), fill=BAD, width=0)
        c.create_line(0, ph, w, ph, fill=GREY)
        t0 = t_end - span
        for e in events:
            if e["last"] < t0 or e["ts"] > t_end:
                continue
            x = max(1, min(w - 2, (max(e["ts"], t0) - t0) / span * w))
            col = self.SEV_COLOR.get(e["sev"], FG)
            c.create_line(x, 0, x, ph, fill=col, dash=(3, 3))
            c.create_polygon(x, ph + 2, x - lane * 0.45, h - 1, x + lane * 0.45, h - 1, fill=col, outline="")
        font = self.font(self.sz["rowsm"])
        label = {30: "last 30 s", 300: "last 5 min", 1800: "last 30 min"}.get(span, "")
        tag = c.create_text(6, 4, anchor="nw", fill=FG, font=font,
                            text=f"{top:.0f}{'+' if clipped else ''} ms  ·  {label}")
        box = c.bbox(tag)
        if box:
            c.tag_lower(c.create_rectangle(box[0] - 4, box[1] - 2, box[2] + 4, box[3] + 2, fill=BG, width=0), tag)

    def render_trace(self, s, v, now):
        t = s["trace"]
        v.set_action(0, "Stop" if t["running"] else "Run", RED if t["running"] else BLUE)
        state = "running…" if t["running"] else ("done" if t["hops"] else "tap Run")
        v.set_summary(f"{t['label']}: {t['target'] or '—'}", FG,
                      f"{state} · up to 20 hops, sourced from the Ethernet port")
        rows = []
        for ttl, ip, rtt, status in t["hops"]:
            if ttl == 0:
                rows.append((status, WARN, "row"))
                continue
            vendor = ""
            if ip and status == "ttl" and ttl == 1:
                vendor = "  (first hop)"
            label = f"{ttl:>2}  {ip or '*':<16} {fmt_ms(rtt) if ip else 'timeout'}{vendor}"
            rows.append((label, OK if status == "ok" else BAD if not ip else FG, "mono"))
        v.list.set_rows(rows, "")

    def render_speed(self, s, v, now):
        sp = s["speed"]
        if sp["down"] is not None or sp["up"] is not None:
            summ = f"↓ {N.fmt_mbps(sp['down'])}    ↑ {N.fmt_mbps(sp['up'])}"
        else:
            summ = "Running…" if sp["running"] else "Pick a test"
        srv = self.be.settings.get("iperf_server")
        sub = (f"iperf3 server: {srv or 'not set (Settings)'} · Internet = {N.SPEED_HOST}")
        v.set_summary(summ, OK if sp["down"] else FG, sub)
        v.list.set_rows([(t, c, "row") for t, c in sp["lines"]],
                        "iperf3 tests against your own server (best for LAN speed). "
                        "Internet tests download/upload through this port.")

    def render_arp(self, s, v, now):
        a = s["arp_table"]
        rows = []
        for ip, mac, state in a["rows"]:
            vendor = self.be.oui.lookup(mac)
            rows.append((f"{ip:<15} {mac}  {state}", FG, "mono"))
            if vendor:
                rows.append(("      " + vendor, DIM, "dim"))
        when = time.strftime("%H:%M:%S", time.localtime(a["ts"])) if a["ts"] else "—"
        v.set_summary(f"{len(a['rows'])} entries", FG,
                      "Loading…" if a["running"] else f"Windows ARP cache for {s['sel']} · {when}")
        v.list.set_rows(rows, "No entries yet")

    def render_arpscan(self, s, v, now):
        a = s["arp_scan"]
        v.set_action(0, "Stop" if a["running"] else "Scan", RED if a["running"] else BLUE)
        found = a["found"]
        dups = {ip: m for ip, m in found.items() if len(m) > 1}
        if a["net"]:
            summ = f"{len(found)} hosts on {a['net']}"
            if a["running"]:
                sub = f"Scanning… {a['sent']}/{a['total'] * 2 if a['total'] else 0} requests"
            else:
                sub = "Done" + (" · subnet too big, scanned the /24 around you" if a["limited"] else "")
            if dups:
                sub = f"{len(dups)} DUPLICATE IP(s)! · " + sub
        else:
            summ, sub = "Find every host on this subnet", "Tap Scan (needs Npcap)"
        v.set_summary(summ, BAD if dups else FG, sub, BAD if dups else DIM)
        rows = []
        my_ip = s["ipv4"]
        for ip in sorted(found, key=lambda x: N.u32(socket.inet_aton(x), 0)):
            macs = found[ip]
            tag = "  ← this box" if ip == my_ip else ""
            rows.append((f"{ip:<15} {macs[0]}{tag}", BAD if len(macs) > 1 else FG, "mono"))
            vendor = self.be.oui.lookup(macs[0])
            if vendor:
                rows.append(("      " + vendor, DIM, "dim"))
            for m in macs[1:]:
                rows.append((f"{'  DUPLICATE':<15} {m}  {self.be.oui.lookup(m)}", BAD, "mono"))
        v.list.set_rows(rows, "")

    def render_mdns(self, s, v, now):
        m = self.be.mdns.snapshot()
        n_inst = len(m["inst"])
        n_dev = len(m["responders"])
        v.set_action(0, "Scanning" if m["running"] else "Scan", GREY if m["running"] else BLUE)
        if m["error"]:
            v.set_summary("mDNS error", BAD, m["error"])
        elif m["running"] and not n_inst:
            v.set_summary("Scanning…", DIM, "Asking every device on this VLAN")
        elif m["last_scan"] and not n_dev:
            v.set_summary("No mDNS replies", WARN,
                          "Nothing answered on this VLAN — blocked, isolated, or no devices")
        else:
            mc = "yes" if m["multicast_seen"] else "none yet"
            v.set_summary(f"{n_inst} services · {n_dev} devices", OK if n_inst else FG,
                          f"Multicast announcements seen: {mc} · replies: {m['unicast_replies']}")
        rows = [(t, HDR if k == "hdr" else FG, k) for t, k in N.mdns_rows(m)]
        v.list.set_rows(rows, "Tap Scan to browse Bonjour / mDNS services")

    LEVEL_COLOR = {"ok": OK, "info": FG, "warn": WARN, "bad": BAD}

    def render_wire(self, s, v, now):
        w = s["wire"]
        oui = self.be.oui
        findings = N.wire_findings(w, lambda mac: (oui.lookup(mac) if oui else "") or "", IS_LINUX)
        head, level = N.wire_headline(findings)
        mins = max(0, now - w["since"]) / 60
        v.set_summary(head, self.LEVEL_COLOR[level],
                      f"What's on this port that the other pages don't show · watching for {mins:.0f} min"
                      + (f" · {s['sniff_msg']}" if s["sniff_msg"] != "listening" else ""))
        rows, last = [], None
        for sec, lv, text in findings:
            if sec != last:
                rows.append((sec, HDR, "hdr"))
                last = sec
            rows.append((("✓ " if lv == "ok" else "• ") + text, self.LEVEL_COLOR[lv] if lv != "ok" else DIM, "row"))
        v.list.set_rows(rows)

    def render_mcast(self, s, v, now):
        m = s["mcast"]
        snap, run, j = m["snap"], m["running"], m["join"]
        v.set_action(0, "Stop" if run else "Start", RED if run else BLUE)
        v.set_action(1, "Leave" if j else "Join…", RED if j else BLUE)
        if not snap:
            v.set_summary("Multicast browser", FG, m["msg"] or ("Listening…" if run else "Tap Start to listen"),
                          WARN if m["msg"] else DIM)
            v.list.set_rows([], "Nothing heard yet." if run else "")
            return
        groups = snap["groups"]
        live = [g for g in groups if g["pkts"]]
        qtext, level, qnote = N.querier_verdict(snap, probed=bool(m["probed"]) and now - m["probed"] > 3)
        qcolor = {"ok": OK, "wait": DIM, "warn": WARN}[level]
        v.set_summary(f"{len(live)} groups · {N.fmt_rate(snap['bps'])}" + ("" if run else "  (stopped)"),
                      FG, qtext, qcolor)
        rows = [("IGMP querier", HDR, "hdr"), (qtext, qcolor if level != "wait" else FG, "row"), (qnote, DIM, "dim")]
        if j:
            g = next((x for x in groups if x["group"] == j["group"]), None)
            waited = now - j["since"]
            rows.append(("Join test", HDR, "hdr"))
            if g and g["pkts"] and g["pps"] > 0:
                rows.append((f"{j['group']}: arriving at {N.fmt_rate(g['bps'])}, {g['pps']:.0f} packets/s"
                             + (f" from {g['sources'][0]}" if g["sources"] else ""), OK, "row"))
            elif g and g["pkts"]:
                rows.append((f"{j['group']}: {g['pkts']:,} packets so far, none in the last second", WARN, "row"))
            else:
                rows.append((f"{j['group']}: joined {waited:.0f} s ago, nothing arriving",
                             WARN if waited > 5 else FG, "row"))
                if waited > 5:
                    rows.append(("Is anything sending to this group, and is it routed to this VLAN?", DIM, "dim"))
        rows.append(("Groups, busiest first", HDR, "hdr"))
        for g in groups[:40]:
            rows.append((f"{g['group']:<17}{g['name']}", FG if g["pkts"] else DIM, "mono"))
            bits = []
            if g["pkts"]:
                bits.append(f"{g['pps']:.0f} packets/s · {N.fmt_rate(g['bps'])}")
                if g["sources"]:
                    more = len(g["sources"]) - 1
                    bits.append(f"from {g['sources'][0]}" + (f" +{more}" if more else ""))
                if g["port"]:
                    bits.append(f"UDP {g['port']}")
            else:
                bits.append("no traffic seen")
            if g["members"]:
                bits.append(f"joined by {g['members'][0]}" + (f" +{len(g['members']) - 1}" if len(g["members"]) > 1 else ""))
            if N.mcast_is_link_local(g["group"]):
                bits.append("link-local")
            rows.append(("   " + " · ".join(bits), DIM, "dim"))
        if not groups:
            rows.append(("Nothing heard yet.", DIM, "dim"))
        rows.append(("With IGMP snooping on, a port only receives groups something on it has joined, plus "
                     "224.0.0.x link-local traffic. Join a group to pull it to this port.", DIM, "dim"))
        v.list.set_rows(rows)

    def render_capture(self, s, v, now):
        c = s["capture"]
        run = c["running"]
        v.set_action(0, "Stop" if run else "Start", RED if run else BLUE)
        v.set_action(1, "5 min" if c["secs"] >= 300 else f"{c['secs']} s", GREY if run else BLUE)
        counts = f"{c['frames']:,} frames · {N.fmt_bytes(c['bytes'])}"
        if run:
            v.set_summary(f"Recording… {c['left']:.0f} s left", WARN, f"{counts}  →  {c['file'] or '…'}")
        elif c["msg"]:
            v.set_summary(c["msg"], OK if c["ok"] else BAD, c["file"])
        else:
            v.set_summary("Record this port to a .pcap", FG,
                          "Tap Start. The button beside it sets how long. Open the file in Wireshark.")
        rows = [("Saved captures", HDR, "hdr")]
        rows += [(f"{name}   {N.fmt_bytes(size)}", FG, "mono") for name, size, _ in c["files"][:8]]
        if not c["files"]:
            rows.append(("None yet", DIM, "dim"))
        rows += [
            ("What you'll see", HDR, "hdr"),
            ("On a normal switch port: this box's own traffic, plus the broadcast and multicast "
             "the switch sends everyone. On a mirror (SPAN) port: everything the switch copies to it.",
             FG, "row"),
            (f"Saved in {self.be.capture_dir()}. A capture stops by itself at 200 MB.", DIM, "dim"),
        ]
        v.list.set_rows(rows)

    def render_switches(self, s, v, now):
        sw, lst = s["switches"], s["switches"]["list"]
        v1 = self.be.settings.get("snmp_version") == 1
        v.set_action(0, "Stop" if sw["running"] else "Scan", RED if sw["running"] else BLUE)
        v.set_action(3, "v1" if v1 else "v2c", GREY)
        levels = [switch_level(x) for x in lst]
        red, yellow = levels.count(SN.BAD), levels.count(SN.WARN)
        if not lst:
            head, col = "No switches yet", FG
        elif red or yellow:
            head = f"{len(lst)} switches · {red + yellow} need{'s' if red + yellow == 1 else ''} a look"
            col = BAD if red else WARN
        elif None in levels:
            head, col = f"{len(lst)} switches · reading…", FG
        else:
            head, col = f"{len(lst)} switches · all clear", OK
        if sw["running"]:
            sub, sub_col = sw["stage"], WARN
        else:
            sub = (f"SNMP {'v1' if v1 else 'v2c'} · community {self.be.settings.get('snmp_community')} · "
                   f"read every {SW_POLL_SECS} s while this page is open · tap a switch for its ports")
            sub_col = DIM
        v.set_summary(head, col, sub, sub_col)
        self.draw_switches(v.chart, lst)
        rows = []
        for x in lst:
            level = switch_level(x)
            if level not in (SN.BAD, SN.WARN):
                continue
            rows.append((f"{x['name'] or x['ip']}   {x['ip']}", HDR, "hdr"))
            if x["ok"] is False:
                rows.append(("Not answering: " + (x["msg"] or "no reply"), BAD, "row"))
            shown = [p for p in x["ports"] if p["level"] in (SN.BAD, SN.WARN)]
            shown.sort(key=lambda p: -SN.RANK[p["level"]])
            for p in shown[:6]:
                rows.append((f"{p['name']}: {p['reasons'][0]}", SW_COLORS[p["level"]], "row"))
            if len(shown) > 6:
                rows.append((f"and {len(shown) - 6} more ports", DIM, "dim"))
        if lst and not rows:
            rows.append(("No port on any switch shows errors or link trouble.", OK, "row"))
        if lst:
            rows.append(("Green: every port clean. Yellow: something worth a look. Red: a port has errors or "
                         f"link trouble now; a number appears when more than {SN.BADGE_OVER} ports are red.",
                         DIM, "dim"))
        v.list.set_rows(rows, "Tap Scan to look for switches on this network, or Add to type one's address.\n\n"
                              "Scan asks every address on the subnet with the community above, then follows "
                              "CDP from each Cisco switch to the ones plugged into it. Set Community and the "
                              "SNMP version first if your switches don't use 'public' and v2c.")

    def draw_switches(self, c, lst):
        """The switches as a grid of icons, coloured by their worst port."""
        w, h = c.winfo_width(), c.winfo_height()
        sig = (w, h, tuple((x["ip"], x["name"], switch_level(x), x["sum"]["bad"] if x["sum"] else 0)
                           for x in lst))
        if sig == self.sw_sig or w < 20:
            return
        self.sw_sig = sig
        c.delete("all")
        self.sw_hits = []
        n = len(lst)
        if not n:
            return
        for cols in range(1, n + 1):                # the fewest columns whose rows still fit
            tw = min(w / cols, w * 0.3)
            th = tw * 0.62
            if -(-n // cols) * th <= h:
                break
        else:
            th = min(th, h)
        x0, y0 = (w - tw * min(cols, n)) / 2, max(0, (h - -(-n // cols) * th) / 2)
        f_name = self.font(max(10, int(th * 0.13)), "bold")
        f_ip = self.mono(max(10, int(th * 0.12)))
        for i, x in enumerate(lst):
            tx, ty = x0 + (i % cols) * tw, y0 + (i // cols) * th
            col = SW_COLORS.get(switch_level(x), DIM)
            iw, ih = tw * 0.66, th * 0.36
            ix, iy = tx + (tw - iw) / 2, ty + th * 0.12
            lw = max(2, int(ih / 12))
            c.create_rectangle(ix, iy, ix + iw, iy + ih, fill="#0d1117", outline=col, width=lw)
            pitch = iw * 0.62 / 8                   # two rows of eight ports, then a pair of uplinks
            dot = pitch * 0.7
            for r in range(2):
                for k in range(8):
                    px, py = ix + iw * 0.06 + k * pitch, iy + ih / 2 + (r - 1) * pitch + (pitch - dot) / 2
                    c.create_rectangle(px, py, px + dot, py + dot, fill=col, outline="")
            for k in range(2):
                px = ix + iw * 0.72 + k * iw * 0.12
                c.create_rectangle(px, iy + ih * 0.3, px + iw * 0.08, iy + ih * 0.7, outline=col, width=lw)
            bad = x["sum"]["bad"] if x["sum"] else 0
            if bad > SN.BADGE_OVER:
                r = ih * 0.3
                c.create_oval(ix + iw - r, iy - r, ix + iw + r, iy + r, fill=BAD, outline=BG, width=2)
                c.create_text(ix + iw, iy, text=str(bad), fill="white", font=self.font(max(9, int(r * 1.2)), "bold"))
            name = x["name"] or "(no name)"
            while len(name) > 4 and f_name.measure(name) > tw - self.pad:
                name = name[:-2].rstrip("…") + "…"
            c.create_text(tx + tw / 2, iy + ih + th * 0.07, anchor="n", text=name, fill=FG, font=f_name)
            c.create_text(tx + tw / 2, iy + ih + th * 0.09 + f_name.metrics("linespace"), anchor="n",
                          text=x["ip"], fill=DIM, font=f_ip)
            self.sw_hits.append((tx, ty, tx + tw, ty + th, x["ip"]))

    def render_swports(self, s, v, now):
        x = next((x for x in s["switches"]["list"] if x["ip"] == self.sw_open), None)
        if x is None:
            self.show("switches")
            return
        title = x["name"] or x["ip"]
        if v.title.cget("text") != title:
            v.title.config(text=title)
        sm = x["sum"]
        info = " · ".join(b for b in (x["ip"], x["model"]) if b)
        if x["ok"] is False:
            v.set_summary("Not answering", BAD, f"{info} · {x['msg']}", BAD)
        elif not sm:
            v.set_summary("Reading the switch…", FG, info)
        else:
            head = f"{sm['up']} of {sm['total']} ports linked"
            if sm["bad"] or sm["warn"]:
                head += " · " + ", ".join(t for t in (f"{sm['bad']} red" if sm["bad"] else "",
                                                      f"{sm['warn']} yellow" if sm["warn"] else "") if t)
            else:
                head += " · all clean"
            v.set_summary(head, SW_COLORS[sm["level"]],
                          f"{info} · read {max(0, int(now - x['polled']))} s ago · tap a port for its details")
        ports = x["ports"]
        self.draw_front(v.chart, ports)
        sel = next((p for p in ports if p["index"] == self.sw_port), None)
        v.set_action(0, "Clear port" if sel else "Clear all")
        if sel:
            v.list.set_rows(self.port_rows(sel))
            return
        rows = []
        for p in sorted((p for p in ports if p["level"] in (SN.BAD, SN.WARN)), key=lambda p: -SN.RANK[p["level"]]):
            name = p["name"] + (f" ({p['alias']})" if p["alias"] else "")
            rows.append((f"{name}: {'; '.join(p['reasons'])}", SW_COLORS[p["level"]], "row"))
        if ports and not rows:
            rows.append(("Every linked port is clean.", OK, "row"))
        if ports:
            rows.append(("Green: linked and clean. Yellow: worth a look. Red: errors or link trouble now. "
                         "Grey: nothing plugged in. Dark: shut down on the switch.", DIM, "dim"))
            rows.append(("Errors only count from when this page started watching, so old history on the "
                         "switch does not turn a port red. Clear all starts every port fresh.", DIM, "dim"))
        v.list.set_rows(rows, "Waiting for the switch's first answer…")

    def port_rows(self, p):
        col = SW_COLORS[p["level"]] if p["level"] in (SN.GOOD, SN.WARN, SN.BAD) else DIM
        rows = [(p["name"] + (f" · {p['alias']}" if p["alias"] else ""), HDR, "hdr")]
        if not p["admin"]:
            rows.append(("Shut down on the switch", DIM, "row"))
        elif not p["oper"]:
            rows.append(("No link", DIM, "row"))
        else:
            speed = f"{p['speed'] / 1000:g} Gb" if p["speed"] >= 1000 else f"{p['speed']} Mb"
            rows.append((f"Linked at {speed}" + (f", {p['duplex']} duplex" if p["duplex"] else ""), FG, "row"))
        rows += [(r, col, "row") for r in p["reasons"] if p["level"] in (SN.WARN, SN.BAD)]
        if p["level"] == SN.GOOD:
            rows.append(("No problems seen", OK, "row"))
        if p["oper"] and p["out_mbps"] is not None:
            rows.append((f"Traffic: {p['in_mbps']:.1f} Mb/s in, {p['out_mbps']:.1f} Mb/s out"
                         + (f" ({p['busy']}% of the port's speed)" if p["busy"] is not None else ""), FG, "row"))
        def totals(c):
            c = {k: v or 0 for k, v in c.items()}
            return (f"Receive errors {c['in_err']:,} (CRC {c['fcs'] + c['align']:,})   Send errors {c['out_err']:,}"
                    f"   Dropped {c['in_disc'] + c['out_disc']:,}")
        if p["since_clear"] is not None:
            rows += [("Since you tapped Clear", DIM, "dim"), (totals(p["since_clear"]), FG, "row")]
        rows += [("The switch's own totals, which only restart when the switch does", DIM, "dim"),
                 (totals(p["c"]), FG, "row"),
                 ("Clear port wipes what was seen here and watches again from now, so you can tell whether "
                  "the errors come back. Tap an empty part of the switch to go back to the list.", DIM, "dim")]
        return rows

    def draw_front(self, c, ports):
        """The front of the switch: odd ports on top, even below, coloured by what is wrong."""
        w, h = c.winfo_width(), c.winfo_height()
        sig = (w, h, self.sw_port, tuple((p["index"], p["level"]) for p in ports))
        if sig == self.swp_sig or w < 20:
            return
        self.swp_sig = sig
        c.delete("all")
        self.swp_hits = []
        rows = SN.layout(ports)
        if not rows:
            return

        def units(row):                             # widths in port-sized cells, with a gap between blocks
            return sum(max(len(b["top"]), len(b["bottom"])) for b in row) + len(row)
        cell = min((w - 2 * self.pad) / max(units(r) for r in rows), (h - self.pad) / (len(rows) * 3.2), w * 0.07)
        y0 = (h - len(rows) * cell * 3.2) / 2
        font = self.font(max(8, int(cell * 0.4)), "bold")
        for r, row in enumerate(rows):
            cw = units(row) * cell
            cx, cy = (w - cw) / 2, y0 + r * cell * 3.2 + cell * 0.6
            c.create_rectangle(cx, cy, cx + cw, cy + cell * 2.5, fill="#0d1117", outline=GREY, width=2)
            px = cx + cell * 0.5
            for b in row:
                c.create_text(px + cell * 0.07, cy - cell * 0.08, anchor="sw", text=b["label"], fill=DIM,
                              font=self.font(max(9, int(cell * 0.36))))
                for line, ports_in in enumerate((b["top"], b["bottom"])):
                    for k, p in enumerate(ports_in):
                        x1 = px + k * cell + cell * 0.07
                        y1 = cy + cell * (0.25 + line if b["bottom"] else 0.75) + cell * 0.07
                        s = cell * 0.86
                        picked = p["index"] == self.sw_port
                        c.create_rectangle(x1, y1, x1 + s, y1 + s, fill=SW_COLORS[p["level"]],
                                           outline="white" if picked else "", width=3 if picked else 0)
                        if cell >= 18:
                            c.create_text(x1 + s / 2, y1 + s / 2, text=SN.short_name(p["name"]), font=font,
                                          fill=BG if p["level"] in (SN.GOOD, SN.WARN, SN.BAD) else DIM)
                        self.swp_hits.append((x1, y1, x1 + s, y1 + s, p["index"]))
                px += (max(len(b["top"]), len(b["bottom"])) + 1) * cell

    def render_blink(self, s, v, now):
        b = s["blink"]
        v.set_action(0, "Stop" if b["running"] else "Start", RED if b["running"] else BLUE)
        if b["running"]:
            v.set_summary(f"Blinking… {b['cycles']} cycles", WARN,
                          "The port LED goes dark ~1.5 s every 4.5 s. Tap Stop when you find it.")
        else:
            v.set_summary("Find this port on the switch", FG, "Tap Start, then watch the switch")
        v.list.set_rows([
            ("How it works", HDR, "hdr"),
            ("PorkChopCheck disables and re-enables this Ethernet adapter on a loop, so the switch "
             "port's link LED flashes off and on — like a toner, but for switch ports.", FG, "row"),
            ("Tip", HDR, "hdr"),
            ("Also try 'show cdp neighbors' or 'show lldp neighbors' on the switch: this box "
             f"announces itself as {self.be.hostname()}.", FG, "row"),
            ("Needs admin. The adapter is always re-enabled when you stop or exit.", DIM, "dim"),
        ])

    def render_log(self, s, v, now):
        rows = self.be.portlog.rows()
        v.set_summary(f"{len(rows)} ports logged", FG, os.path.join(DATA_DIR, "ports.csv"))
        out = []
        for r in rows:
            head = f"{r.get('switch', '')}  {r.get('port', '')}"
            if r.get("label"):
                head += f"  —  {r['label']}"
            out.append((head, HDR, "hdr"))
            bits = [f"VLAN {r['vlan']}" if r.get("vlan") else "", r.get("speed", ""),
                    r.get("ip", ""), f"voice {r['voice_vlan']}" if r.get("voice_vlan") else "",
                    r.get("poe", ""), f"802.1X {r['dot1x']}" if r.get("dot1x") not in ("", "—", "Not detected") else ""]
            out.append(("  ·  ".join(b for b in bits if b), FG, "row"))
            out.append((f"last {r.get('last_seen', '')}  ·  first {r.get('first_seen', '')}", DIM, "dim"))
        v.list.set_rows(out, "Nothing yet. Ports are logged automatically once CDP/LLDP names "
                             "the switch port, or tap SAVE to log one with a label.")


# ================================================================ main
def parse_size():
    if "--size" in sys.argv:
        try:
            w, h = sys.argv[sys.argv.index("--size") + 1].lower().split("x")
            return int(w), int(h)
        except (IndexError, ValueError):
            pass
    return None


def maybe_elevate():
    """Relaunch elevated (one UAC prompt) so renew / bounce / port finder / capture all work."""
    if not IS_WIN or FROZEN or DEMO or "--no-elevate" in sys.argv or N.is_admin():
        return                       # the .exe elevates through its manifest; Linux uses capabilities
    try:
        import ctypes
        exe = sys.executable
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(w):
            exe = w
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:] + ["--no-elevate"])
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, SCRIPT_DIR, 1)
        if r > 32:
            sys.exit(0)
    except Exception:  # noqa: BLE001
        pass


def main():
    if "--version" in sys.argv:
        print(f"PorkChopCheck {VERSION}")
        return
    maybe_elevate()
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass
    if not psutil and not DEMO:
        _fatal("psutil is missing.\n" + ("Run ./install-linux.sh" if IS_LINUX
                                          else "Run:  py -m pip install psutil scapy"))
    root = tk.Tk()
    root.title("PorkChopCheck")
    size = parse_size()
    if WINDOWED:
        size = size or ((1024, 640) if IS_LINUX and not DEMO else (800, 480))
        root.geometry(f"{size[0]}x{size[1]}")
    else:
        size = size or (root.winfo_screenwidth(), root.winfo_screenheight())
        root.attributes("-fullscreen", True)
    st = State()
    settings = N.Settings(DATA_DIR)
    portlog = N.PortLog(DATA_DIR)
    oui = N.Oui(os.path.join(DATA_DIR, "manuf.txt"))
    mdns = N.MdnsBrowser()
    be = (DemoBackend if DEMO else Backend)(st, settings, portlog, oui, mdns)
    be.start()
    ui = UI(root, st, be, size)
    root.protocol("WM_DELETE_WINDOW", ui.quit)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        import traceback
        _fatal("PorkChopCheck crashed while starting:\n\n" + traceback.format_exc())
