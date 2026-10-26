"""The PorkChopCheck router service: tests the port the WAN is plugged into, shows it on the router's
screen and on a phone page, and lets the screen go back to GL.iNet's own screen program.

Runs under procd (router/pcc-router.init). Threads:
- link: the WAN's carrier, speed and duplex from /sys, and what each end offered from ethtool
- listen: every frame on the WAN, decoded by pc_net.classify (CDP, LLDP, STP, DHCP, 802.1X...)
- wan: the router's own DHCP client's status (ubus), and the gateway's MAC
- checks: gateway, DNS and internet, and the public address
- a DHCP DISCOVER of our own a few seconds after every link up, so a second server shows itself
- the screen and its touch input, when the screen is ours
- ping, four a second, to the chosen target, for the event timeline (tools.py)
- the port log, filled in whenever CDP/LLDP names a port
- the phone page (web.py), which also starts the tick test, reflector, speed test and port finder
- the network mode (Router or Access point) and the side switch's position; netmode.lua changes it
"""

import json
import os
import random
import socket
import subprocess
import threading
import time

import pc_net as N

from . import tools, web
from .screen import PAGES, Display, Touch
from .tester import Tester

CONFIG = os.environ.get("PCC_CONFIG", "/etc/pcc-router/config.json")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NETMODE_STATE = "/tmp/pcc-netmode.json"
NETMODE_LOCK = "/var/lock/pcc-netmode.lock"
MODE_NAMES = {"router": "Router", "ap": "Access point"}
CHANGE_SECS = 120  # a change that says "changing" for longer than this has died
DEFAULTS = {"iface": "eth0", "wan": "wan", "screen": "pcc", "port": 8088,
            "ping_target": "gateway", "tick_server": "", "iperf_server": "", "iperf_port": 5201}


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


class Service:
    def __init__(self, config_path=CONFIG):
        self.config_path = config_path
        self.config = {**DEFAULTS, **self._load()}
        self.iface = self.config["iface"]
        self.tester = Tester(self.iface)
        self.display = Display()
        self.page = 0
        self.stop = threading.Event()
        self.screen_changed = threading.Event()
        self.recheck = threading.Event()
        folder = os.path.dirname(self.config_path)
        self.pinger = tools.Pinger(lambda: self.tester.wan.get("address"), self.ping_target)
        self.tick = tools.Tick()
        self.reflector = tools.ReflectorTool()
        self.speed = tools.Speed()
        self.blink = tools.Blink(self.iface, self.tester)
        self.log = tools.PortLog(folder)
        self._resolved = {}
        self.netmode = {"mode": None, "switch": None, "switch_set": False, "state": None, "lan_ip": None}
        self.hold_hint = 0  # when a finger on the Mode page passed the first hold: "keep holding"

    # ---------- config ----------
    def _load(self):
        try:
            with open(self.config_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def save(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        tmp = self.config_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.config, f, indent=1)
        os.replace(tmp, self.config_path)

    # ---------- tools ----------
    def ping_target(self):
        """The address pinged now: the gateway, the first DNS server, the internet, or a name."""
        want, wan = self.config.get("ping_target") or "gateway", self.tester.wan
        if want == "gateway":
            return wan.get("gateway")
        if want == "dns":
            return (wan.get("dns") or [None])[0]
        if want == "internet":
            return "1.1.1.1"
        if want not in self._resolved:
            try:
                self._resolved = {want: socket.gethostbyname(want)}
            except OSError:
                return None
        return self._resolved[want]

    def set_option(self, key, value):
        self.config[key] = value
        self.save()

    def log_loop(self):
        while not self.stop.is_set():
            try:
                self.log.auto(self.tester.snapshot())
            except OSError:
                pass
            self.stop.wait(3)

    # ---------- Router or Access point ----------
    def read_netmode(self):
        """The mode GL.iNet is in, the side switch's position, and any change in progress."""
        mode = run(["uci", "-q", "get", "glconfig.general.mode"]).strip() or None
        func = run(["uci", "-q", "get", "switch-button.@main[0].func"]).strip()
        gpio = read("/proc/gl-hw-info/switch-button")
        switch = None
        if gpio:
            for line in read("/sys/kernel/debug/gpio").splitlines():
                parts = line.split()
                if parts and parts[0] == gpio:
                    switch = "on" if " hi" in line else "off"
        state = {}
        try:
            with open(NETMODE_STATE) as f:
                state = json.load(f)
        except (OSError, ValueError):
            pass
        if state.get("state") == "changing" and time.time() - state.get("t", 0) > CHANGE_SECS:
            state = {"state": "error", "error": "The change did not finish", "t": state.get("t", 0) + CHANGE_SECS}
        if state.get("state") == "error" and time.time() - state.get("t", 0) > 600:
            state = {}  # an old failure: stop showing it
        lan_ip = run(["uci", "-q", "get", "network.lan.ipaddr"]).strip() or None
        return {"mode": mode, "switch": switch, "switch_set": func == "netmode", "state": state.get("state"),
                "want": state.get("want"), "error": state.get("error"), "lan_ip": lan_ip}

    def netmode_loop(self):
        while not self.stop.is_set():
            was = self.netmode.get("mode")
            self.netmode = self.read_netmode()
            if was and self.netmode["mode"] != was:
                with self.tester.lock:
                    self.tester.event(f"Now in {MODE_NAMES.get(self.netmode['mode'], self.netmode['mode'])} mode")
                    self.tester.wan = {}
                self.recheck.set()
            self.stop.wait(2)

    def set_netmode(self, want):
        """Starts a change to "router" or "ap". It runs on its own (the network restarts under it)."""
        if want not in ("router", "ap"):
            raise ValueError("mode is router or ap")
        if self.netmode.get("state") == "changing":
            raise ValueError("Already changing")
        if want == "ap" and read(f"/sys/class/net/{self.iface}/carrier") != "1":
            raise ValueError("Plug a cable into WAN first")
        subprocess.Popen(["flock", "-n", NETMODE_LOCK, "lua", os.path.join(HERE, "netmode.lua"), "set", want],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)  # fmt: skip
        self.netmode = {**self.netmode, "state": "changing", "want": want, "error": None}
        self.screen_changed.set()

    def toggle_netmode(self):
        self.set_netmode("router" if self.netmode.get("mode") == "ap" else "ap")

    def screen_snap(self):
        snap = self.tester.snapshot()
        snap["netmode"] = {**self.netmode, "hold": time.monotonic() - self.hold_hint < 2.5}
        return snap

    # ---------- whose screen ----------
    def set_screen(self, mode):
        """"pcc" (ours) or "gl" (GL.iNet's screen program). Remembered across reboots."""
        if mode not in ("pcc", "gl"):
            raise ValueError(mode)
        self.config["screen"] = mode
        self.save()
        self.apply_screen()

    def apply_screen(self):
        if self.config["screen"] == "pcc":
            run(["/etc/init.d/gl_screen", "stop"])
            self.display.light(True)
        else:
            run(["/etc/init.d/gl_screen", "start"])
        self.screen_changed.set()

    def screen_loop(self):
        while not self.stop.is_set():
            self.screen_changed.clear()
            if self.config["screen"] != "pcc":
                self.screen_changed.wait(5)
                continue
            last = 0
            while self.config["screen"] == "pcc" and not self.stop.is_set() and not self.screen_changed.is_set():
                if time.monotonic() - last >= 1:
                    if not self.display.lit():  # something blanked it: light it again
                        self.display.light(True)
                    try:
                        snap = self.screen_snap()
                        snap["blink"] = self.blink.state()
                        if PAGES[self.page % len(PAGES)] == "ping":
                            snap["ping"] = self.pinger.state(60, [], cols=270)
                        self.display.show(snap, self.page)
                    except OSError:
                        pass
                    last = time.monotonic()
                time.sleep(0.1)

    def touch_loop(self):
        touch = Touch()
        while not self.stop.is_set():
            if self.config["screen"] != "pcc":
                time.sleep(1)
                continue
            for press in touch.presses(lambda: self.stop.is_set() or self.config["screen"] != "pcc"):
                on_mode = PAGES[self.page % len(PAGES)] == "mode"
                if press in ("tap", "next", "prev"):
                    self.page = (self.page + (-1 if press == "prev" else 1)) % len(PAGES)
                    self.screen_changed.set()  # redraw now
                elif on_mode:  # the Mode page: hold 1.5 s shows "keep holding", 3 s changes mode
                    if press == "hold":
                        self.hold_hint = time.monotonic()
                    elif press == "long":
                        self.hold_hint = 0
                        try:
                            self.toggle_netmode()
                        except ValueError as e:
                            self.netmode = {**self.netmode, "state": "error", "error": str(e)}
                    self.screen_changed.set()
                elif press == "long":
                    pass  # the hold already handed the screen over
                else:  # held: give the screen back to GL.iNet's program
                    self.set_screen("gl")
                    break
            time.sleep(1)

    # ---------- the port ----------
    def link_loop(self):
        base = f"/sys/class/net/{self.iface}"
        last, last_ethtool = None, 0
        while not self.stop.is_set():
            up = read(f"{base}/carrier") == "1"
            speed = int(read(f"{base}/speed", "0") or 0) if up else None
            duplex = read(f"{base}/duplex") if up else None
            state = (up, speed, duplex)
            if self.tester.blinking:  # the port finder's own bounces: not news
                last = state
                time.sleep(0.5)
                continue
            if state != last or (up and time.monotonic() - last_ethtool > 60):
                text = run(["ethtool", self.iface]) if up else None
                last_ethtool = time.monotonic()
                came_up = up and (last is None or not last[0])
                self.tester.on_link(up, speed if speed and speed > 0 else None, duplex, text)
                last = state
                if came_up:
                    threading.Timer(4, self.dhcp_probe).start()
                    self.recheck.set()
            time.sleep(0.5)

    def listen_loop(self):
        while not self.stop.is_set():
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                s.bind((self.iface, 0))
                s.settimeout(1)
            except OSError:
                time.sleep(5)
                continue
            with s:
                while not self.stop.is_set():
                    try:
                        raw = s.recv(4096)
                    except TimeoutError:
                        continue
                    except OSError:
                        break
                    try:
                        self.tester.on_frame(raw)
                    except Exception:  # noqa: BLE001 - one odd frame must not stop the listener
                        pass

    def dhcp_probe(self):
        """A DISCOVER of our own: every server that answers shows up, so a rogue one cannot hide."""
        mac = read(f"/sys/class/net/{self.iface}/address")
        if not mac:
            return
        try:
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
                s.bind((self.iface, 0))
                self.tester.on_probe()
                s.send(N.build_dhcp_discover(mac, random.randint(1, 0xFFFFFFFF)))
        except OSError:
            return
        time.sleep(4)
        self.tester.probe_done()

    def wan_loop(self):
        while not self.stop.is_set():
            # in Access point mode the WAN port joins the LAN bridge and the router's own address
            # comes from the network on "lan"
            name = "lan" if self.netmode.get("mode") == "ap" else self.config["wan"]
            try:
                status = json.loads(run(["ubus", "call", f"network.interface.{name}", "status"]) or "{}")
            except ValueError:
                status = {}
            self.tester.on_wan(status)
            gw = self.tester.wan.get("gateway")
            if gw:
                out = run(["ip", "neigh", "show", gw])
                parts = out.split()
                if "lladdr" in parts:
                    self.tester.set_gateway_mac(parts[parts.index("lladdr") + 1])
            time.sleep(2)

    def checks_loop(self):
        last_public = 0
        while not self.stop.is_set():
            wan = dict(self.tester.wan)
            src = wan.get("address")
            if src and self.tester.link["up"]:
                if wan.get("gateway"):
                    ms = N.ping_ms(wan["gateway"], src)
                    self.tester.on_check("gateway", ms is not None, ms)
                if wan.get("dns"):
                    ms = N.dns_probe(wan["dns"][0], src)
                    self.tester.on_check("dns", ms is not None, ms, wan["dns"][0])
                ms = N.ping_ms("1.1.1.1", src)
                self.tester.on_check("internet", ms is not None, ms, "1.1.1.1")
                if ms is not None and (time.monotonic() - last_public > 300 or not self.tester.public_ip):
                    self.tester.public_ip = N.public_ip(src)
                    last_public = time.monotonic()
            self.recheck.wait(5)
            self.recheck.clear()

    # ---------- running ----------
    def start(self):
        self.apply_screen()
        self.reflector.tidy()
        self.netmode = self.read_netmode()
        for target in (self.link_loop, self.listen_loop, self.wan_loop, self.checks_loop, self.screen_loop,
                       self.touch_loop, self.log_loop, self.netmode_loop):  # fmt: skip
            threading.Thread(target=target, daemon=True, name=target.__name__).start()
        threading.Thread(target=self.pinger.run, args=(self.stop,), daemon=True, name="ping").start()
        web.serve(self, self.config["port"])  # blocks


def main():
    Service().start()


if __name__ == "__main__":
    main()
