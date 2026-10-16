"""The router port tester (router/pcc_router): frames in, verdict out, screen pages, the phone page.
Runs on a PC; nothing here needs a router."""
import json, os, socket, struct, sys, tempfile, threading, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "router"))
import pc_net as N
from pcc_router import screen, web
from pcc_router.tester import Tester, findings
ok = 0
def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1; print("ok ", name)

class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t

SWITCH = "00:26:6c:0b:1a:2b"
OURS = "94:83:c4:b1:fe:94"

def offer(server, yiaddr="10.2.1.108", lease=3600, extra=b""):
    opts = (bytes([53, 1, 2]) + bytes([54, 4]) + socket.inet_aton(server) + bytes([51, 4]) + struct.pack("!I", lease)
            + bytes([3, 4]) + socket.inet_aton("10.2.1.254") + bytes([6, 4]) + socket.inet_aton("10.2.1.5")
            + bytes([150, 4]) + socket.inet_aton("10.9.9.9") + extra + b"\xff")
    bootp = (struct.pack("!BBBBIHH", 2, 1, 6, 0, 0x1234, 0, 0) + bytes(4) + socket.inet_aton(yiaddr) + bytes(8)
             + N.mac_bytes(OURS) + bytes(10) + bytes(192) + N.DHCP_MAGIC + opts)
    return N.ipv4_udp_frame(SWITCH, N.BCAST, server, "255.255.255.255", 67, 68, bootp)

WAN = {"ipv4-address": [{"address": "10.2.1.108", "mask": 24}],
       "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "10.2.1.254"}],
       "dns-server": ["10.2.1.5", "10.2.1.6"], "dns-search": ["shiner.lab"]}

# ---------- no link, then a link ----------
clock = Clock()
t = Tester(clock=clock)
s = t.snapshot()
check("no link is red", s["verdict"] == "bad" and s["findings"] == [("bad", "No link")])
t.on_link(True, 1000, "full", "Advertised link modes: 10baseT/Full 100baseT/Full 1000baseT/Full\n"
                               "Link partner advertised link modes: 10baseT/Full 100baseT/Full 1000baseT/Full\nSpeed: 1000Mb/s")
s = t.snapshot()
check("link up, waiting for an address", s["link"]["up"] and ("bad", "Waiting for an address") in s["findings"], s["findings"])
clock.t += 3; t.on_wan(WAN)
clock.t += 1; t.on_check("gateway", True, 0.4); t.on_check("internet", True, 12.0); t.on_check("dns", True, 2.0)
s = t.snapshot()
check("address and checks", s["wan"]["address"] == "10.2.1.108" and s["wan"]["gateway"] == "10.2.1.254" and s["wan"]["dns"] == ["10.2.1.5", "10.2.1.6"])
check("time to online", s["timing"] == {"address": 3.0, "gateway": 4.0, "internet": 4.0}, s["timing"])

# ---------- the switch speaks ----------
t.on_frame(N.build_cdp(SWITCH, "Texas-CORE.shiner.lab", "GigabitEthernet1/0/14", "10.2.1.1"))
t.on_frame(N.build_lldp(SWITCH, "Gi1/0/14", "Texas-CORE"))
s = t.snapshot()
check("switch from CDP wins over LLDP", s["switch"]["name"] == "Texas-CORE.shiner.lab" and s["switch"]["port"] == "GigabitEthernet1/0/14"
      and s["switch"]["protocols"] == ["CDP", "LLDP"], s["switch"])
check("good port is green", s["verdict"] == "good" and s["findings"] == [("good", "Port looks good")], s["findings"])

# ---------- DHCP: options, then a rogue server ----------
t.on_frame(offer("10.2.1.5"))
s = t.snapshot()
check("dhcp server and phone option 150", s["dhcp"]["servers"] == ["10.2.1.5"] and s["dhcp"]["options"]["tftp_ips"] == ["10.9.9.9"]
      and s["dhcp"]["options"]["lease"] == 3600, s["dhcp"])
t.on_frame(offer("192.168.0.1", yiaddr="192.168.0.50"))
s = t.snapshot()
check("a second DHCP server is red", s["verdict"] == "bad" and any("2 DHCP servers" in f[1] for f in s["findings"]), s["findings"])
check("and an event says so", any("second DHCP server" in e["text"] for e in s["events"]))

# ---------- a new port forgets the last one ----------
t.on_link(False); t.on_link(True, 100, "half")
s = t.snapshot()
check("new port forgets the switch and servers", not s["switch"]["heard"] and s["dhcp"]["servers"] == [] and s["link"]["drops"] == 1)
check("half duplex is amber", ("warn", "Half duplex") in s["findings"], s["findings"])

# ---------- 802.1X ----------
t2 = Tester(clock=Clock()); t2.on_link(True, 1000, "full")
req = N.PAE_DST + N.mac_bytes(SWITCH) + b"\x88\x8e" + bytes([2, 0, 0, 5, 1, 1, 0, 5, 1])
t2.on_frame(N.pad60(req))
check("802.1X with no address is red", ("bad", "802.1X: needs a login") in t2.snapshot()["findings"])

# ---------- other findings ----------
base = t.snapshot()
def with_(**kw):
    s = json.loads(json.dumps(base, default=str))
    for path, value in kw.items():
        a, b = path.split("__")
        s[a][b] = value
    return findings(s)
check("downshift is amber", any("cable?" in f[1] for f in with_(link__duplex="full", link__downshift=1000, link__speed=100)))
check("slow to pass traffic flags portfast", any("portfast" in f[1] for f in with_(timing__gateway=35.0, link__duplex="full")))
check("no CDP or LLDP after a while", any("No CDP" in f[1] for f in with_(link__age=200, link__duplex="full")))

# ---------- the screen ----------
c = screen.Canvas()
c._px(0, 0, 0xFFFF)
i = (screen.FB_H - 1) * screen.FB_W * 2
check("landscape top-left is the framebuffer's bottom-left pixel, as GL.iNet draws", c.buf[i:i + 2] == b"\xff\xff")
good = Tester(clock=Clock()); good.on_link(True, 1000, "full"); good.on_wan(WAN)
good.on_frame(N.build_cdp(SWITCH, "Texas-CORE", "GigabitEthernet1/0/14"))
for p in range(len(screen.PAGES)):
    for snap in (good.snapshot(), Tester(clock=Clock()).snapshot()):
        screen.draw(c, snap, p)
        check(f"page {screen.PAGES[p]} draws", any(c.buf) and len(c.frame()) == 76 * 284 * 2)
check("short port names", screen.short_port("GigabitEthernet1/0/14") == "Gi1/0/14" and screen.short_port("TenGigabitEthernet1/1/1") == "Te1/1/1")
check("speed text", screen.speed_text({"up": True, "speed": 2500, "duplex": "full"}) == "2G" and screen.speed_text({"up": False}) == "no link")

# ---------- touch: event sequences as the Slate 7's CST816 sends them ----------
E = screen.Touch.EVENT
def ev(code, value, typ=3):
    return E.pack(0, 0, typ, code, value)
def presses(batches):
    """batches: [(seconds since start, bytes)]; returns what Touch.read yields."""
    clock = {"t": 0.0}
    queue = list(batches)
    def chunk():
        if queue and queue[0][0] <= clock["t"]:
            return queue.pop(0)[1]
        return b""
    def idle():
        clock["t"] += 0.05
    return list(screen.Touch().read(chunk, lambda: not queue and clock["t"] > 10,
                                    now=lambda: clock["t"], idle=idle))
tap = [(0.0, ev(0, 25) + ev(1, 105) + ev(0x39, 0)), (0.05, ev(0x39, -1))]
check("tap", presses(tap) == ["tap"])
swipe = [(0.0, ev(0, 28) + ev(1, 211) + ev(0x39, 0))] + [(0.1 + i * 0.01, ev(1, 211 - i * 15) + ev(0x39, 0)) for i in range(11)] + [(0.3, ev(0x39, -1))]
check("swipe towards the strip's start is the previous page", presses(swipe) == ["prev"])
swipe_back = [(0.0, ev(1, 40) + ev(0x39, 0)), (0.1, ev(1, 200) + ev(0x39, 0)), (0.2, ev(0x39, -1))]
check("swipe the other way is the next page", presses(swipe_back) == ["next"])
hold = [(0.0, ev(1, 100) + ev(0x39, 0))] + [(0.01 * i, ev(0x39, 0)) for i in range(1, 250)] + [(2.6, ev(0x39, -1))]
check("hold fires while still holding, and only once", presses(hold) == ["hold"])
check("BTN_TOUCH screens work too", presses([(0.0, ev(0x14A, 1, typ=1)), (0.1, ev(0x14A, 0, typ=1))]) == ["tap"])

# ---------- the backlight ----------
with tempfile.TemporaryDirectory() as d:
    for name, value in (("max_brightness", "11"), ("brightness", "5"), ("bl_power", "1")):
        open(os.path.join(d, name), "w").write(value)
    disp = screen.Display(fb=os.path.join(d, "fb0"), backlight=d)
    check("a blanked backlight is not lit", not disp.lit())
    disp.light(True)
    check("lighting powers the backlight at full brightness", disp.lit() and open(os.path.join(d, "brightness")).read() == "11")

# ---------- the phone page ----------
class FakeService:
    def __init__(self):
        self.tester, self.config, self.page = good, {"screen": "pcc"}, 0
        self.recheck = threading.Event(); self.probed = threading.Event()
    def set_screen(self, mode):
        if mode not in ("pcc", "gl"): raise ValueError(mode)
        self.config["screen"] = mode
    def dhcp_probe(self): self.probed.set()
svc = FakeService()
srv = web.ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(svc))
threading.Thread(target=srv.serve_forever, daemon=True).start()
base_url = f"http://127.0.0.1:{srv.server_address[1]}"
def post(path, body):
    req = urllib.request.Request(base_url + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, None
html = urllib.request.urlopen(base_url + "/").read().decode()
check("page served", "PorkChopCheck" in html and "api/state" in html)
state = json.loads(urllib.request.urlopen(base_url + "/api/state").read())
check("state served", state["switch"]["port"] == "GigabitEthernet1/0/14" and state["screen"] == "pcc")
check("switch the screen to GL.iNet", post("/api/screen", {"mode": "gl"}) == (200, {"screen": "gl"}) and svc.config["screen"] == "gl")
check("a bad screen mode is refused", post("/api/screen", {"mode": "nope"})[0] == 400)
check("re-check", post("/api/recheck", {})[0] == 200 and svc.recheck.is_set() and svc.probed.wait(2))
srv.shutdown()

# ---------- the service keeps the screen choice ----------
from pcc_router import service as S
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "pcc", "config.json")
    calls = []
    S.run = lambda cmd, timeout=10: calls.append(cmd) or ""
    svc = S.Service(path)
    svc.display.light = lambda on=True: calls.append(["light", on])
    svc.set_screen("gl")
    check("GL.iNet's screen started", ["/etc/init.d/gl_screen", "start"] in calls)
    check("choice saved", json.load(open(path))["screen"] == "gl" and S.Service(path).config["screen"] == "gl")
    svc.set_screen("pcc")
    check("ours stops theirs and lights the screen", ["/etc/init.d/gl_screen", "stop"] in calls and ["light", True] in calls)
    try:
        svc.set_screen("other"); check("bad mode refused", False)
    except ValueError:
        check("bad mode refused", True)

# ---------- tools ----------
from pcc_router import tools as T
import time
req = T.echo_request(0x1234, 7)
check("icmp checksum checks out", T.icmp_checksum(req) == 0)
reply = bytes([0x45]) + bytes(19) + bytes([0, 0]) + req[2:4] + req[4:]
check("echo reply read", T.parse_echo_reply(reply) == (0x1234, 7))
check("echo request is not a reply", T.parse_echo_reply(bytes([0x45]) + bytes(19) + req) is None)

pinger = T.Pinger(lambda: "10.2.1.108", lambda: "10.2.1.254")
now = time.time()
for i in range(40):  # 10 s of pings, two lost around a link event at -5 s
    pinger._add(now - 10 + i * 0.25, None if i in (20, 21) else 1.0 + (i % 3))
pinger.target = "10.2.1.254"
st = pinger.state(30, [{"t": now - 5, "text": "Link down", "sev": "bad"}])
check("ping summary", st["sent"] == 40 and st["lost"] == 2 and st["loss_pct"] == 5.0 and st["avg"] is not None and len(st["cols"]) == 120)
check("event impact on the timeline", st["events"][0]["hit"] and "2 pings lost" in st["events"][0]["impact"], st["events"])

ref = N.Reflector(0, "127.0.0.1"); ref.start()
tick = T.Tick()
tick.start("127.0.0.1", f"127.0.0.1:{ref.sock.getsockname()[1]}", rate=64, secs=1)
time.sleep(2.3)
ts = tick.state()
check("tick test against a real reflector", not ts["running"] and ts["summary"]["n"] >= 40 and ts["summary"]["lost"] <= 2 and ts["grade"] in ("excellent", "good"), ts.get("headline"))
check("tick ratings named", {r["key"] for r in ts["ratings"]} >= {"loss", "burst", "ping"})
ref.stop()

T.N.run_iperf = lambda exe, server, src, reverse, secs, port: ((812e6 if reverse else 640e6), 3, None)
sp = T.Speed(); sp.start("10.2.1.108", "10.2.1.143", 5202, secs=1)
for _ in range(50):
    if not sp.state()["running"]: break
    time.sleep(0.02)
check("speed test both ways", sp.state()["up_mbps"] == 640.0 and sp.state()["down_mbps"] == 812.0 and sp.state()["server"] == "10.2.1.143:5202")

cmds = []
T.run = lambda cmd, timeout=10: cmds.append(cmd) or type("R", (), {"returncode": 1})()
bt = Tester(clock=Clock()); bt.on_link(True, 1000, "full")
bt.on_frame(N.build_cdp(SWITCH, "Texas-CORE", "GigabitEthernet1/0/14"))
blink = T.Blink("eth0", bt)
blink.set(True); time.sleep(0.2)
check("port finder takes the link down and up", ["ip", "link", "set", "eth0", "down"] in cmds and bt.blinking)
bt.on_link(False); bt.on_link(True, 1000, "full")
check("the tester ignores the port finder's bounces", bt.snapshot()["switch"]["heard"] and bt.snapshot()["link"]["drops"] == 0)
blink.set(False); time.sleep(1.7)
check("port finder stops with the link up", not blink.state()["running"] and cmds[-1] == ["ip", "link", "set", "eth0", "up"])

rt = T.ReflectorTool(0); cmds.clear()
rt.ref = type("R", (), {"stop": lambda self: None, "count": 0, "peers": {}})()
rt._firewall(True)
check("reflector opens only its UDP port on the WAN", ["uci", "set", "firewall.pcc_reflector.dest_port=0"] in cmds and ["uci", "set", "firewall.pcc_reflector.src=wan"] in cmds)
rt.set(False)
check("and closes it again", ["uci", "-q", "delete", "firewall.pcc_reflector"] in cmds and rt.ref is None)

with tempfile.TemporaryDirectory() as d:
    log = T.PortLog(d)
    log.auto(good.snapshot())
    check("port logged when CDP names it", [r["port"] for r in log.list()] == ["GigabitEthernet1/0/14"])
    saved = log.save(good.snapshot(), "Row C seat 7")
    check("save with a label", saved["label"] == "Row C seat 7" and os.path.exists(os.path.join(d, "history.csv")))
    log.last_key = None; log.auto(good.snapshot())
    check("auto logging keeps the label", log.list()[0]["label"] == "Row C seat 7" and len(log.list()) == 1)
    check("csv out", log.csv_text().splitlines()[0].startswith("time,switch,port") and "Row C seat 7" in log.csv_text())
    check("log survives a restart", T.PortLog(d).list()[0]["label"] == "Row C seat 7")

    class ToolService(FakeService):
        def __init__(self):
            super().__init__()
            self.pinger, self.tick, self.speed, self.blink, self.log = pinger, T.Tick(), sp, blink, log
            self.reflector = T.ReflectorTool(0)
            self.config.update(ping_target="gateway", tick_server="", iperf_server="", iperf_port=5201)
        def set_option(self, k, v): self.config[k] = v
    tsvc = ToolService()
    tsrv = web.ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(tsvc))
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{tsrv.server_address[1]}"
    tj = json.loads(urllib.request.urlopen(base_url + "/api/tools?span=300").read())
    check("tools state served", tj["ping"]["span"] == 300 and tj["log"][0]["label"] == "Row C seat 7" and tj["options"]["ping_target"] == "gateway")
    check("ping target set", post("/api/ping", {"target": "dns"})[0] == 200 and tsvc.config["ping_target"] == "dns")
    check("tick test needs a server", post("/api/tick", {"server": ""})[0] == 400)
    check("port log save from the page", post("/api/log", {"label": "Stage left"})[1]["label"] == "Stage left")
    check("csv download", "Stage left" in urllib.request.urlopen(base_url + "/ports.csv").read().decode())
    tsrv.shutdown()

print(f"\n{ok} checks passed")
