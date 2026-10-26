"""The router port tester (router/pcc_router): frames in, verdict out, screen pages, the phone page.
Runs on a PC; nothing here needs a router."""
import json, os, socket, struct, sys, tempfile, threading, time, types, urllib.request
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
# the network mode: badge on every page, and the Mode page in each state
NM = {"mode": "router", "switch": "off", "switch_set": True, "state": None, "lan_ip": "192.168.8.1"}
mode_states = [NM, {**NM, "mode": "ap", "switch": "on"}, {**NM, "state": "changing", "want": "ap"},
               {**NM, "state": "error", "error": "Plug a cable into WAN first"}, {**NM, "hold": True}, {**NM, "switch_set": False}, {}]
for m in mode_states:
    snap = good.snapshot(); snap["netmode"] = m
    for p in range(len(screen.PAGES)):
        screen.draw(c, snap, p)
    check(f"mode page draws ({m.get('state') or m.get('mode') or 'unknown'})", any(c.buf))
ap_snap = good.snapshot(); ap_snap["netmode"] = {**NM, "mode": "ap"}
check("phone page address: AP mode shows the address the network gave", screen.phone_address(ap_snap) == "10.2.1.108:8088")
rt_snap = good.snapshot(); rt_snap["netmode"] = NM
check("phone page address: Router mode shows the LAN address", screen.phone_address(rt_snap) == "192.168.8.1:8088")
def badge_px(m):
    snap = good.snapshot(); snap["netmode"] = m
    screen.draw(c, snap, 0)
    i = ((screen.FB_H - 1 - (screen.W - 30)) * screen.FB_W + 12) * 2  # inside the badge, bottom row
    return int.from_bytes(c.buf[i:i + 2], "little")
check("AP badge is blue, Router grey, changing amber",
      (badge_px({**NM, "mode": "ap"}), badge_px(NM), badge_px({**NM, "state": "changing", "want": "ap"})) == (screen.ACC, screen.DIM, screen.WARN))
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
long_hold = [(0.0, ev(1, 100) + ev(0x39, 0))] + [(0.01 * i, ev(0x39, 0)) for i in range(1, 350)] + [(3.6, ev(0x39, -1))]
check("a 3 s hold gives hold, then long, once each", presses(long_hold) == ["hold", "long"])
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
from pcc_router import auth as A
AUTH_DIR = tempfile.mkdtemp()
class FakeService:
    def __init__(self):
        self.tester, self.config, self.page = good, {"screen": "pcc"}, 0
        self.recheck = threading.Event(); self.probed = threading.Event()
        self.auth = A.Auth(AUTH_DIR, owner_check=lambda pw: pw == "owner-pass")
    def set_screen(self, mode):
        if mode not in ("pcc", "gl"): raise ValueError(mode)
        self.config["screen"] = mode
    def dhcp_probe(self): self.probed.set()
    def screen_snap(self):
        snap = self.tester.snapshot(); snap["netmode"] = dict(NM); return snap
    def set_netmode(self, mode):
        if mode not in ("router", "ap"): raise ValueError("mode is router or ap")
        self.netmode_set = mode
svc = FakeService()
srv = web.Server(("127.0.0.1", 0), web.make_handler(svc))
threading.Thread(target=srv.serve_forever, daemon=True).start()
base_url = f"http://127.0.0.1:{srv.server_address[1]}"
COOKIE = {"v": ""}
def call(path, body=None, cookie=None, ctype="application/json"):
    """(status, decoded JSON or text, Set-Cookie value)"""
    headers = {"Cookie": COOKIE["v"] if cookie is None else cookie}
    if body is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(base_url + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            raw, code, sc = r.read(), r.status, r.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        raw, code, sc = e.read(), e.code, e.headers.get("Set-Cookie")
    try:
        data = json.loads(raw)
    except ValueError:
        data = raw.decode(errors="replace")
    return code, data, sc
def post(path, body): return call(path, body)[:2]
def jar(set_cookie): return set_cookie.split(";")[0] if set_cookie else ""
html = call("/", cookie="")[1]
check("page served without a login (it shows the login itself)", "PorkChopCheck" in html and 'id="gate"' in html)
check("hidden tabs really hide", "[hidden] { display: none !important; }" in html and 'id="tab-tools" hidden' in html)
check("state needs a login", call("/api/state", cookie="")[0] == 401)
check("first visit asks for setup", call("/api/auth/me", cookie="")[1] == {"user": None, "setup": True})
check("setup needs the router's admin password", call("/api/auth/setup", {"name": "kt", "password": "longpass1", "owner": "wrong"}, cookie="")[0] == 400)
code, _, sc = call("/api/auth/setup", {"name": "kt", "password": "longpass1", "owner": "owner-pass"}, cookie="")
COOKIE["v"] = jar(sc)
check("setup makes the admin and logs in", code == 200 and "HttpOnly" in sc and "SameSite=Strict" in sc and call("/api/auth/me")[1]["user"] == {"name": "kt", "role": "admin"})
check("setup only once", call("/api/auth/setup", {"name": "x", "password": "longpass1", "owner": "owner-pass"}, cookie="")[0] == 400)
check("a form post from another site is refused", call("/api/screen", {"mode": "gl"}, ctype="text/plain")[0] == 415)
state = call("/api/state")[1]
check("state served", state["switch"]["port"] == "GigabitEthernet1/0/14" and state["screen"] == "pcc")
check("switch the screen to GL.iNet", post("/api/screen", {"mode": "gl"}) == (200, {"screen": "gl"}) and svc.config["screen"] == "gl")
check("a bad screen mode is refused", post("/api/screen", {"mode": "nope"})[0] == 400)
check("network mode shown on the page", state["netmode"]["mode"] == "router" and 'id="nmseg"' in html)
check("change the network mode from the page", post("/api/netmode", {"mode": "ap"})[0] == 200 and svc.netmode_set == "ap")
check("a bad network mode is refused", post("/api/netmode", {"mode": "bridge"})[0] == 400)
check("re-check", post("/api/recheck", {})[0] == 200 and svc.recheck.is_set() and svc.probed.wait(2))
check("add a viewer", post("/api/users", {"action": "add", "name": "crew", "password": "crewpass1", "role": "viewer"})[0] == 200)
admin_cookie = COOKIE["v"]
check("wrong password refused", call("/api/auth/login", {"name": "crew", "password": "nope"}, cookie="")[0] == 400)
code, _, sc = call("/api/auth/login", {"name": "crew", "password": "crewpass1"}, cookie="")
COOKIE["v"] = jar(sc)
check("viewer logs in", code == 200 and call("/api/auth/me")[1]["user"]["role"] == "viewer")
check("viewer can look and re-check", call("/api/state")[0] == 200 and post("/api/recheck", {})[0] == 200)
check("viewer can't change things", post("/api/screen", {"mode": "pcc"})[0] == 403 and post("/api/netmode", {"mode": "router"})[0] == 403 and call("/api/users")[0] == 403)
check("log out", call("/api/auth/logout", {})[0] == 200 and call("/api/state")[0] == 401)
COOKIE["v"] = admin_cookie
check("last admin can't be made a viewer", post("/api/users", {"action": "role", "name": "kt", "role": "viewer"})[0] == 400)
srv.shutdown()

# ---------- HTTPS: the certificate, and http and https on one port ----------
import ssl
from pcc_router import tls as TL
with tempfile.TemporaryDirectory() as d:
    t = TL.TLS(d, lambda: ["10.2.1.235"])
    t.ensure()
    info = t.info()
    check("certificate made on first start", t.ctx is not None and "10.2.1.235" in info["names"] and "192.168.8.1" in info["names"] and info["self_signed"])
    late = {"a": []}
    t3 = TL.TLS(os.path.join(d, "late"), lambda: late["a"])
    t3.ensure()
    late["a"] = ["10.2.1.77"]  # DHCP answered after the first start
    t3.cover_addresses(wait=3, step=1, sleep=lambda s: None)
    check("a first-start certificate is remade to name the address DHCP gave", "10.2.1.77" in t3.info()["names"] and not t3.fresh)
    t2 = TL.TLS(d, lambda: ["10.9.9.9"])
    t2.load()
    check("an address it doesn't cover is pointed out", t2.info()["missing"] == ["10.9.9.9"])
    try:
        t.generate("not a name!"); check("bad names refused", False)
    except ValueError:
        check("bad names refused", True)
    other = TL.TLS(os.path.join(d, "other"), lambda: [])
    other.generate("elsewhere")
    cert_a, key_b = t.cert.read_text(), other.key.read_text()
    try:
        t.upload(cert_a, key_b); check("a key that doesn't match is refused", False)
    except ValueError as e:
        check("a key that doesn't match is refused", "match" in str(e))
    try:
        t.upload("hello", key_b); check("not PEM refused", False)
    except ValueError:
        check("not PEM refused", True)
    t.upload(other.cert.read_text(), key_b)
    check("your own certificate and key installed", t.info()["cn"] == "elsewhere")
    class TlsService(FakeService):
        def __init__(self):
            super().__init__(); self.tls = t
    ts = TlsService()
    tsrv = web.Server(("127.0.0.1", 0), web.make_handler(ts), t)
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    port = tsrv.server_address[1]
    import http.client
    hc = http.client.HTTPConnection("127.0.0.1", port, timeout=5); hc.request("GET", "/api/state", headers={"Host": f"router.lan:{port}"})
    r = hc.getresponse()
    check("plain http is sent to https on the same port", r.status == 308 and r.getheader("Location") == f"https://router.lan:{port}/api/state")
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    hs = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ctx); hs.request("GET", "/api/auth/me")
    r = hs.getresponse()
    check("https works on the same port", r.status == 200 and "setup" in json.loads(r.read()))
    hs = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ctx)
    hs.request("POST", "/api/auth/login", body=json.dumps({"name": "kt", "password": "longpass1"}), headers={"Content-Type": "application/json"})
    r = hs.getresponse()
    check("login over https sets a Secure cookie", r.status == 200 and "Secure" in (r.getheader("Set-Cookie") or ""))
    tsrv.shutdown()

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
    # reading the mode and the side switch the way GL.iNet's firmware does
    files = {"/proc/gl-hw-info/switch-button": "gpio35",
             "/sys/kernel/debug/gpio": " gpio34  : in  low  func0\n gpio35  : in  hi   func0 8mA pull up\n"}
    uci = {"glconfig.general.mode": "ap\n", "switch-button.@main[0].func": "netmode\n", "network.lan.ipaddr": "192.168.8.1\n"}
    real_read, real_run = S.read, S.run
    S.read = lambda path, default="": files.get(path, default)
    S.run = lambda cmd, timeout=10: uci.get(cmd[-1], "") if cmd[:2] == ["uci", "-q"] else ""
    S.NETMODE_STATE = os.path.join(d, "none.json")
    nm = svc.read_netmode()
    check("mode and switch read", (nm["mode"], nm["switch"], nm["switch_set"]) == ("ap", "on", True))
    open(S.NETMODE_STATE, "w").write(json.dumps({"state": "changing", "want": "router", "t": time.time() - 500}))
    check("a change stuck for minutes shows as failed", svc.read_netmode()["state"] == "error")
    asked = []
    S.run = lambda cmd, timeout=10: asked.append(cmd) or "{}"
    svc.netmode = {"mode": "ap"}
    import types
    svc.stop = types.SimpleNamespace(is_set=lambda it=iter([False, True]): next(it))  # one pass of the loop (it sleeps 2 s)
    svc.wan_loop()
    check("AP mode reads the router's address from lan", ["ubus", "call", "network.interface.lan", "status"] in asked)
    svc.stop = threading.Event()
    S.read, S.run = real_read, lambda cmd, timeout=10: calls.append(cmd) or ""
    try:
        S.read = lambda path, default="": "0" if path.endswith("carrier") else default
        svc.netmode = {"mode": "router"}
        svc.set_netmode("ap"); check("AP mode needs a cable in WAN", False)
    except ValueError as e:
        check("AP mode needs a cable in WAN", "cable" in str(e))
    S.read = real_read
    svc.set_screen("pcc")
    check("ours stops theirs and lights the screen", ["/etc/init.d/gl_screen", "stop"] in calls and ["light", True] in calls)
    try:
        svc.set_screen("other"); check("bad mode refused", False)
    except ValueError:
        check("bad mode refused", True)

# ---------- tools ----------
from pcc_router import tools as T
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
    tsrv = web.Server(("127.0.0.1", 0), web.make_handler(tsvc))
    COOKIE["v"] = admin_cookie
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{tsrv.server_address[1]}"
    tj = call("/api/tools?span=300")[1]
    check("tools state served", tj["ping"]["span"] == 300 and tj["log"][0]["label"] == "Row C seat 7" and tj["options"]["ping_target"] == "gateway")
    check("ping target set", post("/api/ping", {"target": "dns"})[0] == 200 and tsvc.config["ping_target"] == "dns")
    check("tick test needs a server", post("/api/tick", {"server": ""})[0] == 400)
    check("port log save from the page", post("/api/log", {"label": "Stage left"})[1]["label"] == "Stage left")
    check("csv download", "Stage left" in call("/ports.csv")[1])
    tsrv.shutdown()

# ---------- Wi-Fi name and password ----------
from pcc_router import wifi as WF
MLO = {"ifaces": [{"name": "mld0", "ssid": "GL-MLO", "key": "old-key-123", "hidden": False, "mlo_enable": True, "encryption": "sae-mixed", "mlo_band": ["2g", "5g"], "guest": False}]}
CFG = [{"band": "2G", "device": "wifi0", "channel": "auto", "ifaces": [
          {"name": "wifi2g", "ssid": "GL-2G", "key": "k2-123456", "enabled": True, "hidden": True, "encryption": "psk2", "guest": False},
          {"name": "guest2g", "ssid": "GL-Guest", "enabled": False, "guest": True, "encryption": "psk2"},
          {"name": "iot2g", "ssid": "GL-IoT", "enabled": False, "guest": False, "encryption": "psk2"}]}]
calls = []
def fake_gl(module, func, params=None, timeout=10):
    calls.append((func, params))
    return {"get_mlo_config": MLO, "get_config": CFG}.get(func, {})
if True:
    w = WF.Wifi(call=fake_gl)
    nets = w.networks()
    check("own networks listed, MLO first, no guest or IoT", [n["id"] for n in nets] == ["mld0", "wifi2g"] and nets[1]["hidden"])
    check("passwords never listed", "key" not in json.dumps(nets) and "old-key" not in json.dumps(nets))
    for bad in (("mld0", "", ""), ("mld0", "x" * 33, ""), ("mld0", "ok", "short"), ("nope", "ok", "")):
        try:
            w.change(*bad); check(f"bad input refused {bad}", False)
        except ValueError:
            check(f"bad input refused {bad}", True)
    def settle():
        for _ in range(100):
            if w.state["state"] != "saving": return
            time.sleep(0.02)
    w.change("mld0", "Event-WiFi", ""); settle()
    sent = [p for f, p in calls if f == "set_mlo_config"][-1]
    check("MLO rename keeps its password and bands", sent["ssid"] == "Event-WiFi" and sent["key"] == "old-key-123" and sent["mlo_band"] == ["2g", "5g"] and w.state["state"] == "done")
    w.change("wifi2g", "Event-2G", "brand-new-pass"); settle()
    sent = [p for f, p in calls if f == "set_config"][-1]
    check("2.4 GHz change sends the new password", sent["iface_name"] == "wifi2g" and sent["key"] == "brand-new-pass" and sent["device"] == "wifi0" and sent["hidden"] is True)
    w.change("mld0", hidden=True); settle()
    sent = [p for f, p in calls if f == "set_mlo_config"][-1]
    check("hide a network: keeps its name and password", sent["hidden"] is True and sent["ssid"] == "GL-MLO" and sent["key"] == "old-key-123")
    w.change("wifi2g", hidden=False); settle()
    sent = [p for f, p in calls if f == "set_config"][-1]
    check("make a hidden network visible", sent["hidden"] is False and sent["ssid"] == "GL-2G")
    # the phone page: admins only
    class WifiService(FakeService):
        def __init__(self):
            super().__init__(); self.wifi = WF.Wifi(call=fake_gl)
    wsvc = WifiService()
    wsrv = web.Server(("127.0.0.1", 0), web.make_handler(wsvc))
    threading.Thread(target=wsrv.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{wsrv.server_address[1]}"
    COOKIE["v"] = admin_cookie
    wj = call("/api/wifi")[1]
    check("Wi-Fi list served without passwords", wj["networks"][0]["ssid"] == "GL-MLO" and "old-key" not in json.dumps(wj))
    check("Wi-Fi save from the page", post("/api/wifi", {"id": "wifi2g", "ssid": "Page-2G"})[0] == 200)
    for _ in range(100):
        if wsvc.wifi.state["state"] != "saving": break
        time.sleep(0.02)
    check("visibility button from the page", post("/api/wifi", {"id": "mld0", "hidden": True})[0] == 200 and [p for f, p in calls if f == "set_mlo_config"][-1]["hidden"] is True)
    COOKIE["v"] = jar(call("/api/auth/login", {"name": "crew", "password": "crewpass1"}, cookie="")[2])
    check("viewers can't change Wi-Fi", post("/api/wifi", {"id": "wifi2g", "ssid": "Nope"})[0] == 403)
    wsrv.shutdown()

# ---------- the Deck: Probe Deck's pages on the router ----------
from pcc_router import deckhost as D
class DeckSvc:
    def __init__(self):
        self.tester, self.iface, self.netmode = good, "eth0", {"mode": "router"}
pr = D.Probe(DeckSvc(), tempfile.mkdtemp())
check("the probe shim: address, prefix, broadcast, gateway", pr.net["ip"] == "10.2.1.108" and pr.net["broadcast"] == "10.2.1.255" and pr.net["gateway"] == "10.2.1.254")
check("the probe shim: the switch port", pr.neighbor == {"port": "GigabitEthernet1/0/14", "switch": "Texas-CORE"})
check("router mode tests on the WAN port", pr.l3() == "eth0" and pr.watch.iface == "eth0")
pr.s.netmode = {"mode": "ap"}
check("Access point mode: the address is on the LAN bridge", pr.l3() == "br-lan")
dk = D.Deck.__new__(D.Deck)
check("Deck files: the page, page scripts and the map only", dk.file("index.html")[0] and dk.file("web/stats.js")[0] and dk.file("vendor/us-map.json")[0]
      and dk.file("../deckhost.py") == (None, None) and dk.file("web/../../auth.py") == (None, None) and dk.file("appbase.py") == (None, None))
html_deck = dk.file("index.html")[0].decode()
check("Deck page has every view and its scripts", all(f'id="v-{v}"' in html_deck for v in ("mtr", "hosts", "mdns", "mcast", "cache", "speed", "wake", "stats", "ts"))
      and all(f'/deck/web/{v}.js' in html_deck for v in ("mtr", "hosts", "mdns", "mcast", "cache", "speed", "stats")))
check("Deck speed page has only the internet test", "LAN speed test" not in html_deck and 'id="f-inet"' in html_deck)
class FakeDeck:
    def __init__(self): self.posts = []
    def file(self, rel): return dk.file(rel)
    def state(self, user): return {"name": "r", "user": user}
    def app_get(self, name, sub, arg, q, user):
        if name != "stats": raise LookupError(name)
        return {"cpu": 5}
    def app_post(self, name, action, body, user):
        if user["role"] != "admin" and action != "peek": raise PermissionError("Admins only")
        self.posts.append((name, action)); return {"ok": 1}
    def wol(self, action, body): self.posts.append(("wol", action)); return {}
    def settings(self, body): return {}
class DeckService(FakeService):
    def __init__(self):
        super().__init__(); self.deck = FakeDeck()
dsvc = DeckService()
dsrv = web.Server(("127.0.0.1", 0), web.make_handler(dsvc))
threading.Thread(target=dsrv.serve_forever, daemon=True).start()
base_url = f"http://127.0.0.1:{dsrv.server_address[1]}"
check("the Deck page loads without a login (it checks itself)", "PorkChopCheck Deck" in call("/deck", cookie="")[1])
check("Deck data needs a login", call("/api/deck/state", cookie="")[0] == 401 and call("/api/x/stats", cookie="")[0] == 401)
COOKIE["v"] = admin_cookie
check("Deck tool data", call("/api/x/stats")[1] == {"cpu": 5} and call("/api/x/nope")[0] == 404)
check("Deck tool action", post("/api/x/hosts/scan", {})[0] == 200 and ("hosts", "scan") in dsvc.deck.posts)
check("Wake from the Deck", post("/api/wol/wake", {"mac": "02:00:00:00:00:01"})[0] == 200 and ("wol", "wake") in dsvc.deck.posts)
COOKIE["v"] = jar(call("/api/auth/login", {"name": "crew", "password": "crewpass1"}, cookie="")[2])
check("viewers can't start Deck tools", post("/api/x/hosts/scan", {})[0] == 403 and post("/api/wol/wake", {})[0] == 403)
check("viewers can look at Deck tools", call("/api/x/stats")[0] == 200)
dsrv.shutdown()

# ---------- Send to GXL ----------
from pcc_router import gxl as G
import io
class GxlSvc:
    def __init__(self):
        self.config = {}
        self.log = types.SimpleNamespace(list=lambda: [
            {"label": "A1", "switch": "sw-a", "port": "Gi0/1", "vlan": "10", "speed": "1000", "verdict": "good", "findings": "Port looks good"},
            {"label": "", "switch": "sw-a", "port": "Gi0/2", "verdict": "good", "findings": ""},
            {"label": "A2", "switch": "sw-a", "port": "Gi0/3", "vlan": "10", "speed": "100", "verdict": "warn", "findings": "Link 100M; Slow"}])
    def set_option(self, k, v): self.config[k] = v
sent = {}
class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): pass
def opener(req, timeout=10):
    sent["url"], sent["auth"], sent["body"] = req.full_url, req.headers.get("Authorization"), json.loads(req.data)
    return Resp(json.dumps({"updated": ["A1"], "unknown": ["A2"]}).encode())
gs = GxlSvc(); g = G.Gxl(gs, opener)
try:
    g.send(); check("GXL needs its address and key first", False)
except ValueError:
    check("GXL needs its address and key first", True)
try:
    g.settings({"url": "not a url"}); check("bad GXL address refused", False)
except ValueError:
    check("bad GXL address refused", True)
g.settings({"url": "http://10.2.1.143:8000/", "key": "event-key-1234"})
check("the key is never shown back", "event-key" not in json.dumps(g.state()) and g.state()["key_set"])
r = g.send()
recs = sent["body"]["records"]
check("only labelled rows go to GXL, graded the way GXL reads them", [x["label"] for x in recs] == ["A1", "A2"] and recs[0]["level"] == "good" and recs[0]["why"] == []
      and recs[1]["level"] == "check" and recs[1]["why"] == ["Link 100M", "Slow"])
check("sent to GXL's survey with the agent key", sent["url"] == "http://10.2.1.143:8000/agent/survey" and sent["auth"] == "Agent event-key-1234" and r["updated"] == 1 and r["unknown"] == ["A2"])

print(f"\n{ok} checks passed")
