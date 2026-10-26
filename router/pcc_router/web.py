"""The phone page: open https://192.168.8.1:8088 (or the address the screen's Mode page shows).
Everything the tester knows, refreshed every 2 seconds, behind a login.

One port speaks both: a browser that starts TLS gets HTTPS, and plain http:// is sent to https://.
The certificate is made on the router (tls.py) and can be replaced from Settings. Logins and users
work like Probe Deck's (auth.py): admins change things, viewers look.

Open without a login:
GET /                 the page (it shows the login itself)
GET /api/auth/me      who is logged in, and whether the first admin still has to be made
POST /api/auth/login {"name", "password"}, /api/auth/setup {"name", "password", "owner"}, /api/auth/logout

Logged in:
GET /api/state, /api/tools?span=30, /api/wifi, /api/tls, /cert.pem, /ports.csv
POST /api/recheck, /api/auth/password {"current", "new"}   (viewers too)
Admins only:
POST /api/screen {"mode": "pcc" | "gl"}, /api/netmode {"mode": "router" | "ap"},
     /api/wifi {"id", "ssid", "key"}, /api/ping, /api/tick, /api/reflector, /api/speed, /api/blink, /api/log,
     /api/tls/generate {"names", "days"}, /api/tls/upload {"cert", "key"},
GET /api/users; POST /api/users {"action": "add" | "role" | "password" | "delete", "name", "role", "password"}

In Router mode GL.iNet's firewall keeps this port closed on the WAN side, so only the router's own
Wi-Fi and LAN reach it. In Access point mode there is no WAN side: the page is open to the network
on WAN, which is why it has a login.
"""

import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

OPEN_GET = ("/", "/index.html", "/api/auth/me")
OPEN_POST = ("/api/auth/login", "/api/auth/setup", "/api/auth/logout")
VIEWER_POST = ("/api/recheck", "/api/auth/password")
MAX_BODY = 256 * 1024


def tools_state(service, span):
    return {
        "ping": service.pinger.state(span, service.tester.snapshot()["events"]),
        "tick": service.tick.state(), "reflector": service.reflector.state(), "speed": service.speed.state(),
        "blink": service.blink.state(), "log": service.log.list(),
        "options": {k: service.config.get(k) for k in ("ping_target", "tick_server", "iperf_server", "iperf_port")},
    }  # fmt: skip


def make_handler(service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PorkChopCheck-router"
        timeout = 60

        def log_message(self, *args):  # quiet: procd keeps the log small
            pass

        @property
        def is_tls(self):
            return isinstance(self.connection, ssl.SSLSocket)

        def _send(self, code, body, kind="application/json", headers=()):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj, headers=()):
            self._send(code, json.dumps(obj, default=str), headers=headers)

        def _to_https(self):
            """Plain http:// while HTTPS works: send the browser to https:// on the same port."""
            tls = getattr(service, "tls", None)
            if self.is_tls or not tls or not tls.ctx:
                return False
            host = self.headers.get("Host") or f"{self.server.server_address[0]}:{self.server.server_address[1]}"
            body = b"Moved to HTTPS"
            self.send_response(308)
            self.send_header("Location", f"https://{host}{self.path}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return True

        def _user(self):
            return service.auth.user(self.headers)

        def do_GET(self):
            if self._to_https():
                return
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(200, PAGE, "text/html; charset=utf-8")
            user = self._user()
            if url.path == "/api/auth/me":
                return self._json(200, {"user": user, "setup": service.auth.needs_setup()})
            if not user:
                return self._json(401, {"error": "log in first", "login": True})
            if url.path == "/api/tools":
                try:
                    span = int(parse_qs(url.query).get("span", ["30"])[0])
                except ValueError:
                    span = 30
                return self._json(200, tools_state(service, max(10, min(span, 1800))))
            if url.path == "/api/wifi":
                try:
                    nets, err = service.wifi.networks(), None
                except ValueError as e:
                    nets, err = [], str(e)
                return self._json(200, {"networks": nets, "error": err, "save": service.wifi.state})
            if url.path == "/api/tls":
                return self._json(200, service.tls.info() or {"error": service.tls.error or "no certificate"})
            if url.path == "/cert.pem":
                try:
                    data = service.tls.cert.read_bytes()
                except OSError:
                    return self._json(404, {"error": "no certificate"})
                return self._send(200, data, "application/x-pem-file", [("Content-Disposition", 'attachment; filename="pcc-router.pem"')])
            if url.path == "/api/users":
                if user["role"] != "admin":
                    return self._json(403, {"error": "Admins only"})
                return self._json(200, {"users": service.auth.listing(), "me": user["name"]})
            if url.path == "/ports.csv":
                return self._send(200, service.log.csv_text().encode(), "text/csv", [("Content-Disposition", 'attachment; filename="ports.csv"')])
            if url.path == "/api/state":
                snap = service.screen_snap()
                snap["screen"] = service.config["screen"]
                snap["page"] = service.page
                return self._json(200, snap)
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if self._to_https():
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "too big"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._json(400, {"error": "not JSON"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "not JSON"})
            # forms on other sites can't send JSON without asking first, so this stops them posting here
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                return self._json(415, {"error": "send JSON"})
            ip = self.client_address[0]
            try:
                if self.path in OPEN_POST:
                    return self._auth(body, ip)
                user = self._user()
                if not user:
                    return self._json(401, {"error": "log in first", "login": True})
                if self.path not in VIEWER_POST and user["role"] != "admin":
                    return self._json(403, {"error": "Admins only: you're logged in as a viewer"})
                return self._post(body, user)
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            except (ValueError, OSError) as e:
                return self._json(400, {"error": str(e) or "could not do that"})

        def _auth(self, body, ip):
            au = service.auth
            if self.path == "/api/auth/logout":
                au.logout(self.headers)
                return self._json(200, {"ok": True}, [("Set-Cookie", au.cookie(None, self.is_tls))])
            if self.path == "/api/auth/setup":
                tok = au.setup(body.get("name"), body.get("password"), body.get("owner"), ip)
            else:
                tok = au.login(body.get("name"), body.get("password"), ip)
            return self._json(200, {"ok": True}, [("Set-Cookie", au.cookie(tok, self.is_tls))])

        def _post(self, body, user):
            if self.path == "/api/recheck":
                threading.Thread(target=service.dhcp_probe, daemon=True).start()
                service.recheck.set()
                return self._json(200, {"ok": True})
            if self.path == "/api/auth/password":
                service.auth.change_own(user["name"], body.get("current"), body.get("new"), service.auth.token(self.headers))
                return self._json(200, {"ok": True})
            if self.path == "/api/screen":
                try:
                    service.set_screen(body.get("mode"))
                except ValueError:
                    return self._json(400, {"error": "mode is pcc or gl"})
                return self._json(200, {"screen": service.config["screen"]})
            if self.path == "/api/netmode":
                service.set_netmode(body.get("mode"))
                return self._json(200, {"ok": True})
            if self.path == "/api/wifi":
                service.wifi.change(str(body.get("id") or ""), body.get("ssid"), str(body.get("key") or ""))
                return self._json(200, {"ok": True})
            if self.path == "/api/tls/generate":
                service.tls.generate(body.get("names") or ", ".join(service.tls.default_names()), body.get("days") or 3650)
                return self._json(200, service.tls.info() or {})
            if self.path == "/api/tls/upload":
                service.tls.upload(body.get("cert"), body.get("key"))
                return self._json(200, service.tls.info() or {})
            if self.path == "/api/users":
                au, act, name = service.auth, body.get("action"), str(body.get("name") or "")
                if act == "add":
                    au.add(name, body.get("role") or "viewer", body.get("password"))
                elif act == "role":
                    au.update(name, role=body.get("role"))
                elif act == "password":
                    au.update(name, pw=body.get("password"))
                elif act == "delete":
                    au.delete(name, user["name"])
                else:
                    raise ValueError("Unknown action")
                return self._json(200, {"users": au.listing(), "me": user["name"]})
            return self._tool(body)

        def _tool(self, body):
            src = service.tester.wan.get("address")
            if self.path == "/api/ping":
                service.set_option("ping_target", str(body.get("target") or "gateway").strip()[:120])
            elif self.path == "/api/tick":
                if body.get("action") == "stop":
                    service.tick.stop()
                else:
                    server = str(body.get("server") or "").strip()
                    if not server:
                        raise ValueError("Enter the reflector's address")
                    if not src:
                        raise ValueError("No address on the WAN yet")
                    service.set_option("tick_server", server)
                    service.tick.start(src, server, int(body.get("rate") or 64), int(body.get("secs") or 30))
            elif self.path == "/api/reflector":
                service.reflector.set(bool(body.get("on")))
            elif self.path == "/api/speed":
                server, port = str(body.get("server") or "").strip(), int(body.get("port") or 5201)
                if not server:
                    raise ValueError("Enter the iperf3 server's address")
                if not src:
                    raise ValueError("No address on the WAN yet")
                service.set_option("iperf_server", server)
                service.set_option("iperf_port", port)
                service.speed.start(src, server, port)
            elif self.path == "/api/blink":
                service.blink.set(bool(body.get("on")))
            elif self.path == "/api/log":
                return self._json(200, service.log.save(service.tester.snapshot(), str(body.get("label") or "")))
            else:
                return self._json(404, {"error": "not found"})
            self._json(200, {"ok": True})

    return Handler


class Server(ThreadingHTTPServer):
    """HTTP and HTTPS on one port: a connection that opens with a TLS handshake (first byte 0x16) is
    wrapped in TLS, anything else is plain HTTP (and gets sent to https:// by the handler)."""

    daemon_threads = True

    def __init__(self, addr, handler, tls=None):
        super().__init__(addr, handler)
        self.tls = tls

    def finish_request(self, request, client_address):
        ctx = self.tls.ctx if self.tls else None
        wrapped = None
        if ctx:
            try:
                request.settimeout(10)
                if request.recv(1, socket.MSG_PEEK) == b"\x16":
                    wrapped = request = ctx.wrap_socket(request, server_side=True)
                request.settimeout(None)
            except (OSError, ssl.SSLError):
                return  # e.g. a browser that hasn't accepted the self-signed certificate yet
        try:
            super().finish_request(request, client_address)
        finally:
            if wrapped:
                try:
                    wrapped.close()
                except OSError:
                    pass


def serve(service, port):
    Server(("0.0.0.0", port), make_handler(service), getattr(service, "tls", None)).serve_forever()


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PorkChopCheck</title>
<style>
:root { --bg:#111110; --panel:#1b1b1a; --well:#141413; --line:rgba(255,255,255,.08); --text:#f0efec; --muted:#898781;
  --good:#3ddc5a; --warn:#fab219; --bad:#ff4d4d; --acc:#5aa9ff; }
* { box-sizing: border-box; }
[hidden] { display: none !important; }  /* main is a flex column, which would otherwise show hidden tabs */
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.4 system-ui, sans-serif; }
header { display:flex; flex-wrap:wrap; align-items:center; gap:8px 10px; padding:12px 14px; background:var(--panel); border-bottom:1px solid var(--line); position:sticky; top:0; }
header b { font-size:17px; }
.spacer { flex:1; }
.grp { display:flex; align-items:center; gap:8px; margin-left:auto; }
.seg { display:flex; border:1px solid var(--line); border-radius:8px; overflow:hidden; }
.seg button { background:none; border:0; color:var(--muted); padding:6px 10px; font:inherit; font-size:13px; }
.seg button.on { background:var(--acc); color:#fff; }
main { padding:12px; display:flex; flex-direction:column; gap:12px; max-width:640px; margin:0 auto; }
.banner { border-radius:10px; padding:14px; font-weight:700; font-size:20px; }
.banner.good { background:color-mix(in srgb, var(--good) 22%, var(--panel)); color:var(--good); }
.banner.warn { background:color-mix(in srgb, var(--warn) 22%, var(--panel)); color:var(--warn); }
.banner.bad { background:color-mix(in srgb, var(--bad) 22%, var(--panel)); color:var(--bad); }
.banner ul { margin:6px 0 0; padding-left:18px; font-size:14px; font-weight:500; color:var(--text); }
section { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px 14px; }
h2 { margin:0 0 8px; font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); }
.big { font:700 30px/1.1 ui-monospace, monospace; }
.rows { display:grid; grid-template-columns:max-content 1fr; gap:4px 14px; }
.k { color:var(--muted); }
.v { font-family:ui-monospace, monospace; overflow-wrap:anywhere; }
.good { color:var(--good); } .warn { color:var(--warn); } .bad { color:var(--bad); } .acc { color:var(--acc); }
.ev { font-size:13px; display:flex; gap:10px; border-top:1px solid var(--line); padding:4px 0; }
.ev .t { color:var(--muted); font-family:ui-monospace, monospace; flex:none; }
button.act { background:var(--acc); color:#fff; border:0; border-radius:8px; padding:9px 14px; font:inherit; }
.sub { color:var(--muted); font-size:12.5px; }
nav.tabs { display:flex; gap:6px; padding:8px 12px 0; max-width:640px; margin:0 auto; }
nav.tabs button { flex:1; background:var(--panel); border:1px solid var(--line); color:var(--muted); padding:8px; border-radius:8px; font:inherit; }
nav.tabs button.on { color:var(--text); border-color:var(--acc); }
.line { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin:6px 0; }
input, select { background:var(--well); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:8px; font:inherit; min-width:0; }
input.grow { flex:1; }
button.key { background:var(--well); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:8px 12px; font:inherit; }
button.key.on { border-color:var(--acc); color:var(--acc); }
canvas { width:100%; height:120px; background:var(--well); border-radius:8px; display:block; }
table { width:100%; border-collapse:collapse; font-size:13px; }
td, th { text-align:left; padding:4px 6px; border-top:1px solid var(--line); }
th { color:var(--muted); font-weight:600; }
.excellent, .good2 { color:var(--good); } .fair { color:var(--warn); } .badg { color:var(--bad); }
.gate { position:fixed; inset:0; background:var(--bg); display:flex; align-items:center; justify-content:center; padding:16px; z-index:10; }
.gate form { width:min(380px,100%); background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:18px; display:flex; flex-direction:column; gap:10px; }
.gate h1 { margin:0 0 4px; font-size:20px; }
.gate input { width:100%; }
.gate label { display:flex; flex-direction:column; gap:4px; font-size:13px; color:var(--muted); }
.who { display:flex; align-items:center; gap:8px; font-size:13px; }
.who a { color:var(--muted); cursor:pointer; text-decoration:underline; }
.role { font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--warn); }
body.viewer .admin-only { display:none !important; }
textarea { width:100%; min-height:90px; background:var(--well); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:8px; font:12px ui-monospace, monospace; }
.ok { color:var(--good); }
</style></head><body>
<div class="gate" id="gate" hidden>
  <form id="gform" autocomplete="on">
    <h1>🐷 PorkChopCheck</h1>
    <div class="sub" id="gintro">Log in to the router's tester.</div>
    <label id="gownl" hidden>Router admin password <input id="gown" type="password" autocomplete="off"><span class="sub">The one for GL.iNet's admin page. It proves you own this router; it isn't stored.</span></label>
    <label>User name <input id="guser" autocomplete="username" autocapitalize="none" spellcheck="false"></label>
    <label>Password <input id="gpass" type="password" autocomplete="current-password"></label>
    <label id="gpass2l" hidden>Password again <input id="gpass2" type="password" autocomplete="new-password"></label>
    <button class="act" type="submit" id="gbtn">Log in</button>
    <div class="sub bad" id="gerr"></div>
  </form>
</div>
<header><b>🐷 PorkChopCheck</b>
  <span class="grp"><span class="admin-only sub">Screen</span>
  <div class="seg admin-only" id="seg"><button data-m="gl">GL.iNet</button><button data-m="pcc">PorkChop</button></div>
  <span class="who"><span id="me"></span><span class="role" id="myrole"></span><a id="logout">Log out</a></span></span>
</header>
<nav class="tabs"><button data-t="port" class="on">Port</button><button data-t="tools">Tools</button><button data-t="settings">Settings</button></nav>
<main id="tab-port">
  <div class="banner" id="banner">Loading…</div>
  <section><h2>Network mode</h2>
    <div class="line"><span class="big" id="nm" style="font-size:22px">…</span><span class="spacer"></span>
      <div class="seg admin-only" id="nmseg"><button data-n="router">Router</button><button data-n="ap">Access point</button></div></div>
    <div class="sub" id="nminfo"></div><div class="sub bad" id="nmerr"></div></section>
  <section><h2>Wi-Fi</h2>
    <div id="wf"><div class="sub">Loading…</div></div>
    <form id="wform" hidden autocomplete="off">
      <div class="sub" id="wfor" style="margin:8px 0 4px"></div>
      <div class="line"><label class="k" for="wssid" style="width:130px">Wi-Fi name</label><input id="wssid" class="grow" maxlength="32" spellcheck="false"></div>
      <div class="line"><label class="k" for="wkey" style="width:130px">New password</label><input id="wkey" class="grow" type="password" maxlength="63" placeholder="leave blank to keep it" autocomplete="new-password"></div>
      <div class="line"><label class="k" style="width:130px"></label><label class="sub"><input type="checkbox" id="wshow"> show password</label></div>
      <div class="line"><button class="act" type="submit" id="wsave">Save</button><button class="key" type="button" id="wcancel">Cancel</button></div>
      <div class="sub bad" id="werr"></div>
    </form>
    <div class="sub" id="wmsg"></div>
    <p class="sub">Changes go through GL.iNet's own Wi-Fi settings, so its admin page shows them too. Saving restarts Wi-Fi: phones on it drop and must join again with the new name or password. Only admins can change them, and current passwords are never shown here.</p>
  </section>
  <section><h2>Switch</h2><div id="sw"></div></section>
  <section><h2>Port</h2><div class="rows" id="port"></div></section>
  <section><h2>DHCP and layer 2</h2><div class="rows" id="l2"></div></section>
  <section><h2>Events</h2><div id="ev"></div></section>
  <div><button class="act" id="re">Re-check now</button> <span class="sub" id="age"></span></div>
  <p class="sub">The router's WAN port is the one being tested. Tap or swipe the router's screen for the next page; hold it to hand the screen back to GL.iNet. On the screen's Mode page, hold 3 s to change the network mode. The side switch changes it too: on = Access point, off = Router.</p>
</main>
<main id="tab-tools" hidden>
  <section><h2>Ping</h2>
    <div class="line"><select id="pt"><option value="gateway">Gateway</option><option value="dns">DNS server</option><option value="internet">Internet (1.1.1.1)</option><option value="custom">Custom…</option></select>
      <input id="ptc" class="grow" placeholder="address or name" hidden><button class="key" id="ptgo" hidden>Ping</button></div>
    <div class="line" id="spans"><button class="key on" data-s="30">30 s</button><button class="key" data-s="300">5 min</button><button class="key" data-s="1800">30 min</button></div>
    <canvas id="graph" width="600" height="120"></canvas>
    <div class="sub" id="psum" style="margin-top:6px"></div>
    <div id="pev"></div>
  </section>
  <section><h2>Tick test (game-rate UDP)</h2>
    <div class="line"><input id="ts" class="grow" placeholder="reflector address (host or host:port)">
      <select id="tr"><option>64</option><option>128</option></select><select id="td"><option value="30">30 s</option><option value="60">1 min</option><option value="120">2 min</option></select>
      <button class="act" id="tgo">Start</button></div>
    <div id="tres"></div>
    <p class="sub">The far end runs a reflector: <span class="v">porkchopcheck --reflector</span> on the game server, or another router with Reflector on below.</p>
  </section>
  <section><h2>Reflector</h2><div class="line"><button class="key" id="rgo">Off</button><span class="sub" id="rinfo"></span></div>
    <p class="sub">Answers tick tests on UDP 27777 through the WAN (its firewall is opened for that port only while this is on).</p></section>
  <section><h2>Speed test (iperf3)</h2>
    <div class="line"><input id="ss" class="grow" placeholder="iperf3 server address"><input id="sp" style="width:90px" placeholder="5201"><button class="act" id="sgo">Run</button></div>
    <div id="sres" class="rows"></div></section>
  <section><h2>Port finder</h2><div class="line"><button class="key" id="bgo">Start</button><span class="sub" id="binfo"></span></div>
    <p class="sub">Bounces the WAN link (down 1.5 s, then up for 2 s once it is back: a flash every 6 to 7 s) so the switch port's LED blinks. Walk the switch and look for it. The router's own internet drops while it runs.</p></section>
  <section><h2>Port log</h2>
    <div class="line"><input id="lab" class="grow" placeholder="label, e.g. Row C seat 7"><button class="act" id="lgo">Save</button><a class="sub" href="/ports.csv">Download CSV</a></div>
    <table id="log"></table></section>
</main>
<main id="tab-settings" hidden>
  <section><h2>HTTPS certificate</h2>
    <div class="rows" id="tlsinfo"></div>
    <div class="sub warn" id="tlswarn" style="margin-top:6px"></div>
    <p class="sub"><a href="/cert.pem" style="color:var(--acc)">Download the certificate</a> and install it on a phone or PC to trust this router and stop the browser warning.</p>
    <div class="admin-only">
      <h2 style="margin-top:14px">Make a new one</h2>
      <div class="line"><input id="tlsnames" class="grow" placeholder="names and addresses, comma separated" spellcheck="false"></div>
      <div class="line"><button class="act" id="tlsgen">Make certificate</button><span class="sub">Self-signed, good for 10 years. Browsers warn once for each new one.</span></div>
      <h2 style="margin-top:14px">Use your own</h2>
      <div class="sub">For example one signed by your own CA. PEM text: the certificate (with its chain after it, if any), and its private key without a password.</div>
      <textarea id="tlscert" placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false"></textarea>
      <textarea id="tlskey" placeholder="-----BEGIN PRIVATE KEY-----" spellcheck="false" style="margin-top:6px"></textarea>
      <div class="line"><button class="act" id="tlsup">Upload</button><span class="sub">or load files:</span><input type="file" id="tlsfile" multiple accept=".pem,.crt,.cer,.key,.txt"></div>
    </div>
    <div class="sub" id="tlsmsg"></div>
  </section>
  <section class="admin-only"><h2>Users</h2>
    <table id="users"></table>
    <h2 style="margin-top:14px">Add someone</h2>
    <div class="line"><input id="unew" placeholder="user name" autocapitalize="none" spellcheck="false" style="flex:1 1 130px"><input id="upw" type="password" placeholder="password (8+)" autocomplete="new-password" style="flex:1 1 130px">
      <select id="urole"><option value="viewer">Viewer</option><option value="admin">Admin</option></select><button class="act" id="uadd">Add</button></div>
    <div class="sub">Admins change things; viewers look and can re-check the port. Locked out? Over SSH: <span class="v">PYTHONPATH=/usr/share/pcc-router python3 -m pcc_router.auth passwd NAME</span></div>
    <div class="sub" id="umsg"></div>
  </section>
  <section><h2>My password</h2>
    <div class="line"><input id="mycur" type="password" placeholder="current password" autocomplete="current-password" style="flex:1 1 140px"><input id="mynew" type="password" placeholder="new password (8+)" autocomplete="new-password" style="flex:1 1 140px"><button class="act" id="mysave">Change</button></div>
    <div class="sub" id="mymsg"></div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const rows = list => list.map(([k, v, c]) => `<span class="k">${esc(k)}</span><span class="v ${c || ''}">${esc(v ?? '-')}</span>`).join('');
const speed = l => !l.up ? 'no link' : (l.speed >= 1000 ? l.speed / 1000 + ' Gbps' : l.speed + ' Mbps') + ' ' + (l.duplex || '');
const chk = c => !c ? ['…', ''] : c.ok ? [(c.ms != null ? c.ms.toFixed(1) + ' ms' : 'ok'), 'good'] : ['no answer', 'bad'];
const ago = t => { const s = Math.round(Date.now() / 1000 - t); return s < 60 ? s + ' s ago' : Math.round(s / 60) + ' min ago'; };
let screen = null;

const MODES = {router: 'Router', ap: 'Access point'};
let netmode = null;
function renderMode(m) {
  netmode = m;
  const changing = m.state === 'changing';
  $('nm').textContent = changing ? 'Changing to ' + (MODES[m.want] || m.want) + '…' : (MODES[m.mode] || m.mode || '?');
  $('nm').className = 'big ' + (changing ? 'warn' : m.mode === 'ap' ? 'acc' : '');
  document.querySelectorAll('#nmseg button').forEach(b => { b.classList.toggle('on', b.dataset.n === m.mode); b.disabled = changing; });
  const sw = !m.switch_set ? 'The side switch is not set to change the mode.' : m.switch ? `Side switch: ${m.switch} (${m.switch === 'on' ? 'Access point' : 'Router'})${(m.switch === 'on') !== (m.mode === 'ap') && !changing ? ', the other way from the mode now: the next flip changes it' : ''}.` : '';
  $('nminfo').textContent = (changing ? 'Wi-Fi drops for about a minute. In Access point mode this page moves to the address the network gives the router: the screen\'s Mode page shows it. ' : '') + sw;
  $('nmerr').textContent = m.state === 'error' && m.error ? m.error : '';
}
document.querySelectorAll('#nmseg button').forEach(b => b.onclick = async () => {
  if (!netmode || b.dataset.n === netmode.mode) return;
  const ap = b.dataset.n === 'ap';
  if (!confirm(ap ? 'Switch to Access point mode?\n\nThe WAN port joins the LAN, the router stops handing out addresses, and it takes an address from the network on WAN. 192.168.8.1 stops working: this page moves to that new address (shown on the router\'s screen). Wi-Fi drops for about a minute.'
                  : 'Switch to Router mode?\n\nThe router hands out 192.168.8.x addresses again and this page goes back to https://192.168.8.1:8088. Wi-Fi drops for about a minute.')) return;
  const r = await post('/api/netmode', {mode: b.dataset.n});
  if (!r.ok) { $('nmerr').textContent = (await r.json().catch(() => ({}))).error || 'Could not start'; return; }
  load();
});

// ---------- login ----------
let ME = null, setupMode = false;
const realFetch = window.fetch.bind(window);
window.fetch = async (...a) => { const r = await realFetch(...a); if (r.status === 401 && !String(a[0]).startsWith('/api/auth/')) showGate(); return r; };
async function whoami() {
  const j = await (await realFetch('/api/auth/me', {cache: 'no-store'})).json();
  ME = j.user; setupMode = j.setup;
  if (!ME) { showGate(); return false; }
  $('gate').hidden = true;
  $('me').textContent = ME.name; $('myrole').textContent = ME.role === 'admin' ? '' : 'viewer';
  document.body.classList.toggle('viewer', ME.role !== 'admin');
  return true;
}
function showGate() {
  ME = null;
  $('gate').hidden = false;
  $('gintro').textContent = setupMode ? 'First time here: make the admin account. You need the router\'s admin password to prove it\'s yours.' : 'Log in to the router\'s tester.';
  $('gownl').hidden = $('gpass2l').hidden = !setupMode;
  $('gbtn').textContent = setupMode ? 'Make admin and log in' : 'Log in';
  $('gpass').autocomplete = setupMode ? 'new-password' : 'current-password';
  (setupMode ? $('gown') : $('guser')).focus();
}
$('gform').onsubmit = async e => {
  e.preventDefault(); $('gerr').textContent = '';
  if (setupMode && $('gpass').value !== $('gpass2').value) { $('gerr').textContent = 'The passwords don\'t match.'; return; }
  const body = {name: $('guser').value, password: $('gpass').value};
  if (setupMode) body.owner = $('gown').value;
  $('gbtn').disabled = true;
  try {
    const r = await realFetch(setupMode ? '/api/auth/setup' : '/api/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('gerr').textContent = j.error || 'Could not log in'; return; }
    $('gpass').value = $('gpass2').value = $('gown').value = '';
    if (await whoami()) { load(); loadWifi(); }
  } finally { $('gbtn').disabled = false; }
};
$('logout').onclick = async () => { await post('/api/auth/logout'); setupMode = false; showGate(); };

// ---------- settings ----------
const fmtDate = t => new Date(t * 1000).toLocaleDateString([], {year: 'numeric', month: 'short', day: 'numeric'});
async function loadSettings() {
  const t = await (await fetch('/api/tls')).json().catch(() => ({}));
  $('tlsinfo').innerHTML = t.sha256 ? rows([['Names', (t.names || []).join(', ')], ['Issued by', t.self_signed ? 'itself (self-signed)' : t.issuer],
    ['Valid', `${fmtDate(t.from)} to ${fmtDate(t.to)}`, t.to - t.now < 30 * 86400 ? 'warn' : ''], ['Key', t.key], ['SHA-256', t.sha256]]) : `<span class="bad">${esc(t.error || 'No certificate')}</span>`;
  $('tlswarn').textContent = (t.missing || []).length ? `It doesn't cover ${t.missing.join(', ')}: make a new one (the names below include it) or the browser will name-check it and complain.` : '';
  if (!$('tlsnames').value) $('tlsnames').value = t.suggest || '';
  if (ME && ME.role === 'admin') {
    const u = await (await fetch('/api/users')).json().catch(() => ({users: []}));
    renderUsers(u);
  }
}
function renderUsers(u) {
  $('users').innerHTML = '<tr><th>User</th><th>Role</th><th>Last login</th><th></th></tr>' + (u.users || []).map(x => `<tr><td>${esc(x.name)}${x.name === u.me ? ' <span class="sub">(you)</span>' : ''}</td>
    <td><select data-role="${esc(x.name)}"><option value="admin"${x.role === 'admin' ? ' selected' : ''}>Admin</option><option value="viewer"${x.role === 'viewer' ? ' selected' : ''}>Viewer</option></select></td>
    <td class="sub">${x.last ? fmtDate(x.last) : '-'}</td>
    <td><button class="key" data-pw="${esc(x.name)}">Password</button>${x.name === u.me ? '' : ` <button class="key" data-del="${esc(x.name)}">Delete</button>`}</td></tr>`).join('');
}
async function users(body, msg) {
  const r = await post('/api/users', body), j = await r.json().catch(() => ({}));
  $('umsg').className = 'sub ' + (r.ok ? 'ok' : 'bad'); $('umsg').textContent = r.ok ? msg : (j.error || 'Not done');
  if (r.ok) renderUsers(j); else loadSettings();
  return r.ok;
}
$('users').addEventListener('change', e => { const s = e.target.closest('[data-role]'); if (s) users({action: 'role', name: s.dataset.role, role: s.value}, `${s.dataset.role} is now ${s.value === 'admin' ? 'an admin' : 'a viewer'}.`); });
$('users').addEventListener('click', e => {
  const p = e.target.closest('[data-pw]'), d = e.target.closest('[data-del]');
  if (p) { const pw = prompt(`New password for ${p.dataset.pw} (8 or more characters). They log in again with it.`); if (pw) users({action: 'password', name: p.dataset.pw, password: pw}, 'Password set.'); }
  if (d && confirm(`Delete ${d.dataset.del}?`)) users({action: 'delete', name: d.dataset.del}, `${d.dataset.del} deleted.`);
});
$('uadd').onclick = async () => { if (await users({action: 'add', name: $('unew').value, password: $('upw').value, role: $('urole').value}, `${$('unew').value} added.`)) { $('unew').value = $('upw').value = ''; } };
$('mysave').onclick = async () => {
  const r = await post('/api/auth/password', {current: $('mycur').value, new: $('mynew').value}), j = await r.json().catch(() => ({}));
  $('mymsg').className = 'sub ' + (r.ok ? 'ok' : 'bad'); $('mymsg').textContent = r.ok ? 'Changed. Your other browsers are logged out.' : (j.error || 'Not changed');
  if (r.ok) $('mycur').value = $('mynew').value = '';
};
async function tlsDo(url, body, okMsg) {
  $('tlsmsg').className = 'sub'; $('tlsmsg').textContent = 'Working…';
  const r = await post(url, body), j = await r.json().catch(() => ({}));
  $('tlsmsg').className = 'sub ' + (r.ok ? 'ok' : 'bad'); $('tlsmsg').textContent = r.ok ? okMsg : (j.error || 'Not done');
  if (r.ok) { $('tlsnames').value = ''; loadSettings(); }
}
$('tlsgen').onclick = () => { if (confirm('Make a new certificate? The browser will warn once more, and devices that trusted the old one need the new one.')) tlsDo('/api/tls/generate', {names: $('tlsnames').value}, 'New certificate in use. Reload the page and accept it.'); };
$('tlsup').onclick = () => tlsDo('/api/tls/upload', {cert: $('tlscert').value, key: $('tlskey').value}, 'Your certificate is in use. Reload the page.');
$('tlsfile').onchange = async e => {
  for (const f of e.target.files) {
    const t = await f.text();
    if (/PRIVATE KEY-----/.test(t)) $('tlskey').value = t; else if (/BEGIN CERTIFICATE/.test(t)) $('tlscert').value = ($('tlscert').value ? $('tlscert').value.trim() + '\n' : '') + t;
  }
};

let wnets = [], wedit = null;
async function loadWifi() {
  try {
    const j = await (await fetch('/api/wifi')).json();
    wnets = j.networks || [];
    $('wf').innerHTML = j.error ? `<div class="sub bad">${esc(j.error)}</div>` : wnets.map(n => `<div class="line" style="justify-content:space-between;border-top:1px solid var(--line);padding-top:6px">
      <span><span class="v" style="font-weight:700">${esc(n.ssid)}</span><br><span class="sub">${esc(n.label)} · ${n.on ? (n.hidden ? 'on, hidden' : 'on, visible') : 'off'}${n.secured ? '' : ' · open, no password'}</span></span>
      <button class="key admin-only" type="button" data-w="${esc(n.id)}">Change</button></div>`).join('') || '<div class="sub">No networks found.</div>';
    const sv = j.save || {};
    $('wmsg').className = 'sub ' + (sv.state === 'error' ? 'bad' : sv.state === 'saving' ? 'warn' : 'good');
    $('wmsg').textContent = sv.state === 'saving' ? `Saving ${sv.ssid}… Wi-Fi restarts now.` : sv.state === 'done' && Date.now() / 1000 - sv.t < 300 ? `Saved: ${sv.ssid}.` : sv.state === 'error' ? 'Not saved: ' + sv.error : '';
  } catch (e) { $('wf').innerHTML = '<div class="sub">router not answering</div>'; }
}
$('wf').addEventListener('click', e => {
  const b = e.target.closest('[data-w]'); if (!b) return;
  wedit = wnets.find(n => n.id === b.dataset.w); if (!wedit) return;
  $('wfor').textContent = 'Changing ' + wedit.label + (wedit.hidden ? ' (hidden network)' : '');
  $('wssid').value = wedit.ssid || ''; $('wkey').value = ''; $('werr').textContent = '';
  $('wkey').disabled = !wedit.secured; $('wkey').placeholder = wedit.secured ? 'leave blank to keep it' : 'open network: set a password in GL.iNet first';
  $('wform').hidden = false; $('wssid').focus();
});
$('wshow').onchange = () => { $('wkey').type = $('wshow').checked ? 'text' : 'password'; };
$('wcancel').onclick = () => { $('wform').hidden = true; wedit = null; };
$('wform').onsubmit = async e => {
  e.preventDefault(); if (!wedit) return;
  const ssid = $('wssid').value.trim(), key = $('wkey').value;
  if (key && (key.length < 8 || key.length > 63)) { $('werr').textContent = 'The password must be 8 to 63 characters.'; return; }
  if (!confirm(`Save "${ssid}"${key ? ' with the new password' : ''}?\n\nWi-Fi restarts. If this phone is on it, join "${ssid}" again${key ? ' with the new password' : ''}.`)) return;
  $('wsave').disabled = true; $('werr').textContent = '';
  try {
    const r = await post('/api/wifi', {id: wedit.id, ssid, key});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('werr').textContent = j.error || 'Not saved'; return; }
    $('wform').hidden = true; wedit = null; $('wkey').value = '';
    loadWifi();
  } finally { $('wsave').disabled = false; }
};

function render(s) {
  screen = s.screen;
  if (s.netmode) renderMode(s.netmode);
  document.querySelectorAll('#seg button').forEach(b => b.classList.toggle('on', b.dataset.m === s.screen));
  const bad = s.findings.filter(f => f[0] !== 'good');
  $('banner').className = 'banner ' + s.verdict;
  $('banner').innerHTML = esc(s.findings[0][1]) + (bad.length > 1 ? '<ul>' + bad.slice(1).map(f => `<li>${esc(f[1])}</li>`).join('') + '</ul>' : '');
  const sw = s.switch;
  $('sw').innerHTML = sw.heard
    ? `<div class="big">${esc(sw.port)}</div><div class="rows" style="margin-top:6px">${rows([
        ['Switch', sw.name], ['VLAN', (sw.vlan ?? '-') + (sw.vlan_name ? ' (' + sw.vlan_name + ')' : '') + (sw.voice_vlan ? ' · voice ' + sw.voice_vlan : ''), 'acc'],
        ['Model', sw.platform], ['Mgmt IP', sw.mgmt_ip], ['PoE', sw.poe], ['Duplex (switch)', sw.duplex], ['Heard by', sw.protocols.join(' + ')]])}</div>`
    : `<div class="sub">${s.link.up ? 'Waiting for CDP or LLDP (the switch sends one every 30 to 60 seconds)…' : 'No link'}</div>`;
  const w = s.wan, t = s.timing, [g, gc] = chk(s.checks.gateway), [d, dc] = chk(s.checks.dns), [i, ic] = chk(s.checks.internet);
  $('port').innerHTML = rows([
    ['Link', speed(s.link) + (s.link.downshift ? ` (both ends can do ${s.link.downshift / 1000} Gbps)` : ''), s.link.downshift ? 'warn' : ''],
    ['Address', w.address ? w.address + '/' + w.mask : null, w.address ? '' : 'bad'],
    ['Gateway', (w.gateway || '-') + ' · ' + g, gc], ['DNS', (w.dns || []).join(', ') + ' · ' + d, dc],
    ['Internet', i, ic], ['Public IP', s.public_ip],
    ['Online in', t.gateway != null ? t.gateway + ' s (address ' + (t.address ?? '-') + ' s)' : '-', t.gateway > 25 ? 'warn' : ''],
    ['Link drops', s.link.drops]]);
  const l2 = s.l2, o = s.dhcp.options, stp = l2.stp;
  $('l2').innerHTML = rows([
    ['DHCP servers', s.dhcp.servers.join(', ') || '-', s.dhcp.servers.length > 1 ? 'bad' : ''],
    ['Lease', o.lease ? Math.round(o.lease / 60) + ' min' : null], ['Domain', o.domain || w.domain],
    ['Phone options', [o.tftp_ips && '150: ' + o.tftp_ips.join(', '), o.tftp_name && '66: ' + o.tftp_name, o.opt43 && '43: ' + o.opt43].filter(Boolean).join(' · ') || null],
    ['802.1X', l2.dot1x ? 'switch asks for a login' : 'none seen', l2.dot1x ? 'warn' : ''],
    ['Spanning tree', stp ? `${stp.proto} root ${stp.root_mac}${stp.vlan ? ' vlan ' + stp.vlan : ''}${stp.role ? ' · ' + stp.role : ''}` : 'none seen'],
    ['STP changes', l2.stp_changes, l2.stp_changes > 5 ? 'warn' : ''],
    ['Trunk (DTP)', l2.dtp ? `${l2.dtp.oper} (${l2.dtp.admin})` : '-'], ['VLAN tags seen', l2.vlans_tagged.join(', ') || null],
    ['Gateway MAC', (l2.gateway_mac || '-') + (l2.gateway_kind ? ' · ' + l2.gateway_kind : '')],
    ['IPv6 routers', l2.ipv6_routers.join(', ') || null, l2.ipv6_routers.length > 1 ? 'warn' : ''],
    ['Broadcasts/s', l2.broadcasts_per_s, l2.broadcasts_per_s > 50 ? 'warn' : '']]);
  $('ev').innerHTML = s.events.slice().reverse().map(e => `<div class="ev"><span class="t">${new Date(e.t * 1000).toLocaleTimeString([], {hour12: false})}</span><span class="${e.sev === 'bad' ? 'bad' : e.sev === 'warn' ? 'warn' : ''}">${esc(e.text)}</span></div>`).join('') || '<div class="sub">Nothing yet.</div>';
  $('age').textContent = 'updated ' + ago(s.time);
}

async function load() {
  try { render(await (await fetch('/api/state')).json()); } catch (e) { $('age').textContent = 'router not answering'; }
}
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})});
document.querySelectorAll('#seg button').forEach(b => b.onclick = async () => { if (b.dataset.m !== screen) { await post('/api/screen', {mode: b.dataset.m}); load(); } });
$('re').onclick = async () => { $('re').disabled = true; await post('/api/recheck'); setTimeout(() => { $('re').disabled = false; load(); }, 4500); };
let tab = 'port', span = 30, tools = null, typing = false;
document.querySelectorAll('nav.tabs button').forEach(b => b.onclick = () => {
  tab = b.dataset.t;
  document.querySelectorAll('nav.tabs button').forEach(x => x.classList.toggle('on', x === b));
  $('tab-port').hidden = tab !== 'port'; $('tab-tools').hidden = tab !== 'tools'; $('tab-settings').hidden = tab !== 'settings';
  if (tab === 'tools') loadTools();
  if (tab === 'settings') loadSettings();
});
document.querySelectorAll('#spans button').forEach(b => b.onclick = () => {
  span = +b.dataset.s; document.querySelectorAll('#spans button').forEach(x => x.classList.toggle('on', x === b)); loadTools();
});
async function act(url, body) {
  const r = await post(url, body);
  if (!r.ok) { const j = await r.json().catch(() => ({})); alert(j.error || 'Could not do that'); }
  loadTools();
}
$('pt').onchange = () => { const c = $('pt').value === 'custom'; $('ptc').hidden = $('ptgo').hidden = !c; if (!c) act('/api/ping', {target: $('pt').value}); };
$('ptgo').onclick = () => act('/api/ping', {target: $('ptc').value});
$('tgo').onclick = () => act('/api/tick', tools && tools.tick.running ? {action: 'stop'} : {server: $('ts').value, rate: +$('tr').value, secs: +$('td').value});
$('rgo').onclick = () => act('/api/reflector', {on: !(tools && tools.reflector.on)});
$('sgo').onclick = () => act('/api/speed', {server: $('ss').value, port: +($('sp').value || 5201)});
$('bgo').onclick = () => act('/api/blink', {on: !(tools && tools.blink.running)});
$('lgo').onclick = async () => { await act('/api/log', {label: $('lab').value}); $('lab').value = ''; };
['ts', 'ss', 'sp', 'ptc', 'lab'].forEach(id => { $(id).onfocus = () => typing = true; $(id).onblur = () => typing = false; });

function graph(p) {
  const c = $('graph'), g = c.getContext('2d'), W = c.width, H = c.height;
  g.clearRect(0, 0, W, H);
  const worst = Math.max(5, ...p.cols.map(x => x[0] || 0));
  const top = worst <= 10 ? 10 : worst <= 50 ? 50 : worst <= 100 ? 100 : Math.ceil(worst / 100) * 100;
  const cw = W / p.cols.length;
  p.cols.forEach((col, i) => {
    const [rtt, lost, sent] = col;
    if (!sent) return;
    if (lost) { g.fillStyle = '#ff4d4d'; g.fillRect(i * cw, 0, Math.max(1, cw - 1), H); }
    if (rtt != null) { const h = Math.max(2, rtt / top * (H - 14)); g.fillStyle = '#5aa9ff'; g.fillRect(i * cw, H - h, Math.max(1, cw - 1), h); }
  });
  const now = Date.now() / 1000;
  p.events.forEach(e => { const x = (1 - (now - e.t) / p.span) * W; g.fillStyle = e.sev === 'bad' ? '#ff4d4d' : '#fab219'; g.fillRect(x, 0, 2, H); });
  g.fillStyle = '#898781'; g.font = '11px monospace'; g.fillText(top + ' ms', 4, 11);
}

function renderTools(t) {
  tools = t;
  const p = t.ping, o = t.options;
  if (!typing) {
    const known = ['gateway', 'dns', 'internet'].includes(o.ping_target);
    $('pt').value = known ? o.ping_target : 'custom';
    if (!known) { $('ptc').hidden = $('ptgo').hidden = false; if (document.activeElement !== $('ptc')) $('ptc').value = o.ping_target; }
    if (!$('ts').value) $('ts').value = o.tick_server || '';
    if (!$('ss').value) $('ss').value = o.iperf_server || '';
    if (!$('sp').value && o.iperf_port) $('sp').value = o.iperf_port;
  }
  graph(p);
  $('psum').textContent = !p.target ? 'No address to ping yet' : p.sent ? `${p.target} · loss ${p.loss_pct}% (${p.lost}/${p.sent}) · avg ${p.avg ?? '-'} ms · jitter ${p.jitter ?? '-'} ms · 99% under ${p.p99 != null ? p.p99.toFixed(1) : '-'} ms` : `pinging ${p.target}…`;
  $('pev').innerHTML = p.events.slice().reverse().map(e => `<div class="ev"><span class="t">${new Date(e.t * 1000).toLocaleTimeString([], {hour12: false})}</span><span><span class="${e.sev === 'bad' ? 'bad' : e.sev === 'warn' ? 'warn' : ''}">${esc(e.text)}</span> <span class="${e.hit ? 'warn' : 'sub'}">· ${esc(e.impact)}</span></span></div>`).join('');
  const k = t.tick;
  $('tgo').textContent = k.running ? 'Stop' : 'Start';
  $('tres').innerHTML = !k.summary ? '' : `<div class="banner ${k.grade === 'excellent' || k.grade === 'good' ? 'good' : k.grade === 'fair' ? 'warn' : k.grade === 'wait' ? '' : 'bad'}" style="font-size:16px;margin-top:8px">${esc(k.headline)}${k.running ? ' <span class="sub">(running)</span>' : ''}</div>
    <table>${k.ratings.map(r => `<tr><td>${esc(r.label)}</td><td class="v">${esc(r.value)}</td><td class="${r.grade === 'excellent' || r.grade === 'good' ? 'good' : r.grade === 'fair' ? 'warn' : r.grade === 'bad' ? 'bad' : 'sub'}">${esc(r.grade)}</td></tr>`).join('')}
    <tr><td>Sent / answered</td><td class="v">${k.counters.sent} / ${k.counters.recv}</td><td class="sub">${k.counters.reorder} out of order, ${k.counters.dup} twice</td></tr>
    <tr><td>Reflector delay</td><td class="v">${k.holds.p50 != null ? k.holds.p50.toFixed(2) + ' ms typical, ' + k.holds.max.toFixed(2) + ' longest' : '-'}</td><td class="sub">${esc(k.hold_mode || '')}, taken out</td></tr></table>
    ${k.lost_at && k.lost_at.length ? `<div class="sub">Lost at ${k.lost_at.map(x => x.toFixed(1) + ' s').join(', ')} into the test</div>` : ''}
    ${k.error ? `<div class="bad sub">${esc(k.error)}</div>` : ''}`;
  const r = t.reflector;
  $('rgo').textContent = r.on ? 'On' : 'Off'; $('rgo').classList.toggle('on', r.on);
  $('rinfo').textContent = r.on ? `UDP ${r.port} · ${r.answered} packets answered${r.peers.length ? ' · testing now: ' + r.peers.join(', ') : ''}` : '';
  const sp = t.speed;
  $('sgo').disabled = !!sp.running; $('sgo').textContent = sp.running ? 'Running…' : 'Run';
  $('sres').innerHTML = sp.server && !sp.running ? rows([['Upload', sp.up_mbps != null ? sp.up_mbps + ' Mbps' : '-'], ['Download', sp.down_mbps != null ? sp.down_mbps + ' Mbps' : '-'], ['Retransmits', sp.retransmits], ['Server', sp.server]].concat(sp.error ? [['Error', sp.error, 'bad']] : [])) : '';
  const b = t.blink;
  $('bgo').textContent = b.running ? 'Stop' : 'Start'; $('bgo').classList.toggle('on', b.running);
  $('binfo').textContent = b.running ? `blinking · ${b.cycles} flashes` : '';
  $('log').innerHTML = '<tr><th>When</th><th>Switch / port</th><th>VLAN</th><th>Label</th><th></th></tr>' + t.log.slice(0, 30).map(x => `<tr><td class="sub">${esc(x.time.slice(5, 16))}</td><td>${esc(x.switch.split('.')[0])} ${esc(x.port)}</td><td>${esc(x.vlan)}</td><td>${esc(x.label)}</td><td class="${x.verdict === 'good' ? 'good' : x.verdict === 'warn' ? 'warn' : 'bad'}">●</td></tr>`).join('');
}
async function loadTools() {
  if (tab !== 'tools') return;
  try { renderTools(await (await fetch('/api/tools?span=' + span)).json()); } catch (e) {}
}
whoami().then(ok => { if (ok) { load(); loadWifi(); } });
setInterval(() => { if (!ME) return; tab === 'port' ? load() : tab === 'tools' ? loadTools() : null; }, 2000);
setInterval(() => { if (ME && tab === 'port' && $('wform').hidden) loadWifi(); }, 10000);
</script></body></html>
"""
