"""The phone page: join the router's Wi-Fi and open http://192.168.8.1:8088. Everything the tester
knows, refreshed every 2 seconds, and the switch between GL.iNet's screen and ours.

GET /            the page
GET /api/state   everything, as JSON
POST /api/screen {"mode": "pcc" | "gl"}
POST /api/recheck  run the DHCP probe and the checks again now
GET /api/tools?span=30  ping (with the event timeline), tick test, reflector, speed test, port finder, port log
POST /api/ping {"target"}, /api/tick {"action", "server", "rate", "secs"}, /api/reflector {"on"},
     /api/speed {"server", "port"}, /api/blink {"on"}, /api/log {"label"}
GET /ports.csv     the port log

GL.iNet's firewall keeps this port closed on the WAN side, so only the router's own Wi-Fi and LAN
can reach it.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


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

        def log_message(self, *args):  # quiet: procd keeps the log small
            pass

        def _send(self, code, body, kind="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/api/tools":
                try:
                    span = int(parse_qs(url.query).get("span", ["30"])[0])
                except ValueError:
                    span = 30
                return self._send(200, json.dumps(tools_state(service, max(10, min(span, 1800))), default=str))
            if url.path == "/ports.csv":
                data = service.log.csv_text().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", 'attachment; filename="ports.csv"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif self.path == "/api/state":
                snap = service.tester.snapshot()
                snap["screen"] = service.config["screen"]
                snap["page"] = service.page
                self._send(200, json.dumps(snap, default=str))
            else:
                self._send(404, '{"error": "not found"}')

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._send(400, '{"error": "not JSON"}')
            if self.path == "/api/screen":
                try:
                    service.set_screen(body.get("mode"))
                except ValueError:
                    return self._send(400, '{"error": "mode is pcc or gl"}')
                return self._send(200, json.dumps({"screen": service.config["screen"]}))
            if self.path == "/api/recheck":
                threading.Thread(target=service.dhcp_probe, daemon=True).start()
                service.recheck.set()
                return self._send(200, '{"ok": true}')
            try:
                return self._tool(body)
            except (ValueError, OSError) as e:
                return self._send(400, json.dumps({"error": str(e) or "could not start"}))

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
                return self._send(200, json.dumps(service.log.save(service.tester.snapshot(), str(body.get("label") or ""))))
            else:
                return self._send(404, '{"error": "not found"}')
            self._send(200, '{"ok": true}')

    return Handler


def serve(service, port):
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(service)).serve_forever()


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
</style></head><body>
<header><b>🐷 PorkChopCheck</b>
  <span class="grp"><span class="sub">Screen</span>
  <div class="seg" id="seg"><button data-m="gl">GL.iNet</button><button data-m="pcc">PorkChop</button></div></span>
</header>
<nav class="tabs"><button data-t="port" class="on">Port</button><button data-t="tools">Tools</button></nav>
<main id="tab-port">
  <div class="banner" id="banner">Loading…</div>
  <section><h2>Switch</h2><div id="sw"></div></section>
  <section><h2>Port</h2><div class="rows" id="port"></div></section>
  <section><h2>DHCP and layer 2</h2><div class="rows" id="l2"></div></section>
  <section><h2>Events</h2><div id="ev"></div></section>
  <div><button class="act" id="re">Re-check now</button> <span class="sub" id="age"></span></div>
  <p class="sub">The router's WAN port is the one being tested. Tap or swipe the router's screen for the next page; hold it to hand the screen back to GL.iNet.</p>
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
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const rows = list => list.map(([k, v, c]) => `<span class="k">${esc(k)}</span><span class="v ${c || ''}">${esc(v ?? '-')}</span>`).join('');
const speed = l => !l.up ? 'no link' : (l.speed >= 1000 ? l.speed / 1000 + ' Gbps' : l.speed + ' Mbps') + ' ' + (l.duplex || '');
const chk = c => !c ? ['…', ''] : c.ok ? [(c.ms != null ? c.ms.toFixed(1) + ' ms' : 'ok'), 'good'] : ['no answer', 'bad'];
const ago = t => { const s = Math.round(Date.now() / 1000 - t); return s < 60 ? s + ' s ago' : Math.round(s / 60) + ' min ago'; };
let screen = null;

function render(s) {
  screen = s.screen;
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
  $('tab-port').hidden = tab !== 'port'; $('tab-tools').hidden = tab !== 'tools';
  if (tab === 'tools') loadTools();
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
load(); setInterval(() => tab === 'port' ? load() : loadTools(), 2000);
</script></body></html>
"""
