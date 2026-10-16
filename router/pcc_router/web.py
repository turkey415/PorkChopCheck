"""The phone page: join the router's Wi-Fi and open http://192.168.8.1:8088. Everything the tester
knows, refreshed every 2 seconds, and the switch between GL.iNet's screen and ours.

GET /            the page
GET /api/state   everything, as JSON
POST /api/screen {"mode": "pcc" | "gl"}
POST /api/recheck  run the DHCP probe and the checks again now

GL.iNet's firewall keeps this port closed on the WAN side, so only the router's own Wi-Fi and LAN
can reach it.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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
            self._send(404, '{"error": "not found"}')

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
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.4 system-ui, sans-serif; }
header { display:flex; align-items:center; gap:10px; padding:12px 14px; background:var(--panel); border-bottom:1px solid var(--line); position:sticky; top:0; }
header b { font-size:17px; }
.spacer { flex:1; }
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
</style></head><body>
<header><b>🐷 PorkChopCheck</b><span class="spacer"></span>
  <span class="sub">Screen</span>
  <div class="seg" id="seg"><button data-m="gl">GL.iNet</button><button data-m="pcc">PorkChopCheck</button></div>
</header>
<main>
  <div class="banner" id="banner">Loading…</div>
  <section><h2>Switch</h2><div id="sw"></div></section>
  <section><h2>Port</h2><div class="rows" id="port"></div></section>
  <section><h2>DHCP and layer 2</h2><div class="rows" id="l2"></div></section>
  <section><h2>Events</h2><div id="ev"></div></section>
  <div><button class="act" id="re">Re-check now</button> <span class="sub" id="age"></span></div>
  <p class="sub">The router's WAN port is the one being tested. Tap the router's screen for the next page; hold it to hand the screen back to GL.iNet.</p>
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
load(); setInterval(load, 2000);
</script></body></html>
"""
