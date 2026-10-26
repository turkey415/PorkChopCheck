"""Builds the router's Deck page (router/pcc_router/deck/index.html) from a Probe Deck checkout, so the
router shows Probe Deck's own pages: its styles, sidebar, page scripts and the Tailscale tab.

    python3 router/tools/build_deck.py ~/probe-deck

Copies, unchanged: the page scripts (web/*.js) and the US map. Cuts out of Probe Deck's index.html:
the stylesheet, the chosen views, and the shared helpers from its main script (charts, gauges,
seven-segment readouts, Wake, Tailscale and its map). Then adds the router's glue: the sidebar, the
login check (the phone page's login), and the few changes the router needs (Tailscale shares the
router's networks through GL.iNet's settings). Every cut is checked, so a changed Probe Deck fails
loudly here instead of making a broken page.

The backends (router/pcc_router/deck/*.py) are copied by hand from the same checkout.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

VIEWS = ["mtr", "hosts", "mdns", "mcast", "cache", "speed", "wake", "stats", "ts"]
SCRIPTS = ["mtr", "hosts", "mdns", "mcast", "cache", "speed", "stats"]
OUT = Path(__file__).resolve().parent.parent / "pcc_router" / "deck"


def between(text, start, end, inclusive_end=False):
    a = text.index(start)
    b = text.index(end, a + len(start))
    return text[a:b + (len(end) if inclusive_end else 0)]


def sub1(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f"build_deck: expected one {old[:60]!r} in Probe Deck, found {text.count(old)}")
    return text.replace(old, new)


def view(html, name):
    """One <div class="layout..." id="v-name">…</div>, up to the next section marker."""
    m = re.search(rf'<div class="[^"]*view[^"]*" id="v-{name}"[^>]*>', html)
    if not m:
        raise SystemExit(f"build_deck: no view v-{name}")
    rest = html[m.start():]
    stop = min(i for i in (rest.find("\n<!-- ================="), rest.find("\n</div><!-- .content -->")) if i > 0)
    return rest[:stop].rstrip() + "\n"


def js_block(js, start, end):
    """Main-script lines from the line starting with `start` up to (not including) the one starting with `end`."""
    return between(js, "\n" + start, "\n" + end)[1:] + "\n"


def build(src):
    src = Path(src).expanduser()
    html = (src / "index.html").read_text()
    commit = subprocess.run(["git", "-C", str(src), "log", "-1", "--format=%h"], capture_output=True, text=True).stdout.strip() or "?"
    style = between(html, "<style>", "</style>", inclusive_end=True)
    js = between(html, "<script>\n'use strict';", "\n</script>")

    views = {v: view(html, v) for v in VIEWS}
    # the speed page: only the internet test (the phone page has the LAN iperf3 test)
    sp = views["speed"]
    sp = re.sub(r'\n  <section class="card admin-only">\n    <h2>LAN speed test.*?\n  </section>', "", sp, count=1, flags=re.S)
    sp = re.sub(r'\n  <section class="card">\n    <h2>Stations .*?\n  </section>', "", sp, count=1, flags=re.S)
    sp = re.sub(r'\n  <section class="card">\n    <h2>LAN test history.*?\n  </section>', "", sp, count=1, flags=re.S)
    if "LAN speed test" in sp or "st-list" in sp:
        raise SystemExit("build_deck: couldn't take the LAN test out of the speed page")
    views["speed"] = sp
    # Tailscale: PorkChopCheck's own tailscaled on the router (deckhost.RouterTailscale)
    ts = views["ts"]
    ts = sub1(ts, "<small>SSH to the probe with tailnet logins", "<small>SSH to the router with tailnet logins")
    ts = sub1(ts, "Looks up public IPs (the probe's, and devices", "Looks up public IPs (the router's, and devices")
    ts = sub1(ts, "<h2>This probe on the tailnet", "<h2>This router on the tailnet")
    ts = sub1(ts, "So tailnet devices reach PCs and switches on this LAN through the probe.", "So tailnet devices reach PCs and switches on the network the WAN port is plugged into, through the router.")
    ts = ts.replace("probe sends</span>", "router sends</span>").replace("probe receives</span>", "router receives</span>")
    views["ts"] = ts
    views["stats"] = views["stats"].replace("SD card reads and writes", "Flash reads and writes")

    helpers = "".join([
        js_block(js, "const $ = ", "// ---------- charts ----------"),          # $, esc, colours, formatting, seven-segment
        js_block(js, "// ---------- charts ----------", "const cLat = "),         # Chart
        js_block(js, "const legend = ", "let S = null"),                           # legend, api
        js_block(js, "const lsGet = ", "// ---------- sidebar ----------"),        # lsGet … shortMac
        js_block(js, "const ifShort = ", "function renderJack"),
        js_block(js, "const num3 = ", "function gBlm("),                           # LEVEL_COLOR, sty, gSeg, gLeds, gNeedle
        js_block(js, "const pct = ", "function gauges("),
    ])
    wake = js_block(js, "// ---------- wake ----------", "// ---------- https ----------")
    tsjs = js_block(js, "// ---------- Tailscale ----------", "// ---------- polling ----------")
    tsjs = sub1(tsjs, "Log the probe out of the tailnet?", "Log the router out of the tailnet?")
    tsjs = sub1(tsjs, "['IP forwarding', t.forwarding ? 'on' : 'off']", "['Networking', 'userspace (PorkChopCheck’s own Tailscale)']")
    tsjs = tsjs.replace("Machines → probe → Edit route settings", "Machines → this router → Edit route settings")
    tsjs = tsjs.replace("Tailscale isn’t installed on the probe.", "Tailscale isn’t installed on the router.")

    page = TEMPLATE
    for k, v in {"STYLE": style, "VIEWS": "\n".join(views[v] for v in VIEWS), "HELPERS": helpers, "WAKE": wake,
                 "TAILSCALE": tsjs, "COMMIT": commit,
                 "SCRIPTS": "\n".join(f'<script src="/deck/web/{s}.js"></script>' for s in SCRIPTS)}.items():
        page = page.replace("{{" + k + "}}", v)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "index.html").write_text(page)
    (OUT / "web").mkdir(exist_ok=True)
    for s in SCRIPTS:
        text = (src / "web" / f"{s}.js").read_text()
        if s == "stats":  # the router keeps its files on internal flash, not an SD card
            text = text.replace("'SD card'", "'Flash'").replace("SD card", "flash")
        (OUT / "web" / f"{s}.js").write_text(text)
    (OUT / "vendor").mkdir(exist_ok=True)
    shutil.copy(src / "vendor" / "us-map.json", OUT / "vendor" / "us-map.json")
    print(f"wrote {OUT / 'index.html'} from Probe Deck {commit}")


ICON = '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="{d}"/></svg>'


def mod(key, title, icon, items):
    links = "".join(f'      <a href="#{v}" data-view="{v}"><span class="dot" id="t-{v}"></span><span class="nm">{n}</span><span class="badge" id="tb-{v}" hidden></span></a>\n' for v, n in items)
    return (f'  <div class="mod" data-mod="{key}">\n    <button type="button" aria-expanded="true">{ICON.format(d=icon)}<span class="mn">{title}</span>'
            f'<span class="dot" data-lamp></span><span class="chev" aria-hidden="true">▾</span></button>\n    <div class="items">\n{links}    </div>\n  </div>\n')


SIDEBAR = (
    mod("net", "Network", "M4 5h16v5H4z M4 14h16v5H4z M7.5 7.5h.01 M7.5 16.5h.01 M12 10v4",
        [("mtr", "Traceroute"), ("hosts", "Host scan"), ("mdns", "mDNS"), ("mcast", "Multicast"), ("cache", "LAN cache")])
    + mod("tests", "Tests", "M4 18a8 8 0 1 1 16 0 M12 18l4-6", [("speed", "Internet speed")])
    + mod("tools", "Tools", "M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z", [("wake", "Wake")])
    + mod("sys", "System", "M4 7h9 M17 7h3 M4 17h3 M11 17h9 M15 5v4 M9 15v4", [("stats", "System stats"), ("ts", "Tailscale")])
)

TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PorkChopCheck Deck</title>
<!-- Built by router/tools/build_deck.py from Probe Deck {{COMMIT}}: its styles, pages and scripts, on the router. -->
{{STYLE}}
<style>
/* the router's additions */
#v-speed .sx-src { display: none; }      /* only the internet test here */
#v-wake section:has(#seen) { display: none; }   /* fed by Probe Deck's Watchdog, which the router doesn't have */
.backlink { text-decoration: none; }
</style>
</head>
<body class="gated">
<div id="sx-tip" hidden></div>
<header class="top">
  <button class="btn ghost navbtn ro-ok" id="b-nav" type="button" aria-label="Show the page list" aria-expanded="false"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button>
  <div class="brand"><span style="font-size:20px">🐷</span> PorkChopCheck Deck</div>
  <span class="pill"><span class="dot" id="h-dot"></span><span id="h-name">connecting…</span></span>
  <span class="spacer"></span>
  <a class="btn ghost backlink ro-ok" href="/">◂ Port tester</a>
  <span class="pill" id="h-temp">— °C</span>
  <span class="pill userpill ro-ok" id="h-user"><span id="h-uname">—</span><span class="role" id="h-role"></span><button type="button" id="b-logout">Log out</button></span>
</header>
<div class="shell">
<nav class="side ro-ok" id="side" aria-label="Pages">
""" + SIDEBAR + """  <span class="k ver" id="sj-ver"></span>
</nav>
<div class="scrim" id="scrim"></div>
<div class="content">
<div class="banner" id="offline" hidden style="margin:14px 20px 0">Lost contact with the router. Retrying…</div>
{{VIEWS}}
</div><!-- .content -->
</div><!-- .shell -->
<script>
'use strict';
// ---------- Probe Deck's shared helpers ----------
{{HELPERS}}
// ---------- the router's glue: login, views, state ----------
let S = null, ME = null, timer = 0;
const isAdmin = () => !!ME && ME.role === 'admin';
const showGate = () => { location.href = '/'; };   // the phone page has the login
const PAGES = {};
const VIEWS = ['mtr', 'hosts', 'mdns', 'mcast', 'cache', 'speed', 'wake', 'stats', 'ts'];
let view = 'stats';
lsSet('pd-speed-src', 'inet');
function showView() {
  const v = location.hash.slice(1);
  view = VIEWS.includes(v) ? v : 'stats';
  for (const n of VIEWS) $('#v-' + n).hidden = n !== view;
  for (const a of document.querySelectorAll('.side .items a')) a.classList.toggle('on', a.dataset.view === view);
  for (const m of document.querySelectorAll('.side .mod')) m.classList.toggle('has-on', !!m.querySelector('a.on'));
  navOpen(false);
  if (view === 'ts') tsRefresh();
  if (view === 'wake') poll();
  if (PAGES[view] && ME) PAGES[view].show();
}
addEventListener('hashchange', showView);
function navOpen(open) { document.body.classList.toggle('navopen', open); $('#b-nav').setAttribute('aria-expanded', String(open)); }
$('#b-nav').addEventListener('click', () => navOpen(!document.body.classList.contains('navopen')));
$('#scrim').addEventListener('click', () => navOpen(false));
let navClosed;
try { navClosed = new Set(JSON.parse(lsGet('pcc-deck-nav-closed', '[]'))); } catch { navClosed = new Set(); }
for (const m of document.querySelectorAll('.side .mod')) {
  const btn = m.querySelector('button'), id = m.dataset.mod;
  const set = closed => { m.classList.toggle('closed', closed); btn.setAttribute('aria-expanded', String(!closed)); };
  set(navClosed.has(id));
  btn.addEventListener('click', () => { const c = !m.classList.contains('closed'); set(c); c ? navClosed.add(id) : navClosed.delete(id); lsSet('pcc-deck-nav-closed', JSON.stringify([...navClosed])); });
}
{ const hdr = $('header.top'); new ResizeObserver(() => document.documentElement.style.setProperty('--hdr', hdr.offsetHeight + 'px')).observe(hdr); }
function navLamps() {
  for (const m of document.querySelectorAll('.side .mod')) {
    let worst = 0;
    for (const a of m.querySelectorAll('.items a')) {
      const d = a.querySelector('.dot').classList;
      worst = Math.max(worst, d.contains('err') ? 3 : d.contains('warn') ? 2 : d.contains('on') ? 1 : 0);
    }
    m.querySelector('[data-lamp]').className = 'dot ' + ['', 'on', 'warn', 'err'][worst];
  }
}
async function poll() {
  clearTimeout(timer);
  try {
    const r = await fetch('/api/deck/state', { cache: 'no-store' });
    if (r.status === 401) return showGate();
    S = await r.json();
    $('#offline').hidden = true;
    $('#h-dot').className = 'dot ' + (S.link && S.link.up ? 'on' : 'err');
    $('#h-name').textContent = `${S.name} · ${S.ip || 'no address'} · ${S.mode === 'ap' ? 'Access point' : 'Router'}`;
    const t = S.temp;
    $('#h-temp').innerHTML = `<span class="dot ${t == null ? '' : t >= 85 ? 'err' : t >= 75 ? 'warn' : 'on'}"></span>${t == null ? '—' : t.toFixed(0)} °C`;
    $('#sj-ver').textContent = `${S.name} · Deck from Probe Deck {{COMMIT}}`;
    for (const [k, a] of Object.entries(S.apps || {})) {
      const d = $('#t-' + k), b = $('#tb-' + k);
      if (d) d.className = 'dot ' + ((a && a.dot) || '');
      if (b) { b.hidden = !(a && a.badge); b.textContent = (a && a.badge) || ''; }
    }
    navLamps();
    if (view === 'wake') renderWake();
  } catch { $('#offline').hidden = false; }
  timer = setTimeout(poll, view === 'wake' ? 2000 : 5000);
}
async function boot() {
  let a;
  try { a = await (await fetch('/api/auth/me', { cache: 'no-store' })).json(); } catch { return setTimeout(boot, 3000); }
  if (!a.user) return showGate();
  ME = a.user;
  document.body.classList.toggle('ro', ME.role !== 'admin');
  $('#h-uname').textContent = ME.name; $('#h-role').textContent = ME.role; $('#h-role').className = 'role ' + ME.role;
  document.body.classList.remove('gated');
  showView(); poll();
}
$('#b-logout').onclick = async () => { await api('/api/auth/logout').catch(() => {}); showGate(); };

// ---------- Wake (Probe Deck's) ----------
{{WAKE}}
// ---------- Tailscale and its map (Probe Deck's) ----------
{{TAILSCALE}}
boot();
</script>
{{SCRIPTS}}
</body></html>
"""

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "~/probe-deck")
