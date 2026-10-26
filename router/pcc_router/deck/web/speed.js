'use strict';
// Speed test page: iPerf Deck's instruments and charts, for the LAN test (iperf3) and the internet test (Cloudflare).
// render() hands over the LAN state (SPV.lan); the internet test is polled from /api/x/speed.
window.SPV = (() => {
  const COL = { down: C.s[0], up: C.s[1], retr: C.s[7], rtt: C.s[6], cwnd: C.s[2], lat: C.s[3], idle: C.muted };
  const BPS_STEPS = [1e6, 2.5e6, 5e6, 1e7, 2.5e7, 5e7, 1e8, 2.5e8, 5e8, 1e9, 2.5e9, 5e9, 1e10, 2.5e10, 4e10, 1e11];
  const clamp01 = v => Math.max(0, Math.min(1, v || 0));
  const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
  const trim3 = v => String(parseFloat(v.toPrecision(3)));
  const ladder = (max, floor) => { const v = Math.max(max || 0, floor), p = 10 ** Math.floor(Math.log10(v)); return [1, 2, 5, 10].map(m => m * p).find(x => x >= v * .9999); };
  function splitBytes(b) {
    if (b == null) return ['—', ''];
    for (const [u, d] of [['TiB', 2 ** 40], ['GiB', 2 ** 30], ['MiB', 2 ** 20], ['KiB', 2 ** 10]]) if (b >= d) return [sig(b / d), u];
    return [String(Math.round(b)), 'B'];
  }

  // ---------- the arc dial (mkDial from iPerf Deck) ----------
  function mkDial(id, o) {
    const N = o.big ? 48 : 30, R = 84, gap = 1.4, step = 270 / N, nl = o.big ? 5 : 3;
    const pt = (r, deg) => [100 + r * Math.cos(deg * Math.PI / 180), 100 + r * Math.sin(deg * Math.PI / 180)].map(v => v.toFixed(2));
    let segs = '', labels = '';
    for (let i = 0; i < N; i++) {
      const a = pt(R, 135 + i * step + gap / 2), b = pt(R, 135 + (i + 1) * step - gap / 2);
      segs += `<path class="sg" stroke-width="${o.big ? 9 : 12}" d="M${a[0]} ${a[1]}A${R} ${R} 0 0 1 ${b[0]} ${b[1]}"/>`;
    }
    for (let j = 0; j < nl; j++) {
      const [x, y] = pt(o.big ? 57 : 59, 135 + 270 * j / (nl - 1));
      labels += `<text class="sl" x="${x}" y="${y}" text-anchor="middle" dominant-baseline="middle"></text>`;
    }
    const host = $(id);
    host.innerHTML = `<div class="dial ${o.big ? 'big' : 'mini'}" style="--c:${o.color}"><svg class="face" viewBox="0 0 200 200" aria-hidden="true">${segs}${labels}
      <g class="pk"><path d="M${100 + R + 7} 100l8 -4.5v9z"/></g>${o.big ? `<g class="nd"><path d="M${100 + R - 8} 100l-11 -4.5v9z"/></g>` : ''}
      <text class="ttl" x="100" y="${o.big ? 180 : 186}" text-anchor="middle"></text></svg>
      <div class="ctr"><div class="rd"></div><div class="un"></div></div></div>`;
    const root = host.firstChild, sg = [...root.querySelectorAll('.sg')], sl = [...root.querySelectorAll('.sl')];
    const pk = $('.pk', root), nd = $('.nd', root), rd = $('.rd', root), un = $('.un', root), ttl = $('.ttl', root);
    return v => {
      root.classList.toggle('off', !!v.off);
      if (v.color) root.style.setProperty('--c', v.color);
      const f = clamp01(v.f), lit = v.f > 0 ? Math.max(1, Math.round(f * N)) : 0;
      sg.forEach((e, i) => e.classList.toggle('on', i < lit));
      pk.style.transform = `rotate(${135 + 270 * clamp01(v.pf)}deg)`; pk.style.opacity = v.pf > 0 ? 1 : 0;
      if (nd) nd.style.transform = `rotate(${135 + 270 * f}deg)`;
      sl.forEach((e, i) => e.textContent = v.labels[i] ?? '');
      ttl.textContent = v.title || o.title || '';
      const h = seg7(v.text, 4); if (rd._h !== h) { rd.innerHTML = h; rd._h = h; }
      un.textContent = v.unit;
    };
  }

  // ---------- the hover chart (iPerf Deck's Chart): area fill, shared crosshair, tooltip ----------
  const tip = $('#sx-tip'), charts = [];
  let hoverT = null;
  class HChart {
    constructor(id, o) {
      this.host = $(id); this.o = o; this.series = []; this.xMax = 10; this.live = false;
      this.cv = document.createElement('canvas'); this.host.appendChild(this.cv);
      this.ctx = this.cv.getContext('2d');
      new ResizeObserver(() => this.draw()).observe(this.host);
      this.host.addEventListener('pointermove', e => this.move(e));
      this.host.addEventListener('pointerleave', () => { hoverT = null; tip.hidden = true; charts.forEach(c => c.draw()); });
      charts.push(this);
    }
    set(series, xMax, live) { this.series = series; this.xMax = Math.max(xMax, 1); this.live = live; this.draw(); }
    geom() { const w = this.host.clientWidth, h = this.host.clientHeight, l = 50, r = 16, t = 10, b = 24; return { w, h, l, t, pw: w - l - r, ph: h - t - b }; }
    x(g, t) { return g.l + (t - (this.o.bar ? .5 : 0)) / this.xMax * g.pw; }
    draw() {
      const g = this.geom(), ctx = this.ctx, dpr = window.devicePixelRatio || 1;
      if (g.w < 40 || g.h < 40) return;
      if (this.cv.width !== Math.round(g.w * dpr) || this.cv.height !== Math.round(g.h * dpr)) { this.cv.width = Math.round(g.w * dpr); this.cv.height = Math.round(g.h * dpr); }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, g.w, g.h);
      let max = 0;
      for (const s of this.series) for (const p of s.pts) if (p[1] > max) max = p[1];
      const sc = niceScale(Math.max(max * 1.04, this.o.minTop || 0), g.h > 220 ? 4 : 3), y = v => g.t + g.ph - v / sc.top * g.ph;
      ctx.font = '11px system-ui, sans-serif'; ctx.fillStyle = C.muted; ctx.lineWidth = 1; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      for (let v = 0; v <= sc.top + sc.step / 2; v += sc.step) {
        const yy = Math.round(y(v)) + .5;
        ctx.strokeStyle = v === 0 ? C.axis : C.grid; ctx.beginPath(); ctx.moveTo(g.l, yy); ctx.lineTo(g.l + g.pw, yy); ctx.stroke();
        ctx.fillText(this.o.axis(v), g.l - 8, yy);
      }
      ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      const xs = Math.max(1, niceScale(this.xMax, Math.max(2, Math.floor(g.pw / 80))).step);
      for (let t = 0; t <= this.xMax + 1e-6; t += xs) ctx.fillText(Math.round(t) + 's', g.l + t / this.xMax * g.pw, g.t + g.ph + 7);
      ctx.save(); ctx.beginPath(); ctx.rect(g.l - 6, 0, g.pw + 12, g.t + g.ph + .5); ctx.clip();
      for (const s of this.series) this.o.bar ? this.bars(g, s, y) : this.line(g, s, y);
      if (hoverT != null && !this.o.bar) {
        const hx = Math.round(this.x(g, hoverT)) + .5;
        ctx.strokeStyle = C.axis; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(hx, g.t); ctx.lineTo(hx, g.t + g.ph); ctx.stroke();
        for (const s of this.series) { const p = this.near(s.pts, hoverT); if (p && Math.abs(p[0] - hoverT) < .6) this.marker(this.x(g, p[0]), y(p[1]), s.color); }
      } else if (this.live && !this.o.bar) {
        for (const s of this.series) { const p = s.pts.at(-1); if (p && !s.flat) this.marker(this.x(g, p[0]), y(p[1]), s.color); }
      }
      ctx.restore();
    }
    near(pts, t) { return pts.length ? pts.reduce((a, p) => Math.abs(p[0] - t) < Math.abs(a[0] - t) ? p : a) : null; }
    marker(x, y, color) { const ctx = this.ctx; ctx.beginPath(); ctx.arc(x, y, 6, 0, 7); ctx.fillStyle = C.panel; ctx.fill(); ctx.beginPath(); ctx.arc(x, y, 4, 0, 7); ctx.fillStyle = color; ctx.fill(); }
    line(g, s, y) {
      const ctx = this.ctx, pts = s.pts;
      if (!pts.length) return;
      if (pts.length === 1) return this.marker(this.x(g, pts[0][0]), y(pts[0][1]), s.color);
      ctx.beginPath(); pts.forEach((p, i) => ctx[i ? 'lineTo' : 'moveTo'](this.x(g, p[0]), y(p[1])));
      if (this.o.area && !s.flat) {
        const fill = new Path2D(); pts.forEach((p, i) => fill[i ? 'lineTo' : 'moveTo'](this.x(g, p[0]), y(p[1])));
        fill.lineTo(this.x(g, pts.at(-1)[0]), y(0)); fill.lineTo(this.x(g, pts[0][0]), y(0)); fill.closePath();
        const grad = ctx.createLinearGradient(0, g.t, 0, g.t + g.ph); grad.addColorStop(0, s.color + '38'); grad.addColorStop(1, s.color + '00');
        ctx.fillStyle = grad; ctx.fill(fill);
      }
      ctx.strokeStyle = s.color; ctx.lineWidth = s.flat ? 1.5 : 2; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
      ctx.setLineDash(s.flat ? [5, 5] : []); ctx.stroke(); ctx.setLineDash([]);
    }
    bars(g, s, y) {
      const ctx = this.ctx, slot = g.pw / this.xMax, bw = Math.max(2, Math.min(24, slot - 2));
      for (const p of s.pts) {
        if (!(p[1] > 0)) continue;
        const cx = this.x(g, p[0]), top = y(p[1]), h = y(0) - top, r = Math.min(4, bw / 2, h);
        ctx.globalAlpha = hoverT == null || Math.abs(hoverT - p[0]) < .5 ? 1 : .45; ctx.fillStyle = s.color;
        ctx.beginPath(); ctx.roundRect(cx - bw / 2, top, bw, h, [r, r, 0, 0]); ctx.fill();
      }
      ctx.globalAlpha = 1;
    }
    move(e) {
      const g = this.geom(), rect = this.host.getBoundingClientRect();
      const ref = this.series.filter(s => !s.flat).reduce((a, s) => s.pts.length > a.length ? s.pts : a, []);
      if (!ref.length) return;
      const t = (e.clientX - rect.left - g.l) / g.pw * this.xMax + (this.o.bar ? .5 : 0);
      const near = this.near(ref, t)[0];
      if (near !== hoverT) { hoverT = near; charts.forEach(c => c.draw()); }
      const rows = this.series.map(s => { const p = this.near(s.pts, near); return p && (s.flat || Math.abs(p[0] - near) < .6) ? `<div class="r"><i class="sw" style="background:${s.color}"></i>${esc(s.name)}<b>${esc(this.o.tip(p[1]))}</b></div>` : ''; }).join('');
      tip.innerHTML = `<div class="t">${near.toFixed(near % 1 > .05 && near % 1 < .95 ? 1 : 0)} s</div>${rows}`;
      tip.hidden = false;
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      let tx = e.clientX + 16, ty = e.clientY - th - 12;
      if (tx + tw > innerWidth - 8) tx = e.clientX - tw - 16;
      if (ty < 8) ty = e.clientY + 16;
      tip.style.left = tx + 'px'; tip.style.top = ty + 'px';
    }
  }

  const ms3 = v => trim3(v) + ' ms';
  const I = {
    down: mkDial('#sx-down', { big: true, title: 'DOWNLOAD', color: COL.down }), up: mkDial('#sx-up', { big: true, title: 'UPLOAD', color: COL.up }),
    m1: mkDial('#sx-m1', { color: COL.rtt }), m2: mkDial('#sx-m2', { color: COL.retr }), m3: mkDial('#sx-m3', { color: COL.cwnd }), m4: mkDial('#sx-m4', { color: COL.lat }),
  };
  const cMain = new HChart('#sx-main', { area: true, axis: axisBps, tip: fmtBps, minTop: 1e7 });
  const cBars = new HChart('#sx-c1', { bar: true, minTop: 4, axis: v => String(Math.round(v)), tip: v => String(Math.round(v)) });
  const cLine1 = new HChart('#sx-c1', { minTop: 2, axis: v => trim3(v), tip: ms3 });
  const cLine2 = new HChart('#sx-c2', { minTop: 1, axis: v => trim3(v), tip: ms3 });

  // ---------- the tests, as one shape for both kinds ----------
  let S0 = null, D = null, busy = false, poll = 4000;
  let SRC = lsGet('pd-speed-src', 'lan'), SEL = null;
  function lanTests() {
    if (!S0) return [];
    const sp = S0.speed, out = [];
    if (sp.running) out.push({ id: 'lan:live', kind: 'lan', live: true, phase: sp.phase, t: sp.started, title: sp.label || sp.server, secs: sp.secs, pts: sp.points || [], res: sp.result || {} });
    for (const h of S0.history) out.push({ id: 'lan:' + h.t, kind: 'lan', t: h.t, title: h.label && h.label !== h.server ? h.label : h.server, secs: h.secs, pts: h.pts || [], res: { down: h.down, up: h.up }, port: h.port, switch: h.switch });
    return out;
  }
  function inetTests() {
    if (!D) return [];
    const r = D.run, out = [];
    const shape = (h, live) => ({ id: live ? 'inet:live' : 'inet:' + h.t, kind: 'inet', live, t: h.t || r.started, phase: live ? r.phase : null, secs: h.secs || D.secs,
      title: h.asn ? 'AS' + h.asn + (h.colo ? ' · Cloudflare ' + h.colo : '') : 'Internet', pts: (live ? r.points : h.pts) || [], lat: (live ? r.lat : h.lat) || [],
      idle: h.idle_ms, jitter: h.jitter_ms, res: { down: h.down ? { bps: h.down, bytes: h.down_bytes } : null, up: h.up ? { bps: h.up, bytes: h.up_bytes } : null },
      error: h.error, ok: h.ok, port: h.port, switch: h.switch, ip: h.ip, city: h.city });
    if (r.running) out.push(shape({ secs: D.secs }, true));
    for (const h of D.history) out.push(shape(h, false));
    return out;
  }
  const tests = () => SRC === 'lan' ? lanTests() : inetTests();

  function phaseStats(cur, ph) {
    const pts = cur.pts.filter(p => p[0] === ph), v = pts.map(p => p[2]);
    if (!v.length) return null;
    const steady = v.length > 2 ? v.slice(1) : v, res = (cur.res || {})[ph] || {};
    let bytes = res.bytes;
    if (bytes == null) { bytes = 0; pts.forEach((p, i) => { bytes += p[2] / 8 * (p[1] - (i ? pts[i - 1][1] : 0)); }); }
    return { pts, last: v.at(-1), avg: res.bps || avg(steady), max: Math.max(...v), min: Math.min(...steady), bytes, live: cur.live && cur.phase === ph };
  }
  const sub = (label, pair) => `<div class="sr"><span class="k">${label}</span>${seg7(pair[0] === '—' ? '0' : pair[0], 4)}<span class="un">${pair[1] || '·'}</span></div>`;
  function mini(fn, title, val, max, unit, off, why) {
    if (off || val == null) return fn({ off: true, f: 0, pf: 0, text: '---', unit: why || 'no reading', labels: ['0', '', ''], title });
    const range = ladder(max, 1);
    fn({ f: val / range, pf: max / range, text: val >= 100 ? String(Math.round(val)) : val >= 10 ? val.toFixed(1) : val.toFixed(2), unit, labels: ['0', trim3(range / 2), trim3(range)], title });
  }

  function draw() {
    if (view !== 'speed') return;
    const list = tests();
    const cur = list.find(x => x.id === SEL) || list[0];
    for (const r of document.querySelectorAll('input[name=sx-src]')) r.checked = r.value === SRC;
    $('#sx-title').textContent = SRC === 'lan' ? 'LAN · iperf3' : 'Internet · Cloudflare';
    if (!cur) {
      for (const k of ['down', 'up']) { I[k]({ off: true, f: 0, pf: 0, text: '----', unit: 'Mbps', labels: ['0', '', '', '', ''] }); $('#sx-sub-' + k).innerHTML = ''; }
      ['m1', 'm2', 'm3', 'm4'].forEach(k => mini(I[k], '', null));
      $('#sx-lamp').innerHTML = '<span class="dot"></span>no tests yet';
      $('#sx-note').textContent = SRC === 'lan' ? 'Run a LAN test (left), or press Send / Receive on a station below.' : 'Press Test the internet (left).';
      cMain.set([], 10, false); cBars.set([], 10); cLine1.set([], 10); cLine2.set([], 10); drawWaterfall([]);
      return;
    }
    // big dials
    const st = { down: phaseStats(cur, 'down'), up: phaseStats(cur, 'up') };
    for (const ph of ['down', 'up']) {
      const d = st[ph], val = d ? (d.live ? d.last : d.avg) : 0, range = d ? (BPS_STEPS.find(x => x >= d.max) || ladder(d.max, 1e6)) : 1e9;
      const [text, unit] = splitBps(val || 0);
      I[ph]({ off: !d, f: val / range, pf: d ? d.max / range : 0, text: d ? text : '----', unit: d ? (unit || 'bps') + (d.live ? ' · live' : ' avg') : 'not run', labels: [0, .25, .5, .75, 1].map(f => f ? axisBps(range * f) : '0') });
      $('#sx-sub-' + ph).innerHTML = sub('Avg', splitBps(d ? d.avg : 0)) + sub('Peak', splitBps(d ? d.max : 0)) + sub('Low', splitBps(d ? d.min : 0)) + sub('Data', splitBytes(d ? d.bytes : 0));
    }
    // small dials
    const up = cur.pts.filter(p => p[0] === 'up');
    if (cur.kind === 'lan') {
      const rtt = up.map(p => p[4]).filter(v => v != null), retr = up.map(p => p[3]).filter(v => v != null), cw = up.map(p => p[5]).filter(v => v != null);
      const why = st.up ? 'not reported' : 'upload only';
      mini(I.m1, 'ROUND TRIP', rtt.length ? (cur.live ? rtt.at(-1) : avg(rtt)) : null, Math.max(...rtt, 1), 'ms', false, why);
      mini(I.m2, 'RETRANS / S', retr.length ? (cur.live ? retr.at(-1) : avg(retr)) : null, Math.max(...retr, 4), 'per sec', false, why);
      mini(I.m3, 'CONG WINDOW', cw.length ? (cur.live ? cw.at(-1) : avg(cw)) : null, Math.max(...cw, 64), 'KiB', false, why);
      const gw = S0 && (S0.pings || []).find(p => p.gw);
      mini(I.m4, 'GATEWAY', gw && gw.avg != null ? gw.avg : null, Math.max(gw && gw.avg || 0, 1), 'ms ping now', false, 'no gateway');
    } else {
      const ld = cur.lat.filter(p => p[0] === 'down').map(p => p[2]), lu = cur.lat.filter(p => p[0] === 'up').map(p => p[2]);
      const top = Math.max(cur.idle || 0, ...ld, ...lu, 1);
      mini(I.m1, 'IDLE', cur.idle, top, 'ms to 1.1.1.1', false, cur.live ? 'measuring' : 'no reading');
      mini(I.m2, 'LOADED · DOWN', ld.length ? (cur.live && cur.phase === 'down' ? ld.at(-1) : avg(ld)) : null, top, 'ms under load', false, 'download first');
      mini(I.m3, 'LOADED · UP', lu.length ? (cur.live && cur.phase === 'up' ? lu.at(-1) : avg(lu)) : null, top, 'ms under load', false, 'upload next');
      const loaded = [...ld, ...lu], bloat = cur.idle != null && loaded.length ? Math.max(0, avg(loaded) - cur.idle) : null;
      mini(I.m4, 'BUFFERBLOAT', bloat, Math.max(bloat || 0, 30), bloat == null ? '' : bloat > 30 ? 'ms extra · high' : 'ms extra', false, 'after the test');
    }
    // lamp and note
    const PH = { meta: 'finding Cloudflare', latency: 'measuring latency', down: 'downloading', up: 'uploading' };
    $('#sx-lamp').innerHTML = cur.live ? `<span class="dot live"></span>${esc(PH[cur.phase] || 'running')} · ${esc(cur.title || '')}`
      : cur.error ? `<span class="dot err"></span>${esc(cur.error)}` : `<span class="dot on"></span>${esc(cur.title || '')} · ${esc(fmtWhen(cur.t))}`;
    const where = cur.port ? `on ${ifShort(cur.port)}${cur.switch ? ' of ' + cur.switch.split('.')[0] : ''}` : '';
    $('#sx-note').textContent = cur.kind === 'lan'
      ? [where, !st.up && !cur.live ? 'Round trip, retransmits and congestion window come from the sender: run Upload or Both to see them.' : ''].filter(Boolean).join(' · ')
      : [cur.ip ? `public IP ${cur.ip}` : '', cur.city || '', where, cur.jitter != null ? `idle jitter ${cur.jitter} ms` : ''].filter(Boolean).join(' · ');
    // charts
    const xMax = Math.max(cur.secs || 0, ...cur.pts.map(p => p[1]));
    const main = ['down', 'up'].map(ph => ({ name: ph === 'down' ? 'Download' : 'Upload', color: COL[ph], pts: cur.pts.filter(p => p[0] === ph).map(p => [p[1], p[2]]) })).filter(s => s.pts.length);
    legend('#sx-lg-main', main); cMain.set(main, xMax, !!cur.live);
    if (cur.kind === 'lan') {
      $('#sx-t1').textContent = 'Retransmits per second'; $('#sx-p2').hidden = false;
      cLine1.cv.hidden = true; cBars.cv.hidden = false; cLine1.set([], 1);
      const rs = [{ name: 'Retransmits', color: COL.retr, pts: up.filter(p => p[3] != null).map(p => [Math.max(1, Math.round(p[1])), p[3]]) }];
      legend('#sx-lg1', []); cBars.set(rs, xMax, !!cur.live);
      const rt = [{ name: 'Round trip', color: COL.rtt, pts: up.filter(p => p[4] != null).map(p => [p[1], p[4]]) }];
      $('#sx-t2').textContent = 'Round-trip time'; legend('#sx-lg2', []); cLine2.set(rt, xMax, !!cur.live);
    } else {
      $('#sx-t1').textContent = 'Latency under load'; $('#sx-p2').hidden = true;
      cBars.cv.hidden = true; cLine1.cv.hidden = false; cBars.set([], 1); cLine2.set([], 1);
      const lat = ['down', 'up'].map(ph => ({ name: ph === 'down' ? 'During download' : 'During upload', color: COL[ph], pts: cur.lat.filter(p => p[0] === ph).map(p => [p[1], p[2]]) })).filter(s => s.pts.length);
      if (cur.idle != null) lat.push({ name: 'Idle', color: COL.idle, flat: true, pts: [[0, cur.idle], [xMax, cur.idle]] });
      legend('#sx-lg1', lat); cLine1.set(lat, xMax, !!cur.live);
    }
    drawWaterfall(list, cur);
    for (const tr of document.querySelectorAll('tr[data-sel]')) tr.classList.toggle('picked', tr.dataset.sel === cur.id);
  }

  // ---------- the waterfall: one row per test, colour = speed ----------
  let WF_ROW = 6; const WF_STOPS = [[10, 14, 28], [16, 42, 110], [40, 110, 220], [90, 190, 255], [230, 245, 255]];
  let wfRows = [];
  function drawWaterfall(list, cur) {
    const host = $('#sx-wf'), cv = $('canvas', host), W = host.clientWidth, H = host.clientHeight;
    WF_ROW = Math.max(6, Math.min(26, Math.floor(H / Math.max(1, list.length))));
    // tests from before 0.27 kept only their averages: a row of download then upload
    const vals = x => x.pts.length ? x.pts.map(p => p[2]) : [x.res.down && x.res.down.bps, x.res.up && x.res.up.bps].filter(v => v);
    wfRows = list.slice(0, Math.floor(H / WF_ROW)).map(x => ({ id: x.id, vals: vals(x), part: x.live && x.secs ? Math.min(1, x.pts.length / (x.secs * (x.kind === 'inet' ? 4 : 2))) : 1 }));
    $('#sx-wfn').textContent = list.length ? `${list.length} test${list.length === 1 ? '' : 's'}` : '';
    if (W < 20) return;
    cv.width = W; cv.height = H;
    const ctx = cv.getContext('2d'), img = ctx.createImageData(W, H);
    const hi = Math.log10(Math.max(1e6, ...wfRows.flatMap(r => r.vals))), lo = hi - 3, sel = cur ? wfRows.findIndex(r => r.id === cur.id) : -1;
    for (let y = 0; y < H; y++) {
      const ri = Math.floor(y / WF_ROW), row = wfRows[ri], gap = y % WF_ROW === WF_ROW - 1;
      for (let x = 0; x < W; x++) {
        let c = [7, 8, 12];
        if (row && !gap && row.vals.length && x / W <= row.part) {
          const v = row.vals[Math.min(row.vals.length - 1, Math.floor(x / (W * row.part) * row.vals.length))];
          const f = v > 0 ? clamp01((Math.log10(v) - lo) / (hi - lo)) * (WF_STOPS.length - 1) : 0, i = Math.min(WF_STOPS.length - 2, Math.floor(f)), k = f - i;
          c = WF_STOPS[i].map((a, j) => a + (WF_STOPS[i + 1][j] - a) * k);
        }
        if (ri === sel && (x < 3 || gap)) c = [255, 176, 0];
        const o = (y * W + x) * 4;
        img.data[o] = c[0]; img.data[o + 1] = c[1]; img.data[o + 2] = c[2]; img.data[o + 3] = 255;
      }
    }
    ctx.putImageData(img, 0, 0);
  }
  new ResizeObserver(() => draw()).observe($('#sx-wf'));
  $('#sx-wf').addEventListener('click', e => { const r = wfRows[Math.floor((e.clientY - $('#sx-wf').getBoundingClientRect().top) / WF_ROW)]; if (r) { SEL = r.id; draw(); } });

  // ---------- picking a test ----------
  function pick(id) { const [k] = id.split(':'); SRC = k; lsSet('pd-speed-src', SRC); SEL = id; draw(); $('#sv-deck').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  document.addEventListener('click', e => { const tr = e.target.closest('tr[data-sel]'); if (tr && !e.target.closest('button, a')) pick(tr.dataset.sel); });
  for (const r of document.querySelectorAll('input[name=sx-src]')) r.addEventListener('change', () => { SRC = r.value; lsSet('pd-speed-src', SRC); SEL = null; draw(); });

  // ---------- the internet test: form, history, polling ----------
  let wasInet = false;
  async function refresh() {
    if (busy) return;
    busy = true;
    try { const r = await fetch('/api/x/speed', { cache: 'no-store' }); if (r.ok) { D = await r.json(); drawInet(); } }
    finally { busy = false; }
  }
  function drawInet() {
    const run = D.run;
    poll = run.running ? 700 : 4000;
    if (run.running && !wasInet) { SRC = 'inet'; SEL = null; }   // a test just started: show it
    wasInet = run.running;
    $('#in-go').disabled = run.running;
    $('#in-go').textContent = run.running ? 'Testing…' : 'Test the internet';
    setHTML('#in-hist', D.history.map(h => `<tr class="click" data-sel="inet:${h.t}"><td>${esc(fmtWhen(h.t))}</td><td class="l">${esc(h.ok ? (h.asn ? 'AS' + h.asn : '—') + (h.colo ? ' · ' + h.colo : '') : h.error || 'failed')}</td>`
      + `<td>${h.down ? fmtBps(h.down) : '—'}</td><td>${h.up ? fmtBps(h.up) : '—'}</td><td>${h.idle_ms != null ? h.idle_ms + ' ms' : '—'}</td>`
      + `<td>${h.down_ms != null ? Math.max(h.down_ms, h.up_ms || 0) + ' ms' : '—'}</td><td class="l">${esc(h.port ? ifShort(h.port) + (h.switch ? ' · ' + h.switch.split('.')[0] : '') : '—')}</td></tr>`).join('')
      || '<tr><td colspan="7" class="sub">No tests yet.</td></tr>');
    if (!$('#f-inet')._filled) { $('#in-secs').value = D.secs; $('#in-streams').value = D.streams; $('#f-inet')._filled = true; }
    draw();
  }
  $('#f-inet').addEventListener('submit', async e => {
    e.preventDefault();
    $('#in-err').hidden = true;
    try { await api('/api/x/speed/start', { secs: +$('#in-secs').value, streams: +$('#in-streams').value }); SRC = 'inet'; SEL = null; refresh(); }
    catch (err) { $('#in-err').textContent = err.message; $('#in-err').hidden = false; }
  });
  $('#in-clear').addEventListener('click', async () => { if (confirm('Clear the internet test history?')) { await api('/api/x/speed/clear').catch(() => {}); refresh(); } });
  PAGES.speed = { show: () => { refresh(); draw(); } };
  const tick = () => { if (view === 'speed' && ME) refresh(); setTimeout(tick, poll); };
  setTimeout(tick, poll);

  let wasLan = false;
  return {
    lan(s) {
      S0 = s;
      if (s.speed.running && !wasLan) { SRC = 'lan'; SEL = null; }
      wasLan = s.speed.running;
      draw();
    },
  };
})();
