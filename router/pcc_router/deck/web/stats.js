'use strict';
// System stats: the probe's own CPU, heat, memory, storage, network and processes (stats.py).
(() => {
  let D = null, busy = false;
  const POLL = 2000, SPAN = 600;
  const num = v => parseFloat(v.toPrecision(3)) + '';
  const charts = {
    cpu: new Chart('#st-c-cpu', { ago: true, minTop: 100, axis: v => v + '%' }),
    temp: new Chart('#st-c-temp', { ago: true, minTop: 80, axis: v => v + '°' }),
    mem: new Chart('#st-c-mem', { ago: true, minTop: 1, axis: v => fmtB(v * 2 ** 20, 0) }),
    net: new Chart('#st-c-net', { ago: true, minTop: 1e6, axis: axisBps }),
    disk: new Chart('#st-c-disk', { ago: true, minTop: 1e6, axis: v => fmtB(v, 0) + '/s' }),
  };
  function fmtB(b, dp = 1) {
    if (b == null) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
    while (Math.abs(b) >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b >= 100 ? 0 : dp) : Math.round(b)) + ' ' + u[i];
  }
  const kv = rows => rows.filter(r => r).map(([k, v, t]) => `<div${t ? ` title="${esc(t)}"` : ''}><dt>${esc(k)}</dt><dd>${esc(v ?? '—')}</dd></div>`).join('');
  const lvl = (v, warn, crit) => v == null ? 'ok' : v >= crit ? 'crit' : v >= warn ? 'warn' : 'ok';
  const pctOf = (a, b) => b ? 100 * a / b : null;
  // the first passive trip point is where the kernel starts slowing the CPU down
  const throttleAt = t => Math.min(...t.trips.filter(x => x.type === 'passive').map(x => x.c), Infinity);
  const critAt = t => Math.min(...t.trips.filter(x => x.type === 'critical').map(x => x.c), Infinity);

  async function refresh() {
    if (busy) return;
    busy = true;
    try { const r = await fetch('/api/x/stats', { cache: 'no-store' }); if (r.ok) { D = await r.json(); draw(); } }
    finally { busy = false; }
  }

  function draw() {
    const d = D, c = d.cur || {}, st = d.static, m = c.mem || {};
    if (!c.temps) return;
    const temps = c.temps, cpuT = temps.find(t => /cpu/i.test(t.name)) || temps[0];
    const thr = cpuT ? throttleAt(cpuT) : Infinity, crit = cpuT ? critAt(cpuT) : Infinity;
    const rootFs = (d.fs || []).find(f => f.mount === '/') || (d.fs || [])[0];
    const eth = (c.ifaces || []).find(i => i.name === 'eth0') || (c.ifaces || []).find(i => i.name !== 'lo');
    const memPct = pctOf(m.used, m.total), fsPct = rootFs ? pctOf(rootFs.used, rootFs.total) : null;
    const throttled = (c.cooling || []).some(x => /cpu/i.test(x.name) && x.cur > 0);

    // headline lamp
    const worst = [lvl(cpuT && cpuT.c, isFinite(thr) ? thr - 5 : 65, isFinite(thr) ? thr + 10 : 85), lvl(memPct, 85, 95), lvl(fsPct, 85, 95), throttled ? 'warn' : 'ok'];
    const w = worst.includes('crit') ? 'crit' : worst.includes('warn') ? 'warn' : 'ok';
    $('#st-lamp').innerHTML = `<span class="dot ${{ ok: 'on', warn: 'warn', crit: 'err' }[w]}"></span>${throttled ? 'CPU is being slowed to cool down' : w === 'ok' ? 'All normal' : w === 'warn' ? 'Running warm or full' : 'Needs attention'}`;

    // panel meters
    const lc = l => LEVEL_COLOR[l];
    const cpuL = lvl(c.cpu, 80, 95), tL = lvl(cpuT && cpuT.c, isFinite(thr) ? thr - 5 : 65, isFinite(thr) ? thr + 10 : 85);
    const meters = [
      gNeedle({ title: 'CPU', value: c.cpu, max: 100, readout: c.cpu == null ? '' : Math.round(c.cpu) + '', unit: '% busy', warn: 80, crit: 95, color: lc(cpuL), cells: 3 }),
      cpuT ? gNeedle({ title: 'CPU temp', value: cpuT.c, max: isFinite(crit) ? Math.max(100, crit) : 100, readout: Math.round(cpuT.c) + '', unit: '°C', warn: isFinite(thr) ? thr : 70, crit: isFinite(crit) ? crit - 10 : 85, color: lc(tL), cells: 3 }) : '',
      gNeedle({ title: 'Memory', value: memPct, max: 100, readout: memPct == null ? '' : Math.round(memPct) + '', unit: '% used', warn: 85, crit: 95, color: lc(lvl(memPct, 85, 95)), cells: 3 }),
      rootFs ? gNeedle({ title: 'Flash', value: fsPct, max: 100, readout: Math.round(fsPct) + '', unit: '% full', warn: 85, crit: 95, color: lc(lvl(fsPct, 85, 95)), cells: 3 }) : '',
      eth ? gNeedle({ title: `${eth.name} traffic`, value: Math.max(eth.rx_bps, eth.tx_bps) / 1e6, max: eth.speed || 1000, log: true, readout: num(Math.max(eth.rx_bps, eth.tx_bps) / 1e6), unit: 'Mbps', color: 'var(--accent)', cells: 4 }) : '',
    ];
    setHTML('#st-meters', meters.join(''));
    const well = (k, v, u) => `<div class="well"><span class="k">${k}</span><div class="big-port" style="font-size:22px">${esc(v)}</div><span class="un">${esc(u)}</span></div>`;
    const pr = c.procs;
    setHTML('#st-wells', [
      well('Uptime', fmtDur(d.uptime), d.boot ? 'since ' + fmtWhen(d.boot) : ''),
      well('Load', d.load.map(x => x.toFixed(2)).join(' '), `1 / 5 / 15 min · ${st.cores} cores`),
      well('Processes', pr ? String(pr.count) : '…', pr ? `${pr.threads} threads` : ''),
      well('Clock', d.ntp ? (d.ntp.synced ? 'In sync' : 'Not synced') : '—', d.ntp ? (d.ntp.tz || '') + ' · NTP' : ''),
    ].join(''));

    // CPU
    $('#st-cpusub').textContent = `${st.cores} × ${st.cpu}`;
    setHTML('#st-cores', (c.cores || []).map((p, i) => gauge(`CPU ${i}`, (p || 0) / 100, `${p == null ? '—' : Math.round(p) + '%'} · ${c.freqs[i] ? Math.round(c.freqs[i]) + ' MHz' : '—'}`, lvl(p, 80, 95))).join(''));
    const fq = c.freqs.filter(Boolean);
    setHTML('#st-cpukv', kv([['Busy', c.cpu == null ? '—' : c.cpu + '%'], ['Waiting on the flash', c.iowait == null ? '—' : c.iowait + '%', 'iowait: time the CPU sat idle waiting for storage'],
      ['Clock now', fq.length ? Math.round(Math.max(...fq)) + ' MHz' : '—'], ['Clock range', st.freq_min ? `${Math.round(st.freq_min)}–${Math.round(st.freq_max)} MHz` : '—'],
      ['Governor', st.governor, 'How the kernel picks the clock speed'], ['Slowed for heat', throttled ? 'Yes' : 'No']]));

    // heat
    $('#st-heatsub').textContent = isFinite(thr) ? `slows down at ${thr} °C` : '';
    setHTML('#st-temps', temps.map(t => {
      const top = isFinite(critAt(t)) ? critAt(t) : 100, tt = throttleAt(t);
      return gauge(t.name.toUpperCase(), t.c / top, `${t.c.toFixed(1)} °C`, lvl(t.c, isFinite(tt) ? tt - 5 : 65, isFinite(tt) ? tt + 10 : 85));
    }).join('') + (c.fans || []).map(f => gauge('FAN', f.rpm != null ? Math.min(1, f.rpm / 6000) : f.pwm / 100, f.rpm != null ? `${f.rpm} rpm` : `${f.pwm}%`, 'ok')).join(''));
    const trips = cpuT ? cpuT.trips.map(x => `${x.c} °C ${x.type === 'critical' ? 'shuts down' : 'slows down'}`).join(', ') : '';
    setHTML('#st-heatkv', kv([
      ['Fan', (c.fans || []).length ? (c.fans.map(f => f.rpm != null ? f.rpm + ' rpm' : f.pwm + '%').join(', ')) : 'None (passive)'],
      ...(c.cooling || []).slice(0, 4).map(x => [`Cooling step: ${x.name}`, `${x.cur} of ${x.max}`, '0 = full speed. Higher steps cap the clock to cut heat.']),
      ['Limits', trips || '—']]));
    $('#st-heatnote').textContent = (c.fans || []).length ? '' : 'No fan sensor on this board. It cools through the heatsink and the case only, so a warm room or a closed box shows up here first.';

    // memory
    const memParts = [['In use', m.used - m.shmem, C.s[0]], ['Shared', m.shmem, C.s[3]], ['Cache (freed when needed)', Math.max(0, m.avail - m.free), C.s[2]], ['Free', m.free, 'var(--led-off)']];
    setHTML('#st-membar', memParts.map(([n, v, col]) => `<i style="width:${Math.max(0, 100 * v / m.total).toFixed(2)}%;background:${col}" title="${esc(n)}: ${fmtB(v)}"></i>`).join(''));
    setHTML('#st-memkey', memParts.map(([n, v, col]) => `<span><i class="sw" style="background:${col}"></i>${esc(n)} ${fmtB(v)}</span>`).join(''));
    $('#st-memsub').textContent = `${fmtB(m.used)} of ${fmtB(m.total)}`;
    setHTML('#st-memkv', kv([['Total', fmtB(m.total)], ['In use', fmtB(m.used)], ['Available', fmtB(m.avail), 'Free plus cache the kernel can hand back'], ['Disk cache', fmtB(m.cache)]]));
    const sw = (d.swaps || []), zr = (d.zram || []);
    setHTML('#st-swap', sw.length || zr.length
      ? `<dl class="kv">${kv([...sw.map(x => [x.name, `${fmtB(x.used)} of ${fmtB(x.size)} (${x.type})`]),
        ...zr.map(z => [`${z.name} (compressed RAM)`, z.data != null ? `${fmtB(z.data)} stored in ${fmtB(z.compressed)}` : fmtB(z.size)])])}</dl>`
      : '<p class="sub" style="margin:0">None. The probe has no swap file, so it never writes memory out to the flash. That saves the card, and with this much free memory it isn\'t needed.</p>');

    // storage
    const card = Object.entries(st.cards || {})[0];
    $('#st-disksub').textContent = rootFs ? `${fmtB(rootFs.used)} of ${fmtB(rootFs.total)}` : '';
    setHTML('#st-fs', (d.fs || []).map(f => gauge(f.mount === '/' ? 'ROOT' : f.mount.split('/').pop().toUpperCase().slice(0, 8), f.used / f.total, `${fmtB(f.total - f.free)} / ${fmtB(f.total, 0)}`, lvl(pctOf(f.used, f.total), 85, 95))).join(''));
    const dk = (c.disks || [])[0];
    setHTML('#st-diskkv', kv([
      card ? ['Flash', [card[1].name, card[1].type, fmtB(card[1].size, 0)].filter(Boolean).join(' · ')] : null,
      card && card[1].date ? ['Made', card[1].date] : null,
      rootFs ? ['Free', fmtB(rootFs.free)] : null, rootFs ? ['File system', `${rootFs.fs}${rootFs.ro ? ' (read-only)' : ''}`] : null,
      dk ? ['Reading', fmtB(dk.r_bps) + '/s'] : null, dk ? ['Writing', fmtB(dk.w_bps) + '/s'] : null,
      dk ? ['Busy', dk.busy + '%'] : null, dk ? ['Written since boot', fmtB(dk.w)] : null]));

    // interfaces
    setHTML('#st-if', (c.ifaces || []).map(i => `<tr><td class="l mono">${esc(i.name)}</td><td class="l"><span class="dot ${i.state === 'up' || i.name === 'lo' || i.state === 'unknown' ? 'on' : 'err'}"></span> ${esc(i.state || '—')}</td>
      <td>${i.speed ? (i.speed >= 1000 ? i.speed / 1000 + ' Gb/s' : i.speed + ' Mb/s') : '—'}</td><td class="l mono">${esc(i.mac || '—')}</td><td>${i.mtu ?? '—'}</td>
      <td>${fmtBps(i.rx_bps)}</td><td>${fmtBps(i.tx_bps)}</td><td>${fmtB(i.rx)}</td><td>${fmtB(i.tx)}</td>
      <td${i.errors ? ' style="color:var(--crit)"' : ''}>${i.errors}</td><td${i.drops ? ' style="color:var(--warn)"' : ''}>${i.drops}</td></tr>`).join(''));

    // charts
    const h = d.hist, ago = t => d.now - t, ser = (name, color, k, f = v => v) => ({ name, color, pts: h.map(r => [ago(r[0]), r[k] == null ? null : f(r[k])]) });
    const sets = {
      cpu: [ser('CPU busy', C.s[0], 1)],
      temp: [ser('CPU °C', C.s[1], 2)],
      mem: [ser('In use (MB)', C.s[2], 3, v => v / 2 ** 20)],
      net: [ser('Down', C.s[0], 4), ser('Up', C.s[1], 5)],
      disk: [ser('Read', C.s[2], 6), ser('Write', C.s[3], 7)],
    };
    charts.mem.o.minTop = m.total / 2 ** 20;
    for (const [k, v] of Object.entries(sets)) { legend('#st-lg-' + k, v); charts[k].set(v, SPAN); }
    $('#st-netsub').textContent = `${eth ? eth.name + ' · ' : ''}last 10 min`;

    // processes
    $('#st-ncores').textContent = st.cores;
    $('#st-procsub').textContent = pr ? 'right now' : 'reading…';
    setHTML('#st-procs', pr ? pr.top.map(p => `<tr><td class="l mono">${esc(p.name)}</td><td>${p.pid}</td><td>${p.cpu.toFixed(1)}%</td><td>${fmtB(p.rss)}</td><td>${p.threads}</td></tr>`).join('')
      : '<tr><td colspan="5" class="sub">Measuring for a couple of seconds…</td></tr>');

    // about
    setHTML('#st-about', kv([['Board', st.model], ['Processor', `${st.cores} × ${st.cpu} (${st.arch})`], ['System', st.os], ['Kernel', st.kernel]]));
  }

  PAGES.stats = { show: refresh };
  const tick = () => { if (view === 'stats' && ME && !document.hidden) refresh(); setTimeout(tick, POLL); };
  setTimeout(tick, POLL);
})();
