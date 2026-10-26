'use strict';
// Traceroute that keeps watching: per-hop loss and latency, and a strip of the last 40 probes.
(() => {
  let D = null, busy = false, poll = 4000;
  async function refresh() {
    if (busy) return;
    busy = true;
    try { const r = await fetch('/api/x/mtr', { cache: 'no-store' }); if (r.ok) { D = await r.json(); draw(); } }
    finally { busy = false; }
  }
  function strip(hist, top) {
    const w = 3, h = 22;
    const bars = hist.map((v, i) => v == null ? `<rect x="${i * (w + 1)}" y="0" width="${w}" height="${h}" fill="var(--crit)"/>`
      : `<rect x="${i * (w + 1)}" y="${(h - Math.max(2, v / top * h)).toFixed(1)}" width="${w}" height="${Math.max(2, v / top * h).toFixed(1)}" fill="var(--s1)"/>`).join('');
    return `<svg width="${40 * (w + 1)}" height="${h}" viewBox="0 0 ${40 * (w + 1)} ${h}" aria-hidden="true" style="display:block">${bars}</svg>`;
  }
  const ms = v => v == null ? '—' : (v >= 100 ? v.toFixed(0) : v.toFixed(1));
  function draw() {
    const d = D, r = d.run, run = !!(r && r.running);
    poll = run ? 1000 : 4000;
    $('#mt-go').hidden = run; $('#mt-stop').hidden = !run;
    if (!$('#mt-q')._filled) { $('#mt-q').value = d.target; $('#mt-q')._filled = true; }
    setHTML('#mt-recent', [d.gateway ? `<button type="button" data-q="${esc(d.gateway)}">Gateway</button>` : '', ...d.recent.map(x => `<button type="button" data-q="${esc(x)}">${esc(x)}</button>`)].join(''));
    if (!r) { $('#mt-lamp').innerHTML = '<span class="dot"></span>not run yet'; setHTML('#mt-list', '<tr><td colspan="9" class="sub">Type a target and press Start.</td></tr>'); return; }
    $('#mt-title').textContent = `To ${r.target}${r.ip !== r.target ? ' (' + r.ip + ')' : ''}`;
    $('#mt-lamp').innerHTML = r.error && !r.hops.length ? `<span class="dot err"></span>${esc(r.error)}` : run ? `<span class="dot live"></span>${r.rounds} rounds · ${r.last_hop ? r.last_hop + ' hops' : 'finding the path'}`
      : `<span class="dot on"></span>stopped after ${r.rounds} rounds`;
    const top = Math.max(1, ...r.hops.flatMap(h => h.hist.filter(v => v != null)));
    setHTML('#mt-list', r.hops.map(h => {
      const end = h.ttl === r.last_hop, lossC = h.loss >= 5 ? 'bad' : h.loss > 0 ? 'meh' : '';
      return `<tr><td>${h.ttl}</td><td class="l">${h.ip ? `<span class="mono">${esc(h.ip)}</span>${h.name ? `<div class="sub">${esc(h.name)}</div>` : ''}${h.ips.length > 1 ? `<div class="sub">also ${esc(h.ips.filter(x => x !== h.ip).join(', '))}</div>` : ''}` : '<span class="sub">no answer</span>'}${end ? ' <span class="chip ok">target</span>' : ''}</td>`
        + `<td class="${lossC}">${h.loss}%</td><td>${h.sent}</td><td>${ms(h.last)}</td><td>${ms(h.avg)}</td><td>${ms(h.best)}</td><td>${ms(h.worst)}</td><td class="l">${strip(h.hist, top)}</td></tr>`;
    }).join('') || '<tr><td colspan="9" class="sub">Probing…</td></tr>');
  }
  $('#mt-recent').addEventListener('click', e => { const b = e.target.closest('[data-q]'); if (b) $('#mt-q').value = b.dataset.q; });
  $('#f-mtr').addEventListener('submit', async e => {
    e.preventDefault();
    try { await api('/api/x/mtr/start', { target: $('#mt-q').value.trim() }); setTimeout(refresh, 600); } catch (err) { alert(err.message); }
  });
  $('#mt-stop').addEventListener('click', async () => { await api('/api/x/mtr/stop').catch(() => {}); setTimeout(refresh, 1200); });
  PAGES.mtr = { show: refresh };
  const tick = () => { if (view === 'mtr' && ME) refresh(); setTimeout(tick, poll); };
  setTimeout(tick, poll);
})();
