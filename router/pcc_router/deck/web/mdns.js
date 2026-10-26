'use strict';
// mDNS browser: services announced on the LAN, grouped by type.
(() => {
  let D = null, busy = false, poll = 5000;
  async function refresh() {
    if (busy) return;
    busy = true;
    try { const r = await fetch('/api/x/mdns', { cache: 'no-store' }); if (r.ok) { D = await r.json(); draw(); } }
    finally { busy = false; }
  }
  function draw() {
    const d = D;
    poll = d.running ? 1200 : 5000;
    $('#md-lamp').innerHTML = d.running ? '<span class="dot live"></span>asking…' : d.error ? `<span class="dot err"></span>${esc(d.error)}` : d.last_scan ? `<span class="dot on"></span>${esc(ago(d.last_scan))}` : '<span class="dot"></span>not yet';
    $('#md-go').disabled = d.running;
    const n = d.types.reduce((a, t) => a + t.items.length, 0);
    setHTML('#md-info', [['Service types', d.types.length], ['Services', n], ['Devices answering', d.responders], ['Announcements heard', d.multicast_seen]]
      .map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join(''));
    const q = $('#md-q').value.trim().toLowerCase();
    const types = d.types.map(t => ({ ...t, items: t.items.filter(i => !q || [t.friendly, t.type, i.name, i.host, ...i.ips, ...(i.txt || [])].join(' ').toLowerCase().includes(q)) })).filter(t => t.items.length);
    $('#md-count').textContent = `${n} services · ${d.types.length} types`;
    setHTML('#md-list', types.map(t => `<div class="mdtype"><div class="mdh"><b>${esc(t.friendly)}</b> <span class="sub mono">${esc(t.type.replace('.local', ''))}</span> <span class="chip">${t.items.length}</span></div>`
      + `<div class="tablewrap"><table><tbody>${t.items.map(i => `<tr><td class="l">${esc(i.name)}</td><td class="l mono">${esc(i.ips[0] || i.host || '?')}${i.port ? ':' + i.port : ''}</td>`
        + `<td class="l sub">${esc(i.host)}</td><td class="l wrap sub mono" style="font-size:11.5px">${esc((i.txt || []).slice(0, 4).join(' · '))}</td></tr>`).join('')}</tbody></table></div></div>`).join('')
      || `<div class="empty">${n ? 'Nothing matches.' : d.running ? 'Asking…' : 'Nothing announced yet.'}</div>`);
    $('#md-empty').textContent = d.empty.length ? `Types announced with nobody answering for them: ${d.empty.join(', ')}` : '';
  }
  $('#md-q').addEventListener('input', () => D && draw());
  $('#md-go').addEventListener('click', async () => { await api('/api/x/mdns/scan').catch(err => alert(err.message)); setTimeout(refresh, 500); });
  $('#md-reset').addEventListener('click', async () => { await api('/api/x/mdns/reset').catch(() => {}); await api('/api/x/mdns/scan').catch(() => {}); setTimeout(refresh, 500); });
  PAGES.mdns = { show: refresh };
  const tick = () => { if (view === 'mdns' && ME) refresh(); setTimeout(tick, poll); };
  setTimeout(tick, poll);
})();
