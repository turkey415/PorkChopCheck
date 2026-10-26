'use strict';
// Host scan: who is on this subnet.
(() => {
  let D = null, busy = false, poll = 5000;
  const ipKey = ip => ip.split('.').map(n => n.padStart(3, '0')).join('.');

  async function refresh() {
    if (busy) return;
    busy = true;
    try {
      const r = await fetch('/api/x/hosts', { cache: 'no-store' });
      if (r.ok) { D = await r.json(); draw(); }
    } finally { busy = false; }
  }

  function draw() {
    const d = D, sc = d.scan, last = sc.last;
    poll = sc.running ? 1500 : 5000;
    $('#hs-lamp').innerHTML = sc.running ? `<span class="dot live"></span>${esc(sc.step || 'scanning')}…` : sc.error ? `<span class="dot err"></span>${esc(sc.error)}`
      : last ? `<span class="dot on"></span>${esc(ago(last.t))}` : '<span class="dot"></span>not yet';
    setHTML('#hs-info', [['Subnet', d.subnet || '—'], ['Last scan', last ? fmtWhen(last.t) : '—'], ['Took', last ? last.took + ' s' : '—'], ['Every', d.every ? d.every + ' min' : 'by hand']]
      .map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join(''));
    $('#hs-net').innerHTML = d.subnet ? `<span class="dot on"></span>${esc(d.subnet)}` : '<span class="dot"></span>no address';
    $('#hs-go').disabled = sc.running;
    const up = d.hosts.filter(h => h.up), news = d.hosts.filter(h => h.new);
    const makers = {};
    for (const h of up) { const m = h.vendor || 'Unknown'; makers[m] = (makers[m] || 0) + 1; }
    setSeg('#hs-up', up.length, 4); setSeg('#hs-new', news.length, 3); setSeg('#hs-nmk', Object.keys(makers).length, 3);
    setSeg('#hs-nport', up.filter(h => h.ports.length).length, 3);
    $('#hs-neww').classList.toggle('off', !news.length);
    setHTML('#hs-makers', Object.entries(makers).sort((a, b) => b[1] - a[1]).slice(0, 14).map(([m, n]) => `<tr><td class="wrap">${esc(m)}</td><td>${n}</td></tr>`).join('')
      || '<tr><td class="sub">No scan yet.</td></tr>');
    const q = $('#hs-q').value.trim().toLowerCase(), onlyUp = $('#hs-onlyup').checked, onlyNew = $('#hs-onlynew').checked, onlySmart = $('#hs-onlysmart').checked;
    const rows = d.hosts.filter(h => (!onlyUp || h.up) && (!onlyNew || h.new) && (!onlySmart || (h.smart && h.smart.smart)) && (!q || [h.ip, h.mac, h.name, h.label, h.vendor, ...(h.smart ? [h.smart.category, h.smart.brand, h.smart.model, h.smart.serial] : []), ...Object.values(h.names || {}), ...h.ports.map(p => p.port + ' ' + p.name)].join(' ').toLowerCase().includes(q)))
      .sort((a, b) => (a.up === b.up ? 0 : a.up ? -1 : 1) || ipKey(a.ip).localeCompare(ipKey(b.ip)));
    $('#hs-count').textContent = `${rows.length} of ${d.hosts.length}`;
    setHTML('#hs-list', rows.map(h => {
      const other = Object.entries(h.names || {}).filter(([, v]) => v && v !== h.name).map(([k, v]) => `${k}: ${v}`).join(' · ');
      const sm = h.smart, smart = sm ? `<small>${sm.category && sm.category !== 'unknown' ? `<span class="chip">${esc(sm.category)}</span> ` : ''}${esc([sm.brand, sm.model].filter(Boolean).join(' '))}`
        + `${sm.serial ? ` · serial ${esc(sm.serial)}` : ''}${sm.name && sm.name !== h.name ? ` · ${esc(sm.name)}` : ''}</small>` : '';
      return `<tr><td class="l mono"><span class="dot ${h.up ? 'on' : ''}"></span> ${esc(h.ip)}</td>`
        + `<td class="l nm">${h.label ? `<b>${esc(h.label)}</b>` : ''}${h.name ? (h.label ? `<small>${esc(h.name)}</small>` : esc(h.name)) : h.label ? '' : '<span class="sub">—</span>'}${h.new ? ' <span class="chip warn">new</span>' : ''}${smart}${other ? `<small>${esc(other)}</small>` : ''}</td>`
        + `<td class="l"><span class="mono">${esc(h.mac)}</span><span class="mk" title="${esc(h.vendor || '')}">${esc(h.vendor || 'unknown maker')}</span></td>`
        + `<td class="l wrap">${h.ports.map(p => `<span class="chip" title="${esc(p.name)}">${p.port}${p.name ? ' ' + esc(p.name) : ''}</span>`).join('') || '<span class="sub">—</span>'}</td>`
        + `<td>${esc(gAgo(h.first))}</td><td>${h.up ? 'now' : esc(gAgo(h.last))}</td>`
        + `<td><span class="keys"><a class="key ro-ok" style="text-decoration:none" href="#trace?q=${encodeURIComponent(h.ip)}" title="Find its switch port">Trace</a>`
        + `<button class="key admin-only" data-forget="${esc(h.mac)}" title="Forget this host">✕</button></span></td></tr>`;
    }).join('') || `<tr><td colspan="7" class="sub">${d.hosts.length ? 'Nothing matches.' : sc.running ? 'Scanning…' : 'No hosts yet: press Scan now.'}</td></tr>`);
    if (!$('#f-hosts')._filled) { $('#hs-every').value = d.every; $('#hs-ports').value = d.ports; $('#hs-names').checked = d.names; $('#hs-smart').checked = d.smart; $('#f-hosts')._filled = true; }
  }

  $('#hs-go').addEventListener('click', async () => { try { await api('/api/x/hosts/scan'); flash($('#hs-msg'), 'Scanning', true); setTimeout(refresh, 500); } catch (e) { flash($('#hs-msg'), e.message); } });
  for (const id of ['#hs-onlyup', '#hs-onlynew', '#hs-onlysmart']) $(id).addEventListener('change', draw);
  $('#hs-q').addEventListener('input', () => D && draw());
  $('#hs-list').addEventListener('click', async e => {
    const b = e.target.closest('[data-forget]');
    if (b) { await api('/api/x/hosts/forget', { mac: b.dataset.forget }).catch(() => {}); refresh(); }
  });
  $('#hs-forget').addEventListener('click', async () => { if (confirm('Forget every host? The next scan starts the list again (and nothing counts as new).')) { await api('/api/x/hosts/forget', { all: true }).catch(() => {}); refresh(); } });
  $('#f-hosts').addEventListener('submit', async e => {
    e.preventDefault();
    try { await api('/api/x/hosts/settings', { every: +$('#hs-every').value, ports: $('#hs-ports').value, names: $('#hs-names').checked, smart: $('#hs-smart').checked }); flash($('#hs-smsg'), 'Saved', true); }
    catch (err) { flash($('#hs-smsg'), err.message); }
  });
  PAGES.hosts = { show: refresh };
  const tick = () => { if (view === 'hosts' && ME) refresh(); setTimeout(tick, poll); };
  setTimeout(tick, poll);
})();
