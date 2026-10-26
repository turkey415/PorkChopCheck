'use strict';
// LAN cache: are the game downloads going to the cache?
(() => {
  let D = null, busy = false, poll = 5000;
  async function refresh() {
    if (busy) return;
    busy = true;
    try { const r = await fetch('/api/x/cache', { cache: 'no-store' }); if (r.ok) { D = await r.json(); draw(); } }
    finally { busy = false; }
  }
  function draw() {
    const d = D, r = d.result;
    poll = d.running ? 1500 : 5000;
    $('#lc-lamp').innerHTML = d.running ? '<span class="dot live"></span>checking…' : r ? (r.error ? `<span class="dot err"></span>${esc(r.error)}` : `<span class="dot on"></span>${esc(ago(r.t))}`) : '<span class="dot"></span>not yet';
    $('#lc-go').disabled = d.running;
    $('#lc-at').innerHTML = r ? `<span class="dot ${r.error ? 'err' : 'on'}"></span>checked ${esc(fmtWhen(r.t))} · ${r.took} s` : '';
    const hb = (r && r.heartbeat) || null;
    $('#lc-cache').textContent = r && r.cache_ip ? r.cache_ip : 'none found';
    $('#lc-wc').classList.toggle('off', !(r && r.cache_ip));
    $('#lc-wc').classList.toggle('alarm', !!(hb && !hb.ok));
    $('#lc-hb').textContent = !r ? '' : !r.cache_ip ? 'No game name points at a LAN address. Is lancache-dns (or your DNS) set up?'
      : hb ? (hb.ok ? `Heartbeat OK in ${hb.ms} ms${hb.by ? ' · ' + hb.by : ''} · HTTPS ${r.https ? 'open' : 'closed'}${r.cache_auto ? ' · found automatically' : ''}`
        : `No heartbeat: ${hb.error || 'answered ' + hb.code}`) : '';
    if (r && r.names_total) {
      setSeg('#lc-names', `${r.names_cached}`, 2);
      $('#lc-names2').textContent = `of ${r.names_total} names`;
      $('#lc-wn').classList.toggle('alarm', r.cache_ip && r.names_cached < r.names_total);
    } else { setSeg('#lc-names', '--', 2); $('#lc-names2').textContent = '—'; }
    const t = r && r.test, second = t && t[1];
    $('#lc-hit').textContent = second ? (second.error ? 'FAIL' : (second.cache || '?').toUpperCase()) : '—';
    $('#lc-speed').textContent = !d.test_url ? 'not set' : second && second.bps ? fmtBps(second.bps) + ' from the cache' : second && second.error ? second.error : '—';
    $('#lc-wt').classList.toggle('off', !second);
    $('#lc-wt').classList.toggle('alarm', !!(second && (second.error || (second.cache && second.cache.toUpperCase() !== 'HIT'))));
    const srv = (r && r.dns_servers) || [];
    const from = (r && r.dns_from) || [];
    $('#lc-dnsw').textContent = srv.length ? (r.trial ? 'trial of ' : 'asked ') + srv.join(', ') : '';
    setHTML('#lc-head', `<tr><th class="l">Service</th><th class="l">Name</th>${srv.map((s, i) => `<th class="l">via ${esc(s)}${from[i] ? ` <span class="chip${from[i] === 'trial' ? ' warn' : ''}">${esc(from[i])}</span>` : ''}</th>`).join('')}</tr>`);
    setHTML('#lc-list', r && r.services ? r.services.flatMap(sv => sv.names.map((n, i) => `<tr>${i ? '<td></td>' : `<td class="l"><span class="dot ${sv.cached ? 'on' : r.cache_ip ? 'warn' : ''}"></span> <b>${esc(sv.name)}</b></td>`}`
      + `<td class="l mono">${esc(n.name)}</td>${n.per.map(p => `<td class="l mono">${p.ip ? `<span class="chip ${p.cached ? 'ok' : p.lan ? 'warn' : ''}">${esc(p.ip)}</span>` : `<span class="chip bad">${esc(p.status)}</span>`}</td>`).join('')}</tr>`)).join('')
      : '<tr><td class="sub">Not checked yet.</td></tr>');
    $('#lc-testcard').hidden = !t;
    if (t) setHTML('#lc-test', t.map((f, i) => `<tr><td class="l">${i ? 'Second' : 'First'}</td>${f.error ? `<td colspan="5" class="l bad">${esc(f.error)}</td>`
      : `<td>${f.code}</td><td class="l">${esc(f.cache || '—')}</td><td>${(f.bytes / 1e6).toFixed(1)} MB</td><td>${f.secs} s</td><td>${f.bps ? fmtBps(f.bps) : '—'}</td>`}</tr>`).join(''));
    if (!$('#f-cache')._filled) { $('#lc-ip').value = d.cache_ip; $('#lc-every').value = d.every; $('#lc-url').value = d.test_url; $('#lc-dns').value = d.dns_extra; $('#lc-dhcp').checked = d.dns_dhcp; $('#f-cache')._filled = true; }
    $('#lc-dhcp').nextElementSibling.querySelector('small').textContent = d.dhcp_dns.length ? `Now: ${d.dhcp_dns.join(', ')}. Untick to check only the ones above.` : 'DHCP gave none.';
  }
  $('#lc-go').addEventListener('click', async () => { try { await api('/api/x/cache/run'); setTimeout(refresh, 400); } catch (e) { flash($('#lc-msg'), e.message); } });
  $('#f-cache').addEventListener('submit', async e => {
    e.preventDefault();
    try { await api('/api/x/cache/settings', { cache_ip: $('#lc-ip').value, every: +$('#lc-every').value, test_url: $('#lc-url').value, dns_extra: $('#lc-dns').value, dns_dhcp: $('#lc-dhcp').checked }); flash($('#lc-smsg'), 'Saved: checking', true); setTimeout(refresh, 400); }
    catch (err) { flash($('#lc-smsg'), err.message); }
  });
  $('#f-lctry').addEventListener('submit', async e => {
    e.preventDefault();
    const v = $('#lc-try').value.trim();
    if (!v) return flash($('#lc-msg'), 'Type a DNS server');
    try { await api('/api/x/cache/run', { dns: v }); flash($('#lc-msg'), 'Checking ' + v, true); setTimeout(refresh, 400); } catch (err) { flash($('#lc-msg'), err.message); }
  });
  PAGES.cache = { show: refresh };
  const tick = () => { if (view === 'cache' && ME) refresh(); setTimeout(tick, poll); };
  setTimeout(tick, poll);
})();
