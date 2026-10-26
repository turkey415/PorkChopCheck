'use strict';
// Multicast: IGMP querier, groups seen on the port, and a join test.
(() => {
  let D = null, busy = false, poll = 3000;
  const LV = { ok: 'on', warn: 'warn', wait: '' };
  async function refresh() {
    if (busy) return;
    busy = true;
    try { const r = await fetch('/api/x/mcast', { cache: 'no-store' }); if (r.ok) { D = await r.json(); draw(); } }
    finally { busy = false; }
  }
  function draw() {
    const d = D, q = d.querier, j = d.join;
    $('#mc-qlamp').innerHTML = `<span class="dot ${LV[q.level] || ''}"></span>${esc(q.level === 'ok' ? 'found' : q.level === 'warn' ? 'none' : 'listening')}`;
    $('#mc-q').textContent = q.text;
    $('#mc-q').style.color = q.level === 'warn' ? 'var(--warn)' : '';
    $('#mc-qnote').textContent = q.note;
    $('#mc-lamp').innerHTML = `<span class="dot on"></span>listening ${fmtDur(d.elapsed)}`;
    setSeg('#mc-ng', d.groups.length, 3);
    const [bn, bu] = splitBps(d.bps); setSeg('#mc-bps', d.bps ? bn : '0', 4); $('#mc-bpsu').textContent = bu || 'bps';
    setSeg('#mc-nq', d.queriers.length, 2); $('#mc-wq').classList.toggle('alarm', q.level === 'warn');
    setHTML('#mc-list', d.groups.map(g => `<tr${j && j.group === g.group ? ' class="sel"' : ''}><td class="l mono">${esc(g.group)}${g.port ? ':' + g.port : ''}</td><td class="l">${esc(g.name || '')}</td>`
      + `<td>${g.bps ? fmtBps(g.bps) : '—'}</td><td>${g.pkts.toLocaleString()}</td><td class="l mono">${esc(g.sources.slice(0, 3).join(', ') || '—')}</td>`
      + `<td class="l mono">${esc(g.members.slice(0, 3).join(', ') || '—')}${g.members.length > 3 ? ` +${g.members.length - 3}` : ''}</td><td>${g.last ? esc(ago(g.last)) : '—'}</td></tr>`).join('')
      || '<tr><td colspan="7" class="sub">Nothing yet.</td></tr>');
    $('#mc-join').hidden = !!j; $('#mc-leave').hidden = !j;
    $('#mc-jstate').textContent = j ? `Joined ${j.group} ${fmtDur(d.now - j.since)} ago: ${j.pkts ? `${j.pkts.toLocaleString()} packets arrived (${fmtBps(j.bps)} now) from ${j.sources.join(', ')}.`
      : d.now - j.since > 5 ? 'nothing has arrived. Either nobody is sending to it, or the switch or router isn’t forwarding it here.' : 'waiting for traffic…'}` : '';
  }
  $('#mc-probe').addEventListener('click', async () => { try { await api('/api/x/mcast/probe'); flash($('#mc-msg'), 'Asking…', true); setTimeout(refresh, 2500); } catch (e) { alert(e.message); } });
  $('#f-mcjoin').addEventListener('submit', async e => { e.preventDefault(); try { await api('/api/x/mcast/join', { group: $('#mc-group').value }); refresh(); } catch (err) { flash($('#mc-msg'), err.message); } });
  $('#mc-leave').addEventListener('click', async () => { await api('/api/x/mcast/leave').catch(() => {}); refresh(); });
  $('#mc-reset').addEventListener('click', async () => { await api('/api/x/mcast/reset').catch(() => {}); refresh(); });
  PAGES.mcast = { show: refresh };
  const tick = () => { if (view === 'mcast' && ME) refresh(); setTimeout(tick, poll); };
  setTimeout(tick, poll);
})();
