let latest = null;
const $ = id => document.getElementById(id);

// --- security: escape any user-controlled text before it goes into innerHTML ---
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function toast(msg, isError) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '');
  clearTimeout(toast._h);
  toast._h = setTimeout(() => t.classList.add('hidden'), 3500);
}

function go(page) {
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('active'));
  $(page).classList.add('active');
  const b = document.querySelector(`[data-page="${page}"]`);
  if (b) b.classList.add('active');
  $('title').textContent = {
    dashboard: 'Threat Detection Dashboard', analyzer: 'Email Threat Analyzer', gmail: 'Gmail Inbox',
    alerts: 'Live Alerts', ioc: 'IOC Intelligence', geo: 'IP Geolocation', reports: 'Forensic Reports'
  }[page] || 'ThreatLens';
  if (page === 'reports') loadReports();
  if (page === 'dashboard') loadHistory();
  if (page === 'gmail') loadGmail();
  if (page === 'alerts') loadAlerts();
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => go(b.dataset.page));

function severityColor(sev) {
  return { high: '#ff7e82', medium: '#f4c95d', low: '#8fb6ff' }[sev] || '#8fb6ff';
}

function render(d) {
  latest = d;
  $('empty').classList.add('hidden');
  $('result').classList.remove('hidden');
  const findingsHtml = d.findings.length
    ? d.findings.map(f => `<div class="ioc" style="border-left:3px solid ${severityColor(f.severity)}"><b>${esc(f.type)}</b><br><span class="muted">${esc(f.value)}</span></div>`).join('')
    : '<p class="ok">No obvious indicators detected.</p>';
  const featuresHtml = (d.top_features && d.top_features.length)
    ? `<h3>Why the model flagged this</h3><div class="iocbox">${d.top_features.map(f => `<div class="ioc"><b>${esc(f.term)}</b> <span class="muted">contribution ${f.weight}</span></div>`).join('')}</div>`
    : '';
  $('result').innerHTML = `
    <span class="eyebrow">ANALYSIS ${esc(d.analysis_id)}</span>
    <div class="gauge"><div class="risk">${d.risk}%</div><span class="badge">${esc(d.label)}</span></div>
    <div class="metric">
      <div><small>ML PROBABILITY</small><br><b>${d.ml_probability}%</b></div>
      <div><small>ML CLASS</small><br><b>${esc(d.ml_label)}</b></div>
      <div><small>URLs</small><br><b>${d.urls.length}</b></div>
      <div><small>IPs</small><br><b>${d.ips.length}</b></div>
    </div>
    <div class="actions"><button onclick="downloadReport('${d.analysis_id}','json')">Download JSON</button><button onclick="downloadReport('${d.analysis_id}','txt')">Download Report</button></div>
    <h3>Forensic Findings</h3>${findingsHtml}
    ${featuresHtml}`;
  renderIOC(d);
  loadHistory();
}

function renderIOC(d) {
  const blocks = [];
  if (d.urls.length) blocks.push(`<div class="ioc"><b>URLs</b><br>${d.urls.map(esc).join('<br>')}</div>`);
  if (d.ips.length) blocks.push(`<div class="ioc"><b>IP addresses</b><br>${d.ips.map(esc).join(', ')}</div>`);
  if (d.emails.length) blocks.push(`<div class="ioc"><b>Email addresses</b><br>${d.emails.map(esc).join(', ')}</div>`);
  $('iocbox').innerHTML = blocks.length ? blocks.join('') : '<div class="ioc">No IOCs extracted.</div>';
}

async function analyzeEmail() {
  const payload = { subject: $('subject').value, sender: $('sender').value, reply: $('reply').value, body: $('body').value };
  try {
    const r = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    render(d);
  } catch (e) { toast(e.message, true); }
}

async function demo() {
  const r = await fetch('/api/demo', { method: 'POST' });
  const d = await r.json();
  $('subject').value = d.subject || '';
  $('sender').value = d.sender || '';
  $('body').value = d.raw || '';
  render(d);
}

async function uploadEml() {
  const f = $('eml').files[0];
  if (!f) return toast('Select an .eml file first.', true);
  const fd = new FormData();
  fd.append('file', f);
  try {
    const r = await fetch('/api/analyze-eml', { method: 'POST', body: fd });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    $('subject').value = d.subject || '';
    $('sender').value = d.sender || '';
    render(d);
  } catch (e) { toast(e.message, true); }
}

function clearForm() {
  ['subject', 'sender', 'reply', 'body'].forEach(x => $(x).value = '');
  $('result').classList.add('hidden');
  $('empty').classList.remove('hidden');
}

function downloadReport(id, format) {
  window.open(`/api/export/${id}?format=${format}`, '_blank');
}

async function loadHistory() {
  const r = await fetch('/api/history');
  const a = await r.json();
  $('statAnalyses').textContent = a.length;
  $('statThreats').textContent = a.filter(x => x.risk >= 35).length;
  $('statRisk').textContent = (a.length ? Math.round(a.reduce((s, x) => s + x.risk, 0) / a.length) : 0) + '%';
  $('recent').innerHTML = a.length
    ? a.slice(0, 8).map(x => `<div class="row"><span>${esc(x.created)}</span><span>${esc(x.subject || '(no subject)')}</span><span>${esc(x.sender || '-')}</span><b>${x.risk}%</b></div>`).join('')
    : 'No investigations yet.';
  drawTrend();
}

async function loadReports() {
  const r = await fetch('/api/history');
  const a = await r.json();
  $('reportsbox').innerHTML = a.length
    ? a.map(x => `<div class="row"><span>${esc(x.id)}</span><span>${esc(x.subject || '-')}</span><span>${esc(x.label)}</span><b>${x.risk}%</b> <button onclick="downloadReport('${x.id}','txt')">Export</button></div>`).join('')
    : 'No reports yet.';
}

async function lookupGeo() {
  const ip = $('geoip').value.trim();
  if (!ip) return toast('Enter an IP address.', true);
  $('geobox').innerHTML = 'Looking up...';
  try {
    const r = await fetch('/api/geo/' + encodeURIComponent(ip));
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    $('geobox').innerHTML = `<div class="georesult"><h3>${esc(d.city || '-')}, ${esc(d.country || '-')}</h3><p>Region: ${esc(d.region || '-')}</p><p>ISP: ${esc(d.connection?.isp || '-')}</p><p>Organization: ${esc(d.connection?.org || '-')}</p><p>Timezone: ${esc(d.timezone?.id || '-')}</p><small class="muted">Approximate IP geolocation; not an exact physical location.</small></div>`;
  } catch (e) { $('geobox').innerHTML = `<p class="error">${esc(e.message)}</p>`; }
}

// --- Gmail integration (optional; gracefully degrades if not configured) ---
async function loadGmail() {
  const panel = $('gmailPanel');
  try {
    const r = await fetch('/api/gmail/status');
    const s = await r.json();
    if (!s.enabled) {
      panel.innerHTML = `<h3>Gmail auto-fetch is not set up yet</h3>
        <p class="muted">To pull emails directly from a Gmail inbox instead of pasting them in, add OAuth credentials for this app.
        See the "Enable Gmail auto-fetch" section in README.txt — you'll create a free Google Cloud OAuth client and drop the
        downloaded <code>credentials.json</code> into this project folder, then restart the app.</p>`;
      return;
    }
    if (!s.connected) {
      panel.innerHTML = `<h3>Connect your Gmail account</h3><p class="muted">Grant read-only access so ThreatLens can pull recent inbox messages for analysis. No emails are sent anywhere except this local app.</p><button class="primary" onclick="location.href='/api/gmail/login'">Connect Gmail</button>`;
      return;
    }
    panel.innerHTML = 'Loading inbox...';
    const mr = await fetch('/api/gmail/messages');
    const msgs = await mr.json();
    if (!mr.ok) throw new Error(msgs.error);
    panel.innerHTML = `<div class="panelhead"><h3>Recent Inbox Messages</h3><div class="actions"><button onclick="loadGmail()">Refresh</button><button onclick="switchGmailAccount()">Switch account</button></div></div>` +
      (msgs.length ? msgs.map(m => `<div class="row"><span>${esc(m.from)}</span><span>${esc(m.subject)}</span><span class="muted">${esc(m.snippet.slice(0, 60))}</span><button onclick="analyzeGmailMsg('${m.id}')">Analyze</button></div>`).join('')
        : 'No messages found.');
  } catch (e) {
    panel.innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

async function switchGmailAccount() {
  try {
    await fetch('/api/gmail/disconnect', { method: 'POST' });
    toast('Disconnected. Connect a different Gmail account whenever you\'re ready.');
    loadGmail();
  } catch (e) { toast(e.message, true); }
}

async function analyzeGmailMsg(id) {
  try {
    const r = await fetch('/api/gmail/analyze/' + id, { method: 'POST' });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    go('analyzer');
    $('subject').value = d.subject || '';
    $('sender').value = d.sender || '';
    $('body').value = d.raw || '';
    render(d);
    toast('Fetched and analyzed message from Gmail.');
  } catch (e) { toast(e.message, true); }
}

// --- lightweight trend chart, no external chart library needed ---
async function drawTrend() {
  const canvas = $('trendChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const r = await fetch('/api/stats');
  const data = (await r.json()).slice(-20);
  if (!data.length) { ctx.fillStyle = '#728197'; ctx.fillText('No data yet.', 10, 20); return; }
  const w = canvas.width, h = canvas.height, pad = 24;
  ctx.strokeStyle = '#1c2734'; ctx.beginPath(); ctx.moveTo(pad, h - pad); ctx.lineTo(w - 5, h - pad); ctx.stroke();
  const stepX = (w - pad - 10) / Math.max(1, data.length - 1);
  ctx.strokeStyle = '#42eaa0'; ctx.lineWidth = 2; ctx.beginPath();
  data.forEach((p, i) => {
    const x = pad + i * stepX, y = h - pad - (p.risk / 100) * (h - pad * 2);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = '#42eaa0';
  data.forEach((p, i) => {
    const x = pad + i * stepX, y = h - pad - (p.risk / 100) * (h - pad * 2);
    ctx.beginPath(); ctx.arc(x, y, 3, 0, 7); ctx.fill();
  });
}

loadHistory();

// --- Live alerts: background Gmail polling happens on the server side
// (and rings a real alarm on the PC even with no browser open); this part
// just keeps the "Live Alerts" tab, badge, and an in-tab beep up to date
// whenever the browser happens to be open. ---
let lastUnseenCount = 0;

function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(); const g = ctx.createGain();
    o.type = 'square'; o.frequency.value = 880;
    o.connect(g); g.connect(ctx.destination);
    g.gain.setValueAtTime(0.15, ctx.currentTime);
    o.start(); o.stop(ctx.currentTime + 0.25);
  } catch (e) { /* Web Audio not available; the OS-level alarm still rings server-side */ }
}

async function pollAlertBadge() {
  try {
    const r = await fetch('/api/gmail/alerts/unseen-count');
    const d = await r.json();
    if (d.count > lastUnseenCount) {
      beep();
      toast(`⚠️ ${d.count} suspicious email(s) flagged from Gmail`, true);
    }
    lastUnseenCount = d.count;
    const badge = $('alertBadge');
    if (badge) { badge.textContent = d.count; badge.classList.toggle('hidden', d.count === 0); }
  } catch (e) { /* Gmail not connected yet, or feature not enabled — ignore quietly */ }
}

async function loadAlerts() {
  loadNotifyConfig();
  const panel = $('alertsPanel');
  try {
    const r = await fetch('/api/gmail/alerts');
    const a = await r.json();
    panel.innerHTML = a.length
      ? a.map(x => `<div class="row alertrow ${x.seen ? '' : 'unseen'}"><span>${esc(x.created)}</span><span>${esc(x.subject || '(no subject)')}</span><span class="muted">${esc(x.sender || '-')}</span><b>${x.risk}%</b>${x.seen ? '' : `<button onclick="dismissAlert('${x.id}')">Mark read</button>`}</div>`).join('')
      : 'No alerts yet. Connect Gmail and leave the app running — anything risky that arrives will show up here.';
  } catch (e) { panel.innerHTML = `<p class="error">${esc(e.message)}</p>`; }
}

async function dismissAlert(id) {
  await fetch(`/api/gmail/alerts/${id}/dismiss`, { method: 'POST' });
  loadAlerts();
  pollAlertBadge();
}

async function dismissAllAlerts() {
  await fetch('/api/gmail/alerts/dismiss-all', { method: 'POST' });
  loadAlerts();
  pollAlertBadge();
}

async function loadNotifyConfig() {
  try {
    const r = await fetch('/api/notify/config');
    const d = await r.json();
    $('notifyEmail').value = d.email || '';
    $('notifyTo').value = d.to || '';
  } catch (e) { /* ignore */ }
}

async function saveNotifyConfig(enabled) {
  const payload = { enabled, email: $('notifyEmail').value, app_password: $('notifyAppPassword').value, to: $('notifyTo').value };
  try {
    const r = await fetch('/api/notify/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!r.ok) throw new Error('Could not save settings.');
    $('notifyAppPassword').value = '';
    toast(enabled ? 'Email alerts enabled.' : 'Email alerts disabled.');
  } catch (e) { toast(e.message, true); }
}

pollAlertBadge();
setInterval(pollAlertBadge, 20000);