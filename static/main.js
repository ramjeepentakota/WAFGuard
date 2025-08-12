const el = (id) => document.getElementById(id);
const $ = (sel) => document.querySelector(sel);

async function jsonGet(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return await r.json();
}

async function loadStatus() {
  try {
    const s = await jsonGet('/status');
    el('svc-status').textContent = s.in_progress ? 'Run in progress' : 'Idle';
  } catch {
    el('svc-status').textContent = 'Unavailable';
  }
}

async function loadSummary() {
  const period = el('period').value;
  const date = el('date').value || new Date().toISOString().slice(0,10);
  const s = await jsonGet(`/api/summary?period=${encodeURIComponent(period)}&date=${encodeURIComponent(date)}`);
  el('total').textContent = s.totals.total;
  el('confirmed').textContent = s.totals.confirmed;
  el('blocked').textContent = s.totals.blocked;
  el('sev-critical').textContent = s.totals.severity.critical;
  el('sev-high').textContent = s.totals.severity.high;
  el('sev-medium').textContent = s.totals.severity.medium;
  el('sev-low').textContent = s.totals.severity.low;
  el('sev-info').textContent = s.totals.severity.info;
  drawTimeline(s.timeline);
  drawSeverity(s.totals);
}

let timelineChart, severityChart;
function drawTimeline(data) {
  const ctx = document.getElementById('timeline');
  const labels = data.map(d => d.bucket);
  const counts = data.map(d => d.count);
  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        borderColor: '#2f6dea',
        backgroundColor: 'rgba(47,109,234,0.2)',
        data: counts,
        tension: 0.3,
        fill: true,
      }]
    },
    options: {
      plugins: { legend: { labels: { color: '#eaf0ff' } } },
      scales: {
        x: { ticks: { color: '#cbd6f0' } },
        y: { ticks: { color: '#cbd6f0' } }
      }
    }
  });
}

function drawSeverity(totals) {
  const ctx = document.getElementById('severity');
  const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const c = totals.severity;
  const data = [c.critical, c.high, c.medium, c.low, c.info];
  const colors = ['#ff4d4f','#ff7a45','#faad14','#36cfc9','#7e89a7'];
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors }] },
    options: { plugins: { legend: { labels: { color: '#eaf0ff' } } } }
  });
}

async function loadFiles() {
  const data = await jsonGet('/api/csv/list');
  const wrap = el('files');
  wrap.textContent = '';
  data.files.forEach(f => {
    const a = document.createElement('a');
    a.href = `/api/csv/download?date=${encodeURIComponent(f.date)}`;
    a.textContent = `${f.date}`;
    wrap.appendChild(a);
  });
}

async function loadEvents() {
  const date = el('date').value || new Date().toISOString().slice(0,10);
  const data = await jsonGet(`/api/events?date=${encodeURIComponent(date)}&limit=100`);
  const tbody = document.querySelector('#events tbody');
  tbody.textContent = '';
  data.events.forEach(ev => {
    const tr = document.createElement('tr');
    const score = parseInt(ev.anomaly_score || '0', 10);
    const sev = score>=20? 'Critical' : score>=15? 'High' : score>=10? 'Medium' : score>=5? 'Low' : 'Info';
    tr.innerHTML = `
      <td>${ev.timestamp || ''}</td>
      <td>${ev.client_ip || ''}</td>
      <td title="${ev.url || ''}">${(ev.url || '').slice(0,64)}</td>
      <td>${score}</td>
      <td>${sev}</td>
      <td>${ev.blocked}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadLog() {
  const data = await jsonGet('/logs?tail=200');
  el('log').textContent = data.log;
}

async function triggerRun() {
  const apply = $('#apply').checked ? 1 : 0;
  $('#btn-run').disabled = true;
  try {
    await jsonGet(`/run?apply=${apply}`);
    await loadStatus();
    await loadLog();
    await loadSummary();
  } catch (e) {
    console.error(e);
  } finally {
    $('#btn-run').disabled = false;
  }
}

function init() {
  const today = new Date().toISOString().slice(0,10);
  el('date').value = today;
  el('rep-day').value = today;
  // Menu switching
  const pageDash = document.getElementById('page-dashboard');
  const pageReports = document.getElementById('page-reports');
  const pageLogs = document.getElementById('page-logs');
  const menuDash = document.getElementById('menu-dashboard');
  const menuReports = document.getElementById('menu-reports');
  const menuLogs = document.getElementById('menu-logs');
  function setActive(menu) {
    [menuDash, menuReports, menuLogs].forEach(m => m.parentElement.classList.remove('active'));
    menu.parentElement.classList.add('active');
  }
  function showPage(which) {
    pageDash.style.display = which === 'dashboard' ? '' : 'none';
    pageReports.style.display = which === 'reports' ? '' : 'none';
    pageLogs.style.display = which === 'logs' ? '' : 'none';
    if (which === 'dashboard') setActive(menuDash);
    if (which === 'reports') setActive(menuReports);
    if (which === 'logs') setActive(menuLogs);
  }
  menuDash.addEventListener('click', (e) => { e.preventDefault(); showPage('dashboard'); });
  menuReports.addEventListener('click', (e) => { e.preventDefault(); showPage('reports'); });
  menuLogs.addEventListener('click', async (e) => { e.preventDefault(); showPage('logs'); await refreshLogsTabs(); });

  // Dashboard actions
  $('#btn-refresh').addEventListener('click', async () => {
    await loadSummary();
    await loadEvents();
    await loadFiles();
  });
  $('#btn-run').addEventListener('click', triggerRun);

  // Reports actions (Month/Year removed)
  $('#btn-dl-day').addEventListener('click', () => {
    const d = el('rep-day').value;
    if (!d) return;
    window.location = `/api/reports/download?period=day&date=${encodeURIComponent(d)}`;
  });
  // Hide month/year groups if present in markup
  const monthEl = document.getElementById('rep-month');
  if (monthEl && monthEl.closest('.group')) monthEl.closest('.group').style.display = 'none';
  const yearEl = document.getElementById('rep-year');
  if (yearEl && yearEl.closest('.group')) yearEl.closest('.group').style.display = 'none';
  $('#btn-refresh-active-log').addEventListener('click', async () => {
    const data = await jsonGet('/api/active-log?tail=400');
    el('active-log').textContent = data.log;
  });
  $('#btn-refresh-blocked').addEventListener('click', async () => {
    const data = await jsonGet('/api/blocked_recent?limit=100&days=30');
    const tbody = document.querySelector('#blocked tbody');
    tbody.textContent = '';
    data.items.forEach(item => {
      const r = item.reason || {};
      const reason = [r.rule_ids, r.messages, r.url].filter(Boolean).join(' | ');
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${item.ip}</td>
        <td>${item.blocked_at || ''}</td>
        <td>${item.expiry || ''}</td>
        <td>${reason}</td>
      `;
      tbody.appendChild(tr);
    });
  });

  // Logs tab controls
  async function refreshLogsTabs() {
    try {
      const activeTail = parseInt(el('tail-active').value || '400', 10);
      const a = await jsonGet(`/api/active-log?tail=${activeTail}`);
      el('logs-active').textContent = a.log;
    } catch (e) { el('logs-active').textContent = 'Error loading active log'; }
    try {
      const serviceTail = parseInt(el('tail-service').value || '400', 10);
      const s = await jsonGet('/logs?tail=' + serviceTail);
      el('logs-service').textContent = s.log;
    } catch (e) { el('logs-service').textContent = 'Error loading service log'; }
  }
  $('#btn-refresh-active-tab').addEventListener('click', refreshLogsTabs);
  $('#btn-refresh-service-tab').addEventListener('click', refreshLogsTabs);
  let autoActiveTimer = null, autoServiceTimer = null;
  el('auto-active').addEventListener('change', () => {
    if (el('auto-active').checked) {
      autoActiveTimer = setInterval(refreshLogsTabs, 5000);
    } else { clearInterval(autoActiveTimer); }
  });
  el('auto-service').addEventListener('change', () => {
    if (el('auto-service').checked) {
      autoServiceTimer = setInterval(refreshLogsTabs, 5000);
    } else { clearInterval(autoServiceTimer); }
  });

  // initial load
  loadStatus();
  loadSummary();
  loadEvents();
  loadFiles();
  loadLog();
  setInterval(loadStatus, 5000);
  setInterval(loadLog, 7000);
}

document.addEventListener('DOMContentLoaded', init);
