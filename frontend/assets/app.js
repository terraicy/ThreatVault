const API = '/api/v1';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function riskClass(score) {
  if (score >= 70) return 'risk-high';
  if (score >= 40) return 'risk-medium';
  return 'risk-low';
}

function truncate(s, n = 16) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '...' : s;
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// Navigation
$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.nav-item').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    $$('.view').forEach(v => v.classList.remove('active'));
    $(`#view-${btn.dataset.view}`).classList.add('active');
    const titles = { dashboard: 'SOC Dashboard', upload: 'Submit Sample', reports: 'All Reports', iocs: 'IOC Feed' };
    $('#page-title').textContent = titles[btn.dataset.view];
    if (btn.dataset.view === 'reports') loadReports();
    if (btn.dataset.view === 'iocs') loadIOCFeed();
  });
});

// Stats & Dashboard
async function loadDashboard() {
  try {
    const [stats, reports] = await Promise.all([
      api('/stats'),
      api('/reports?limit=20'),
    ]);

    $('#stats-grid').innerHTML = `
      <div class="stat-card"><div class="label">Total Scans</div><div class="value">${stats.total_scans}</div></div>
      <div class="stat-card success"><div class="label">Completed</div><div class="value">${stats.completed_scans}</div></div>
      <div class="stat-card danger"><div class="label">High Risk</div><div class="value">${stats.high_risk_samples}</div></div>
      <div class="stat-card warning"><div class="label">Cache Hits</div><div class="value">${stats.cache_hits}</div></div>
    `;

    const buckets = [0, 0, 0, 0, 0];
    reports.forEach(r => {
      const idx = Math.min(Math.floor(r.risk_score / 20), 4);
      buckets[idx]++;
    });
    const max = Math.max(...buckets, 1);
    $('#risk-chart').innerHTML = buckets.map((c, i) => `
      <div class="bar" style="height: ${(c / max) * 100}%">
        <span class="bar-label">${i * 20}-${(i + 1) * 20}</span>
      </div>
    `).join('');

    $('#flags-list').innerHTML = stats.top_flags.length
      ? stats.top_flags.map(f => `
          <div class="flag-row">
            <span>${f.flag}</span>
            <span class="risk-badge risk-medium">${f.count}</span>
          </div>
        `).join('')
      : '<p style="color: var(--text-muted)">No detection flags yet. Submit a sample</p>';

    renderRecentTable(reports);
  } catch (e) {
    console.error('Dashboard load failed:', e);
  }
}

function renderRecentTable(reports) {
  const tbody = $('#recent-table tbody');
  tbody.innerHTML = reports.map(r => `
    <tr>
      <td>${r.filename}</td>
      <td class="hash-cell" title="${r.sha256}">${truncate(r.sha256, 20)}</td>
      <td><span class="risk-badge ${riskClass(r.risk_score)}">${r.risk_score}</span></td>
      <td>${r.status}</td>
      <td>${(r.flags || []).slice(0, 3).map(f => `<span class="flag-tag">${f}</span>`).join('')}</td>
      <td><button class="btn secondary small" onclick="viewReport('${r.id}')">View</button></td>
    </tr>
  `).join('');
}

async function loadReports() {
  const reports = await api('/reports?limit=100');
  $('#reports-table tbody').innerHTML = reports.map(r => `
    <tr>
      <td>${truncate(r.id, 12)}</td>
      <td>${r.filename}</td>
      <td><span class="risk-badge ${riskClass(r.risk_score)}">${r.risk_score}</span></td>
      <td>${r.sandbox_analysis?.verdict || 'None'}</td>
      <td>${new Date(r.created_at).toLocaleString()}</td>
      <td><button class="btn secondary small" onclick="viewReport('${r.id}')">Details</button></td>
    </tr>
  `).join('');
}

async function loadIOCFeed() {
  const reports = await api('/reports?limit=50');
  const allDomains = new Set();
  const allIPs = new Set();
  const allPaths = new Set();

  reports.forEach(r => {
    const ioc = r.iocs || {};
    (ioc.domains || []).forEach(d => allDomains.add(d));
    (ioc.ips || []).forEach(ip => allIPs.add(ip));
    (ioc.file_paths || []).forEach(p => allPaths.add(p));
  });

  $('#ioc-feed').innerHTML = `
    <div class="ioc-group"><h4>Domains (${allDomains.size})</h4><ul>${[...allDomains].slice(0, 20).map(d => `<li>${d}</li>`).join('') || '<li>None yet</li>'}</ul></div>
    <div class="ioc-group"><h4>IPs (${allIPs.size})</h4><ul>${[...allIPs].slice(0, 20).map(ip => `<li>${ip}</li>`).join('') || '<li>None yet</li>'}</ul></div>
    <div class="ioc-group"><h4>File Paths</h4><ul>${[...allPaths].slice(0, 15).map(p => `<li>${p}</li>`).join('') || '<li>None yet</li>'}</ul></div>
    <div class="ioc-group"><h4>Hashes</h4><ul>${reports.slice(0, 10).map(r => `<li>${truncate(r.sha256, 32)}</li>`).join('') || '<li>None yet</li>'}</ul></div>
  `;
}

// Report detail
window.viewReport = async function(scanId) {
  const report = await api(`/report/${scanId}`);
  const modal = $('#report-modal');
  const detail = $('#report-detail');

  detail.innerHTML = `
    <div class="report-header">
      <div>
        <h3>${report.filename}</h3>
        <p style="font-family: var(--mono); font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">${report.sha256}</p>
      </div>
      <div class="report-score ${riskClass(report.risk_score)}">${report.risk_score}</div>
    </div>

    <div class="report-section">
      <h4>Detection Flags</h4>
      ${(report.flags || []).map(f => `<span class="flag-tag">${f}</span>`).join(' ') || 'None'}
    </div>

    <div class="report-section">
      <h4>Behavior Timeline (Sandbox Replay)</h4>
      <div class="timeline">
        ${(report.timeline || []).map(e => `
          <div class="timeline-item">
            <strong>[${e.phase}]</strong> ${e.event}
            <span style="color: var(--text-muted)"> @ ${e.timestamp?.toFixed(2)}s</span>
          </div>
        `).join('')}
      </div>
    </div>

    <div class="grid-2" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
      <div class="report-section">
        <h4>Processes</h4>
        <div class="code-block">${(report.behavior?.processes || []).join('\n') || 'None'}</div>
      </div>
      <div class="report-section">
        <h4>Network / Domains</h4>
        <div class="code-block">${(report.behavior?.domains || []).join('\n') || 'None'}</div>
      </div>
    </div>

    <div class="report-section">
      <h4>Static Analysis</h4>
      <div class="code-block">${JSON.stringify({
        file_type: report.static_analysis?.file_type,
        entropy: report.static_analysis?.entropy,
        packers: report.static_analysis?.packers,
        indicators: report.static_analysis?.suspicious_indicators,
        imports_count: report.static_analysis?.imports?.length,
      }, null, 2)}</div>
    </div>

    <div class="report-section">
      <h4>ML Scoring</h4>
      <div class="code-block">${JSON.stringify(report.ml_analysis, null, 2)}</div>
    </div>

    <div class="report-section">
      <h4>YARA Matches</h4>
      <div class="code-block">${JSON.stringify(report.yara_matches, null, 2)}</div>
    </div>

    <div class="report-section">
      <h4>Full Report JSON</h4>
      <div class="code-block">${JSON.stringify({
        risk_score: report.risk_score,
        flags: report.flags,
        behavior: report.behavior,
      }, null, 2)}</div>
    </div>
  `;

  modal.classList.remove('hidden');
};

$('#modal-close').addEventListener('click', () => $('#report-modal').classList.add('hidden'));
$('#report-modal').addEventListener('click', (e) => {
  if (e.target === $('#report-modal')) $('#report-modal').classList.add('hidden');
});

// Upload
const dropzone = $('#dropzone');
const fileInput = $('#file-input');

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length) uploadFile(fileInput.files[0]);
});

async function uploadFile(file) {
  const progress = $('#upload-progress');
  progress.classList.remove('hidden');

  const form = new FormData();
  form.append('file', file);

  try {
    const result = await fetch(API + '/scan', { method: 'POST', body: form });
    const data = await result.json();
    progress.classList.add('hidden');
    if (data.scan_id) {
      viewReport(data.scan_id);
      loadDashboard();
    }
  } catch (e) {
    progress.classList.add('hidden');
    alert('Upload failed: ' + e.message);
  }
}

// Hash search
$('#search-btn').addEventListener('click', async () => {
  const hash = $('#hash-search').value.trim();
  if (!hash) return;
  try {
    const report = await api(`/report/hash/${hash}`);
    viewReport(report.id);
  } catch {
    alert('No report found for this hash');
  }
});

loadDashboard();
// Project version: ThreatVault V1.2
