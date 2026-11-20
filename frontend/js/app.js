/**
 * BreachHunter OSINT - Frontend Application Logic
 * Connects frontend dashboard with backend REST APIs.
 */

const API_BASE = window.location.origin.startsWith('http') 
  ? window.location.origin 
  : 'http://127.0.0.1:5000';

let currentSearchResults = null;
let currentFilter = 'all';
let currentSearchTerm = '';

// DOM Elements
const statusBadge = document.getElementById('backend-status-badge');
const statusText = document.getElementById('backend-status-text');
const hunterForm = document.getElementById('hunter-form');
const btnSubmit = document.getElementById('btn-submit-search');
const btnSearchText = document.getElementById('btn-search-text');
const btnSearchIcon = document.getElementById('btn-search-icon');
const rawTargetsInput = document.getElementById('raw-targets');
const fileInput = document.getElementById('targets-file-input');
const btnLoadBreachedSample = document.getElementById('btn-load-breached-sample');
const btnClear = document.getElementById('btn-clear-targets');
const resultsSection = document.getElementById('results-section');
const resultsTbody = document.getElementById('results-tbody');
const toastEl = document.getElementById('toast');

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  checkBackendStatus();
  setupEventListeners();
  loadConfigKeys();
  loadHistory();
});

// Toast Notifications
function showToast(message, isError = false) {
  toastEl.textContent = message;
  toastEl.style.borderColor = isError ? 'var(--accent-danger)' : 'var(--accent-cyan)';
  toastEl.style.display = 'block';
  setTimeout(() => {
    toastEl.style.display = 'none';
  }, 3500);
}

// Navigation Tabs
function setupTabs() {
  const tabBtns = document.querySelectorAll('.nav-btn');
  const panes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');

      if (targetId === 'tab-history') {
        loadHistory();
      }
    });
  });
}

// Backend Health Check
async function checkBackendStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (res.ok) {
      const data = await res.json();
      statusBadge.classList.remove('offline');
      statusText.textContent = `Online • v${data.version}`;
    } else {
      throw new Error('Non-200 status');
    }
  } catch (err) {
    statusBadge.classList.add('offline');
    statusText.textContent = 'Backend Offline';
  }
}

// Setup Event Listeners
function setupEventListeners() {
  // Load known breached sample targets for instant verification
  if (btnLoadBreachedSample) {
    btnLoadBreachedSample.addEventListener('click', () => {
      rawTargetsInput.value = 'sayanchakraborty9@gmail.com\nadmin@evilcorp.com\njohn.smith@gmail.com';
      document.getElementById('opt-sample-db').checked = true;
      document.getElementById('opt-skip-defaults').checked = false;
      showToast('Loaded known sample targets (Click Launch OSINT Hunt to scan)');
    });
  }

  // Clear inputs
  if (btnClear) {
    btnClear.addEventListener('click', () => {
      rawTargetsInput.value = '';
      if (fileInput) fileInput.value = '';
      showToast('Inputs cleared');
    });
  }

  // File upload reader
  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        rawTargetsInput.value = event.target.result;
        showToast(`Loaded ${file.name}`);
      };
      reader.readAsText(file);
    });
  }

  // Search submission
  if (hunterForm) {
    hunterForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await executeSearch();
    });
  }

  // Filter Buttons
  const filterBtns = document.querySelectorAll('.filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter');
      applyResultsFilter();
    });
  });

  // Search filter input
  const searchInput = document.getElementById('results-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearchTerm = e.target.value.toLowerCase().trim();
      applyResultsFilter();
    });
  }

  // Export Buttons
  document.getElementById('btn-export-csv').addEventListener('click', exportCSV);
  document.getElementById('btn-export-json').addEventListener('click', exportJSON);

  // Local Scans: Load Demo DB
  const btnLocalDemo = document.getElementById('btn-local-load-demo');
  if (btnLocalDemo) {
    btnLocalDemo.addEventListener('click', () => {
      document.getElementById('local-cleartext-path').value = 'backend/data/sample_breaches.txt';
      document.getElementById('local-targets').value = 'sayanchakraborty9@gmail.com\njohn.smith@gmail.com\nadmin@evilcorp.com';
      showToast('Loaded demo dump path and targets');
    });
  }

  // Local scan form
  const localScanForm = document.getElementById('local-scan-form');
  if (localScanForm) {
    localScanForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await executeLocalScan();
    });
  }

  // API Config Form
  const configForm = document.getElementById('config-form');
  if (configForm) {
    configForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await saveConfigKeys();
    });
  }

  // Refresh History
  const btnRefreshHistory = document.getElementById('btn-refresh-history');
  if (btnRefreshHistory) {
    btnRefreshHistory.addEventListener('click', loadHistory);
  }

  // Clear History
  const btnClearHistory = document.getElementById('btn-clear-history');
  if (btnClearHistory) {
    btnClearHistory.addEventListener('click', clearHistory);
  }

  // Modal Close Events
  const modalCloseBtn = document.getElementById('modal-close-btn');
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', () => {
      document.getElementById('history-modal').style.display = 'none';
    });
  }
  const modalCloseAction = document.getElementById('modal-close-action');
  if (modalCloseAction) {
    modalCloseAction.addEventListener('click', () => {
      document.getElementById('history-modal').style.display = 'none';
    });
  }
  const historyModal = document.getElementById('history-modal');
  if (historyModal) {
    historyModal.addEventListener('click', (e) => {
      if (e.target.id === 'history-modal') {
        historyModal.style.display = 'none';
      }
    });
  }
}

// Execute OSINT Search
async function executeSearch() {
  const rawTargets = rawTargetsInput.value.trim();
  if (!rawTargets) {
    showToast('Please enter at least one target.', true);
    return;
  }

  const queryType = document.getElementById('query-type').value;
  const skipDefaults = document.getElementById('opt-skip-defaults').checked;
  const includeSampleDb = document.getElementById('opt-sample-db').checked;
  const hidePasswords = document.getElementById('opt-hide-passwords').checked;
  const debug = document.getElementById('opt-debug').checked;

  // Set loading state
  setLoading(true);

  const payload = {
    raw_targets: rawTargets,
    query_type: queryType,
    skip_defaults: skipDefaults,
    include_sample_db: includeSampleDb,
    hide_passwords: hidePasswords,
    debug: debug
  };

  try {
    const response = await fetch(`${API_BASE}/api/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Search request failed');
    }

    currentSearchResults = data;
    renderResults(data);
    showToast(`Reconnaissance finished: ${data.breached_targets} breached, ${data.safe_targets} safe.`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    setLoading(false);
  }
}

// Execute Local File Scan
async function executeLocalScan() {
  const cleartext = document.getElementById('local-cleartext-path').value.trim();
  const gzip = document.getElementById('local-gzip-path').value.trim();
  const targets = document.getElementById('local-targets').value.trim();

  if (!targets) {
    showToast('Enter targets to scan for in local dumps.', true);
    return;
  }

  if (!cleartext && !gzip) {
    showToast('Specify at least one cleartext or gzip file path.', true);
    return;
  }

  const payload = {
    raw_targets: targets,
    query_type: 'email',
    skip_defaults: true,
    include_sample_db: false,
    local_breach_files: cleartext ? [cleartext] : [],
    local_gzip_files: gzip ? [gzip] : []
  };

  const btnLocalSubmit = document.getElementById('btn-local-submit');
  const btnLocalIcon = document.getElementById('btn-local-icon');
  const btnLocalText = document.getElementById('btn-local-text');
  if (btnLocalSubmit) {
    btnLocalSubmit.disabled = true;
    if (btnLocalIcon) btnLocalIcon.innerHTML = '<span class="spinner"></span>';
    if (btnLocalText) btnLocalText.textContent = 'Searching Local Files...';
  }

  setLoading(true);

  try {
    const response = await fetch(`${API_BASE}/api/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Local scan failed');

    // Switch to hunter tab to see results
    document.querySelector('.nav-btn[data-tab="tab-hunter"]').click();
    currentSearchResults = data;
    renderResults(data);
    showToast('Local dump search completed!');
  } catch (err) {
    showToast(err.message, true);
  } finally {
    setLoading(false);
    if (btnLocalSubmit) {
      btnLocalSubmit.disabled = false;
      if (btnLocalIcon) btnLocalIcon.textContent = '⚡';
      if (btnLocalText) btnLocalText.textContent = 'Run Local File Scan';
    }
  }
}

// Loading state handler
function setLoading(isLoading) {
  if (isLoading) {
    btnSubmit.disabled = true;
    btnSearchIcon.innerHTML = '<span class="spinner"></span>';
    btnSearchText.textContent = 'Hunting Breaches & Exposures...';
  } else {
    btnSubmit.disabled = false;
    btnSearchIcon.innerHTML = '⚡';
    btnSearchText.textContent = 'Launch OSINT Hunt';
  }
}

// Render Results Table & Cards
function renderResults(data) {
  // Update stats counters
  document.getElementById('stat-total').textContent = data.total_targets || 0;
  document.getElementById('stat-breached').textContent = data.breached_targets || 0;
  document.getElementById('stat-safe').textContent = data.safe_targets || 0;
  document.getElementById('stat-time').textContent = `${data.execution_time_seconds || 0}s`;

  // Update filter pill counts
  document.getElementById('count-filter-all').textContent = data.total_targets || 0;
  document.getElementById('count-filter-breached').textContent = data.breached_targets || 0;
  document.getElementById('count-filter-safe').textContent = data.safe_targets || 0;

  applyResultsFilter();

  // Display and scroll
  resultsSection.style.display = 'block';
  resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Filter and Render Results
function applyResultsFilter() {
  if (!currentSearchResults || !currentSearchResults.results) return;

  resultsTbody.innerHTML = '';

  const filtered = currentSearchResults.results.filter(item => {
    // Status filter
    if (currentFilter === 'breached' && !item.is_breached) return false;
    if (currentFilter === 'safe' && item.is_breached) return false;

    // Search filter
    if (currentSearchTerm) {
      const matchTarget = item.target.toLowerCase().includes(currentSearchTerm);
      const matchFindings = (item.findings || []).some(f => 
        f.source.toLowerCase().includes(currentSearchTerm) || 
        f.detail.toLowerCase().includes(currentSearchTerm)
      );
      if (!matchTarget && !matchFindings) return false;
    }
    return true;
  });

  document.getElementById('results-count-label').textContent = `Showing ${filtered.length} of ${currentSearchResults.results.length} targets`;

  if (filtered.length === 0) {
    resultsTbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 2rem;">
          No matching targets found for the selected filter.
        </td>
      </tr>
    `;
    return;
  }

  filtered.forEach((item, targetIdx) => {
    const tr = document.createElement('tr');

    // Target Cell
    const tdTarget = document.createElement('td');
    tdTarget.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.35rem;">
        <span class="target-badge" style="color: ${item.is_breached ? '#f87171' : 'var(--text-primary)'}; word-break: break-all;">
          ${escapeHtml(item.target)}
        </span>
        <span style="font-size: 0.72rem; color: var(--text-muted);">
          Findings: <strong style="color: ${item.is_breached ? '#f87171' : 'var(--accent-emerald)'};">${item.pwned_count || 0}</strong> record(s)
        </span>
      </div>
    `;

    // Status Cell
    const tdStatus = document.createElement('td');
    if (item.is_breached) {
      tdStatus.innerHTML = `
        <span class="badge badge-breached" style="font-size: 0.8rem; padding: 0.35rem 0.75rem;">
          🔴 ${escapeHtml(item.status)}
        </span>
      `;
    } else {
      tdStatus.innerHTML = `
        <span class="badge badge-safe" style="font-size: 0.8rem; padding: 0.35rem 0.75rem;">
          🟢 Clean / Not Compromised
        </span>
      `;
    }

    // Findings Cell
    const tdFindings = document.createElement('td');
    let findingsHtml = '';

    if (item.findings && item.findings.length > 0) {
      // Categorize findings
      const localFindings = [];
      const xonFindings = [];
      const leaklookupFindings = [];
      const otherFindings = [];

      item.findings.forEach(f => {
        const src = (f.source || '').toUpperCase();
        if (src === 'LOCALSEARCH') {
          localFindings.push(f);
        } else if (src === 'XPOSEDORNOT') {
          xonFindings.push(f);
        } else if (src.includes('LEAKLOOKUP')) {
          leaklookupFindings.push(f);
        } else {
          otherFindings.push(f);
        }
      });

      findingsHtml += '<div class="breach-groups-wrapper">';

      // 1. High Priority: Local Credential / Dump Matches
      if (localFindings.length > 0) {
        findingsHtml += `
          <div class="credential-alert-box">
            <span class="cred-icon">🚨</span>
            <div style="flex: 1;">
              <strong style="color: #f87171;">Local Credential Match (${localFindings.length}):</strong>
              ${localFindings.map(l => `<div class="cred-content" style="margin-top: 3px;">${escapeHtml(l.detail)}</div>`).join('')}
            </div>
          </div>
        `;
      }

      // 2. XposedOrNot Breaches (Categorized Chip Cloud)
      if (xonFindings.length > 0) {
        const cleanBreaches = xonFindings.map(f => f.detail.replace(/^Breach Exposure:\s*/i, '').trim());
        findingsHtml += `
          <div class="breach-group-card">
            <div class="breach-group-header">
              <div class="breach-group-title">
                <span class="source-tag" style="background: rgba(239, 68, 68, 0.18); color: #f87171;">XposedOrNot</span>
                <span class="breach-count-pill">${xonFindings.length} Breaches</span>
              </div>
              <div class="breach-group-actions">
                ${cleanBreaches.length > 12 ? `<input type="text" class="chip-filter-input" placeholder="Search (${cleanBreaches.length})..." oninput="filterChips(this, 'chips-xon-${targetIdx}')">` : ''}
                ${cleanBreaches.length > 20 ? `<button class="toggle-chips-btn" onclick="toggleChips('chips-xon-${targetIdx}', this, ${cleanBreaches.length})">Show All (${cleanBreaches.length})</button>` : ''}
              </div>
            </div>
            <div class="breach-chips-container" id="chips-xon-${targetIdx}">
              ${cleanBreaches.map(b => `<span class="breach-chip source-xon">${escapeHtml(b)}</span>`).join('')}
            </div>
          </div>
        `;
      }

      // 3. Leak-Lookup Breaches (Categorized Chip Cloud)
      if (leaklookupFindings.length > 0) {
        const cleanLL = leaklookupFindings.map(f => f.detail.trim());
        findingsHtml += `
          <div class="breach-group-card">
            <div class="breach-group-header">
              <div class="breach-group-title">
                <span class="source-tag" style="background: rgba(139, 92, 246, 0.18); color: #c4b5fd;">Leak-Lookup</span>
                <span class="breach-count-pill" style="color: #c4b5fd; border-color: rgba(139, 92, 246, 0.3); background: rgba(139, 92, 246, 0.1);">${leaklookupFindings.length} Breaches</span>
              </div>
              <div class="breach-group-actions">
                ${cleanLL.length > 12 ? `<input type="text" class="chip-filter-input" placeholder="Search (${cleanLL.length})..." oninput="filterChips(this, 'chips-ll-${targetIdx}')">` : ''}
                ${cleanLL.length > 20 ? `<button class="toggle-chips-btn" onclick="toggleChips('chips-ll-${targetIdx}', this, ${cleanLL.length})">Show All (${cleanLL.length})</button>` : ''}
              </div>
            </div>
            <div class="breach-chips-container" id="chips-ll-${targetIdx}">
              ${cleanLL.map(b => `<span class="breach-chip source-leaklookup">${escapeHtml(b)}</span>`).join('')}
            </div>
          </div>
        `;
      }

      // 4. Other Sources (EmailRep, Hunter, HIBP, etc.)
      if (otherFindings.length > 0) {
        findingsHtml += `
          <div class="breach-group-card">
            <div class="breach-group-header">
              <div class="breach-group-title">
                <span class="source-tag">Other OSINT Sources</span>
                <span class="breach-count-pill">${otherFindings.length}</span>
              </div>
            </div>
            <div style="display: flex; flex-direction: column; gap: 0.35rem;">
              ${otherFindings.map(o => `
                <div class="finding-item">
                  <span class="source-tag">${escapeHtml(o.source)}</span>
                  <span>${escapeHtml(o.detail)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }

      findingsHtml += '</div>';
    } else {
      const isOffline = document.getElementById('opt-skip-defaults') && document.getElementById('opt-skip-defaults').checked;
      findingsHtml += `<div style="color: var(--text-muted); font-size: 0.82rem; margin-bottom: 0.4rem;">
        No credential exposures or password breaches found in queried databases.
        ${isOffline ? '<div style="margin-top: 0.35rem; color: #fbbf24; font-size: 0.8rem;">⚠️ <strong>Offline Mode was enabled:</strong> Online APIs were skipped. Uncheck <em>"Offline Mode Only"</em> above and click <em>Launch OSINT Hunt</em> to scan live online breach databases!</div>' : ''}
      </div>`;
    }

    // Engine Audit Trail
    if (item.engines_checked && item.engines_checked.length > 0) {
      findingsHtml += '<div style="margin-top: 0.6rem; display: flex; flex-wrap: wrap; gap: 0.35rem;">';
      item.engines_checked.forEach(eng => {
        const statusLower = eng.status.toLowerCase();
        const isFound = statusLower.includes('found') || statusLower.includes('detected') || statusLower.includes('match');
        const isWarn = statusLower.includes('requires') || statusLower.includes('needed') || statusLower.includes('rate') || statusLower.includes('error') || statusLower.includes('failed') || statusLower.includes('timeout') || statusLower.includes('not configured') || statusLower.includes('invalid');
        const isClean = statusLower.includes('clean');

        let color = 'var(--text-muted)';
        let bg = 'rgba(255, 255, 255, 0.05)';
        let border = 'rgba(255, 255, 255, 0.08)';

        if (isFound) {
          color = '#f87171';
          bg = 'rgba(239, 68, 68, 0.15)';
          border = 'rgba(239, 68, 68, 0.3)';
        } else if (isWarn) {
          color = '#fbbf24';
          bg = 'rgba(251, 191, 36, 0.12)';
          border = 'rgba(251, 191, 36, 0.25)';
        } else if (isClean) {
          color = '#34d399';
          bg = 'rgba(52, 211, 153, 0.12)';
          border = 'rgba(52, 211, 153, 0.25)';
        }

        findingsHtml += `
          <span style="font-size: 0.68rem; background: ${bg}; color: ${color}; border-radius: 4px; padding: 0.15rem 0.45rem; border: 1px solid ${border};">
            ${escapeHtml(eng.engine)}: ${escapeHtml(eng.status)}
          </span>
        `;
      });
      findingsHtml += '</div>';
    }

    tdFindings.innerHTML = findingsHtml;

    tr.appendChild(tdTarget);
    tr.appendChild(tdStatus);
    tr.appendChild(tdFindings);
    resultsTbody.appendChild(tr);
  });
}

// Export CSV
function exportCSV() {
  if (!currentSearchResults || !currentSearchResults.results) {
    showToast('No search results to export', true);
    return;
  }

  const rows = [
    ['Target', 'Status', 'Pwned Count', 'Source', 'Details']
  ];

  currentSearchResults.results.forEach(r => {
    if (r.findings && r.findings.length > 0) {
      r.findings.forEach(f => {
        rows.push([
          `"${r.target}"`,
          `"${r.status}"`,
          r.pwned_count,
          `"${f.source}"`,
          `"${f.detail.replace(/"/g, '""')}"`
        ]);
      });
    } else {
      rows.push([
        `"${r.target}"`,
        `"${r.status}"`,
        0,
        'N/A',
        'None'
      ]);
    }
  });

  const csvContent = 'data:text/csv;charset=utf-8,' + rows.map(e => e.join(',')).join('\n');
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', `breachhunter_osint_results_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast('Downloaded results as CSV');
}

// Export JSON
function exportJSON() {
  if (!currentSearchResults) {
    showToast('No search results to export', true);
    return;
  }

  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentSearchResults, null, 2));
  const link = document.createElement('a');
  link.setAttribute('href', dataStr);
  link.setAttribute('download', `breachhunter_osint_results_${Date.now()}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast('Downloaded results as JSON');
}

// Load and Save API Config
async function loadConfigKeys() {
  try {
    const res = await fetch(`${API_BASE}/api/config`);
    if (res.ok) {
      const data = await res.json();
      if (data.keys) {
        if (data.keys.hibp) document.getElementById('cfg-hibp').placeholder = `Configured: ${data.keys.hibp}`;
        if (data.keys.hunterio) document.getElementById('cfg-hunterio').placeholder = `Configured: ${data.keys.hunterio}`;
        if (data.keys.emailrep) document.getElementById('cfg-emailrep').placeholder = `Configured: ${data.keys.emailrep}`;
        if (data.keys.snusbase_token) document.getElementById('cfg-snusbase').placeholder = `Configured: ${data.keys.snusbase_token}`;
        if (data.keys.intelx_key) document.getElementById('cfg-intelx').placeholder = `Configured: ${data.keys.intelx_key}`;
        if (data.keys.dehashed_email) document.getElementById('cfg-dehashed-email').placeholder = `Configured: ${data.keys.dehashed_email}`;
        if (data.keys.dehashed_key) document.getElementById('cfg-dehashed-key').placeholder = `Configured: ${data.keys.dehashed_key}`;
      }
    }
  } catch (err) {
    // Silent on load
  }
}

async function saveConfigKeys() {
  const keys = {
    hibp: document.getElementById('cfg-hibp').value,
    hunterio: document.getElementById('cfg-hunterio').value,
    emailrep: document.getElementById('cfg-emailrep') ? document.getElementById('cfg-emailrep').value : '',
    snusbase_token: document.getElementById('cfg-snusbase').value,
    intelx_key: document.getElementById('cfg-intelx').value,
    dehashed_email: document.getElementById('cfg-dehashed-email').value,
    dehashed_key: document.getElementById('cfg-dehashed-key').value,
    leaklookup_priv: document.getElementById('cfg-leaklookup').value,
    breachdirectory_pass: document.getElementById('cfg-breachdirectory').value,
  };

  try {
    const res = await fetch(`${API_BASE}/api/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keys })
    });
    if (res.ok) {
      showToast('API Keys saved successfully!');
      loadConfigKeys();
    } else {
      showToast('Failed to save API keys', true);
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

// Global cache for history
window.currentHistory = [];

// History
async function loadHistory() {
  const historyTbody = document.getElementById('history-tbody');
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    if (res.ok) {
      const data = await res.json();
      window.currentHistory = data.history || [];
      if (window.currentHistory.length > 0) {
        historyTbody.innerHTML = '';
        window.currentHistory.slice().reverse().forEach(h => {
          const tr = document.createElement('tr');

          // 1. Scan ID
          const scanId = h.id || 'SCN-LEGACY';

          // 2. Target(s) representation
          let targetText = 'No targets';
          let targetBadge = '';
          if (h.targets && h.targets.length > 0) {
            targetText = h.targets[0];
            if (h.targets.length > 1) {
              targetBadge = `<span class="source-tag" style="margin-left: 4px; font-size: 0.65rem;">+${h.targets.length - 1}</span>`;
            }
          } else if (h.targets_count) {
            targetText = `${h.targets_count} target(s)`;
          }

          // 3. Timing
          const timingText = h.execution_time_seconds 
            ? `${h.execution_time_seconds}s` 
            : '0.01s';

          // 4. Result badge
          const isBreached = (h.breached_count || 0) > 0;
          const totalFindings = h.total_findings || h.breached_count || 0;
          const resultBadge = isBreached 
            ? `<span class="badge badge-breached" style="font-size: 0.75rem;">🔴 ${h.breached_count} Breached (${totalFindings} findings)</span>`
            : `<span class="badge badge-safe" style="font-size: 0.75rem;">🟢 All Safe</span>`;

          // 5. Breach Highlights
          let hlHtml = '';
          if (h.breach_highlights && h.breach_highlights.length > 0) {
            hlHtml = '<div style="display: flex; flex-wrap: wrap; gap: 3px;">';
            h.breach_highlights.slice(0, 3).forEach(b => {
              hlHtml += `<span class="breach-chip" style="font-size: 0.68rem; padding: 1px 5px;">${escapeHtml(b)}</span>`;
            });
            if (h.breach_highlights.length > 3) {
              hlHtml += `<span style="font-size: 0.68rem; color: var(--text-muted); align-self: center;">+${h.breach_highlights.length - 3}</span>`;
            }
            hlHtml += '</div>';
          } else {
            hlHtml = `<span style="color: var(--text-muted); font-size: 0.75rem;">${isBreached ? 'Exposures noted' : 'None'}</span>`;
          }

          tr.innerHTML = `
            <td><span class="source-tag" style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(scanId)}</span></td>
            <td style="font-size: 0.78rem; color: var(--text-secondary); white-space: nowrap;">${escapeHtml(h.timestamp)}</td>
            <td>
              <span style="font-family: var(--font-mono); font-size: 0.8rem; word-break: break-all;">${escapeHtml(targetText)}</span>
              ${targetBadge}
            </td>
            <td><span style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 0.8rem;">${timingText}</span></td>
            <td>${resultBadge}</td>
            <td>${hlHtml}</td>
            <td style="text-align: right;">
              <div style="display: flex; gap: 0.4rem; justify-content: flex-end;">
                <button class="btn-action-rescan" onclick="rescanFromHistory('${escapeHtml(scanId)}')">
                  <span>⚡</span> Re-scan
                </button>
                <button class="btn-action-view" onclick="viewHistoryDetails('${escapeHtml(scanId)}')">
                  <span>👁️</span> Details
                </button>
              </div>
            </td>
          `;
          historyTbody.appendChild(tr);
        });
      } else {
        historyTbody.innerHTML = `
          <tr>
            <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No recent searches in this session yet.</td>
          </tr>
        `;
      }
    }
  } catch (err) {
    // Ignore history error
  }
}

// Clear History
async function clearHistory() {
  if (!confirm('Are you sure you want to clear your reconnaissance scan history?')) return;
  try {
    const res = await fetch(`${API_BASE}/api/history/clear`, { method: 'POST' });
    if (res.ok) {
      showToast('Scan history cleared successfully');
      loadHistory();
    } else {
      showToast('Failed to clear history', true);
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

// Re-scan from History
window.rescanFromHistory = function(scanId) {
  const item = (window.currentHistory || []).find(x => x.id === scanId);
  if (!item || !item.targets || item.targets.length === 0) {
    showToast('Targets not found for this scan record', true);
    return;
  }
  // Switch to Breach Hunter tab
  const hunterNav = document.querySelector('.nav-btn[data-tab="tab-hunter"]');
  if (hunterNav) hunterNav.click();

  rawTargetsInput.value = item.targets.join('\n');
  const qType = document.getElementById('query-type');
  if (qType && item.query_type) qType.value = item.query_type;
  
  // Uncheck offline mode so live reconnaissance runs
  const offlineCheck = document.getElementById('opt-skip-defaults');
  if (offlineCheck) offlineCheck.checked = false;

  showToast(`Loaded ${item.targets.length} target(s) from ${scanId}. Launching OSINT hunt...`);
  executeSearch();
};

// View History Details Modal
window.viewHistoryDetails = function(scanId) {
  const item = (window.currentHistory || []).find(x => x.id === scanId);
  if (!item) {
    showToast('Scan details not found', true);
    return;
  }

  const modal = document.getElementById('history-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalBody = document.getElementById('modal-body');
  const rescanBtn = document.getElementById('modal-rescan-btn');

  modalTitle.innerHTML = `<span>📜</span> Scan Report: <span style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 1rem;">${escapeHtml(item.id || 'Session Scan')}</span>`;

  let bodyHtml = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin-bottom: 1.25rem;">
      <div class="stat-card" style="padding: 0.75rem;">
        <span class="stat-label">Timestamp</span>
        <span style="font-size: 0.8rem; font-weight: 600;">${escapeHtml(item.timestamp)}</span>
      </div>
      <div class="stat-card" style="padding: 0.75rem;">
        <span class="stat-label">Execution Time</span>
        <span style="font-size: 0.85rem; font-weight: 600; color: var(--accent-cyan);">${item.execution_time_seconds || 0}s</span>
      </div>
      <div class="stat-card ${(item.breached_count || 0) > 0 ? 'breached' : 'safe'}" style="padding: 0.75rem;">
        <span class="stat-label">Status</span>
        <span style="font-size: 0.85rem; font-weight: 600;">${(item.breached_count || 0) > 0 ? `🔴 ${item.breached_count} Breached` : '🟢 All Safe'}</span>
      </div>
      <div class="stat-card" style="padding: 0.75rem;">
        <span class="stat-label">Total Findings</span>
        <span style="font-size: 0.85rem; font-weight: 600; color: #f87171;">${item.total_findings || item.breached_count || 0} records</span>
      </div>
    </div>
    
    <div style="margin-bottom: 0.5rem;">
      <h4 style="font-size: 0.88rem; color: var(--accent-cyan); margin-bottom: 0.75rem;">Scanned Targets & Findings Breakdown:</h4>
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
  `;

  if (item.results && item.results.length > 0) {
    item.results.forEach(r => {
      bodyHtml += `
        <div style="background: rgba(13, 19, 31, 0.7); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 0.85rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
            <strong style="font-family: var(--font-mono); font-size: 0.9rem; color: ${r.is_breached ? '#f87171' : 'var(--text-primary)'};">${escapeHtml(r.target)}</strong>
            <span class="badge ${r.is_breached ? 'badge-breached' : 'badge-safe'}">${escapeHtml(r.status)}</span>
          </div>
          ${r.findings && r.findings.length > 0 ? `
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.4rem;">Exposures & Breaches (${r.findings.length} findings):</div>
            <div style="display: flex; flex-wrap: wrap; gap: 0.3rem; max-height: 160px; overflow-y: auto; padding-right: 4px;">
              ${r.findings.slice(0, 50).map(f => {
                const cleanDet = (f.detail || '').replace(/^Breach Exposure:\s*/i, '');
                const isLoc = (f.source || '').toUpperCase() === 'LOCALSEARCH';
                const style = isLoc ? 'border-color: rgba(239, 68, 68, 0.4); background: rgba(239,68,68,0.1); color: #fca5a5;' : '';
                return `<span class="breach-chip" style="${style}">${escapeHtml(cleanDet)}</span>`;
              }).join('')}
              ${r.findings.length > 50 ? `<span style="font-size: 0.72rem; color: var(--text-muted); align-self: center;">+${r.findings.length - 50} more</span>` : ''}
            </div>
          ` : `<div style="font-size: 0.78rem; color: var(--text-muted);">No breach exposures or leaked passwords detected.</div>`}
        </div>
      `;
    });
  } else if (item.targets) {
    item.targets.forEach(t => {
      bodyHtml += `
        <div style="background: rgba(13, 19, 31, 0.7); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 0.75rem;">
          <span style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHtml(t)}</span>
        </div>
      `;
    });
  }

  bodyHtml += `
      </div>
    </div>
  `;

  modalBody.innerHTML = bodyHtml;
  rescanBtn.onclick = () => {
    modal.style.display = 'none';
    rescanFromHistory(item.id);
  };

  modal.style.display = 'flex';
};

// Chip expand/collapse toggle
window.toggleChips = function(containerId, btn, totalCount) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (container.classList.contains('expanded')) {
    container.classList.remove('expanded');
    btn.textContent = `Show All (${totalCount})`;
  } else {
    container.classList.add('expanded');
    btn.textContent = 'Collapse';
  }
};

// Mini chip search filter
window.filterChips = function(input, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const filter = input.value.toLowerCase().trim();
  const chips = container.querySelectorAll('.breach-chip');
  chips.forEach(chip => {
    const txt = chip.textContent.toLowerCase();
    chip.style.display = txt.includes(filter) ? 'inline-flex' : 'none';
  });
};

// Utility: HTML Escaping
function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
