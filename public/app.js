const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

let devices = [];
let threatsData = null;
let isBenchmarking = false;
let selectedIncidentId = null;

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const fmt = t => t ? new Date(t).toLocaleTimeString([], {
  hour: '2-digit', minute: '2-digit', second: '2-digit'
}) : '--';

const fmtFull = t => t ? new Date(t).toLocaleString([], {
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit'
}) : '--';

async function api(url, opts = {}) {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function showError(err) {
  const msg = esc(err.message || 'Unexpected error');
  const active = $('.page.active');
  if (active) {
    let box = active.querySelector('.inline-error');
    if (!box) {
      box = document.createElement('div');
      box.className = 'inline-error';
      box.style.cssText = 'padding:10px 14px;margin:14px 0;background:#FBE9E7;color:#D64545;border-radius:5px;font-size:12px;font-weight:600;';
      active.prepend(box);
    }
    box.textContent = msg;
    setTimeout(() => { if (box && box.parentNode) box.remove(); }, 6000);
  }
}

function showSuccess(msg) {
  const active = $('.page.active');
  if (active) {
    let box = active.querySelector('.inline-success');
    if (!box) {
      box = document.createElement('div');
      box.className = 'inline-success';
      box.style.cssText = 'padding:10px 14px;margin:14px 0;background:#E8F5E9;color:#27845B;border-radius:5px;font-size:12px;font-weight:600;';
      active.prepend(box);
    }
    box.textContent = msg;
    setTimeout(() => { if (box && box.parentNode) box.remove(); }, 5000);
  }
}

// -------------------------------------------------------------
// Navigation
// -------------------------------------------------------------
const pageNames = {
  overview: 'Security Overview',
  devices: 'Virtual Devices (4 Supported Models)',
  updates: '3D Attack Simulation',
  lab: 'Safe Attack Simulation Lab',
  investigations: 'Incident Forensics & Investigation (22 Fields)',
  alerts: 'Rule-Based Attack Alerts',
  logs: 'Security Event Logs (SQLite)',
  anomalies: 'Anomaly Detection Rules',
  keys: 'Trusted Public Keys (Ed25519)',
  docker: 'Docker Container Health',
  performance: 'Performance Overhead Measurement',
  threatmodel: 'Threat Model & Security Analysis',
  audit: 'Security Audit Logs',
  reports: 'Reports & Data Exports',
  settings: 'Settings & Detection Thresholds'
};

function go(page) {
  if (page === 'lab') page = 'updates';
  $$('.page').forEach(p => p.classList.toggle('active', p.id === `page-${page}`));
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  $('#pageName').textContent = pageNames[page] || 'Overview';

  if (page === 'overview') loadOverview();
  else if (page === 'devices') loadDevices();
  else if (page === 'updates') {
    loadUpdatesPage();
    setTimeout(() => { if (typeof onWindowResize === 'function') onWindowResize(); }, 60);
  }
  else if (page === 'investigations') loadIncidentsPage();
  else if (page === 'alerts') loadAlertsPage();
  else if (page === 'logs') loadEvents();
  else if (page === 'anomalies') loadAnomalyRulesPage();
  else if (page === 'keys') loadTrustedKeysPage();
  else if (page === 'docker') loadDockerPage();
  else if (page === 'performance') loadBenchmarkHistory();
  else if (page === 'threatmodel') loadThreatModel();
  else if (page === 'audit') loadAuditLogsPage();
  else if (page === 'settings') loadSettingsPage();
}

// -------------------------------------------------------------
// PAGE 1: Overview
// -------------------------------------------------------------
async function loadOverview() {
  try {
    const metrics = await api('/api/metrics');
    $('#metricDevices').textContent = String(metrics.devices).padStart(2, '0');
    $('#metricVerified').textContent = String(metrics.verified).padStart(2, '0');
    $('#metricRejected').textContent = String(metrics.rejected).padStart(2, '0');
    $('#metricAlerts').textContent = String(metrics.alerts).padStart(2, '0');

    devices = await api('/api/devices');
    const tbody = $('#overviewDeviceRows');
    tbody.innerHTML = devices.map(d => `
      <tr>
        <td>
          <div style="display:flex;align-items:center;gap:10px;">
            <img src="${esc(d.image_url)}" class="thumb-inline" alt="${esc(d.name)}">
            <div>
              <strong>${esc(d.name)}</strong>
              <small style="display:block;color:var(--muted);font-size:11px;">${esc(d.id)} · ${esc(d.category)}</small>
            </div>
          </div>
        </td>
        <td>${esc(d.model)}</td>
        <td>v${esc(d.firmware_version)} <span style="color:var(--muted);font-size:10px;">(min v${esc(d.minimum_version)})</span></td>
        <td>
          <span class="badge ${d.risk_level === 'High' ? 'bad' : d.risk_level === 'Medium' ? 'warn' : 'ok'}">
            ${esc(d.risk_level)} Risk
          </span>
        </td>
        <td>
          <button class="btn secondary" style="padding:4px 8px;min-height:26px;font-size:11px;" onclick="openDeviceModal('${esc(d.id)}')">Console ↗</button>
        </td>
      </tr>
    `).join('');

    const events = await api('/api/events?limit=8');
    const eventList = $('#recentEvents');
    if (!events.length) {
      eventList.innerHTML = '<div class="empty">No recent events recorded yet.</div>';
    } else {
      eventList.innerHTML = events.map(e => `
        <div class="event-item">
          <div>
            <strong>${esc(e.event_type)}</strong>
            <small>${esc(e.device_id)} · ${esc(e.description || e.reason_code || '')}</small>
          </div>
          <div style="text-align:right;">
            <span class="badge ${e.severity === 'HIGH' || e.severity === 'CRITICAL' ? 'bad' : e.severity === 'MEDIUM' ? 'warn' : 'ok'}">
              ${esc(e.verification_result || e.response_outcome || 'LOGGED')}
            </span>
            <small style="display:block;margin-top:4px;">${fmt(e.timestamp)}</small>
          </div>
        </div>
      `).join('');
    }

    // Load 3D Simulation Trials Today
    try {
      const trials = await api('/api/ota/auto-update-server/trials?limit=8');
      const trialsRows = $('#overviewTrialsRows');
      if (trialsRows) {
        if (!trials || !trials.length) {
          trialsRows.innerHTML = `<tr><td colspan="7" class="empty" style="text-align:center;padding:16px;">No 3D simulation trials executed yet today. Click "Open 3D Simulator" to run automated tests.</td></tr>`;
        } else {
          trialsRows.innerHTML = trials.map(t => `
            <tr>
              <td><b>${fmt(t.timestamp)}</b></td>
              <td><strong>${esc(t.deviceName)}</strong> <small style="display:block;color:var(--muted);">${esc(t.deviceId)}</small></td>
              <td><code>${esc(t.fileName)}</code></td>
              <td>
                <span class="badge ${t.packageType === 'valid' ? 'ok' : 'bad'}">
                  ${t.packageType === 'valid' ? 'VALID FIRMWARE' : 'ATTACK PAYLOAD'}
                </span>
              </td>
              <td>
                ${t.decision === 'APPROVED'
                  ? '<span style="color:#27845B;font-weight:700;">🟢 Green Path · Delivered</span>'
                  : '<span style="color:#D64545;font-weight:700;">🔴 Red Path · Blocked</span>'}
              </td>
              <td>
                <span class="badge ${t.decision === 'APPROVED' ? 'ok' : 'bad'}">${esc(t.decision)}</span>
              </td>
              <td style="font-size:12px;color:var(--muted);max-width:260px;">${esc(t.reason || 'Checks executed')}</td>
            </tr>
          `).join('');
        }
      }
    } catch (e) {
      console.warn('Could not load 3D trials for overview:', e);
    }
  } catch (err) {
    showError(err);
  }
}

// -------------------------------------------------------------
// PAGE 2: Virtual Devices Inventory (Exactly 4 Supported Models)
// -------------------------------------------------------------
async function loadDevices() {
  try {
    devices = await api('/api/devices');
    const container = $('#deviceCards');
    container.innerHTML = devices.map(d => `
      <article class="device-card">
        <div class="device-img-frame">
          <img src="${esc(d.image_url)}" alt="${esc(d.name)}" onerror="this.src='/images/tapo-c200.png'">
          <span class="badge neutral" style="position:absolute;top:10px;left:10px;background:rgba(255,255,255,0.9);">
            ${esc(d.mode || 'SIMULATED')}
          </span>
          <span class="badge ${d.device_status === 'Online' ? 'ok' : 'warn'}" style="position:absolute;top:10px;right:10px;">
            <span class="dot ${d.device_status === 'Online' ? 'green' : 'warn'}"></span> ${esc(d.device_status)}
          </span>
        </div>
        <div class="device-card-body" style="padding:16px;">
          <h2 style="font-size:15px;margin-bottom:4px;">${esc(d.name)}</h2>
          <p style="color:var(--muted);font-size:12px;margin:0 0 12px;"><strong>${esc(d.id)}</strong> · ${esc(d.model)}</p>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;margin-bottom:14px;background:#faf8f5;padding:10px;border-radius:6px;border:1px solid var(--border);">
            <div><span style="color:var(--muted);">FIRMWARE:</span> <b>v${esc(d.firmware_version)}</b></div>
            <div><span style="color:var(--muted);">MIN POLICY:</span> <b>v${esc(d.minimum_version)}</b></div>
            <div><span style="color:var(--muted);">POLICY RULE:</span> <b>${esc(d.policy_version)}</b></div>
            <div><span style="color:var(--muted);">TRUSTED KEY:</span> <b>${esc(d.trusted_key_id.slice(0, 14))}...</b></div>
            <div><span style="color:var(--muted);">IP ADDRESS:</span> <b>${esc(d.ip_address || 'Unassigned')}</b></div>
            <div><span style="color:var(--muted);">LAST SEEN:</span> <b>${fmt(d.last_seen_at)}</b></div>
          </div>

          <div style="margin-bottom:14px;">
            <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;">
              <span>Security Risk:</span>
              <span class="badge ${d.risk_level === 'High' ? 'bad' : d.risk_level === 'Medium' ? 'warn' : 'ok'}">${esc(d.risk_level)}</span>
            </div>
            <p style="font-size:11px;color:var(--muted);margin:0;line-height:1.3;">${esc(d.risk_explanation)}</p>
          </div>

          <div style="display:flex;gap:8px;">
            <button class="btn primary full" style="font-size:11px;min-height:34px;" onclick="openDeviceModal('${esc(d.id)}')">Interactive Console ⚙</button>
            <button class="btn secondary" style="font-size:11px;min-height:34px;" onclick="triggerHeartbeat('${esc(d.id)}')">Ping ♥</button>
          </div>
        </div>
      </article>
    `).join('');
  } catch (err) {
    showError(err);
  }
}

// -------------------------------------------------------------
// Interactive Device Console Modal
// -------------------------------------------------------------
let keypadBuffer = '';

async function openDeviceModal(deviceId) {
  try {
    const d = await api(`/api/devices/${deviceId}`);
    $('#modalDeviceTitle').textContent = `${d.name} (${d.model})`;

    let specializedControls = '';

    if (d.type === 'smart_lock') {
      // ESP32 Smart Locker Keypad Simulator
      const lockState = d.telemetry?.lockState || 'LOCKED';
      specializedControls = `
        <div class="panel form-panel" style="margin-bottom:16px;">
          <h3>ESP32 Solenoid Lock & 4×4 Matrix Keypad Simulation</h3>
          <p style="font-size:12px;color:var(--muted);">
            Reference hardware: ESP32 DevKit, 4×4 tactile keypad, and 12V solenoid lock. Enter PIN <code>1234</code> to trigger authorized solenoid unlock. Invalid PINs trigger brute-force anomaly detection. Plaintext PINs are never logged.
          </p>
          <div style="display:flex;align-items:center;gap:16px;margin:14px 0;">
            <span style="font-size:13px;font-weight:700;">Current Solenoid State:</span>
            <span class="badge ${lockState === 'UNLOCKED' ? 'ok' : 'bad'}" id="solenoidBadge" style="font-size:13px;padding:6px 12px;">
              ${lockState === 'UNLOCKED' ? '🔓 UNLOCKED (12V ACTIVE)' : '🔒 LOCKED (SECURED)'}
            </span>
          </div>

          <div class="keypad-container">
            <div class="keypad-display" id="keypadScreen">----</div>
            <div class="keypad-grid">
              <button class="key-btn" onclick="pressKey('1')">1</button>
              <button class="key-btn" onclick="pressKey('2')">2</button>
              <button class="key-btn" onclick="pressKey('3')">3</button>
              <button class="key-btn action" onclick="pressKey('A')">A</button>
              <button class="key-btn" onclick="pressKey('4')">4</button>
              <button class="key-btn" onclick="pressKey('5')">5</button>
              <button class="key-btn" onclick="pressKey('6')">6</button>
              <button class="key-btn action" onclick="pressKey('B')">B</button>
              <button class="key-btn" onclick="pressKey('7')">7</button>
              <button class="key-btn" onclick="pressKey('8')">8</button>
              <button class="key-btn" onclick="pressKey('9')">9</button>
              <button class="key-btn action" onclick="pressKey('C')">C</button>
              <button class="key-btn action" onclick="clearKeypad()">CLR</button>
              <button class="key-btn" onclick="pressKey('0')">0</button>
              <button class="key-btn action" style="background:#27845B;" onclick="submitKeypadPin('${d.id}')">ENT</button>
              <button class="key-btn action" onclick="pressKey('D')">D</button>
            </div>
            <small style="color:#aaa;font-size:11px;">Valid Master PIN: <strong>1234</strong> · Click ENT to submit</small>
          </div>
          <div id="keypadFeedback" style="margin-top:10px;font-size:12px;font-weight:600;"></div>
        </div>
      `;
    } else if (d.type === 'environmental_sensor') {
      // DHT22 / AM2302 Sensor Simulator
      const t = d.telemetry?.temperatureCelsius ?? 22.4;
      const h = d.telemetry?.humidityPercent ?? 48.2;
      specializedControls = `
        <div class="panel form-panel" style="margin-bottom:16px;">
          <h3>DHT22 / AM2302 Sensor Telemetry Simulation</h3>
          <p style="font-size:12px;color:var(--muted);">
            Digital capacitive temperature and relative humidity sensor. Normal envelope: -10°C to 45°C, 15% to 85% RH. Values outside this range trigger explainable telemetry alerts.
          </p>
          <div class="config-grid" style="margin-top:14px;">
            <label>Temperature (°C)
              <input type="number" id="inputSensorTemp" value="${t}" step="0.5" min="-20" max="80">
            </label>
            <label>Humidity (% RH)
              <input type="number" id="inputSensorHum" value="${h}" step="1" min="0" max="100">
            </label>
          </div>
          <div style="display:flex;gap:10px;margin-top:12px;">
            <button class="btn primary" onclick="sendSensorTelemetry('${d.id}')">Submit Simulated Telemetry</button>
            <button class="btn secondary" onclick="simulateSensorAnomaly('${d.id}')">Trigger Out-of-Bounds Test (68°C)</button>
          </div>
          <div id="sensorFeedback" style="margin-top:10px;font-size:12px;font-weight:600;"></div>
        </div>
      `;
    } else if (d.type === 'camera') {
      // TP-Link Tapo C200 Camera Simulator
      specializedControls = `
        <div class="panel form-panel" style="margin-bottom:16px;">
          <h3>TP-Link Tapo C200 Service & Access Simulation</h3>
          <p style="font-size:12px;color:var(--muted);">
            Simulates RTSP stream authentication (554/tcp) and local web server. Valid token connects stream; invalid token records authentication failures.
          </p>
          <div style="display:flex;gap:10px;margin-top:14px;">
            <button class="btn primary" onclick="testCameraAccess('${d.id}', true)">Authorized RTSP Stream Test</button>
            <button class="btn secondary" onclick="testCameraAccess('${d.id}', false)">Unauthorized Stream Brute-Force</button>
          </div>
          <div id="cameraFeedback" style="margin-top:10px;font-size:12px;font-weight:600;"></div>
        </div>
      `;
    } else if (d.type === 'router') {
      // TP-Link Archer C6 Router Simulator
      specializedControls = `
        <div class="panel form-panel" style="margin-bottom:16px;">
          <h3>TP-Link Archer C6 Administration & Config Simulation</h3>
          <p style="font-size:12px;color:var(--muted);">
            AC1200 MU-MIMO Gigabit Router. Tests administrative credentials (HTTPS 443) and firewall configuration updates.
          </p>
          <div style="display:flex;gap:10px;margin-top:14px;">
            <button class="btn primary" onclick="testRouterAdmin('${d.id}', true)">Valid Admin Login & Config Write</button>
            <button class="btn secondary" onclick="testRouterAdmin('${d.id}', false)">Invalid Admin Login Test</button>
          </div>
          <div id="routerFeedback" style="margin-top:10px;font-size:12px;font-weight:600;"></div>
        </div>
      `;
    }

    $('#deviceModalBody').innerHTML = `
      <div class="device-header-preview">
        <img src="${esc(d.image_url)}" alt="${esc(d.name)}">
        <div>
          <h2 style="font-size:18px;margin:0 0 4px;">${esc(d.name)}</h2>
          <p style="color:var(--muted);font-size:12px;margin:0;">Model: <strong>${esc(d.model)}</strong> · ID: <code>${esc(d.id)}</code></p>
          <p style="color:var(--muted);font-size:12px;margin:4px 0 0;">Category: <strong>${esc(d.category)}</strong> · Status: <span class="badge ${d.device_status === 'Online' ? 'ok' : 'warn'}">${esc(d.device_status)}</span></p>
        </div>
      </div>

      ${specializedControls}

      <div class="panel">
        <h3>Device Security Policy & Keystore Anchor</h3>
        <div class="table-wrap">
          <table>
            <tbody>
              <tr><td style="width:200px;font-weight:700;">Firmware Version</td><td>v${esc(d.firmware_version)}</td></tr>
              <tr><td style="font-weight:700;">Anti-Rollback Minimum</td><td>v${esc(d.minimum_version)}</td></tr>
              <tr><td style="font-weight:700;">Policy Profile</td><td><code>${esc(d.policy_version)}</code></td></tr>
              <tr><td style="font-weight:700;">Hardware Root Key ID</td><td><code>${esc(d.trusted_key_id)}</code></td></tr>
              <tr><td style="font-weight:700;">Docker Health</td><td>${esc(d.container_health)}</td></tr>
              <tr><td style="font-weight:700;">IP Address</td><td>${esc(d.ip_address || 'Unassigned')}</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    $('#deviceModal').style.display = 'flex';
  } catch (err) {
    showError(err);
  }
}

$('#btnCloseDeviceModal').onclick = () => {
  $('#deviceModal').style.display = 'none';
  keypadBuffer = '';
};

// Keypad functions
window.pressKey = key => {
  if (keypadBuffer.length < 8) keypadBuffer += key;
  $('#keypadScreen').textContent = '*'.repeat(keypadBuffer.length) || '----';
};

window.clearKeypad = () => {
  keypadBuffer = '';
  $('#keypadScreen').textContent = '----';
  $('#keypadFeedback').textContent = '';
};

window.submitKeypadPin = async deviceId => {
  const pin = keypadBuffer;
  keypadBuffer = '';
  $('#keypadScreen').textContent = '----';
  try {
    const res = await api(`/api/devices/${deviceId}/keypad`, {
      method: 'POST',
      body: JSON.stringify({ pin })
    });
    const box = $('#keypadFeedback');
    box.textContent = res.message;
    box.style.color = res.success ? '#27845B' : '#D64545';
    if ($('#solenoidBadge')) {
      $('#solenoidBadge').className = `badge ${res.lockState === 'UNLOCKED' ? 'ok' : 'bad'}`;
      $('#solenoidBadge').textContent = res.lockState === 'UNLOCKED' ? '🔓 UNLOCKED (12V ACTIVE)' : '🔒 LOCKED (SECURED)';
    }
  } catch (err) {
    $('#keypadFeedback').textContent = err.message;
    $('#keypadFeedback').style.color = '#D64545';
  }
};

window.sendSensorTelemetry = async deviceId => {
  const temp = $('#inputSensorTemp').value;
  const hum = $('#inputSensorHum').value;
  try {
    const res = await api(`/api/devices/${deviceId}/telemetry`, {
      method: 'POST',
      body: JSON.stringify({ temperature: temp, humidity: hum })
    });
    const box = $('#sensorFeedback');
    box.textContent = res.status === 'ANOMALOUS' ? `⚠ Anomaly Alert Generated: ${res.reason}` : `✓ Normal telemetry recorded: ${res.temp}°C, ${res.hum}% RH.`;
    box.style.color = res.status === 'ANOMALOUS' ? '#D64545' : '#27845B';
  } catch (err) {
    $('#sensorFeedback').textContent = err.message;
    $('#sensorFeedback').style.color = '#D64545';
  }
};

window.simulateSensorAnomaly = async deviceId => {
  $('#inputSensorTemp').value = '68.0';
  await window.sendSensorTelemetry(deviceId);
};

window.testCameraAccess = async (deviceId, valid) => {
  try {
    const res = await api(`/api/devices/${deviceId}/camera-access`, {
      method: 'POST',
      body: JSON.stringify({ token: valid ? 'tapo-session-auth-token-valid' : 'invalid-rogue-token' })
    });
    const box = $('#cameraFeedback');
    box.textContent = res.message;
    box.style.color = res.authorized ? '#27845B' : '#D64545';
  } catch (err) {
    $('#cameraFeedback').textContent = err.message;
    $('#cameraFeedback').style.color = '#D64545';
  }
};

window.testRouterAdmin = async (deviceId, valid) => {
  try {
    const res = await api(`/api/devices/${deviceId}/router-admin`, {
      method: 'POST',
      body: JSON.stringify({
        username: valid ? 'admin' : 'intruder',
        password: valid ? 'CyberShield@Router2026' : 'wrongpass',
        configChange: valid ? { firewallLevel: 'STRICT', dnsServer: '1.1.1.1' } : null
      })
    });
    const box = $('#routerFeedback');
    box.textContent = res.message;
    box.style.color = res.authorized ? '#27845B' : '#D64545';
  } catch (err) {
    $('#routerFeedback').textContent = err.message;
    $('#routerFeedback').style.color = '#D64545';
  }
};

window.triggerHeartbeat = async deviceId => {
  try {
    const res = await api(`/api/devices/${deviceId}/heartbeat`, { method: 'POST' });
    showSuccess(`Heartbeat confirmed for ${deviceId} at ${fmt(res.timestamp)}`);
    loadDevices();
  } catch (err) {
    showError(err);
  }
};

// -------------------------------------------------------------
// PAGE 3: 3D Attack Simulation & Automatic Firmware Server
// -------------------------------------------------------------

let sim3d = {
  initialized: false,
  webglAvailable: false,
  canvas: null,
  ctx2d: null,
  scene: null,
  camera: null,
  renderer: null,
  animId: null,
  activeDeviceId: 'DEV-CAM-01',
  deviceMeshGroup: null,
  serverMeshGroup: null,
  barrierMeshGroup: null,
  barrierLaser: null,
  barrierRing: null,
  serverPulseRing: null,
  activeTransmission: null,
  isAutoRotating: false,
  isDemoRunning: false,
  sampleBundle: null,
  barrierFlashTime: 0
};

let currentSimMode = 'auto'; // 'auto' | 'manual'
window.switchSimMode = function(mode) {
  currentSimMode = mode;
  const isAuto = mode === 'auto';
  const btnAuto = $('#btnModeAuto');
  const btnManual = $('#btnModeManual');
  if (btnAuto) btnAuto.classList.toggle('active', isAuto);
  if (btnManual) btnManual.classList.toggle('active', !isAuto);
  const panelAuto = $('#simPanelAuto');
  const panelManual = $('#simPanelManual');
  if (panelAuto) panelAuto.style.display = isAuto ? 'block' : 'none';
  if (panelManual) panelManual.style.display = isAuto ? 'none' : 'block';
  const desc = $('#modeDescription');
  if (desc) {
    desc.textContent = isAuto
      ? 'Automatic pipeline: one-click demo of Valid (Green line) then Invalid (Red line blocked).'
      : 'Manual mode: select an individual cryptographic sample dataset (Valid or Invalid) to transmit.';
  }
};

async function loadUpdatesPage() {
  try {
    devices = await api('/api/devices');
    const select = $('#sim3dTargetDevice');
    if (select) {
      select.innerHTML = devices.map(d => `
        <option value="${esc(d.id)}" ${d.id === sim3d.activeDeviceId ? 'selected' : ''}>
          ${esc(d.name)} (${esc(d.id)}) · ${esc(d.model)}
        </option>
      `).join('');

      select.onchange = e => {
        sim3d.activeDeviceId = e.target.value;
        onTargetDeviceChanged();
      };
    }

    // Initialize or re-attach 3D simulation canvas
    init3dSimulation();

    // Ensure mode is synced
    window.switchSimMode(currentSimMode);

    // Load samples and status for active device
    await onTargetDeviceChanged();
    await load3dTrialsHistory();
    await refresh3dStats();

    // Bind action buttons once
    bind3dActionButtons();
  } catch (err) {
    showError(err);
  }
}

async function onTargetDeviceChanged() {
  const d = devices.find(x => x.id === sim3d.activeDeviceId) || devices[0];
  if (!d) return;

  $('#sim3dDeviceFw').textContent = `v${d.firmware_version}`;
  $('#sim3dDeviceMin').textContent = `v${d.minimum_version}`;
  $('#sim3dDeviceModel').textContent = d.model;
  $('#sim3dDeviceRisk').className = `badge ${d.risk_level === 'High' ? 'bad' : d.risk_level === 'Medium' ? 'warn' : 'ok'}`;
  $('#sim3dDeviceRisk').textContent = `${d.risk_level} Risk`;

  $('#sim3dHudTargetText').textContent = `TARGET: ${d.id} (${d.device_status.toUpperCase()})`;
  $('#sim3dTargetLabel').textContent = d.name.toUpperCase();
  $('#sim3dTargetSubLabel').textContent = `v${d.firmware_version} · ${d.model}`;

  // Update procedural 3D model for this device
  if (sim3d.scene && sim3d.deviceMeshGroup) {
    update3dTargetDeviceMesh(d);
  }

  // Generate / Fetch sample firmware bundle
  await fetchAndRenderSamples(d.id);
}

async function fetchAndRenderSamples(deviceId) {
  try {
    const bundle = await api(`/api/ota/auto-update-server/generate/${deviceId}`);
    sim3d.sampleBundle = bundle;

    // Valid sample
    $('#sampleValidFileName').textContent = bundle.validPackage.fileName;
    $('#sampleValidHash').textContent = bundle.validPackage.fileHash;
    $('#btnDownloadValid').href = bundle.validPackage.filePath;

    // Invalid sample
    $('#sampleInvalidFileName').textContent = bundle.invalidPackage.fileName;
    $('#sampleInvalidHash').textContent = bundle.invalidPackage.fileHash;
    $('#btnDownloadInvalid').href = bundle.invalidPackage.filePath;

    $('#badgeSampleStatus').textContent = `READY (v${bundle.targetVersion})`;
    $('#badgeSampleStatus').className = 'badge ok';
  } catch (err) {
    showError(err);
  }
}

async function refresh3dStats() {
  try {
    const status = await api('/api/ota/auto-update-server/status');
    $('#stat3dTrials').textContent = String(status.totalTrialsToday || 0).padStart(2, '0');
    $('#stat3dValid').textContent = String(status.validPassedToday || 0).padStart(2, '0');
    $('#stat3dBlocked').textContent = String(status.invalidBlockedToday || 0).padStart(2, '0');
  } catch (e) {
    console.warn('Stats refresh error:', e);
  }
}

async function load3dTrialsHistory() {
  try {
    const trials = await api('/api/ota/auto-update-server/trials?limit=20');
    const tbody = $('#sim3dTrialsHistoryRows');
    $('#badgeTrialsCount').textContent = `${trials.length} Trials`;

    if (!trials.length) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty" style="text-align:center;padding:20px;">No trials executed yet today. Click "Run Automated Both Tests" above to start!</td></tr>`;
      return;
    }

    tbody.innerHTML = trials.map(t => {
      const isApproved = t.decision === 'APPROVED';
      const animText = isApproved
        ? '<span style="color:#27845B;font-weight:700;">🟢 Green Line · Delivered to Device</span>'
        : '<span style="color:#D64545;font-weight:700;">🔴 Red Line · Blocked at CyberShield Barrier</span>';

      return `
        <tr>
          <td><b>${fmt(t.timestamp)}</b></td>
          <td><code style="font-size:11px;">${esc(t.id)}</code></td>
          <td><strong>${esc(t.deviceName)}</strong> <small style="display:block;color:var(--muted);">${esc(t.deviceId)}</small></td>
          <td>
            <span class="badge ${t.packageType === 'valid' ? 'ok' : 'bad'}">
              ${t.packageType === 'valid' ? 'VALID FIRMWARE' : 'ATTACK PAYLOAD'}
            </span>
          </td>
          <td>v${esc(t.firmwareVersion)}</td>
          <td>${animText}</td>
          <td><span class="badge ${isApproved ? 'ok' : 'bad'}">${esc(t.decision)}</span></td>
          <td style="font-family:monospace;font-size:11px;">${t.durationMs ? t.durationMs.toFixed(1) : '< 1'} ms</td>
          <td>
            ${t.incidentId ? `
              <button class="btn secondary" style="padding:2px 6px;min-height:24px;font-size:10px;" onclick="openIncidentDetail('${esc(t.incidentId)}')">Forensics ↗</button>
            ` : `<span style="color:var(--muted);font-size:11px;">Applied</span>`}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.warn('History load error:', err);
  }
}

function bind3dActionButtons() {
  if (sim3d.actionsBound) return;
  sim3d.actionsBound = true;

  if ($('#btn3dRunBothAuto')) $('#btn3dRunBothAuto').onclick = () => runAutomatedDemonstration();
  if ($('#btnAutoStartFull')) $('#btnAutoStartFull').onclick = () => runAutomatedDemonstration();
  if ($('#btn3dRunValid')) $('#btn3dRunValid').onclick = () => triggerTrial('valid');
  if ($('#btn3dRunInvalid')) $('#btn3dRunInvalid').onclick = () => triggerTrial('invalid');
  if ($('#btnTestValidDirect')) $('#btnTestValidDirect').onclick = () => triggerTrial('valid');
  if ($('#btnTestInvalidDirect')) $('#btnTestInvalidDirect').onclick = () => triggerTrial('invalid');

  if ($('#btnModeAuto')) $('#btnModeAuto').onclick = () => window.switchSimMode('auto');
  if ($('#btnModeManual')) $('#btnModeManual').onclick = () => window.switchSimMode('manual');

  if ($('#btn3dRegenSamples')) {
    $('#btn3dRegenSamples').onclick = async () => {
      try {
        showSuccess('Regenerating cryptographic sample packages with fresh Ed25519 nonces...');
        await fetchAndRenderSamples(sim3d.activeDeviceId);
        showSuccess('Fresh sample packages generated and signed.');
      } catch (err) {
        showError(err);
      }
    };
  }

  if ($('#btn3dResetCam')) {
    $('#btn3dResetCam').onclick = () => {
      if (sim3d.camera) {
        sim3d.camera.position.set(0, 3.2, 7.5);
        sim3d.camera.lookAt(0, 0.4, 0);
      }
    };
  }

  if ($('#btn3dToggleRotate')) {
    $('#btn3dToggleRotate').onclick = () => {
      sim3d.isAutoRotating = !sim3d.isAutoRotating;
      $('#btn3dToggleRotate').style.background = sim3d.isAutoRotating ? '#27845B' : '';
    };
  }
}

/**
 * Execute a trial: Valid or Invalid, animate 3D transmission, and update UI
 */
async function triggerTrial(packageType) {
  if (sim3d.activeTransmission && sim3d.activeTransmission.active) {
    showError(new Error('A 3D simulation transmission is already active. Please wait a moment.'));
    return;
  }

  const deviceId = sim3d.activeDeviceId;
  const isVal = packageType === 'valid';

  // 1. Update status banner
  const banner = $('#sim3dStatusBanner');
  banner.className = `sim-status-banner ${isVal ? 'running-valid' : 'running-invalid'}`;
  $('#sim3dStatusDot').className = `dot ${isVal ? 'green' : 'warn'}`;
  $('#sim3dStatusText').innerHTML = `<strong>TRANSMITTING ${isVal ? 'VALID FIRMWARE' : 'ATTACK PAYLOAD'}</strong>: Calculating SHA-256 digest and dispatching via OTA Staging Core (10.0.8.25)...`;

  // Reset live check indicators
  renderPendingVerificationChecks();

  try {
    const startTime = performance.now();
    const result = await api('/api/ota/auto-update-server/trial', {
      method: 'POST',
      body: JSON.stringify({ deviceId, packageType })
    });
    const roundtrip = performance.now() - startTime;
    $('#stat3dLatency').textContent = `${(result.durationMs || roundtrip).toFixed(1)} ms`;

    // 2. Start 3D animated transmission
    start3dLineAnimation(packageType, result);

    // 3. Update verification checks list
    renderLiveVerificationChecks(result);

    // 4. Update trial summary details
    $('#sim3dTrialId').textContent = result.trialId;
    $('#sim3dDecisionReason').textContent = result.reason;
    $('#sim3dDecisionBadge').className = `badge ${result.decision === 'APPROVED' ? 'ok' : 'bad'}`;
    $('#sim3dDecisionBadge').textContent = result.decision;

    // Refresh devices list to show updated version if valid update passed
    if (result.decision === 'APPROVED') {
      devices = await api('/api/devices');
      const updated = devices.find(x => x.id === deviceId);
      if (updated) {
        $('#sim3dDeviceFw').textContent = `v${updated.firmware_version}`;
        $('#sim3dHudTargetText').textContent = `TARGET: ${updated.id} (FIRMWARE v${updated.firmware_version} INSTALLED)`;
      }
    }

    // Refresh stats & trial history
    await refresh3dStats();
    await load3dTrialsHistory();

    return result;
  } catch (err) {
    showError(err);
    banner.className = 'sim-status-banner idle';
    $('#sim3dStatusText').textContent = 'Transmission error: ' + err.message;
  }
}

/**
 * Run Automated Demonstration: Valid Test (Green) -> Wait 2.5s -> Invalid Test (Red)
 */
async function runAutomatedDemonstration() {
  if (sim3d.isDemoRunning) return;
  sim3d.isDemoRunning = true;

  const btnAuto = $('#btn3dRunBothAuto');
  btnAuto.disabled = true;
  btnAuto.textContent = '⏳ Running Demo (1/2: Valid)...';

  try {
    showSuccess('Demonstration initiated: Running Test 1 (Valid Firmware with Green Path)...');

    // Run Valid Test
    await triggerTrial('valid');

    // Wait 3.5 seconds for the full green transmission and arrival animation
    await new Promise(resolve => setTimeout(resolve, 3500));

    btnAuto.textContent = '⏳ Running Demo (2/2: Invalid Attack)...';
    showSuccess('Demonstration Step 2: Running Test 2 (Adversarial Attack with Red Blocked Path)...');

    // Run Invalid Attack Test
    await triggerTrial('invalid');

    // Wait for the red blocked animation to conclude
    await new Promise(resolve => setTimeout(resolve, 3000));

    showSuccess('✓ Automated Demonstration Complete: Valid firmware delivered (Green) and Invalid attack blocked at barrier (Red)!');
  } catch (err) {
    showError(err);
  } finally {
    sim3d.isDemoRunning = false;
    btnAuto.disabled = false;
    btnAuto.textContent = '▶ Run Automated Both Tests';
  }
}

function renderPendingVerificationChecks() {
  const container = $('#sim3dCheckSteps');
  if (!container) return;
  const steps = [
    '1. Container & Manifest Structure',
    '2. Cryptographic SHA-256 Digest Match',
    '3. Trusted Root Key Lookup (Ed25519)',
    '4. Digital Signature Authenticity',
    '5. Monotonic Anti-Rollback Policy',
    '6. Anti-Replay Nonce Ledger'
  ];
  container.innerHTML = steps.map(s => `
    <div class="timeline-step">
      <div class="timeline-dot"></div>
      <div style="font-size:13px;font-weight:700;">${esc(s)} <span class="badge neutral">EVALUATING...</span></div>
      <p style="font-size:12px;color:var(--muted);margin:2px 0 0;">Cryptographic pipeline actively analyzing binary buffer...</p>
    </div>
  `).join('');
  $('#sim3dIncidentAlert').style.display = 'none';
}

function renderLiveVerificationChecks(result) {
  const container = $('#sim3dCheckSteps');
  if (!container || !result.checks) return;

  container.innerHTML = result.checks.map(c => `
    <div class="timeline-step ${c.status === 'PASSED' ? 'ok' : 'failed'}">
      <div class="timeline-dot"></div>
      <div style="font-size:13px;font-weight:700;">
        ${esc(c.name)} <span class="badge ${c.status === 'PASSED' ? 'ok' : 'bad'}">${esc(c.status)}</span>
      </div>
      <p style="font-size:12px;color:var(--muted);margin:2px 0 0;">${esc(c.detail)}</p>
    </div>
  `).join('');

  const alertBox = $('#sim3dIncidentAlert');
  if (result.decision === 'REJECTED' && result.incidentId) {
    alertBox.style.display = 'block';
    alertBox.innerHTML = `
      <div style="padding:12px;background:#FEF2F2;border:1px solid #FECACA;border-radius:6px;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <strong style="color:var(--danger);font-size:13px;">🚨 Threat Intercepted: Incident ${esc(result.incidentId)} Opened</strong>
          <small style="display:block;color:#7F1D1D;margin-top:2px;">Automated containment dropped payload buffer. Evidence logged to forensic ledger.</small>
        </div>
        <button class="btn secondary" style="padding:4px 10px;min-height:28px;font-size:11px;" onclick="openIncidentDetail('${esc(result.incidentId)}')">Inspect Incident 🔍</button>
      </div>
    `;
  } else {
    alertBox.style.display = 'none';
  }
}

// -------------------------------------------------------------
// THREE.JS 3D ENGINE & ANIMATION SYSTEM (WITH 2D SCHEMATIC FALLBACK)
// -------------------------------------------------------------

function isWebGLSupported() {
  try {
    const testCanvas = document.createElement('canvas');
    const gl = testCanvas.getContext('webgl2') || testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
    return !!(window.WebGLRenderingContext && gl);
  } catch (e) {
    return false;
  }
}

function init3dSimulation() {
  const container = $('#sim3dViewport');
  let canvas = $('#sim3dCanvas');
  if (!container || !canvas) return;

  if (sim3d.initialized) {
    onWindowResize();
    return;
  }

  const width = container.clientWidth || 800;
  const height = container.clientHeight || 440;

  let webglOk = false;

  // 1. Attempt Three.js WebGL initialization with safe error handling
  if (typeof THREE !== 'undefined' && isWebGLSupported()) {
    try {
      const scene = new THREE.Scene();
      scene.fog = new THREE.FogExp2(0x0b0f19, 0.05);
      sim3d.scene = scene;

      const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
      camera.position.set(0, 3.2, 7.5);
      camera.lookAt(0, 0.4, 0);
      sim3d.camera = camera;

      const renderer = new THREE.WebGLRenderer({
        canvas,
        antialias: true,
        alpha: true,
        powerPreference: 'default',
        failIfMajorPerformanceCaveat: false
      });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      sim3d.renderer = renderer;

      // Lights
      const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
      scene.add(ambientLight);

      const keyLight = new THREE.DirectionalLight(0xffffff, 1.2);
      keyLight.position.set(4, 8, 6);
      scene.add(keyLight);

      const fillLight = new THREE.DirectionalLight(0x38bdf8, 0.6);
      fillLight.position.set(-6, 3, -4);
      scene.add(fillLight);

      // Cyber Platform Ground Grid
      const grid = new THREE.GridHelper(14, 28, 0x00f2fe, 0x1e293b);
      grid.position.y = -1.2;
      scene.add(grid);

      // Source Node: OTA Update Server (x: -3.6, y: -0.2, z: 0)
      const serverGroup = new THREE.Group();
      serverGroup.position.set(-3.6, -0.2, 0);
      buildOtaServerMesh(serverGroup);
      scene.add(serverGroup);
      sim3d.serverMeshGroup = serverGroup;

      // Center Node: CyberShield Security Barrier (x: 0, y: 0.1, z: 0)
      const barrierGroup = new THREE.Group();
      barrierGroup.position.set(0, 0.1, 0);
      buildCyberShieldBarrierMesh(barrierGroup);
      scene.add(barrierGroup);
      sim3d.barrierMeshGroup = barrierGroup;

      // Destination Node: Selected IoT Device (x: 3.6, y: -0.2, z: 0)
      const deviceGroup = new THREE.Group();
      deviceGroup.position.set(3.6, -0.2, 0);
      const curDev = devices.find(d => d.id === sim3d.activeDeviceId) || devices[0];
      buildTargetDeviceMesh(deviceGroup, curDev);
      scene.add(deviceGroup);
      sim3d.deviceMeshGroup = deviceGroup;

      // Mouse drag to orbit camera slightly
      setupCameraDrag(canvas);

      webglOk = true;
      sim3d.webglAvailable = true;
      sim3d.canvas = canvas;
    } catch (err) {
      console.warn('WebGL context creation failed, activating 2D Schematic Canvas Fallback:', err);
      webglOk = false;
      sim3d.webglAvailable = false;
      sim3d.renderer = null;
      sim3d.scene = null;
      sim3d.camera = null;
    }
  } else {
    sim3d.webglAvailable = false;
  }

  // 2. Fallback to 2D Schematic Mode if WebGL is unavailable
  if (!webglOk) {
    sim3d.webglAvailable = false;
    let ctx = canvas.getContext('2d');
    if (!ctx) {
      // If WebGL context probe locked the canvas, replace with clean canvas
      const cleanCanvas = document.createElement('canvas');
      cleanCanvas.id = 'sim3dCanvas';
      cleanCanvas.className = 'sim-3d-canvas';
      cleanCanvas.width = width;
      cleanCanvas.height = height;
      canvas.parentNode.replaceChild(cleanCanvas, canvas);
      canvas = cleanCanvas;
      ctx = canvas.getContext('2d');
    }
    sim3d.canvas = canvas;
    sim3d.ctx2d = ctx;
    canvas.width = width;
    canvas.height = height;

    const topHud = $('.sim-3d-hud-top');
    if (topHud && !$('#sim3dHudModeBadge')) {
      const modeBadge = document.createElement('div');
      modeBadge.id = 'sim3dHudModeBadge';
      modeBadge.className = 'sim-3d-hud-pill';
      modeBadge.innerHTML = `<span class="dot" style="background:#00F2FE;"></span><span>SCHEMATIC 2D (ACTIVE)</span>`;
      topHud.appendChild(modeBadge);
    }
  }

  // 3. Start Animation Loop
  sim3d.initialized = true;
  window.addEventListener('resize', onWindowResize);
  if (window.ResizeObserver && container) {
    const ro = new ResizeObserver(() => {
      onWindowResize();
    });
    ro.observe(container);
  }
  if (!sim3d.animId) {
    animate3dLoop();
  }
}

function onWindowResize() {
  const container = $('#sim3dViewport');
  if (!container) return;
  const w = container.clientWidth || 800;
  const h = container.clientHeight || 440;
  if (w <= 0 || h <= 0) return;

  if (sim3d.webglAvailable && sim3d.renderer && sim3d.camera) {
    sim3d.camera.aspect = w / h;
    sim3d.camera.updateProjectionMatrix();
    sim3d.renderer.setSize(w, h);
  } else if (sim3d.canvas) {
    sim3d.canvas.width = w;
    sim3d.canvas.height = h;
  }
}

function setupCameraDrag(canvas) {
  if (!sim3d.webglAvailable) return;
  let isDragging = false;
  let prevX = 0;
  let prevY = 0;

  canvas.addEventListener('mousedown', e => {
    isDragging = true;
    prevX = e.clientX;
    prevY = e.clientY;
  });

  window.addEventListener('mouseup', () => { isDragging = false; });

  canvas.addEventListener('mousemove', e => {
    if (!isDragging || !sim3d.camera) return;
    const deltaX = e.clientX - prevX;
    const deltaY = e.clientY - prevY;
    prevX = e.clientX;
    prevY = e.clientY;

    sim3d.camera.position.x -= deltaX * 0.01;
    sim3d.camera.position.y += deltaY * 0.01;
    sim3d.camera.position.y = Math.max(1.0, Math.min(6.0, sim3d.camera.position.y));
    sim3d.camera.lookAt(0, 0.4, 0);
  });
}

/**
 * Builds the 3D Procedural OTA Firmware Server
 */
function buildOtaServerMesh(group) {
  // Base cabinet
  const baseGeo = new THREE.CylinderGeometry(1.0, 1.15, 0.25, 32);
  const darkMetal = new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.3, metalness: 0.8 });
  const baseMesh = new THREE.Mesh(baseGeo, darkMetal);
  baseMesh.position.y = -1.05;
  group.add(baseMesh);

  // Server rack tower
  const towerGeo = new THREE.BoxGeometry(1.1, 1.8, 0.9);
  const towerMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, roughness: 0.2, metalness: 0.7 });
  const tower = new THREE.Mesh(towerGeo, towerMat);
  tower.position.y = -0.05;
  group.add(tower);

  // Server rack server unit slits with cyan glow
  for (let i = 0; i < 5; i++) {
    const slotGeo = new THREE.BoxGeometry(0.95, 0.16, 0.05);
    const slotMat = new THREE.MeshBasicMaterial({ color: 0x00f2fe });
    const slot = new THREE.Mesh(slotGeo, slotMat);
    slot.position.set(0, -0.65 + i * 0.32, 0.46);
    group.add(slot);

    // Activity LED dots
    const ledGeo = new THREE.SphereGeometry(0.035, 12, 12);
    const ledMat = new THREE.MeshBasicMaterial({ color: i % 2 === 0 ? 0x10b981 : 0x38bdf8 });
    const led = new THREE.Mesh(ledGeo, ledMat);
    led.position.set(-0.35, -0.65 + i * 0.32, 0.49);
    group.add(led);
  }

  // Antenna on top
  const antennaGeo = new THREE.CylinderGeometry(0.03, 0.03, 0.6, 16);
  const antennaMat = new THREE.MeshStandardMaterial({ color: 0x94a3b8, metalness: 0.9 });
  const antenna = new THREE.Mesh(antennaGeo, antennaMat);
  antenna.position.set(0, 1.15, 0);
  group.add(antenna);

  // Pulsing antenna beacon sphere
  const beaconGeo = new THREE.SphereGeometry(0.1, 16, 16);
  const beaconMat = new THREE.MeshBasicMaterial({ color: 0x00f2fe });
  const beacon = new THREE.Mesh(beaconGeo, beaconMat);
  beacon.position.set(0, 1.45, 0);
  group.add(beacon);

  // Rotating holographic base ring
  const ringGeo = new THREE.RingGeometry(1.25, 1.3, 32);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0x00f2fe, side: THREE.DoubleSide, transparent: true, opacity: 0.4 });
  const ring = new THREE.Mesh(ringGeo, ringMat);
  ring.rotation.x = Math.PI / 2;
  ring.position.y = -1.18;
  group.add(ring);
  sim3d.serverPulseRing = ring;
}

/**
 * Builds the CyberShield Security Barrier (Firewall)
 */
function buildCyberShieldBarrierMesh(group) {
  // Holographic defense plane
  const planeGeo = new THREE.PlaneGeometry(1.4, 2.6);
  const planeMat = new THREE.MeshStandardMaterial({
    color: 0xd96c3f,
    transparent: true,
    opacity: 0.25,
    side: THREE.DoubleSide,
    roughness: 0.1,
    metalness: 0.9
  });
  const plane = new THREE.Mesh(planeGeo, planeMat);
  plane.position.y = 0.3;
  group.add(plane);

  // Barrier frame posts
  const postGeo = new THREE.CylinderGeometry(0.06, 0.06, 2.8, 16);
  const postMat = new THREE.MeshStandardMaterial({ color: 0xd96c3f, metalness: 0.8 });
  const leftPost = new THREE.Mesh(postGeo, postMat);
  leftPost.position.set(-0.72, 0.3, 0);
  group.add(leftPost);

  const rightPost = new THREE.Mesh(postGeo, postMat);
  rightPost.position.set(0.72, 0.3, 0);
  group.add(rightPost);

  // Scanning laser beam
  const laserGeo = new THREE.BoxGeometry(1.45, 0.05, 0.08);
  const laserMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8 });
  const laser = new THREE.Mesh(laserGeo, laserMat);
  laser.position.set(0, 0.3, 0);
  group.add(laser);
  sim3d.barrierLaser = laser;

  // Ground shield perimeter ring
  const ringGeo = new THREE.RingGeometry(0.85, 0.9, 32);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0xd96c3f, side: THREE.DoubleSide, transparent: true, opacity: 0.5 });
  const ring = new THREE.Mesh(ringGeo, ringMat);
  ring.rotation.x = Math.PI / 2;
  ring.position.y = -1.18;
  group.add(ring);
  sim3d.barrierRing = ring;
}

/**
 * Builds the 3D Procedural representation of the chosen IoT Device
 */
function buildTargetDeviceMesh(group, device) {
  // Clear any existing children
  while (group.children.length > 0) {
    const c = group.children[0];
    group.remove(c);
  }

  // Common pedestal
  const pedGeo = new THREE.CylinderGeometry(0.9, 1.05, 0.25, 32);
  const pedMat = new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.3, metalness: 0.8 });
  const ped = new THREE.Mesh(pedGeo, pedMat);
  ped.position.y = -1.05;
  group.add(ped);

  const type = device ? device.type : 'camera';

  if (type === 'camera') {
    // 1. TP-Link Tapo C200 Camera
    // Cylindrical base
    const camBaseGeo = new THREE.CylinderGeometry(0.5, 0.65, 0.6, 32);
    const camMat = new THREE.MeshStandardMaterial({ color: 0xf8fafc, roughness: 0.2 });
    const camBase = new THREE.Mesh(camBaseGeo, camMat);
    camBase.position.y = -0.55;
    group.add(camBase);

    // Spherical camera head
    const headGeo = new THREE.SphereGeometry(0.55, 32, 32);
    const head = new THREE.Mesh(headGeo, camMat);
    head.position.y = 0.2;
    group.add(head);

    // Black lens iris
    const lensGeo = new THREE.CylinderGeometry(0.24, 0.24, 0.2, 32);
    const lensMat = new THREE.MeshStandardMaterial({ color: 0x020617, roughness: 0.05, metalness: 0.9 });
    const lens = new THREE.Mesh(lensGeo, lensMat);
    lens.rotation.x = Math.PI / 2;
    lens.position.set(0, 0.2, 0.48);
    group.add(lens);

    // Glowing infrared ring
    const irGeo = new THREE.RingGeometry(0.25, 0.28, 32);
    const irMat = new THREE.MeshBasicMaterial({ color: 0x27845b, side: THREE.DoubleSide });
    const ir = new THREE.Mesh(irGeo, irMat);
    ir.position.set(0, 0.2, 0.58);
    group.add(ir);

  } else if (type === 'smart_lock') {
    // 2. ESP32 Smart Locker
    const boxGeo = new THREE.BoxGeometry(0.95, 1.4, 0.5);
    const steelMat = new THREE.MeshStandardMaterial({ color: 0x475569, metalness: 0.8, roughness: 0.3 });
    const box = new THREE.Mesh(boxGeo, steelMat);
    box.position.y = -0.2;
    group.add(box);

    // 4x4 Keypad representation
    const padGeo = new THREE.BoxGeometry(0.65, 0.7, 0.04);
    const padMat = new THREE.MeshBasicMaterial({ color: 0x0f172a });
    const pad = new THREE.Mesh(padGeo, padMat);
    pad.position.set(0, 0.05, 0.27);
    group.add(pad);

    // Solenoid deadbolt cylinder
    const solGeo = new THREE.CylinderGeometry(0.12, 0.12, 0.5, 16);
    const chromeMat = new THREE.MeshStandardMaterial({ color: 0xe2e8f0, metalness: 0.95 });
    const sol = new THREE.Mesh(solGeo, chromeMat);
    sol.rotation.z = Math.PI / 2;
    sol.position.set(0.48, -0.5, 0);
    group.add(sol);

  } else if (type === 'environmental_sensor') {
    // 3. DHT22 / AM2302 Sensor
    const sensorGeo = new THREE.BoxGeometry(0.8, 1.2, 0.35);
    const sensorMat = new THREE.MeshStandardMaterial({ color: 0xf1f5f9, roughness: 0.4 });
    const sMesh = new THREE.Mesh(sensorGeo, sensorMat);
    sMesh.position.y = -0.3;
    group.add(sMesh);

    // Horizontal grill slats
    for (let i = 0; i < 4; i++) {
      const slatGeo = new THREE.BoxGeometry(0.6, 0.08, 0.05);
      const slatMat = new THREE.MeshBasicMaterial({ color: 0x64748b });
      const slat = new THREE.Mesh(slatGeo, slatMat);
      slat.position.set(0, -0.45 + i * 0.16, 0.19);
      group.add(slat);
    }

    // 4 Header pins
    for (let p = 0; p < 4; p++) {
      const pinGeo = new THREE.CylinderGeometry(0.025, 0.025, 0.35, 8);
      const goldMat = new THREE.MeshStandardMaterial({ color: 0xf59e0b, metalness: 0.9 });
      const pin = new THREE.Mesh(pinGeo, goldMat);
      pin.position.set(-0.25 + p * 0.16, -1.05, 0);
      group.add(pin);
    }

  } else {
    // 4. TP-Link Archer C6 Router
    const routerGeo = new THREE.BoxGeometry(1.3, 0.22, 0.85);
    const routerMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, roughness: 0.2 });
    const router = new THREE.Mesh(routerGeo, routerMat);
    router.position.y = -0.8;
    group.add(router);

    // 4 Antennas angled upwards
    const antGeo = new THREE.CylinderGeometry(0.03, 0.03, 1.2, 12);
    const antMat = new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.3 });
    const xOffsets = [-0.55, -0.2, 0.2, 0.55];
    xOffsets.forEach((x, idx) => {
      const ant = new THREE.Mesh(antGeo, antMat);
      ant.position.set(x, -0.2, -0.35);
      ant.rotation.z = (idx < 2 ? -0.15 : 0.15) * (idx === 0 || idx === 3 ? 1.5 : 0.8);
      group.add(ant);
    });
  }

  // Ground device beacon ring
  const ringGeo = new THREE.RingGeometry(1.15, 1.2, 32);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0x27845b, side: THREE.DoubleSide, transparent: true, opacity: 0.5 });
  const ring = new THREE.Mesh(ringGeo, ringMat);
  ring.rotation.x = Math.PI / 2;
  ring.position.y = -1.18;
  group.add(ring);
}

function update3dTargetDeviceMesh(device) {
  if (!sim3d.deviceMeshGroup) return;
  buildTargetDeviceMesh(sim3d.deviceMeshGroup, device);
}

/**
 * 3D / 2D Animated Transmission along the Green or Red line
 */
function start3dLineAnimation(packageType, trialResult) {
  // Clean up any existing active transmission
  if (sim3d.activeTransmission) {
    if (sim3d.webglAvailable && sim3d.scene) {
      if (sim3d.activeTransmission.packetMesh && sim3d.scene) {
        sim3d.scene.remove(sim3d.activeTransmission.packetMesh);
      }
      if (sim3d.activeTransmission.lineMesh && sim3d.scene) {
        sim3d.scene.remove(sim3d.activeTransmission.lineMesh);
      }
    }
    sim3d.activeTransmission = null;
  }

  const isApproved = trialResult.decision === 'APPROVED';
  const colorHex = isApproved ? 0x10b981 : 0xef4444; // Green for valid, Red for invalid

  // HUD Update
  const barrierPill = $('#sim3dHudBarrierPill');
  if (barrierPill) {
    barrierPill.className = `sim-3d-hud-pill ${isApproved ? 'status-green' : 'status-red'}`;
    barrierPill.innerHTML = `
      <span class="dot" style="background:${isApproved ? '#27845B' : '#D64545'};"></span>
      <span>CYBERSHIELD: ${isApproved ? 'SCANNING · PASSED' : 'ALERT · INTERCEPTING ATTACK'}</span>
    `;
  }

  // Live Floating Data Card HUD
  const card = $('#sim3dFloatingDataCard');
  if (card) {
    card.className = `sim-3d-floating-data-card ${isApproved ? 'green-theme' : 'red-theme'}`;
    card.style.display = 'block';
    const typeEl = $('#dataCardType');
    const badgeEl = $('#dataCardBadge');
    const fileEl = $('#dataCardFileName');
    const hashEl = $('#dataCardHash');
    const signerEl = $('#dataCardSigner');
    const statusEl = $('#dataCardStatus');

    if (typeEl) typeEl.textContent = isApproved ? '📦 VALID FIRMWARE DATA' : '🚨 ADVERSARIAL ATTACK DATA';
    if (badgeEl) {
      badgeEl.className = `badge ${isApproved ? 'ok' : 'bad'}`;
      badgeEl.textContent = isApproved ? 'AUTHENTIC' : 'UNAUTHORIZED';
    }
    if (fileEl) fileEl.textContent = trialResult.fileName || (isApproved ? 'firmware_valid.bin' : 'firmware_tampered.bin');
    if (hashEl) hashEl.textContent = trialResult.fileHash ? trialResult.fileHash.slice(0, 18) + '...' : 'calculating...';
    if (signerEl) signerEl.textContent = isApproved ? 'dev-ed25519-primary (VALID)' : 'FORGED / UNKNOWN KEY';
    if (statusEl) {
      statusEl.textContent = 'Transmitting in flight... (0%)';
      statusEl.style.color = isApproved ? '#27845B' : '#D64545';
    }
  }

  if (sim3d.webglAvailable && sim3d.scene && typeof THREE !== 'undefined') {
    // 3D WebGL Tube and Octahedron/Dodecahedron Mesh setup
    const sourcePt = new THREE.Vector3(-3.6, 0.4, 0);
    const midHighPt = new THREE.Vector3(0, 1.6, 0);
    const barrierPt = new THREE.Vector3(0, 0.4, 0);
    const targetPt = new THREE.Vector3(3.6, 0.4, 0);

    let curve;
    if (isApproved) {
      curve = new THREE.QuadraticBezierCurve3(sourcePt, midHighPt, targetPt);
    } else {
      curve = new THREE.QuadraticBezierCurve3(sourcePt, new THREE.Vector3(-1.8, 1.4, 0), barrierPt);
    }

    const tubeGeo = new THREE.TubeGeometry(curve, 40, 0.055, 8, false);
    const tubeMat = new THREE.MeshBasicMaterial({
      color: colorHex,
      transparent: true,
      opacity: 0.85
    });
    const lineMesh = new THREE.Mesh(tubeGeo, tubeMat);
    sim3d.scene.add(lineMesh);

    const packetGeo = isApproved ? new THREE.OctahedronGeometry(0.22, 1) : new THREE.DodecahedronGeometry(0.24, 0);
    const packetMat = new THREE.MeshStandardMaterial({
      color: colorHex,
      emissive: colorHex,
      emissiveIntensity: 0.8,
      roughness: 0.2,
      metalness: 0.8
    });
    const packetMesh = new THREE.Mesh(packetGeo, packetMat);
    packetMesh.position.copy(sourcePt);
    sim3d.scene.add(packetMesh);

    sim3d.activeTransmission = {
      active: true,
      type: packageType,
      isApproved,
      curve,
      lineMesh,
      packetMesh,
      progress: 0,
      speed: 0.016,
      result: trialResult,
      passedBarrier: false,
      impactTriggered: false
    };
  } else {
    // 2D Schematic Transmission Coordinates
    const container = $('#sim3dViewport');
    const w = container ? container.clientWidth || 800 : 800;
    const h = container ? container.clientHeight || 440 : 440;
    const p0 = { x: w * 0.16, y: h * 0.52 };
    const p1 = isApproved ? { x: w * 0.50, y: h * 0.22 } : { x: w * 0.33, y: h * 0.35 };
    const p2 = isApproved ? { x: w * 0.84, y: h * 0.52 } : { x: w * 0.50, y: h * 0.52 };

    sim3d.activeTransmission = {
      active: true,
      type: packageType,
      isApproved,
      p0,
      p1,
      p2,
      progress: 0,
      speed: 0.016,
      result: trialResult,
      passedBarrier: false,
      impactTriggered: false
    };
  }
}

/**
 * Main Render Loop: Dispatches to WebGL 3D or 2D Schematic Canvas Fallback
 */
function animate3dLoop() {
  sim3d.animId = requestAnimationFrame(animate3dLoop);
  const time = performance.now() * 0.001;

  if (sim3d.webglAvailable && sim3d.renderer && sim3d.scene && sim3d.camera) {
    // 1. Three.js 3D Animations
    if (sim3d.barrierLaser) {
      sim3d.barrierLaser.position.y = 0.3 + Math.sin(time * 3.5) * 0.85;
    }
    if (sim3d.serverPulseRing) {
      sim3d.serverPulseRing.rotation.z = time * 0.5;
    }
    if (sim3d.barrierRing) {
      sim3d.barrierRing.rotation.z = -time * 0.4;
    }

    if (sim3d.isAutoRotating && sim3d.camera) {
      const radius = 7.5;
      sim3d.camera.position.x = Math.sin(time * 0.4) * radius;
      sim3d.camera.position.z = Math.cos(time * 0.4) * radius;
      sim3d.camera.lookAt(0, 0.4, 0);
    }

    const trans = sim3d.activeTransmission;
    if (trans && trans.active && trans.curve && trans.packetMesh) {
      trans.progress += trans.speed;
      const t = Math.min(trans.progress, 1.0);

      const pos = trans.curve.getPoint(t);
      trans.packetMesh.position.copy(pos);
      trans.packetMesh.rotation.x += 0.06;
      trans.packetMesh.rotation.y += 0.08;

      const card = $('#sim3dFloatingDataCard');
      const container = $('#sim3dViewport');
      if (card && container && sim3d.camera) {
        const vector = pos.clone();
        vector.project(sim3d.camera);
        const widthHalf = container.clientWidth / 2;
        const heightHalf = container.clientHeight / 2;
        let screenX = (vector.x * widthHalf) + widthHalf;
        let screenY = -(vector.y * heightHalf) + heightHalf;

        screenX = Math.max(140, Math.min(container.clientWidth - 140, screenX));
        screenY = Math.max(70, Math.min(container.clientHeight - 40, screenY));

        card.style.left = `${Math.round(screenX)}px`;
        card.style.top = `${Math.round(screenY)}px`;

        const pct = Math.min(100, Math.round(t * 100));
        const statusEl = $('#dataCardStatus');
        if (statusEl) {
          if (trans.isApproved) {
            statusEl.textContent = t >= 1.0 ? '✓ Verified & Installed (100%)' : `OTA Stream: In Flight (${pct}%)`;
          } else {
            statusEl.textContent = t >= 0.95 ? '✕ Dropped by Firewall (BLOCKED)' : `In Flight (${pct}%) → Firewall Barrier`;
          }
        }
      }

      // Checkpoint 1: Crossing the CyberShield Barrier
      if (trans.isApproved) {
        if (t >= 0.5 && !trans.passedBarrier) {
          trans.passedBarrier = true;
          if (sim3d.barrierLaser) {
            sim3d.barrierLaser.material.color.setHex(0x10b981);
          }
        }

        if (t >= 1.0) {
          trans.active = false;
          const banner = $('#sim3dStatusBanner');
          if (banner) banner.className = 'sim-status-banner passed';
          const dot = $('#sim3dStatusDot');
          if (dot) dot.className = 'dot green';
          const textEl = $('#sim3dStatusText');
          if (textEl) {
            textEl.innerHTML = `
              <strong>✓ DELIVERED & APPROVED:</strong> Firmware v${trans.result.firmwareVersion} successfully verified with Ed25519 root key and applied to ${esc(trans.result.device.name)}!
            `;
          }

          setTimeout(() => {
            if (sim3d.scene && trans.packetMesh) {
              sim3d.scene.remove(trans.packetMesh);
              sim3d.scene.remove(trans.lineMesh);
            }
            if (sim3d.barrierLaser) {
              sim3d.barrierLaser.material.color.setHex(0x38bdf8);
            }
            const barrierPill = $('#sim3dHudBarrierPill');
            if (barrierPill) {
              barrierPill.className = 'sim-3d-hud-pill';
              barrierPill.innerHTML = `<span class="dot" style="background:#D96C3F;"></span><span>CYBERSHIELD GATEWAY: MONITORING</span>`;
            }
            const c = $('#sim3dFloatingDataCard');
            if (c) c.style.display = 'none';
          }, 2500);
        }
      } else {
        // Invalid attack: Reaches the CyberShield Barrier and gets BLOCKED!
        if (t >= 0.95 && !trans.impactTriggered) {
          trans.impactTriggered = true;
          trans.active = false;

          if (sim3d.barrierLaser) {
            sim3d.barrierLaser.material.color.setHex(0xef4444);
          }

          const banner = $('#sim3dStatusBanner');
          if (banner) banner.className = 'sim-status-banner blocked';
          const dot = $('#sim3dStatusDot');
          if (dot) dot.className = 'dot bad';
          const textEl = $('#sim3dStatusText');
          if (textEl) {
            textEl.innerHTML = `
              <strong>✕ ATTACK BLOCKED AT CYBERSHIELD BOUNDARY:</strong> ${esc(trans.result.reason)} · File rejected before reaching ${esc(trans.result.device.name)}!
            `;
          }

          let flashes = 0;
          const flashInterval = setInterval(() => {
            if (trans.packetMesh) {
              trans.packetMesh.visible = !trans.packetMesh.visible;
            }
            flashes++;
            if (flashes >= 6) {
              clearInterval(flashInterval);
              if (sim3d.scene && trans.packetMesh) {
                sim3d.scene.remove(trans.packetMesh);
                sim3d.scene.remove(trans.lineMesh);
              }
              if (sim3d.barrierLaser) {
                sim3d.barrierLaser.material.color.setHex(0x38bdf8);
              }
              const barrierPill = $('#sim3dHudBarrierPill');
              if (barrierPill) {
                barrierPill.className = 'sim-3d-hud-pill';
                barrierPill.innerHTML = `<span class="dot" style="background:#D96C3F;"></span><span>CYBERSHIELD GATEWAY: MONITORING</span>`;
              }
              const c = $('#sim3dFloatingDataCard');
              if (c) c.style.display = 'none';
            }
          }, 120);
        }
      }
    }

    sim3d.renderer.render(sim3d.scene, sim3d.camera);
  } else {
    // 2. High-Precision 2D Canvas Schematic Fallback
    draw2dSchematic(time);
  }
}

/**
 * 2D Canvas Schematic Fallback Renderer
 */
function draw2dSchematic(time) {
  const canvas = sim3d.canvas || $('#sim3dCanvas');
  const ctx = sim3d.ctx2d || (canvas ? canvas.getContext('2d') : null);
  if (!canvas || !ctx) return;

  const w = canvas.width || 800;
  const h = canvas.height || 440;

  // Clear & Cyber Slate background
  ctx.save();
  ctx.fillStyle = '#0b0f19';
  ctx.fillRect(0, 0, w, h);

  // Perspective Cyber Grid
  ctx.strokeStyle = '#141c2c';
  ctx.lineWidth = 1;
  const step = 38;
  ctx.beginPath();
  for (let x = 0; x < w; x += step) {
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
  }
  for (let y = 0; y < h; y += step) {
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
  }
  ctx.stroke();

  // Horizon base platform line
  const groundY = h * 0.76;
  const grad = ctx.createLinearGradient(0, groundY, w, groundY);
  grad.addColorStop(0, 'rgba(0, 242, 254, 0.05)');
  grad.addColorStop(0.5, 'rgba(0, 242, 254, 0.35)');
  grad.addColorStop(1, 'rgba(0, 242, 254, 0.05)');
  ctx.strokeStyle = grad;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(30, groundY);
  ctx.lineTo(w - 30, groundY);
  ctx.stroke();

  // Nodes Coordinates
  const serverX = w * 0.16;
  const serverY = h * 0.52;
  const barrierX = w * 0.50;
  const barrierY = h * 0.52;
  const deviceX = w * 0.84;
  const deviceY = h * 0.52;

  // Render Schematic Nodes
  draw2dServer(ctx, serverX, serverY, time);
  draw2dBarrier(ctx, barrierX, barrierY, time);
  const curDev = devices.find(d => d.id === sim3d.activeDeviceId) || devices[0] || { id: 'DEV-CAM-01', name: 'IoT Device', model: 'Standard' };
  draw2dTargetDevice(ctx, deviceX, deviceY, curDev, time);

  // Active Transmission
  const trans = sim3d.activeTransmission;
  if (trans && trans.active) {
    trans.progress += trans.speed;
    const t = Math.min(trans.progress, 1.0);

    const p0 = trans.p0 || { x: serverX, y: serverY };
    const p1 = trans.p1 || (trans.isApproved ? { x: barrierX, y: h * 0.22 } : { x: (serverX + barrierX) / 2, y: h * 0.35 });
    const p2 = trans.p2 || (trans.isApproved ? { x: deviceX, y: deviceY } : { x: barrierX, y: barrierY });

    const oneMinusT = 1 - t;
    const curX = oneMinusT * oneMinusT * p0.x + 2 * oneMinusT * t * p1.x + t * t * p2.x;
    const curY = oneMinusT * oneMinusT * p0.y + 2 * oneMinusT * t * p1.y + t * t * p2.y;

    // Faint full path trajectory
    ctx.beginPath();
    ctx.moveTo(p0.x, p0.y);
    ctx.quadraticCurveTo(p1.x, p1.y, p2.x, p2.y);
    ctx.strokeStyle = trans.isApproved ? 'rgba(16, 185, 129, 0.22)' : 'rgba(239, 68, 68, 0.22)';
    ctx.lineWidth = 3;
    ctx.setLineDash([4, 4]);
    ctx.stroke();
    ctx.setLineDash([]);

    // Glowing progressive curve
    ctx.beginPath();
    ctx.moveTo(p0.x, p0.y);
    for (let s = 0; s <= t; s += 0.04) {
      const u = 1 - s;
      const px = u * u * p0.x + 2 * u * s * p1.x + s * s * p2.x;
      const py = u * u * p0.y + 2 * u * s * p1.y + s * s * p2.y;
      ctx.lineTo(px, py);
    }
    ctx.strokeStyle = trans.isApproved ? '#10b981' : '#ef4444';
    ctx.lineWidth = 4;
    ctx.shadowColor = trans.isApproved ? '#10b981' : '#ef4444';
    ctx.shadowBlur = 12;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Glowing traveling packet
    ctx.save();
    ctx.translate(curX, curY);
    ctx.rotate(time * 3);
    const packetColor = trans.isApproved ? '#10b981' : '#ef4444';
    ctx.fillStyle = packetColor;
    ctx.shadowColor = packetColor;
    ctx.shadowBlur = 14;
    ctx.beginPath();
    ctx.moveTo(0, -9);
    ctx.lineTo(9, 0);
    ctx.lineTo(0, 9);
    ctx.lineTo(-9, 0);
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = '#ffffff';
    ctx.beginPath();
    ctx.arc(0, 0, 3, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();

    // Update Floating Data Card HUD
    const card = $('#sim3dFloatingDataCard');
    const container = $('#sim3dViewport');
    if (card && container) {
      let screenX = curX;
      let screenY = curY - 50;
      screenX = Math.max(140, Math.min(container.clientWidth - 140, screenX));
      screenY = Math.max(70, Math.min(container.clientHeight - 40, screenY));
      card.style.left = `${Math.round(screenX)}px`;
      card.style.top = `${Math.round(screenY)}px`;

      const pct = Math.min(100, Math.round(t * 100));
      const statusEl = $('#dataCardStatus');
      if (statusEl) {
        if (trans.isApproved) {
          statusEl.textContent = t >= 1.0 ? '✓ Verified & Installed (100%)' : `OTA Stream: In Flight (${pct}%)`;
        } else {
          statusEl.textContent = t >= 0.95 ? '✕ Dropped by Firewall (BLOCKED)' : `In Flight (${pct}%) → Firewall Barrier`;
        }
      }
    }

    // Checkpoint 1: Crossing the CyberShield Barrier
    if (trans.isApproved) {
      if (t >= 0.5 && !trans.passedBarrier) {
        trans.passedBarrier = true;
      }

      if (t >= 1.0) {
        trans.active = false;
        const banner = $('#sim3dStatusBanner');
        if (banner) banner.className = 'sim-status-banner passed';
        const dot = $('#sim3dStatusDot');
        if (dot) dot.className = 'dot green';
        const textEl = $('#sim3dStatusText');
        if (textEl) {
          textEl.innerHTML = `
            <strong>✓ DELIVERED & APPROVED:</strong> Firmware v${trans.result.firmwareVersion} successfully verified with Ed25519 root key and applied to ${esc(trans.result.device.name)}!
          `;
        }

        setTimeout(() => {
          const barrierPill = $('#sim3dHudBarrierPill');
          if (barrierPill) {
            barrierPill.className = 'sim-3d-hud-pill';
            barrierPill.innerHTML = `<span class="dot" style="background:#D96C3F;"></span><span>CYBERSHIELD GATEWAY: MONITORING</span>`;
          }
          const c = $('#sim3dFloatingDataCard');
          if (c) c.style.display = 'none';
        }, 2500);
      }
    } else {
      // Invalid attack: Reaches the CyberShield Barrier and gets BLOCKED!
      if (t >= 0.95 && !trans.impactTriggered) {
        trans.impactTriggered = true;
        trans.active = false;
        sim3d.barrierFlashTime = performance.now();

        const banner = $('#sim3dStatusBanner');
        if (banner) banner.className = 'sim-status-banner blocked';
        const dot = $('#sim3dStatusDot');
        if (dot) dot.className = 'dot bad';
        const textEl = $('#sim3dStatusText');
        if (textEl) {
          textEl.innerHTML = `
            <strong>✕ ATTACK BLOCKED AT CYBERSHIELD BOUNDARY:</strong> ${esc(trans.result.reason)} · File rejected before reaching ${esc(trans.result.device.name)}!
          `;
        }

        setTimeout(() => {
          const barrierPill = $('#sim3dHudBarrierPill');
          if (barrierPill) {
            barrierPill.className = 'sim-3d-hud-pill';
            barrierPill.innerHTML = `<span class="dot" style="background:#D96C3F;"></span><span>CYBERSHIELD GATEWAY: MONITORING</span>`;
          }
          const c = $('#sim3dFloatingDataCard');
          if (c) c.style.display = 'none';
        }, 2500);
      }
    }
  }

  ctx.restore();
}

function draw2dServer(ctx, x, y, time) {
  ctx.save();
  // Pedestal shadow
  ctx.fillStyle = '#0f172a';
  ctx.beginPath();
  ctx.ellipse(x, y + 48, 42, 12, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.strokeStyle = '#00f2fe';
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Pulse ring
  const pulseScale = 1 + (Math.sin(time * 2.5) * 0.12);
  ctx.beginPath();
  ctx.ellipse(x, y + 48, 52 * pulseScale, 15 * pulseScale, 0, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(0, 242, 254, 0.25)';
  ctx.stroke();

  // Server rack tower
  ctx.fillStyle = '#1e293b';
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 2;
  const rw = 52, rh = 80;
  ctx.beginPath();
  ctx.roundRect(x - rw / 2, y - rh / 2, rw, rh, 4);
  ctx.fill();
  ctx.stroke();

  // 4 Server unit slits with cyan glow
  for (let i = 0; i < 4; i++) {
    const sy = y - 26 + i * 16;
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(x - 20, sy, 40, 10);
    ctx.fillStyle = '#00f2fe';
    ctx.fillRect(x - 18, sy + 3, 22, 4);
    // Green LED
    ctx.fillStyle = (i % 2 === 0 ? '#10b981' : '#38bdf8');
    ctx.beginPath();
    ctx.arc(x + 12, sy + 5, 2.5, 0, Math.PI * 2);
    ctx.fill();
  }

  // Antenna at top
  ctx.strokeStyle = '#94a3b8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(x, y - rh / 2);
  ctx.lineTo(x, y - rh / 2 - 16);
  ctx.stroke();

  // Glowing beacon tip
  ctx.fillStyle = '#00f2fe';
  ctx.shadowColor = '#00f2fe';
  ctx.shadowBlur = 8;
  ctx.beginPath();
  ctx.arc(x, y - rh / 2 - 17, 3.5, 0, Math.PI * 2);
  ctx.fill();
  ctx.shadowBlur = 0;

  ctx.restore();
}

function draw2dBarrier(ctx, x, y, time) {
  ctx.save();
  const isFlashingRed = (performance.now() - (sim3d.barrierFlashTime || 0)) < 1400;
  const trans = sim3d.activeTransmission;
  const isGreen = trans && trans.active && trans.isApproved && trans.passedBarrier;
  const barrierColor = isFlashingRed ? '#ef4444' : (isGreen ? '#10b981' : '#38bdf8');

  // Ground base ring
  ctx.fillStyle = '#0f172a';
  ctx.beginPath();
  ctx.ellipse(x, y + 48, 36, 10, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.strokeStyle = barrierColor;
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Dual barrier boundary posts
  ctx.fillStyle = '#d96c3f';
  ctx.fillRect(x - 30, y - 65, 5, 115);
  ctx.fillRect(x + 25, y - 65, 5, 115);

  // Holographic forcefield plane
  ctx.fillStyle = isFlashingRed ? 'rgba(239, 68, 68, 0.35)' : 'rgba(56, 189, 248, 0.15)';
  ctx.strokeStyle = barrierColor;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.roundRect(x - 25, y - 60, 50, 110, 4);
  ctx.fill();
  ctx.stroke();

  // Center Shield Icon
  ctx.strokeStyle = barrierColor;
  ctx.shadowColor = barrierColor;
  ctx.shadowBlur = isFlashingRed ? 16 : 8;
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(x, y - 18);
  ctx.lineTo(x + 14, y - 10);
  ctx.lineTo(x + 14, y + 6);
  ctx.quadraticCurveTo(x + 14, y + 18, x, y + 24);
  ctx.quadraticCurveTo(x - 14, y + 18, x - 14, y + 6);
  ctx.lineTo(x - 14, y - 10);
  ctx.closePath();
  ctx.stroke();

  // Scanning laser beam moving up and down
  const laserY = y - 45 + ((Math.sin(time * 3.5) + 1) / 2) * 90;
  ctx.strokeStyle = isFlashingRed ? '#ef4444' : '#00f2fe';
  ctx.lineWidth = 3;
  ctx.shadowColor = ctx.strokeStyle;
  ctx.shadowBlur = 10;
  ctx.beginPath();
  ctx.moveTo(x - 24, laserY);
  ctx.lineTo(x + 24, laserY);
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Interception shockwave if flashing red
  if (isFlashingRed) {
    const elapsed = (performance.now() - (sim3d.barrierFlashTime || 0)) / 1400;
    const waveR = 15 + elapsed * 65;
    ctx.strokeStyle = `rgba(239, 68, 68, ${Math.max(0, 1 - elapsed)})`;
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.arc(x, y, waveR, 0, Math.PI * 2);
    ctx.stroke();
  }

  ctx.restore();
}

function draw2dTargetDevice(ctx, x, y, device, time) {
  ctx.save();
  const id = device ? device.id : '';

  // Pedestal
  ctx.fillStyle = '#0f172a';
  ctx.beginPath();
  ctx.ellipse(x, y + 48, 42, 12, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.strokeStyle = '#27845b';
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Pulse ring
  const pulseScale = 1 + (Math.sin(time * 2.8) * 0.12);
  ctx.beginPath();
  ctx.ellipse(x, y + 48, 52 * pulseScale, 15 * pulseScale, 0, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(39, 132, 91, 0.25)';
  ctx.stroke();

  // Device graphic
  if (id === 'DEV-CAM-01') {
    // Dome Camera
    ctx.fillStyle = '#f8fafc';
    ctx.beginPath();
    ctx.arc(x, y - 10, 24, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = '#94a3b8';
    ctx.stroke();
    // Lens
    ctx.fillStyle = '#020617';
    ctx.beginPath();
    ctx.arc(x, y - 10, 12, 0, Math.PI * 2);
    ctx.fill();
    // IR Ring
    ctx.strokeStyle = '#27845b';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(x, y - 10, 15, 0, Math.PI * 2);
    ctx.stroke();
  } else if (id === 'DEV-MED-03') {
    // Medical Infusion Pump
    ctx.fillStyle = '#475569';
    ctx.fillRect(x - 22, y - 40, 44, 70);
    // Display screen
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(x - 16, y - 34, 32, 28);
    // Waveform line
    ctx.strokeStyle = '#10b981';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(x - 14, y - 20);
    ctx.lineTo(x - 8, y - 20);
    ctx.lineTo(x - 4, y - 26);
    ctx.lineTo(x + 2, y - 14);
    ctx.lineTo(x + 6, y - 20);
    ctx.lineTo(x + 14, y - 20);
    ctx.stroke();
  } else if (id === 'DEV-AGR-09') {
    // Soil Sensor
    ctx.fillStyle = '#f1f5f9';
    ctx.fillRect(x - 18, y - 35, 36, 50);
    for (let i = 0; i < 3; i++) {
      ctx.fillStyle = '#64748b';
      ctx.fillRect(x - 12, y - 25 + i * 10, 24, 4);
    }
    // Probes
    ctx.strokeStyle = '#f59e0b';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(x - 8, y + 15);
    ctx.lineTo(x - 8, y + 42);
    ctx.moveTo(x + 8, y + 15);
    ctx.lineTo(x + 8, y + 42);
    ctx.stroke();
  } else {
    // TP-Link Router
    ctx.fillStyle = '#1e293b';
    ctx.fillRect(x - 30, y - 8, 60, 22);
    ctx.strokeStyle = '#0f172a';
    ctx.lineWidth = 2.5;
    const offsets = [-22, -8, 8, 22];
    offsets.forEach((ox, idx) => {
      ctx.beginPath();
      ctx.moveTo(x + ox, y - 8);
      ctx.lineTo(x + ox + (idx < 2 ? -8 : 8), y - 42);
      ctx.stroke();
    });
  }

  // Status indicator LED
  ctx.fillStyle = '#10b981';
  ctx.shadowColor = '#10b981';
  ctx.shadowBlur = 6;
  ctx.beginPath();
  ctx.arc(x, y + 36, 3, 0, Math.PI * 2);
  ctx.fill();
  ctx.shadowBlur = 0;

  ctx.restore();
}


// -------------------------------------------------------------
// PAGE 4: Safe Attack Simulator
// -------------------------------------------------------------
async function loadLabPage() {
  try {
    devices = await api('/api/devices');
    const select = $('#simDevice');
    if (select) {
      select.innerHTML = devices.map(d => `<option value="${esc(d.id)}">${esc(d.name)} (${esc(d.model)})</option>`).join('');
    }
  } catch (err) {
    showError(err);
  }
}

if ($('#simForm')) {
  $('#simForm').onsubmit = async e => {
    e.preventDefault();
    const testMode = $('#simMode') ? $('#simMode').value : 'SECURITY_TEST';
    const deviceId = $('#simDevice') ? $('#simDevice').value : 'DEV-CAM-01';
    const attackType = $('#attackType') ? $('#attackType').value : 'tampering';

  try {
    const res = await api('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({ deviceId, attackType, testMode })
    });

    const isBlocked = res.result === 'BLOCKED' || res.decision === 'REJECTED';
    $('#simBadge').className = `badge ${isBlocked ? 'bad' : 'ok'}`;
    $('#simBadge').textContent = res.result;

    $('#simResults').className = '';
    $('#simResults').innerHTML = `
      <div style="margin-bottom:14px;padding:12px;background:#faf8f5;border-radius:6px;border:1px solid var(--border);">
        <h3 style="font-size:14px;margin:0 0 4px;">${esc(res.title)}</h3>
        <p style="font-size:12px;color:var(--muted);margin:0 0 6px;">Target: <strong>${esc(res.deviceId)}</strong> · Result: <strong>${esc(res.result)}</strong></p>
        <p style="font-size:12px;margin:0;"><strong>Outcome:</strong> ${esc(res.reason)}</p>
      </div>

      <div class="timeline-stepper">
        ${(res.steps || []).map(s => `
          <div class="timeline-step ${s.status === 'PASSED' ? 'ok' : 'failed'}">
            <div class="timeline-dot"></div>
            <div style="font-size:13px;font-weight:700;">${esc(s.label)} <span class="badge ${s.status === 'PASSED' ? 'ok' : 'bad'}">${esc(s.status)}</span></div>
            <p style="font-size:12px;color:var(--muted);margin:2px 0 0;">${esc(s.detail)}</p>
          </div>
        `).join('')}
      </div>

      ${res.incidentId ? `
        <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border);display:flex;gap:10px;">
          <button class="btn primary" onclick="openIncidentDetail('${esc(res.incidentId)}')">View Incident Forensics (${esc(res.incidentId)}) ↗</button>
        </div>
      ` : ''}
    `;
  } catch (err) {
    showError(err);
  }
};
}

// -------------------------------------------------------------
// PAGE 5: Incident Investigations & Forensics (22 Fields)
// -------------------------------------------------------------
async function loadIncidentsPage() {
  try {
    const incidents = await api('/api/incidents');
    $('#incidentCountBadge').textContent = `${incidents.length} Recorded`;

    const listContainer = $('#incidentsList');
    if (!incidents.length) {
      listContainer.innerHTML = '<div class="empty">No incidents recorded yet. Run an attack test in the simulator to generate an incident.</div>';
      return;
    }

    listContainer.innerHTML = incidents.map(inc => `
      <div class="event-item" style="cursor:pointer;transition:background 0.15s;${selectedIncidentId === inc.id ? 'background:#FCE9DE;border-left:3px solid var(--primary);' : ''}" onclick="openIncidentDetail('${esc(inc.id)}')">
        <div>
          <strong style="font-size:13px;">${esc(inc.title)}</strong>
          <small style="display:block;color:var(--muted);margin-top:2px;">${esc(inc.id)} · ${esc(inc.device_id)} (${esc(inc.device_model)})</small>
        </div>
        <div style="text-align:right;">
          <span class="badge ${inc.severity === 'HIGH' || inc.severity === 'CRITICAL' ? 'bad' : inc.severity === 'MEDIUM' ? 'warn' : 'ok'}">
            ${esc(inc.severity)}
          </span>
          <small style="display:block;margin-top:4px;">${fmt(inc.timestamp_utc)}</small>
        </div>
      </div>
    `).join('');

    // If an incident was selected or default to first
    if (!selectedIncidentId && incidents.length > 0) {
      openIncidentDetail(incidents[0].id);
    }
  } catch (err) {
    showError(err);
  }
}

async function openIncidentDetail(incidentId) {
  selectedIncidentId = incidentId;
  go('investigations');

  try {
    const inc = await api(`/api/incidents/${incidentId}`);
    $('#detailStatusBadge').className = `badge ${inc.status === 'RESOLVED' ? 'ok' : 'bad'}`;
    $('#detailStatusBadge').textContent = inc.status;

    // Find device image
    const dev = devices.find(d => d.id === inc.device_id) || { image_url: '/images/tapo-c200.png' };

    $('#incidentDetailContent').className = '';
    $('#incidentDetailContent').innerHTML = `
      <div class="device-header-preview">
        <img src="${esc(dev.image_url)}" alt="${esc(inc.device_model)}" class="thumb-inline" style="width:70px;height:70px;">
        <div style="flex:1;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <h2 style="font-size:16px;margin:0;">${esc(inc.title)}</h2>
            <span class="badge ${inc.severity === 'HIGH' || inc.severity === 'CRITICAL' ? 'bad' : inc.severity === 'MEDIUM' ? 'warn' : 'ok'}">${esc(inc.severity)}</span>
          </div>
          <p style="color:var(--muted);font-size:12px;margin:3px 0 0;">Incident ID: <strong>${esc(inc.id)}</strong> · Classification: <strong>${esc(inc.classification)}</strong></p>
        </div>
      </div>

      <div style="background:#faf8f5;border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:14px;">
        <strong style="display:block;font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:4px;">What Happened (Simple Language):</strong>
        <p style="margin:0;font-size:13px;line-height:1.45;">${esc(inc.summary)}</p>
      </div>

      <!-- 22 REQUIRED FORENSIC FIELDS GRID -->
      <div class="forensic-grid">
        <div class="forensic-item">
          <div class="forensic-label">1. Incident ID</div>
          <div class="forensic-value"><code>${esc(inc.id)}</code></div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">2. Incident Title</div>
          <div class="forensic-value">${esc(inc.title)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">3. Classification</div>
          <div class="forensic-value"><span class="badge neutral">${esc(inc.classification)}</span></div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">4. Severity & Justification</div>
          <div class="forensic-value"><strong>${esc(inc.severity)}:</strong> ${esc(inc.severity_justification)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">5. Target Device & Model</div>
          <div class="forensic-value">${esc(inc.device_id)} — <strong>${esc(inc.device_model)}</strong></div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">6. Timestamp (UTC & Local)</div>
          <div class="forensic-value">UTC: ${esc(inc.timestamp_utc)}<br>Local: ${esc(inc.timestamp_local)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">7. Attack Category</div>
          <div class="forensic-value">${esc(inc.attack_category)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">8. Where Event Occurred</div>
          <div class="forensic-value">${esc(inc.occurred_location)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">9. Source Metadata</div>
          <div class="forensic-value"><code>${esc(inc.source_metadata)}</code></div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">10. Destination Metadata</div>
          <div class="forensic-value">${esc(inc.destination_metadata)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">11. Entry Point</div>
          <div class="forensic-value"><code>${esc(inc.entry_point)}</code></div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">12. Detection Rule ID</div>
          <div class="forensic-value"><span class="badge warn">${esc(inc.detection_rule_id)}</span></div>
        </div>

        <div class="forensic-item" style="grid-column:span 2;">
          <div class="forensic-label">13. Trigger Reason & Evidence</div>
          <div class="forensic-value">
            <p style="margin:0 0 6px;"><strong>Trigger:</strong> ${esc(inc.trigger_reason)}</p>
            <pre style="background:#252830;color:#00ffc4;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;">${esc(JSON.stringify(inc.evidence, null, 2))}</pre>
          </div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">14. Observed Impact</div>
          <div class="forensic-value">${esc(inc.observed_impact)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">15. Defense Response Action</div>
          <div class="forensic-value">${esc(inc.response_action)} (${inc.response_success ? '✓ Succeeded' : '✗ Failed'})</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">16. Recovery Status</div>
          <div class="forensic-value">${esc(inc.recovery_status)}</div>
        </div>

        <div class="forensic-item">
          <div class="forensic-label">17. Confidence Level & Evidence Limits</div>
          <div class="forensic-value">
            <strong>${esc(inc.confidence_level)}</strong><br>
            <small style="color:var(--muted);">${esc(inc.evidence_limitations)}</small>
          </div>
        </div>

        <div class="forensic-item" style="grid-column:span 2;">
          <div class="forensic-label">18. Recommended Next Action</div>
          <div class="forensic-value" style="color:var(--primary-dark);font-weight:600;">${esc(inc.recommended_action)}</div>
        </div>
      </div>

      <!-- Analyst Notes & Resolution Section -->
      <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);">
        <h3 style="font-size:14px;margin:0 0 10px;">Investigation Notes & Status Resolution</h3>
        <div style="display:flex;gap:10px;margin-bottom:12px;">
          <label style="flex:1;">Status:
            <select id="incDetailStatus">
              <option value="OPEN" ${inc.status === 'OPEN' ? 'selected' : ''}>OPEN (Investigating)</option>
              <option value="RESOLVED" ${inc.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED (Mitigated)</option>
              <option value="FALSE_POSITIVE" ${inc.status === 'FALSE_POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option>
              <option value="BENIGN" ${inc.status === 'BENIGN' ? 'selected' : ''}>BENIGN TEST EVENT</option>
            </select>
          </label>
        </div>
        <label>Analyst Notes:
          <textarea id="incDetailNotes" style="width:100%;min-height:70px;padding:8px;border-radius:6px;border:1px solid var(--border);font-family:inherit;font-size:13px;">${esc(inc.investigation_notes || '')}</textarea>
        </label>
        <button class="btn primary" style="margin-top:8px;" onclick="saveIncidentResolution('${esc(inc.id)}')">Save Investigation Updates</button>
      </div>
    `;
  } catch (err) {
    showError(err);
  }
}

window.openIncidentDetail = openIncidentDetail;

window.saveIncidentResolution = async incidentId => {
  const status = $('#incDetailStatus').value;
  const investigationNotes = $('#incDetailNotes').value;
  try {
    await api(`/api/incidents/${incidentId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, investigationNotes })
    });
    showSuccess(`Investigation ${incidentId} updated.`);
    loadIncidentsPage();
  } catch (err) {
    showError(err);
  }
};

// -------------------------------------------------------------
// PAGE 6: Attack Alerts
// -------------------------------------------------------------
async function loadAlertsPage() {
  try {
    const alerts = await api('/api/anomalies/alerts');
    const tbody = $('#alertRows');
    const emptyBox = $('#noAlerts');

    if (!alerts.length) {
      tbody.innerHTML = '';
      emptyBox.style.display = 'block';
    } else {
      emptyBox.style.display = 'none';
      tbody.innerHTML = alerts.map(a => `
        <tr>
          <td>${fmtFull(a.timestamp)}</td>
          <td><b>${esc(a.device_id)}</b></td>
          <td><code>${esc(a.rule_id)}</code></td>
          <td><span class="badge ${a.severity === 'CRITICAL' ? 'crit' : a.severity === 'HIGH' ? 'bad' : 'warn'}">${esc(a.severity)}</span></td>
          <td style="max-width:300px;font-size:12px;">${esc(a.evidence)}</td>
          <td><span class="badge ${a.status === 'ACTIVE' ? 'bad' : 'ok'}">${esc(a.status)}</span></td>
          <td>
            ${a.status === 'ACTIVE' ? `
              <button class="btn secondary" style="padding:4px 8px;min-height:26px;font-size:11px;" onclick="resolveAlert('${esc(a.id)}')">Acknowledge ✓</button>
            ` : '<span style="color:var(--muted);font-size:11px;">Resolved</span>'}
          </td>
        </tr>
      `).join('');
    }
  } catch (err) {
    showError(err);
  }
}

window.resolveAlert = async alertId => {
  const note = prompt('Enter analyst justification / disposition note:');
  if (note === null) return;
  try {
    await api(`/api/anomalies/alerts/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ status: 'ACKNOWLEDGED', note })
    });
    showSuccess(`Alert acknowledged.`);
    loadAlertsPage();
  } catch (err) {
    showError(err);
  }
};

// -------------------------------------------------------------
// PAGE 7: Security Event Logs (SQLite)
// -------------------------------------------------------------
async function loadEvents() {
  try {
    const deviceId = $('#filterLogDevice')?.value || 'ALL';
    const severity = $('#filterLogSeverity')?.value || 'ALL';
    const search = $('#filterLogSearch')?.value || '';

    const events = await api(`/api/events?deviceId=${encodeURIComponent(deviceId)}&severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}`);
    const tbody = $('#logRows');
    const emptyBox = $('#noLogs');

    if (!events.length) {
      tbody.innerHTML = '';
      emptyBox.style.display = 'block';
    } else {
      emptyBox.style.display = 'none';
      tbody.innerHTML = events.map(e => `
        <tr>
          <td>${fmt(e.timestamp)}</td>
          <td><b>${esc(e.device_id)}</b></td>
          <td>${esc(e.event_type)}</td>
          <td><span class="badge ${e.severity === 'HIGH' || e.severity === 'CRITICAL' ? 'bad' : e.severity === 'MEDIUM' ? 'warn' : 'ok'}">${esc(e.severity)}</span></td>
          <td><span class="badge ${e.verification_result === 'PASSED' ? 'ok' : 'bad'}">${esc(e.verification_result)}</span></td>
          <td>${esc(e.response_outcome)}</td>
          <td style="max-width:320px;font-size:12px;">${esc(e.description)}</td>
        </tr>
      `).join('');
    }
  } catch (err) {
    showError(err);
  }
}

$('#filterLogDevice').onchange = loadEvents;
$('#filterLogSeverity').onchange = loadEvents;
$('#filterLogSearch').oninput = () => {
  clearTimeout(window._searchTimer);
  window._searchTimer = setTimeout(loadEvents, 300);
};
$('#refreshLogs').onclick = loadEvents;

// -------------------------------------------------------------
// PAGE 8: Anomaly Rules
// -------------------------------------------------------------
async function loadAnomalyRulesPage() {
  try {
    const rules = await api('/api/anomalies/rules');
    $('#anomalyRuleRows').innerHTML = rules.map(r => `
      <tr>
        <td><code>${esc(r.rule_id)}</code></td>
        <td><strong>${esc(r.name)}</strong></td>
        <td>${esc(r.category)}</td>
        <td><b>${r.threshold}</b> ${esc(r.unit)}</td>
        <td>${r.time_window_sec}s</td>
        <td><span class="badge ${r.severity === 'CRITICAL' ? 'crit' : r.severity === 'HIGH' ? 'bad' : 'warn'}">${esc(r.severity)}</span></td>
        <td style="max-width:280px;font-size:12px;">${esc(r.description)}</td>
        <td>
          <button class="btn secondary" style="padding:4px 8px;min-height:26px;font-size:11px;" onclick="editRuleThreshold('${esc(r.rule_id)}', ${r.threshold})">Edit</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showError(err);
  }
}

window.editRuleThreshold = async (ruleId, current) => {
  const val = prompt(`Enter new threshold for ${ruleId}:`, current);
  if (!val || isNaN(val)) return;
  try {
    await api(`/api/anomalies/rules/${ruleId}`, {
      method: 'PATCH',
      body: JSON.stringify({ threshold: parseFloat(val) })
    });
    showSuccess(`Updated ${ruleId} threshold.`);
    loadAnomalyRulesPage();
  } catch (err) {
    showError(err);
  }
};

// -------------------------------------------------------------
// PAGE 9: Trusted Keys (Ed25519)
// -------------------------------------------------------------
async function loadTrustedKeysPage() {
  try {
    const keys = await api('/api/keys');
    $('#trustedKeyRows').innerHTML = keys.map(k => `
      <tr>
        <td><code>${esc(k.key_id)}</code></td>
        <td><strong>${esc(k.name)}</strong></td>
        <td>${esc(k.algorithm)}</td>
        <td style="font-family:monospace;font-size:11px;">${esc(k.public_key_hex.slice(0, 16))}...${esc(k.public_key_hex.slice(-16))}</td>
        <td><span class="badge ${k.status === 'ACTIVE' ? 'ok' : 'bad'}">${esc(k.status)}</span></td>
        <td>${fmt(k.created_at)}</td>
        <td>
          ${k.status === 'ACTIVE' ? `
            <button class="btn secondary" style="padding:4px 8px;min-height:26px;font-size:11px;color:var(--danger);" onclick="revokeKey('${esc(k.key_id)}')">Revoke</button>
          ` : '<span style="color:var(--muted);font-size:11px;">Revoked</span>'}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showError(err);
  }
}

$('#btnRotateKey').onclick = async () => {
  const name = prompt('Enter alias for the new Ed25519 root key:');
  if (!name) return;
  try {
    const res = await api('/api/keys/rotate', {
      method: 'POST',
      body: JSON.stringify({ name })
    });
    showSuccess(`Generated new key: ${res.keyId}`);
    loadTrustedKeysPage();
  } catch (err) {
    showError(err);
  }
};

window.revokeKey = async keyId => {
  if (!confirm(`Are you sure you want to revoke key '${keyId}'? Firmware updates signed with this key will be permanently rejected.`)) return;
  try {
    await api(`/api/keys/${keyId}/revoke`, { method: 'POST' });
    showSuccess(`Key ${keyId} revoked.`);
    loadTrustedKeysPage();
  } catch (err) {
    showError(err);
  }
};

// -------------------------------------------------------------
// PAGE 10: Docker Health
// -------------------------------------------------------------
async function loadDockerPage() {
  try {
    const status = await api('/api/docker/status');
    const badge = $('#dockerStatusBadge');
    badge.className = `badge ${status.available ? 'ok' : 'neutral'}`;
    badge.textContent = status.status;

    $('#dockerMessageText').textContent = status.message;
    $('#dockerCliText').textContent = status.cliInstalled ? 'Available' : 'Not installed';
    $('#dockerSocketText').textContent = status.socketExists ? 'Active' : 'Unavailable';
    $('#dockerModeText').textContent = status.available ? 'Container Engine' : 'Software Emulation';

    $('#approvedDockerRows').innerHTML = (status.approvedEmulators || []).map(e => `
      <tr>
        <td><b>${esc(e.deviceId)}</b><br><small style="color:var(--muted);">${esc(e.name)}</small></td>
        <td><code>${esc(e.service)}</code></td>
        <td><code>${esc(e.image)}</code></td>
        <td><code>${esc(e.nonRootUser)}</code></td>
        <td>${esc(e.cpuLimit)} CPU</td>
        <td>${esc(e.memoryLimit)}</td>
        <td>${esc(e.ports)}</td>
        <td><span class="badge neutral">${esc(e.capabilitiesDropped.join(', '))}</span></td>
      </tr>
    `).join('');
  } catch (err) {
    showError(err);
  }
}

$('#btnRefreshDocker').onclick = loadDockerPage;

// -------------------------------------------------------------
// PAGE 11: Performance Testing
// -------------------------------------------------------------
async function loadBenchmarkHistory() {
  try {
    const env = await api('/api/benchmark/environment');
    $('#envNodeVersion').textContent = env.nodeVersion;
    $('#envPlatform').textContent = `${env.platform}-${env.arch}`;
    $('#envCores').textContent = env.logicalCores;

    const history = await api('/api/benchmark/history');
    const tbody = $('#benchmarkHistoryRows');
    const emptyBox = $('#noBenchmarkHistory');

    if (!history.length) {
      tbody.innerHTML = '';
      emptyBox.style.display = 'block';
    } else {
      emptyBox.style.display = 'none';
      tbody.innerHTML = history.map(h => `
        <tr>
          <td>${fmt(h.timestamp)}</td>
          <td><b>${h.fleet_size}</b> nodes</td>
          <td>${h.test_runs}</td>
          <td>${h.baseline_ms} ms</td>
          <td>${h.secure_ms} ms</td>
          <td style="color:${h.overhead_ms > 0 ? 'var(--primary-dark)' : 'var(--success)'};font-weight:700;">
            ${h.overhead_ms > 0 ? '+' : ''}${h.overhead_ms} ms
          </td>
          <td>${h.overhead_pct !== null ? `${h.overhead_pct}%` : 'N/A'}</td>
          <td>${h.success_count} / <span style="color:${h.fail_count > 0 ? 'var(--danger)' : 'inherit'};">${h.fail_count}</span></td>
          <td>${h.memory_rss_mb} MB</td>
          <td><button class="btn secondary" style="padding:2px 6px;min-height:24px;font-size:10px;color:var(--danger);" onclick="deleteBenchmark('${esc(h.id)}')">✕</button></td>
        </tr>
      `).join('');
    }
  } catch (err) {
    showError(err);
  }
}

$('#btnRunBenchmark').onclick = async () => {
  if (isBenchmarking) return;
  isBenchmarking = true;
  $('#btnRunBenchmark').disabled = true;
  $('#btnStopBenchmark').disabled = false;
  $('#benchStatusBadge').textContent = 'BENCHMARKING...';
  $('#benchStatusBadge').className = 'badge warn';

  try {
    const fleetSize = $('#benchFleetSize').value;
    const testRuns = $('#benchTestRuns').value;
    const packageSizeBytes = $('#benchPackageSize').value;
    const simulateFailures = $('#benchSimulateFailures').value === 'true';

    const res = await api('/api/benchmark/run', {
      method: 'POST',
      body: JSON.stringify({ fleetSize, testRuns, packageSizeBytes, simulateFailures })
    });

    $('#metricBaselineTime').textContent = `${res.baselineMs} ms`;
    $('#metricSecureTime').textContent = `${res.secureMs} ms`;
    $('#metricOverheadMs').textContent = `${res.overheadMs > 0 ? '+' : ''}${res.overheadMs} ms`;
    $('#metricOverheadPct').textContent = res.overheadPct !== null ? `${res.overheadPct}%` : 'N/A';

    $('#resCpuUser').textContent = `${res.cpuUserMs} ms`;
    $('#resCpuSystem').textContent = `${res.cpuSystemMs} ms`;
    $('#resMemRss').textContent = `${res.memoryRssMb} MB`;
    $('#resMemHeap').textContent = `${res.memoryHeapMb} MB`;

    // Render operation breakdown bars
    $('#chartBreakdown').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:10px;padding:12px;">
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
            <span>SHA-256 Hashing:</span><b>${res.hashingMs} ms</b>
          </div>
          <div style="background:#eee;border-radius:4px;height:8px;overflow:hidden;">
            <div style="background:var(--primary);width:${Math.min(100, (res.hashingMs / (res.secureMs || 1)) * 100)}%;height:100%;"></div>
          </div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
            <span>Ed25519 Signature Verification:</span><b>${res.signatureMs} ms</b>
          </div>
          <div style="background:#eee;border-radius:4px;height:8px;overflow:hidden;">
            <div style="background:#557C9E;width:${Math.min(100, (res.signatureMs / (res.secureMs || 1)) * 100)}%;height:100%;"></div>
          </div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
            <span>Manifest & Version Policy:</span><b>${res.manifestMs} ms</b>
          </div>
          <div style="background:#eee;border-radius:4px;height:8px;overflow:hidden;">
            <div style="background:#27845B;width:${Math.min(100, (res.manifestMs / (res.secureMs || 1)) * 100)}%;height:100%;"></div>
          </div>
        </div>
      </div>
    `;

    $('#chartFleetScaling').innerHTML = `
      <div style="padding:14px;font-size:12px;">
        <p><strong>Fleet Workload:</strong> Processed ${res.fleetSize} virtual devices across ${res.testRuns} test runs (${res.packageSizeBytes / 1024} KB firmware image).</p>
        <p><strong>Execution Latency:</strong> Min ${res.minDurationMs} ms · Avg ${res.avgDurationMs} ms · Max ${res.maxDurationMs} ms</p>
        <p><strong>Success Ratio:</strong> ${res.successCount} verified / ${res.failCount} rejected</p>
      </div>
    `;

    showSuccess('Benchmark completed and persisted to SQLite.');
    loadBenchmarkHistory();
  } catch (err) {
    showError(err);
  } finally {
    isBenchmarking = false;
    $('#btnRunBenchmark').disabled = false;
    $('#btnStopBenchmark').disabled = true;
    $('#benchStatusBadge').textContent = 'READY';
    $('#benchStatusBadge').className = 'badge ok';
  }
};

$('#btnStopBenchmark').onclick = async () => {
  await api('/api/benchmark/stop', { method: 'POST' });
  showSuccess('Benchmark stop signal sent.');
};

$('#btnExportBenchmarkCsv').onclick = () => {
  window.location.href = '/api/benchmark/export-csv';
};

$('#btnRefreshBenchmarkHistory').onclick = loadBenchmarkHistory;

window.deleteBenchmark = async id => {
  try {
    await api(`/api/benchmark/history/${id}`, { method: 'DELETE' });
    loadBenchmarkHistory();
  } catch (err) {
    showError(err);
  }
};

// -------------------------------------------------------------
// PAGE 12: Threat Model & Risk
// -------------------------------------------------------------
async function loadThreatModel() {
  if (threatsData) return;
  try {
    threatsData = await api('/api/threats');

    // 1. Threat register
    renderThreatCards(threatsData.threats);

    // 2. Assets
    $('#assetGrid').innerHTML = threatsData.assets.map(a => `
      <article class="panel">
        <h3 style="font-size:14px;margin:0 0 6px;">${esc(a.name)}</h3>
        <span class="badge ${a.criticality === 'CRITICAL' ? 'crit' : 'bad'}">${esc(a.criticality)}</span>
        <p style="font-size:12px;color:var(--muted);margin:8px 0;">${esc(a.description)}</p>
        <p style="font-size:11px;margin:0;"><strong>Impact if Compromised:</strong> ${esc(a.impactIfCompromised)}</p>
      </article>
    `).join('');

    // 3. Profiles
    $('#profileCardList').innerHTML = threatsData.profiles.map(p => `
      <article class="panel">
        <h3 style="font-size:14px;margin:0 0 4px;">${esc(p.name)}</h3>
        <p style="color:var(--muted);font-size:12px;margin:0 0 8px;"><code>${esc(p.id)}</code></p>
        <p style="font-size:12px;margin:0 0 8px;"><strong>Capabilities:</strong> ${esc(p.capabilities)}</p>
        <p style="font-size:12px;margin:0 0 8px;"><strong>Limitations:</strong> ${esc(p.limitations)}</p>
        <p style="font-size:12px;margin:0;"><strong>Typical Motivation:</strong> ${esc(p.motivation)}</p>
      </article>
    `).join('');

    // 4. Boundaries
    $('#boundaryRows').innerHTML = threatsData.boundaries.map(b => `
      <tr>
        <td><b>${esc(b.name)}</b></td>
        <td><code>${esc(b.flow)}</code></td>
        <td style="font-size:12px;">${esc(b.threatVectors)}</td>
        <td style="font-size:12px;"><strong>${esc(b.requiredSecurityChecks)}</strong></td>
      </tr>
    `).join('');

    // 5. Limitations
    $('#limitationsContainer').innerHTML = threatsData.limitations.map(l => `
      <article class="panel">
        <h3 style="font-size:14px;margin:0 0 6px;">${esc(l.title)}</h3>
        <p style="font-size:12px;color:var(--muted);margin:0 0 6px;">${esc(l.description)}</p>
        <p style="font-size:11px;margin:0;"><strong>Platform Constraint:</strong> ${esc(l.implication)}</p>
      </article>
    `).join('');
  } catch (err) {
    showError(err);
  }
}

function renderThreatCards(threats) {
  $('#threatCardList').innerHTML = threats.map(t => `
    <article class="panel">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">
        <h3 style="font-size:14px;margin:0;">${esc(t.name)}</h3>
        <span class="badge ${t.riskLevel === 'Critical' ? 'crit' : t.riskLevel === 'High' ? 'bad' : t.riskLevel === 'Medium' ? 'warn' : 'ok'}">
          ${esc(t.riskLevel)} (Score: ${t.riskScore})
        </span>
      </div>
      <p style="font-size:11px;color:var(--muted);margin:0 0 8px;"><code>${esc(t.id)}</code> · Likelihood: ${t.likelihood}/5 · Impact: ${t.impact}/5</p>
      <p style="font-size:12px;margin:0 0 8px;">${esc(t.description)}</p>
      <div style="font-size:11px;background:#faf8f5;padding:8px;border-radius:4px;border:1px solid var(--border);">
        <strong>Existing Control:</strong> ${esc(t.existingControl)}<br>
        <strong>Residual Risk:</strong> ${esc(t.residualRisk)}
      </div>
    </article>
  `).join('');
  $('#threatCountBadge').textContent = `Showing ${threats.length} threats`;
}

$$('.tab-btn').forEach(btn => {
  btn.onclick = () => {
    $$('.tab-btn').forEach(b => b.classList.remove('active'));
    $$('.threat-subtab').forEach(s => s.classList.remove('active'));
    btn.classList.add('active');
    $(`#subtab-${btn.dataset.threattab}`).classList.add('active');
  };
});

$('#filterThreatRisk').onchange = () => {
  const risk = $('#filterThreatRisk').value;
  const filtered = risk === 'ALL' ? threatsData.threats : threatsData.threats.filter(t => t.riskLevel === risk);
  renderThreatCards(filtered);
};

$('#btnExportThreatsCsv').onclick = () => {
  window.location.href = '/api/threats/export-csv';
};

$('#btnOpenThreatReport').onclick = () => {
  window.open('/api/threats/report', '_blank');
};

// -------------------------------------------------------------
// PAGE 13: Security Audit Logs
// -------------------------------------------------------------
async function loadAuditLogsPage() {
  try {
    const logs = await api('/api/audit-logs');
    $('#auditRows').innerHTML = logs.map(l => `
      <tr>
        <td>${fmtFull(l.timestamp)}</td>
        <td><strong>${esc(l.actor)}</strong></td>
        <td><code>${esc(l.action)}</code></td>
        <td><b>${esc(l.target)}</b></td>
        <td style="font-size:12px;">${esc(l.details)}</td>
        <td><span class="badge ${l.status === 'SUCCESS' ? 'ok' : 'bad'}">${esc(l.status)}</span></td>
      </tr>
    `).join('');
  } catch (err) {
    showError(err);
  }
}

$('#btnRefreshAudit').onclick = loadAuditLogsPage;

// -------------------------------------------------------------
// PAGE 15: Settings & Thresholds
// -------------------------------------------------------------
async function loadSettingsPage() {
  try {
    const s = await api('/api/settings');
    $('#settingAuthThreshold').value = s.failed_login_lockout_threshold || 3;
    $('#settingLockoutDuration').value = s.lockout_duration_seconds || 300;
    $('#settingMaxUploadMb').value = s.max_upload_size_mb || 10;
    $('#settingTempMax').value = s.sensor_temp_alert_max || 45;
    $('#settingHumMax').value = s.sensor_hum_alert_max || 85;
  } catch (err) {
    showError(err);
  }
}

$('#settingsForm').onsubmit = async e => {
  e.preventDefault();
  try {
    await api('/api/settings', {
      method: 'PATCH',
      body: JSON.stringify({
        failed_login_lockout_threshold: $('#settingAuthThreshold').value,
        lockout_duration_seconds: $('#settingLockoutDuration').value,
        max_upload_size_mb: $('#settingMaxUploadMb').value,
        sensor_temp_alert_max: $('#settingTempMax').value,
        sensor_hum_alert_max: $('#settingHumMax').value
      })
    });
    showSuccess('Settings updated and saved to SQLite.');
  } catch (err) {
    showError(err);
  }
};

$('#btnResetDemoState').onclick = async () => {
  if (!confirm('Are you sure you want to reset transient test data? Core device registry and keystores will remain.')) return;
  try {
    const res = await api('/api/reset-demo', { method: 'POST' });
    showSuccess(res.message);
    loadOverview();
  } catch (err) {
    showError(err);
  }
};

// Quick Safe Test button in topbar
$('#btnQuickSafeTest').onclick = async () => {
  try {
    const res = await api('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({
        deviceId: 'DEV-CAM-01',
        testMode: 'NORMAL_TEST'
      })
    });
    showSuccess(`Safe test completed on DEV-CAM-01: ${res.reason}`);
    loadOverview();
  } catch (err) {
    showError(err);
  }
};

// Global Nav Handlers
$$('.nav-item').forEach(btn => {
  btn.onclick = () => go(btn.dataset.page);
});

$$('[data-goto]').forEach(btn => {
  btn.onclick = () => go(btn.dataset.goto);
});

// Initialization
loadOverview();
