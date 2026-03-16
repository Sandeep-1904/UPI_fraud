/* ═══════════════════════════════════════════
   FRAUDSHIELD — Frontend App Logic
═══════════════════════════════════════════ */

// ── STATE ──────────────────────────────────
const State = {
  alerts: [],
  metrics: { total: 0, flagged: 0, probs: [], severity_counts: {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0}, timeline: [] },
  siemLogs: { json: [], cef: [] },
  currentFmt: 'json',
  currentFilter: 'ALL',
};

// ── CLOCK ──────────────────────────────────
function updateClock() {
  document.getElementById('live-clock').textContent =
    new Date().toLocaleTimeString('en-IN', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── TABS ───────────────────────────────────
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ── SCENARIOS ──────────────────────────────
const scenarios = {
  normal:    { sender_upi:'rahul@okaxis',    receiver_upi:'shop@ybl',    amount:850,   hour:14, velocity:2,  pin_fails:0, new_payee:false, vpn:false, payment_type:'P2P' },
  suspicious:{ sender_upi:'unknown@paytm',  receiver_upi:'anon@upi',    amount:99999, hour:3,  velocity:15, pin_fails:4, new_payee:true,  vpn:true,  payment_type:'P2P' },
  micro:     { sender_upi:'test@oksbi',      receiver_upi:'dest@okaxis', amount:1,     hour:2,  velocity:20, pin_fails:3, new_payee:true,  vpn:false, payment_type:'P2P' },
  critical:  { sender_upi:'fraud@paytm',     receiver_upi:'mule@ybl',    amount:150000,hour:1,  velocity:25, pin_fails:5, new_payee:true,  vpn:true,  payment_type:'P2P' },
};

document.querySelectorAll('.scenario-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const s = scenarios[btn.dataset.scenario];
    document.getElementById('sender_upi').value   = s.sender_upi;
    document.getElementById('receiver_upi').value = s.receiver_upi;
    document.getElementById('amount').value       = s.amount;
    document.getElementById('hour').value         = s.hour;
    document.getElementById('velocity').value     = s.velocity;
    document.getElementById('pin_fails').value    = s.pin_fails;
    document.getElementById('new_payee').checked  = s.new_payee;
    document.getElementById('vpn').checked        = s.vpn;
    document.getElementById('payment_type').value = s.payment_type;
  });
});

// ── SCORING ────────────────────────────────
function collectForm() {
  return {
    sender_upi:   document.getElementById('sender_upi').value,
    receiver_upi: document.getElementById('receiver_upi').value,
    amount:       parseFloat(document.getElementById('amount').value) || 0,
    hour:         parseInt(document.getElementById('hour').value) || 0,
    velocity:     parseInt(document.getElementById('velocity').value) || 1,
    pin_fails:    parseInt(document.getElementById('pin_fails').value) || 0,
    new_payee:    document.getElementById('new_payee').checked ? 1 : 0,
    vpn:          document.getElementById('vpn').checked ? 1 : 0,
    payment_type: document.getElementById('payment_type').value,
    dow:          new Date().getDay(),
    response_ms:  Math.floor(Math.random() * 300) + 100,
  };
}

document.getElementById('txn-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn  = document.getElementById('score-btn');
  btn.classList.add('loading');
  btn.querySelector('.btn-text').textContent = 'ANALYSING...';
  const data = collectForm();
  try {
    const result = await callBackend(data);
    displayResult(result, data);
    recordAlert(result, data);
    updateMetrics(result);
    logToSIEM(result, data);
  } catch(err) {
    console.error(err);
  } finally {
    btn.classList.remove('loading');
    btn.querySelector('.btn-text').textContent = 'ANALYSE TRANSACTION';
  }
});

// ── BACKEND CALL (with local fallback) ─────
async function callBackend(data) {
  try {
    const res = await fetch('/api/score', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('API error');
    return await res.json();
  } catch (_) {
    return localScore(data);
  }
}

// ── LOCAL SCORING ENGINE (runs if backend down) ──
function localScore(d) {
  const isOddHour  = [0,1,2,3,4,23].includes(d.hour) ? 1 : 0;
  const highAmount = d.amount > 50000 ? 1 : 0;
  const microTxn   = d.amount < 10    ? 1 : 0;
  const justBelow  = (d.amount >= 9000 && d.amount <= 9999) ? 1 : 0;
  const highVel    = d.velocity > 6 ? 1 : 0;

  const riskScore = d.pin_fails*2 + d.velocity*1.5 + d.new_payee*3 +
                    d.vpn*4 + isOddHour*2 + highAmount*3 + microTxn*2;

  let prob = 0.02;
  if (d.vpn)       prob += 0.25;
  if (isOddHour)   prob += 0.15;
  if (highAmount)  prob += 0.22;
  if (microTxn)    prob += 0.18;
  if (justBelow)   prob += 0.12;
  if (highVel)     prob += 0.15;
  if (d.pin_fails > 1) prob += d.pin_fails * 0.06;
  if (d.new_payee) prob += 0.10;
  prob += (Math.random() * 0.04 - 0.02);
  prob = Math.max(0.01, Math.min(0.99, prob));

  let severity;
  if (prob >= 0.85 || riskScore >= 20) severity = 'CRITICAL';
  else if (prob >= 0.65 || riskScore >= 14) severity = 'HIGH';
  else if (prob >= 0.45 || riskScore >= 8)  severity = 'MEDIUM';
  else severity = 'LOW';

  const reasons = [];
  if (d.vpn)         reasons.push('VPN/proxy detected');
  if (isOddHour)     reasons.push(`Odd hour (${d.hour}:00)`);
  if (highVel)       reasons.push(`High velocity (${d.velocity}/hr)`);
  if (d.pin_fails>1) reasons.push(`${d.pin_fails} failed PIN attempts`);
  if (d.new_payee)   reasons.push('First-time payee');
  if (highAmount)    reasons.push(`Large amount (₹${d.amount.toLocaleString('en-IN')})`);
  if (microTxn)      reasons.push('Micro test transaction');
  if (justBelow)     reasons.push('Just-below-limit pattern');

  const action = severity === 'CRITICAL' ? 'BLOCK' : severity === 'HIGH' || severity === 'MEDIUM' ? 'REVIEW' : 'ALLOW';
  const txnId  = 'TXN' + Math.random().toString(36).substr(2,8).toUpperCase();

  return { fraud_probability: prob, severity, risk_score: riskScore, action, reason: reasons.join('; ') || 'ML anomaly detection', txn_id: txnId, is_fraud: prob >= 0.5 };
}

// ── DISPLAY RESULT ─────────────────────────
const sevColors = { CRITICAL:'var(--critical)', HIGH:'var(--high)', MEDIUM:'var(--medium)', LOW:'var(--low)' };

function displayResult(r, d) {
  document.getElementById('result-placeholder').classList.add('hidden');
  const rc = document.getElementById('result-content');
  rc.classList.remove('hidden');

  const prob = r.fraud_probability;
  const pct  = (prob * 100).toFixed(1);

  const verdictEl = document.getElementById('verdict-text');
  verdictEl.textContent = r.is_fraud ? '⚠ FRAUD DETECTED' : '✓ LEGITIMATE';
  verdictEl.style.color = r.is_fraud ? sevColors[r.severity] : 'var(--low)';

  const fill = document.getElementById('prob-fill');
  setTimeout(() => { fill.style.width = pct + '%'; }, 50);
  fill.style.background = prob > 0.7 ? 'var(--critical)' : prob > 0.45 ? 'var(--high)' : 'var(--low)';

  document.getElementById('prob-value').textContent = pct + '%';
  document.getElementById('prob-value').style.color = sevColors[r.severity] || 'var(--text)';

  const sevBadge = document.getElementById('severity-badge');
  sevBadge.textContent = r.severity;
  sevBadge.className = 'ri-value badge ' + r.severity;

  document.getElementById('risk-score').textContent   = r.risk_score.toFixed(1);
  document.getElementById('action-val').textContent   = r.action;
  document.getElementById('action-val').className     = 'ri-value action-val ' + r.action;
  document.getElementById('txn-id').textContent       = r.txn_id;
  document.getElementById('reason-text').textContent  = r.reason || 'No flags raised';
}

// ── RECORD ALERT ───────────────────────────
function recordAlert(r, d) {
  const alert = { ...r, ...d, timestamp: new Date() };
  State.alerts.unshift(alert);
  updateAlertStats();
  if (r.is_fraud || r.severity !== 'LOW') renderAlerts();
}

function updateAlertStats() {
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  State.alerts.forEach(a => { if(counts[a.severity] !== undefined) counts[a.severity]++; });
  document.getElementById('stat-total').textContent    = State.alerts.length;
  document.getElementById('stat-critical').textContent = counts.CRITICAL;
  document.getElementById('stat-high').textContent     = counts.HIGH;
  document.getElementById('stat-medium').textContent   = counts.MEDIUM;
  document.getElementById('stat-low').textContent      = counts.LOW;
}

function renderAlerts() {
  const list   = document.getElementById('alert-list');
  const filter = State.currentFilter;
  const visible= State.alerts.filter(a => filter === 'ALL' || a.severity === filter);

  if (visible.length === 0) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">◈</div><p>No alerts match this filter.</p></div>`;
    return;
  }
  list.innerHTML = visible.map(a => {
    const prob = (a.fraud_probability * 100).toFixed(1);
    const ts   = a.timestamp.toLocaleTimeString('en-IN', { hour12:false });
    return `
    <div class="alert-item ${a.severity}">
      <div class="alert-sev"><span class="badge ${a.severity}">${a.severity}</span></div>
      <div class="alert-body">
        <div class="alert-txn">${a.txn_id}</div>
        <div class="alert-meta">${a.sender_upi} → ${a.receiver_upi} &nbsp;|&nbsp; ₹${Number(a.amount).toLocaleString('en-IN')} &nbsp;|&nbsp; ${a.action}</div>
        <div class="alert-reason">${a.reason}</div>
      </div>
      <div class="alert-right">
        <div class="alert-prob" style="color:${sevColors[a.severity]}">${prob}%</div>
        <div class="alert-time">${ts}</div>
      </div>
    </div>`;
  }).join('');
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    State.currentFilter = btn.dataset.filter;
    renderAlerts();
  });
});

document.getElementById('clear-alerts').addEventListener('click', () => {
  State.alerts = [];
  updateAlertStats();
  document.getElementById('alert-list').innerHTML = `<div class="empty-state"><div class="empty-icon">◈</div><p>Alerts cleared.</p></div>`;
});

// ── UPDATE METRICS ─────────────────────────
function updateMetrics(r) {
  const m = State.metrics;
  m.total++;
  if (r.is_fraud) m.flagged++;
  m.probs.push(r.fraud_probability);
  m.severity_counts[r.severity]++;
  const now = new Date();
  const minute = now.getHours() + ':' + String(now.getMinutes()).padStart(2,'0');
  const last = m.timeline[m.timeline.length-1];
  if (last && last.label === minute) { last.count++; }
  else { m.timeline.push({ label: minute, count: 1 }); }
  if (m.timeline.length > 20) m.timeline.shift();

  document.getElementById('m-total').textContent    = m.total;
  document.getElementById('m-flagged').textContent  = m.flagged;
  document.getElementById('m-rate').textContent     = (m.flagged/m.total*100).toFixed(1) + '%';
  const avg = m.probs.reduce((a,b)=>a+b,0)/m.probs.length;
  document.getElementById('m-avg-prob').textContent = (avg*100).toFixed(1) + '%';

  renderSeverityChart();
  renderProbDistChart();
  renderTimeline();
}

function renderSeverityChart() {
  const c = State.metrics.severity_counts;
  const max = Math.max(...Object.values(c), 1);
  const el = document.getElementById('chart-severity');
  el.innerHTML = ['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => `
    <div class="bar-row">
      <span class="bar-lbl">${sev}</span>
      <div class="bar-track">
        <div class="bar-fill ${sev}" style="width:${(c[sev]/max*100).toFixed(1)}%">
          <span>${c[sev]}</span>
        </div>
      </div>
    </div>`).join('');
}

function renderProbDistChart() {
  const probs = State.metrics.probs;
  const buckets = [0,0,0,0,0];
  probs.forEach(p => {
    if(p<0.2)       buckets[0]++;
    else if(p<0.4)  buckets[1]++;
    else if(p<0.6)  buckets[2]++;
    else if(p<0.8)  buckets[3]++;
    else            buckets[4]++;
  });
  const max = Math.max(...buckets, 1);
  const labels = ['0–20%','20–40%','40–60%','60–80%','80–100%'];
  const el = document.getElementById('chart-prob-dist');
  el.innerHTML = buckets.map((v,i) => `
    <div class="bar-row">
      <span class="bar-lbl">${labels[i]}</span>
      <div class="bar-track">
        <div class="bar-fill range" style="width:${(v/max*100).toFixed(1)}%">
          <span>${v}</span>
        </div>
      </div>
    </div>`).join('');
}

function renderTimeline() {
  const tl = State.metrics.timeline;
  if (tl.length < 2) return;
  const max = Math.max(...tl.map(t=>t.count), 1);
  const el = document.getElementById('chart-timeline');
  el.innerHTML = `
    <div class="timeline-bars">
      ${tl.map(t => `<div class="tbar" data-label="${t.label}: ${t.count} alerts"
        style="height:${(t.count/max*90)+5}px; background:linear-gradient(to top, var(--accent2), var(--accent)); opacity:0.8;"></div>`).join('')}
    </div>
    <div class="timeline-labels">
      ${tl.map(t => `<span>${t.label}</span>`).join('')}
    </div>`;
}

// ── SIEM LOGGING ───────────────────────────
function logToSIEM(r, d) {
  const ts = new Date().toISOString();
  const jsonEvent = {
    '@timestamp': ts,
    event: { type: 'fraud_alert', severity: r.severity },
    transaction: { id: r.txn_id, amount: d.amount, sender: d.sender_upi, receiver: d.receiver_upi, payment_type: d.payment_type },
    threat: { fraud_probability: r.fraud_probability.toFixed(4), risk_score: r.risk_score, reason: r.reason },
    source: { vpn: !!d.vpn, hour: d.hour },
    behavioral: { velocity: d.velocity, pin_fails: d.pin_fails },
    alert_id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substr(2,16),
    model: 'UPI-FraudGuard-v1.0'
  };
  const sevNum = { CRITICAL:10, HIGH:7, MEDIUM:5, LOW:3 }[r.severity] || 5;
  const cefLine = `CEF:0|UPI-FraudGuard|AIDetector|1.0|UPI_FRAUD_ALERT|Fraudulent UPI Transaction|${sevNum}|` +
    `src=DEVICE suser=${d.sender_upi} duser=${d.receiver_upi} amt=${d.amount} txnId=${r.txn_id} ` +
    `fraudProb=${r.fraud_probability.toFixed(4)} riskScore=${r.risk_score} reason=${r.reason}`;

  State.siemLogs.json.unshift(jsonEvent);
  State.siemLogs.cef.unshift(cefLine);

  document.getElementById('siem-total').textContent = State.siemLogs.json.length;
  const crits = State.siemLogs.json.filter(e => e.event.severity === 'CRITICAL').length;
  document.getElementById('siem-crit').textContent = crits;

  renderLogViewer();
}

function renderLogViewer() {
  const fmt = State.currentFmt;
  const logs = fmt === 'json' ? State.siemLogs.json : State.siemLogs.cef;
  const viewer = document.getElementById('log-viewer');
  if (logs.length === 0) return;

  if (fmt === 'json') {
    viewer.innerHTML = logs.map(e => {
      const sev  = e.event.severity;
      const ts   = e['@timestamp'].replace('T',' ').split('.')[0];
      const prob = parseFloat(e.threat.fraud_probability)*100;
      return `<div class="log-entry">
        <span class="log-ts">${ts}</span> 
        <span class="log-sev ${sev}">[${sev}]</span> 
        <span class="log-key">txn_id</span>=<span class="log-val">${e.transaction.id}</span> 
        <span class="log-key">amount</span>=<span class="log-val">₹${Number(e.transaction.amount).toLocaleString('en-IN')}</span> 
        <span class="log-key">prob</span>=<span class="log-val">${prob.toFixed(1)}%</span> 
        <span class="log-key">action</span>=<span class="log-val ${sev === 'CRITICAL'?'log-sev CRITICAL':'log-sev '+sev}">${sev==='CRITICAL'?'BLOCK':sev==='HIGH'||sev==='MEDIUM'?'REVIEW':'ALLOW'}</span>
        <br><span style="color:var(--text3);padding-left:16px">→ ${e.threat.reason}</span>
      </div><hr class="log-sep"/>`;
    }).join('');
  } else {
    viewer.innerHTML = logs.map(line => {
      const sev = line.match(/UPI_FRAUD_ALERT\|[^|]+\|(\d+)/)?.[1];
      const sevName = {10:'CRITICAL',7:'HIGH',5:'MEDIUM',3:'LOW'}[parseInt(sev)] || 'INFO';
      return `<div class="log-entry"><span class="log-sev ${sevName}">${line}</span></div><hr class="log-sep"/>`;
    }).join('');
  }
}

document.querySelectorAll('.format-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.format-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    State.currentFmt = btn.dataset.fmt;
    document.getElementById('siem-fmt-lbl').textContent =
      State.currentFmt === 'json' ? 'JSON (Elastic/Sentinel)' : 'CEF (Splunk/QRadar)';
    renderLogViewer();
  });
});

document.getElementById('copy-logs').addEventListener('click', () => {
  const fmt  = State.currentFmt;
  const text = fmt === 'json'
    ? JSON.stringify(State.siemLogs.json, null, 2)
    : State.siemLogs.cef.join('\n');
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('copy-logs');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 1500);
  });
});

document.getElementById('dl-logs').addEventListener('click', () => {
  const fmt  = State.currentFmt;
  const text = fmt === 'json'
    ? JSON.stringify(State.siemLogs.json, null, 2)
    : State.siemLogs.cef.join('\n');
  const ext  = fmt === 'json' ? 'json' : 'log';
  const blob = new Blob([text], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `siem_logs.${ext}`; a.click();
  URL.revokeObjectURL(url);
});
