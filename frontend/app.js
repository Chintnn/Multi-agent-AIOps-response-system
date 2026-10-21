const $ = (id) => document.getElementById(id);
let executionId = null;
let pollTimer = null;
const api = async (path, options = {}) => {
  const response = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...options});
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
};
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const formatTime = (value) => value ? new Date(value).toLocaleString() : 'timestamp unavailable';
function showError(id, message) { const el = $(id); el.textContent = message; el.hidden = false; }
function clearError(id) { $(id).hidden = true; }
function setStatus(phase, workflow) {
  $('worker-phase').textContent = (phase || 'unknown').toUpperCase();
  $('worker-phase').className = `pill ${phase === 'completed' ? 'good' : phase === 'failed' ? 'bad' : ['queued','running'].includes(phase) ? 'wait' : 'neutral'}`;
  $('workflow-status').textContent = (workflow || 'waiting').replaceAll('_',' ').toUpperCase();
  $('workflow-status').className = `pill ${['recovered'].includes(workflow) ? 'good' : ['awaiting_approval','awaiting_information'].includes(workflow) ? 'wait' : workflow === 'failed' ? 'bad' : 'neutral'}`;
  $('phase-label').textContent = phase === 'running' ? 'Agents are investigating generated evidence…' : phase === 'queued' ? 'Investigation queued…' : phase === 'completed' ? 'Investigation finished. Review the report and trace below.' : 'Generate a scenario to begin.';
}
async function loadScenarios() {
  const {scenarios} = await api('/api/scenarios');
  $('scenario').innerHTML = scenarios.map(s => `<option value="${esc(s.id)}">${esc(s.label)}</option>`).join('');
}
async function checkHealth() {
  try { const data = await api('/api/health'); $('health-dot').classList.remove('off'); $('health-label').textContent = data.llm_configured ? 'API ready · LLM configured' : 'API ready · LLM key not configured'; }
  catch { $('health-dot').classList.add('off'); $('health-label').textContent = 'API unavailable'; }
}
function renderCreated(data) {
  $('execution-id').textContent = data.execution_id;
  $('request-outcomes').textContent = `${data.request_count} generated`;
  $('evidence-window').textContent = `${formatTime(data.evidence_window.start)} — ${formatTime(data.evidence_window.end)}`;
  $('created-summary').innerHTML = `${esc(data.scenario)} · ${data.request_count} actual simulated requests · HTTP ${Object.entries(data.status_codes).map(([code,count])=>`${esc(code)} × ${count}`).join(', ')} · mean ${esc(data.mean_latency_ms)} ms · ${data.telemetry_record_count} timestamped records`;
  $('created-summary').hidden = false;
  $('investigate-button').disabled = false;
  $('report-content').innerHTML = '<div class="empty-state"><span class="empty-icon">◷</span><strong>Simulation generated</strong><p>Telemetry is ready. Start the investigation to request LLM-driven triage and agent analysis.</p></div>';
  $('trace-content').innerHTML = '<div class="empty-state"><strong>Waiting for investigation</strong><p>Trace events will appear as they are returned by the API.</p></div>';
  loadEvidence();
}
async function loadEvidence() {
  if (!executionId) return;
  const {results=[]} = await api(`/api/incidents/${executionId}/evidence`);
  const cards = results.map(result => {
    const records = result.records || [];
    return `<article class="evidence-card"><h3>${esc(result.query.source.replaceAll('_',' '))}</h3><p class="evidence-meta">${esc(result.status)} · ${records.length} observations</p>${records.length ? records.slice(0,18).map(record => `<div class="evidence-record"><time>${esc(formatTime(record.observed_at))} · ${esc(record.source_id)} · ${esc(record.record_id)}</time>${esc(record.message)}<br>${esc(JSON.stringify(record.values))}</div>`).join('') : `<div class="evidence-record">${esc((result.missing_evidence||[]).join('; ') || result.reason || 'No observations')}</div>`}</article>`;
  });
  $('evidence-content').innerHTML = cards.join('');
}
function renderReport(report, remediation) {
  const findings = (report.findings||[]).map(f => `<div class="report-cell"><label>${esc(f.agent)} · ${esc(f.reasoning_status)}</label><div>${esc(f.summary)}${f.observed_facts?.length ? `<br>${f.observed_facts.map(esc).join('<br>')}` : ''}${f.uncertainty?.length ? `<br>Uncertainty: ${f.uncertainty.map(esc).join('; ')}` : ''}${f.evidence_refs?.length ? `<br>Evidence: ${f.evidence_refs.map(r=>esc(r.ref)).join(', ')}` : ''}</div></div>`).join('');
  const questions = (report.outstanding_questions||[]).map(esc).join('<br>') || 'None recorded';
  const hypotheses = (report.hypotheses||[]).map(h=>`<div class="report-cell"><label>Hypothesis · ${esc(h.uncertainty)}</label><div>${esc(h.statement)}<br>${esc(h.rationale)}</div></div>`).join('');
  $('report-content').innerHTML = `<div class="report-content"><p class="report-summary">${esc(report.root_cause_assessment)}</p><p>${esc(report.summary)}</p><div class="report-grid"><div class="report-cell"><label>Final status</label><div>${esc(report.status)}</div></div><div class="report-cell"><label>Service / severity</label><div>${esc(report.service)} / ${esc(report.severity)}</div></div><div class="report-cell"><label>Outstanding questions</label><div>${questions}</div></div><div class="report-cell"><label>Next steps</label><div>${(report.next_steps||[]).map(esc).join('<br>')||'None recorded'}</div></div>${hypotheses}${findings}</div></div>`;
  renderRemediation(remediation, report);
}
function renderTrace(trace) {
  const events = trace.events || [];
  $('trace-count').textContent = `${events.length} EVENTS`;
  if (!events.length) { $('trace-content').innerHTML = '<div class="empty-state"><strong>No trace events yet</strong><p>Events appear when the workflow has recorded actual decisions and handoffs.</p></div>'; return; }
  $('trace-content').className = 'trace-list';
  $('trace-content').innerHTML = events.map(event => `<div class="trace-row"><div class="trace-time">${esc(new Date(event.timestamp).toLocaleTimeString())}</div><div><strong>${esc(event.agent || 'workflow')} · ${esc(event.event_type)}</strong><p>${esc(JSON.stringify(event.details))}</p></div></div>`).join('');
}
function renderRemediation(data, report) {
  const p = data.proposal;
  const recovery = data.recovery;
  if (!p) { $('remediation-content').innerHTML = '<div class="empty-state compact"><strong>No remediation proposal</strong><p>The investigation did not provide a validated proposal, or evidence was insufficient.</p></div>'; return; }
  $('remediation-content').innerHTML = `<div class="proposal-card"><div class="proposal-top"><strong>${esc(p.action.replaceAll('_',' '))}</strong><span class="risk">${esc(p.risk_level)} RISK · ${esc(p.approval_status)}</span></div><p>${esc(p.rationale)}<br>Expected benefit: ${esc(p.expected_benefit)}</p><div class="evidence-meta">Proposal ID: ${esc(p.proposal_id)} · Evidence refs: ${esc((p.evidence_refs||[]).join(', ')||'none')}</div>${data.execution ? `<div class="recovery">Simulated action: ${esc(data.execution.reason)}<br>Executed: ${esc(data.execution.executed)}</div>` : ''}${recovery ? `<div class="recovery">Recovery: ${esc(recovery.outcome)} — ${esc(recovery.explanation)}<br>Missing metrics: ${esc((recovery.missing_metrics||[]).join(', ')||'none')}</div>` : ''}</div>`;
}
async function refreshExecution() {
  if (!executionId) return;
  const status = await api(`/api/incidents/${executionId}/status`);
  setStatus(status.phase, status.status);
  const trace = await api(`/api/incidents/${executionId}/trace`);
  renderTrace(trace);
  await loadEvidence();
  if (status.phase === 'completed' || status.phase === 'failed') {
    clearInterval(pollTimer); pollTimer = null;
    try {
      const report = await api(`/api/incidents/${executionId}/report`);
      const remediation = await api(`/api/incidents/${executionId}/remediation`);
      renderReport(report, remediation);
    } catch (error) { showError('create-error', error.message); }
  }
}
async function startPoll() {
  await refreshExecution();
  if (!pollTimer) pollTimer = setInterval(() => refreshExecution().catch(error => showError('create-error', error.message)), 1200);
}
$('create-form').addEventListener('submit', async event => {
  event.preventDefault(); clearError('create-error');
  $('investigate-button').disabled = true;
  try {
    const data = await api('/api/incidents', {method:'POST', body:JSON.stringify({scenario:$('scenario').value, requests:Number($('request-count').value)})});
    executionId = data.execution_id; renderCreated(data); setStatus('created','received');
    $('worker-phase').textContent = 'CREATED'; $('workflow-status').textContent = 'RECEIVED';
  } catch (error) { showError('create-error', error.message); }
});
$('investigate-button').addEventListener('click', async () => {
  if (!executionId) return;
  clearError('create-error'); $('investigate-button').disabled = true;
  try { await api(`/api/incidents/${executionId}/investigation`, {method:'POST',body:'{}'}); await startPoll(); }
  catch (error) { showError('create-error', error.message); $('investigate-button').disabled = false; }
});
Promise.all([loadScenarios(), checkHealth()]).catch(error => showError('create-error',error.message));
setInterval(checkHealth, 15000);
