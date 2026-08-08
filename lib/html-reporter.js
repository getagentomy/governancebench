/**
 * GovernanceBench -- HTML Report Generator
 *
 * Generates a standalone HTML report with inline CSS and JS.
 * No external dependencies. Save the file, open in any browser.
 */

const SCORE_TIERS = [
  { min: 90, label: 'Excellent', color: '#22c55e' },
  { min: 75, label: 'Good', color: '#22c55e' },
  { min: 60, label: 'Adequate', color: '#f59e0b' },
  { min: 40, label: 'Insufficient', color: '#ef4444' },
  { min: 0, label: 'Critical', color: '#ef4444' },
];

function scoreTier(score) {
  if (score === null || score === undefined) {
    return { label: 'N/A', color: '#6b7280' };
  }
  for (const tier of SCORE_TIERS) {
    if (score >= tier.min) { return tier; }
  }
  return SCORE_TIERS[SCORE_TIERS.length - 1];
}

function escapeHtml(str) {
  if (str === null || str === undefined) { return ''; }
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function dimensionName(suiteName) {
  const map = {
    authorization: 'Authorization',
    audit: 'Auditability',
    override: 'Override',
    behavioral: 'Behavioral',
    owasp: 'OWASP Coverage',
  };
  return map[suiteName] || suiteName;
}

function scoreColor(score) {
  return scoreTier(score).color;
}

function badgeHtml(pass, skipped) {
  if (skipped) {
    return '<span class="badge badge-skip">SKIP</span>';
  }
  return pass
    ? '<span class="badge badge-pass">PASS</span>'
    : '<span class="badge badge-fail">FAIL</span>';
}

/**
 * Generate a self-contained HTML report string.
 * @param {object} benchResult - The benchmark result object
 * @returns {string} Complete HTML document
 */
export function generateHtmlReport(benchResult) {
  const { target, timestamp, suites, scores, results, suiteResults } = benchResult;

  const tier = scoreTier(scores.overall);
  const failedScenarios = results.filter(r => !r.pass && !r.skipped);
  const passedScenarios = results.filter(r => r.pass && !r.skipped);
  const skippedScenarios = results.filter(r => r.skipped);
  const overallStr = scores.overall !== null ? scores.overall : 'N/A';
  const dateStr = new Date(timestamp).toUTCString();

  const dimensionOrder = ['Authorization', 'Auditability', 'Override', 'Behavioral', 'OWASP Coverage'];

  // Build dimension cards
  let dimensionCards = '';
  for (const dim of dimensionOrder) {
    const ds = scores.dimensions[dim];
    if (!ds) { continue; }
    const dimTier = scoreTier(ds.score);
    const dimScore = ds.score !== null ? ds.score : 'N/A';
    const pct = ds.score !== null ? ds.score : 0;
    dimensionCards += `
      <div class="dim-card">
        <div class="dim-name">${escapeHtml(dim)}</div>
        <div class="dim-score" style="color: ${dimTier.color}">${dimScore}${ds.score !== null ? '<span class="dim-unit">/100</span>' : ''}</div>
        <div class="dim-tier" style="color: ${dimTier.color}">${dimTier.label}</div>
        <div class="dim-bar-track">
          <div class="dim-bar-fill" style="width: ${pct}%; background: ${dimTier.color}"></div>
        </div>
        <div class="dim-stats">${ds.passed} passed / ${ds.failed} failed / ${ds.skipped} skipped</div>
      </div>`;
  }

  // Build failed scenarios section
  let failedHtml = '';
  if (failedScenarios.length > 0) {
    failedHtml = '<h2 class="section-title section-fail">Failed Scenarios</h2>';
    for (const r of failedScenarios) {
      failedHtml += `
        <div class="scenario-card scenario-fail">
          <div class="scenario-header" onclick="toggleDetail(this)">
            <span class="badge badge-fail">FAIL</span>
            <span class="scenario-id">${escapeHtml(r.id)}</span>
            <span class="scenario-name">${escapeHtml(r.name)}</span>
            <span class="scenario-time">${r.elapsed}ms</span>
            <span class="expand-icon">&#9660;</span>
          </div>
          <div class="scenario-detail" style="display:none">
            <div><strong>Suite:</strong> ${escapeHtml(r.suite)}</div>
            <div><strong>Reason:</strong> ${escapeHtml(r.reason)}</div>
            ${r.detail ? `<pre class="detail-json">${escapeHtml(JSON.stringify(r.detail, null, 2).split('\n').slice(0, 20).join('\n'))}</pre>` : ''}
          </div>
        </div>`;
    }
  } else {
    failedHtml = '<h2 class="section-title">Failed Scenarios</h2><p class="no-failures">None. All scoreable scenarios passed.</p>';
  }

  // Build all scenarios grouped by suite
  let allScenariosHtml = '<h2 class="section-title">All Scenarios</h2>';
  const suiteGroups = {};
  for (const r of results) {
    if (!suiteGroups[r.suite]) { suiteGroups[r.suite] = []; }
    suiteGroups[r.suite].push(r);
  }

  for (const [suiteName, scenarios] of Object.entries(suiteGroups)) {
    const dim = dimensionName(suiteName);
    allScenariosHtml += `
      <div class="suite-group">
        <div class="suite-header" onclick="toggleSuite(this)">
          <span class="expand-icon">&#9660;</span>
          <span class="suite-label">${escapeHtml(dim)}</span>
          <span class="suite-count">${scenarios.length} scenarios</span>
        </div>
        <div class="suite-scenarios">`;

    for (const r of scenarios) {
      const statusClass = r.skipped ? 'scenario-skip' : r.pass ? 'scenario-pass' : 'scenario-fail';
      allScenariosHtml += `
          <div class="scenario-card ${statusClass}">
            <div class="scenario-header" onclick="toggleDetail(this)">
              ${badgeHtml(r.pass, r.skipped)}
              <span class="scenario-id">${escapeHtml(r.id)}</span>
              <span class="scenario-name">${escapeHtml(r.name)}</span>
              <span class="scenario-time">${r.elapsed}ms</span>
              <span class="expand-icon">&#9660;</span>
            </div>
            <div class="scenario-detail" style="display:none">
              <div><strong>Suite:</strong> ${escapeHtml(r.suite)}</div>
              <div><strong>Result:</strong> ${r.skipped ? 'SKIP' : r.pass ? 'PASS' : 'FAIL'}</div>
              <div><strong>Reason:</strong> ${escapeHtml(r.reason)}</div>
              <div><strong>Time:</strong> ${r.elapsed}ms</div>
            </div>
          </div>`;
    }

    allScenariosHtml += `
        </div>
      </div>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GovernanceBench Report - ${escapeHtml(target)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: #1a1a2e;
    color: #e0e0e0;
    line-height: 1.6;
    padding: 0;
  }

  .container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 24px 16px;
  }

  /* Header */
  .report-header {
    background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
    border-bottom: 2px solid #2a2a4a;
    padding: 32px 0;
    margin-bottom: 32px;
  }

  .report-header .container {
    padding-top: 0;
    padding-bottom: 0;
  }

  .report-title {
    font-size: 28px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 8px;
  }

  .report-meta {
    font-size: 14px;
    color: #9ca3af;
  }

  .report-meta span {
    margin-right: 24px;
  }

  /* Overall Score */
  .overall-section {
    text-align: center;
    padding: 40px 20px;
    background: #16213e;
    border-radius: 12px;
    margin-bottom: 32px;
    border: 1px solid #2a2a4a;
  }

  .overall-score {
    font-size: 72px;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 4px;
  }

  .overall-unit {
    font-size: 28px;
    font-weight: 400;
    opacity: 0.6;
  }

  .overall-tier {
    font-size: 24px;
    font-weight: 600;
    margin-top: 8px;
  }

  .overall-summary-counts {
    margin-top: 16px;
    font-size: 14px;
    color: #9ca3af;
  }

  .overall-summary-counts span { margin: 0 12px; }

  /* Dimension Cards */
  .dim-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }

  .dim-card {
    background: #16213e;
    border-radius: 10px;
    padding: 20px;
    border: 1px solid #2a2a4a;
    text-align: center;
  }

  .dim-name {
    font-size: 14px;
    font-weight: 600;
    color: #9ca3af;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
  }

  .dim-score {
    font-size: 36px;
    font-weight: 700;
    line-height: 1.1;
  }

  .dim-unit {
    font-size: 16px;
    opacity: 0.5;
  }

  .dim-tier {
    font-size: 13px;
    font-weight: 600;
    margin-top: 4px;
    margin-bottom: 12px;
  }

  .dim-bar-track {
    width: 100%;
    height: 6px;
    background: #2a2a4a;
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 8px;
  }

  .dim-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s ease;
  }

  .dim-stats {
    font-size: 12px;
    color: #6b7280;
  }

  /* Section titles */
  .section-title {
    font-size: 20px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #2a2a4a;
  }

  .section-fail { color: #ef4444; }

  .no-failures {
    color: #22c55e;
    font-size: 15px;
    margin-bottom: 24px;
  }

  /* Scenario cards */
  .scenario-card {
    background: #16213e;
    border-radius: 8px;
    margin-bottom: 8px;
    border-left: 4px solid #2a2a4a;
    overflow: hidden;
  }

  .scenario-pass { border-left-color: #22c55e; }
  .scenario-fail { border-left-color: #ef4444; }
  .scenario-skip { border-left-color: #f59e0b; }

  .scenario-header {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    cursor: pointer;
    gap: 12px;
    user-select: none;
  }

  .scenario-header:hover { background: #1e2a47; }

  .scenario-id {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 13px;
    color: #9ca3af;
    min-width: 80px;
  }

  .scenario-name {
    flex: 1;
    font-size: 14px;
    color: #e0e0e0;
  }

  .scenario-time {
    font-size: 12px;
    color: #6b7280;
    min-width: 60px;
    text-align: right;
  }

  .expand-icon {
    font-size: 10px;
    color: #6b7280;
    transition: transform 0.2s;
  }

  .expanded > .scenario-header .expand-icon,
  .expanded > .expand-icon {
    transform: rotate(180deg);
  }

  .scenario-detail {
    padding: 12px 16px 16px 16px;
    border-top: 1px solid #2a2a4a;
    font-size: 13px;
    color: #9ca3af;
    line-height: 1.8;
  }

  .detail-json {
    background: #0d1117;
    padding: 12px;
    border-radius: 6px;
    font-size: 12px;
    overflow-x: auto;
    margin-top: 8px;
    color: #8b949e;
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    min-width: 48px;
    text-align: center;
  }

  .badge-pass { background: rgba(34,197,94,0.15); color: #22c55e; }
  .badge-fail { background: rgba(239,68,68,0.15); color: #ef4444; }
  .badge-skip { background: rgba(245,158,11,0.15); color: #f59e0b; }

  /* Suite groups */
  .suite-group {
    margin-bottom: 24px;
  }

  .suite-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: #0f1629;
    border-radius: 8px;
    cursor: pointer;
    margin-bottom: 8px;
    user-select: none;
  }

  .suite-header:hover { background: #1a2340; }

  .suite-label {
    font-size: 16px;
    font-weight: 600;
    color: #ffffff;
    flex: 1;
  }

  .suite-count {
    font-size: 13px;
    color: #6b7280;
  }

  .suite-scenarios {
    padding-left: 8px;
  }

  /* Footer */
  .report-footer {
    text-align: center;
    padding: 32px 0;
    margin-top: 48px;
    border-top: 1px solid #2a2a4a;
    font-size: 13px;
    color: #6b7280;
  }

  .report-footer a {
    color: #6366f1;
    text-decoration: none;
  }

  /* Print styles */
  @media print {
    body { background: #ffffff; color: #1a1a1a; }
    .report-header { background: #ffffff; border-bottom-color: #d1d5db; }
    .report-title { color: #1a1a1a; }
    .report-meta { color: #6b7280; }
    .overall-section { background: #f9fafb; border-color: #d1d5db; }
    .dim-card { background: #f9fafb; border-color: #d1d5db; }
    .scenario-card { background: #f9fafb; }
    .scenario-header { cursor: default; }
    .expand-icon { display: none; }
    .scenario-detail { display: block !important; }
    .suite-header { background: #f3f4f6; cursor: default; }
    .suite-scenarios { display: block !important; }
    .detail-json { background: #f3f4f6; }
  }

  /* Responsive */
  @media (max-width: 640px) {
    .report-title { font-size: 22px; }
    .overall-score { font-size: 48px; }
    .dim-grid { grid-template-columns: 1fr 1fr; }
    .scenario-id { display: none; }
    .scenario-time { min-width: auto; }
  }

  @media (max-width: 400px) {
    .dim-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="report-header">
  <div class="container">
    <div class="report-title">GovernanceBench Report</div>
    <div class="report-meta">
      <span><strong>Target:</strong> ${escapeHtml(target)}</span>
      <span><strong>Date:</strong> ${escapeHtml(dateStr)}</span>
      <span><strong>Suites:</strong> ${escapeHtml(suites.join(', '))}</span>
    </div>
  </div>
</div>

<div class="container">

  <!-- Overall Score -->
  <div class="overall-section">
    <div class="overall-score" style="color: ${tier.color}">
      ${overallStr}${scores.overall !== null ? '<span class="overall-unit">/100</span>' : ''}
    </div>
    <div class="overall-tier" style="color: ${tier.color}">${tier.label}</div>
    <div class="overall-summary-counts">
      <span>${scores.summary.passed} passed</span>
      <span>${scores.summary.failed} failed</span>
      <span>${scores.summary.skipped} skipped</span>
      <span>${scores.summary.total} total</span>
    </div>
  </div>

  <!-- Dimension Cards -->
  <div class="dim-grid">
    ${dimensionCards}
  </div>

  <!-- Failed Scenarios -->
  ${failedHtml}

  <!-- All Scenarios -->
  ${allScenariosHtml}

</div>

<div class="report-footer">
  Generated by <a href="https://github.com/getagentomy/governancebench">GovernanceBench v1.0.0</a>
  &middot; ${escapeHtml(dateStr)}
</div>

<script>
function toggleDetail(headerEl) {
  var card = headerEl.parentElement;
  var detail = card.querySelector('.scenario-detail');
  if (!detail) return;
  var isVisible = detail.style.display !== 'none';
  detail.style.display = isVisible ? 'none' : 'block';
  card.classList.toggle('expanded', !isVisible);
}

function toggleSuite(headerEl) {
  var group = headerEl.parentElement;
  var scenarios = group.querySelector('.suite-scenarios');
  if (!scenarios) return;
  var isVisible = scenarios.style.display !== 'none';
  scenarios.style.display = isVisible ? 'none' : 'block';
  group.classList.toggle('expanded', !isVisible);
}
</script>

</body>
</html>`;
}
