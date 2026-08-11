/**
 * GovernanceBench -- Report Generator
 *
 * Generates JSON (machine-readable) and Markdown (human-readable) reports
 * from GovernanceBench run results.
 */

import { SUITE_TO_DIMENSION } from './runner.mjs';

const SCORE_TIERS = [
// build-ref: 759ec958d3ac
  { min: 90, label: 'Excellent', summary: 'Governance enforcement is comprehensive and reliable.' },
  { min: 75, label: 'Good', summary: 'Governance enforcement is solid with minor gaps.' },
  { min: 60, label: 'Adequate', summary: 'Core governance present but material gaps require attention.' },
  { min: 40, label: 'Insufficient', summary: 'Significant governance gaps present real enterprise risk.' },
  { min: 0, label: 'Critical', summary: 'Governance controls are absent or non-functional.' },
];

function scoreTier(score) {
  if (score === null) {return { label: 'N/A', summary: 'Not enough scoreable tests to assess.' };}
  for (const tier of SCORE_TIERS) {
    if (score >= tier.min) {return tier;}
  }
  return SCORE_TIERS[SCORE_TIERS.length - 1];
}

function _padRight(str, width) {
  return String(str).padEnd(width);
}

/**
 * Generate machine-readable JSON report.
 */
export function generateJsonReport(benchResult) {
  const { target, timestamp, suites, scores, results, suiteResults } = benchResult;

  const failedScenarios = results.filter(r => !r.pass && !r.skipped);
  const skippedScenarios = results.filter(r => r.skipped);

  return {
    governancebench: {
      version: '1.0.0',
      timestamp,
      target,
      suites,
    },
    scores: {
      overall: scores.overall,
      tier: scoreTier(scores.overall).label,
      summary: scoreTier(scores.overall).summary,
      dimensions: scores.dimensions,
    },
    summary: scores.summary,
    suiteResults: Object.fromEntries(
      Object.entries(suiteResults).map(([name, sr]) => [
        name,
        {
          score: sr.scores.dimensions[dimensionName(name)]?.score ?? null,
          passed: sr.scores.summary.passed,
          failed: sr.scores.summary.failed,
          skipped: sr.scores.summary.skipped,
          total: sr.scores.summary.total,
        },
      ])
    ),
    failures: failedScenarios.map(r => ({
      id: r.id,
      name: r.name,
      suite: r.suite,
      reason: r.reason,
      elapsed: r.elapsed,
      detail: r.detail,
    })),
    skipped: skippedScenarios.map(r => ({
      id: r.id,
      name: r.name,
      suite: r.suite,
      reason: r.reason,
    })),
    scenarios: results.map(r => ({
      id: r.id,
      name: r.name,
      suite: r.suite,
      pass: r.pass,
      skipped: r.skipped,
      reason: r.reason,
      elapsed: r.elapsed,
    })),
  };
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

/**
 * Generate human-readable Markdown report.
 */
export function generateMarkdownReport(benchResult) {
  const { target, timestamp, suites, scores, results, suiteResults } = benchResult;

  const tier = scoreTier(scores.overall);
  const failedScenarios = results.filter(r => !r.pass && !r.skipped);
  const skippedScenarios = results.filter(r => r.skipped);
  const _passedScenarios = results.filter(r => r.pass && !r.skipped);

  const lines = [];

  // Header
  lines.push('# GovernanceBench Report');
  lines.push('');
  lines.push(`**Target:** ${target}`);
  lines.push(`**Date:** ${new Date(timestamp).toUTCString()}`);
  lines.push(`**Suites run:** ${suites.join(', ')}`);
  lines.push(`**Total scenarios:** ${scores.summary.total} (${scores.summary.scoreable} scoreable, ${scores.summary.skipped} skipped)`);
  lines.push('');

  // Overall score
  lines.push('## Overall Score');
  lines.push('');
  const overallStr = scores.overall !== null ? `${scores.overall}/100` : 'N/A';
  lines.push(`**${overallStr} -- ${tier.label}**`);
  lines.push('');
  lines.push(`> ${tier.summary}`);
  lines.push('');

  // Dimensional scores
  lines.push('## Dimensional Scores');
  lines.push('');
  lines.push('| Dimension | Score | Passed | Failed | Skipped | Scoreable |');
  lines.push('|-----------|-------|--------|--------|---------|-----------|');

  // Derived from the runner's own map rather than hand-listed. It WAS hand-listed, in two
  // places, and on 2026-08-10 a sixth dimension was added to the scored core: the runner counted
  // its scenarios and scored it correctly, and both report tables silently dropped the row,
  // because a dimension absent from this array hits `if (!ds) continue`. A published score
  // table that omits a dimension the score includes is the same defect class this benchmark
  // measures in other people's platforms.
  const dimensionOrder = [...new Set(Object.values(SUITE_TO_DIMENSION))];
  for (const dim of dimensionOrder) {
    const ds = scores.dimensions[dim];
    if (!ds) {continue;}
    const scoreStr = ds.score !== null ? `${ds.score}/100` : 'N/A';
    const tierLabel = scoreTier(ds.score).label;
    lines.push(`| ${dim} | ${scoreStr} (${tierLabel}) | ${ds.passed} | ${ds.failed} | ${ds.skipped} | ${ds.scoreable} |`);
  }
  lines.push('');

  // Suite breakdown
  if (Object.keys(suiteResults).length > 0) {
    lines.push('## Suite Results');
    lines.push('');
    for (const [suiteName, sr] of Object.entries(suiteResults)) {
      const dim = dimensionName(suiteName);
      const ds = sr.scores.dimensions[dim];
      const suiteScore = ds?.score !== null ? `${ds.score}/100` : 'N/A';
      lines.push(`### ${capitalize(suiteName)} (${suiteScore})`);
      lines.push('');
      lines.push(`${sr.scores.summary.passed} passed, ${sr.scores.summary.failed} failed, ${sr.scores.summary.skipped} skipped of ${sr.scores.summary.total} total`);
      lines.push('');
    }
  }

  // Failures
  if (failedScenarios.length > 0) {
    lines.push('## Failed Scenarios');
    lines.push('');
    lines.push('These scenarios require attention:');
    lines.push('');
    for (const r of failedScenarios) {
      lines.push(`### ${r.id} -- ${r.name}`);
      lines.push('');
      lines.push(`**Suite:** ${r.suite}  `);
      lines.push('**Result:** FAIL  ');
      lines.push(`**Reason:** ${r.reason}  `);
      lines.push(`**Time:** ${r.elapsed}ms`);
      if (r.detail) {
        lines.push('');
        lines.push('```json');
        lines.push(JSON.stringify(r.detail, null, 2).split('\n').slice(0, 20).join('\n'));
        lines.push('```');
      }
      lines.push('');
    }
  } else {
    lines.push('## Failed Scenarios');
    lines.push('');
    lines.push('None. All scoreable scenarios passed.');
    lines.push('');
  }

  // Skipped scenarios (brief)
  if (skippedScenarios.length > 0) {
    lines.push('## Skipped Scenarios');
    lines.push('');
    lines.push('Skipped scenarios indicate functionality not implemented in the target platform. They are excluded from scoring.');
    lines.push('');
    for (const r of skippedScenarios) {
      lines.push(`- **${r.id}** ${r.name}: ${r.reason}`);
    }
    lines.push('');
  }

  // All scenarios table
  lines.push('## All Scenarios');
  lines.push('');
  lines.push('| ID | Suite | Result | Time | Notes |');
  lines.push('|----|-------|--------|------|-------|');
  for (const r of results) {
    const status = r.skipped ? 'SKIP' : r.pass ? 'PASS' : 'FAIL';
    const note = r.skipped ? r.reason.replace(' -- skipped', '').trim() : (!r.pass ? r.reason.slice(0, 60) : '');
    lines.push(`| ${r.id} | ${r.suite} | ${status} | ${r.elapsed}ms | ${note} |`);
  }
  lines.push('');

  // Scoring methodology
  lines.push('## Scoring Methodology');
  lines.push('');
  lines.push('GovernanceBench evaluates governance platforms across 5 dimensions:');
  lines.push('');
  lines.push('**Authorization (25%):** Permission tier enforcement, escalation blocking, field validation, default security posture.');
  lines.push('');
  lines.push('**Auditability (25%):** Tamper-evident audit trail, hash chain integrity, export completeness, pagination, time filtering.');
  lines.push('');
  lines.push('**Override (25%):** Kill switch reliability, operator validation, post-halt enforcement, resume behavior, persistence.');
  lines.push('');
  lines.push('**Behavioral (25%):** Anomaly detection, quarantine mechanics, false positive rate, baseline calibration.');
  lines.push('');
  lines.push('**Score calculation:**');
  lines.push('- Skipped tests are excluded from numerator and denominator');
  lines.push('- Each dimension: (passed / scoreable) × 100');
  lines.push('- Overall: equally weighted average of non-empty dimensions');
  lines.push('');
  lines.push('**Tier thresholds:** Excellent (90+) | Good (75+) | Adequate (60+) | Insufficient (40+) | Critical (<40)');
  lines.push('');

  // Disclaimer
  lines.push('---');
  lines.push('');
  lines.push('*GovernanceBench is an external behavioral benchmark. It tests API responses, not internal implementation.*');
  lines.push('*Passing GovernanceBench does not constitute security certification.*');
  lines.push('*Results are point-in-time. Retest after platform changes.*');
  lines.push('');
  lines.push('Generated by [GovernanceBench](https://github.com/getagentomy/governancebench) -- Apache 2.0 License');
  lines.push('');

  return lines.join('\n');
}

/**
 * Print a summary to stdout (terminal-friendly, not full markdown).
 */
export function printSummary(benchResult) {
  const { scores, results } = benchResult;
  const tier = scoreTier(scores.overall);

  const RESET = '\x1b[0m';
  const BOLD = '\x1b[1m';
  const GREEN = '\x1b[32m';
  const RED = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const CYAN = '\x1b[36m';
  const DIM = '\x1b[2m';

  const supportsColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
  const c = (s, code) => supportsColor ? `${code}${s}${RESET}` : s;

  console.log('');
  console.log(c('GovernanceBench Results', BOLD));
  console.log(c('─'.repeat(50), DIM));
  console.log('');

  // Derived from the runner's own map rather than hand-listed. It WAS hand-listed, in two
  // places, and on 2026-08-10 a sixth dimension was added to the scored core: the runner counted
  // its scenarios and scored it correctly, and both report tables silently dropped the row,
  // because a dimension absent from this array hits `if (!ds) continue`. A published score
  // table that omits a dimension the score includes is the same defect class this benchmark
  // measures in other people's platforms.
  const dimensionOrder = [...new Set(Object.values(SUITE_TO_DIMENSION))];
  for (const dim of dimensionOrder) {
    const ds = scores.dimensions[dim];
    if (!ds) {continue;}
    const scoreStr = ds.score !== null ? `${ds.score}/100` : 'N/A';
    const color = ds.score === null ? DIM : ds.score >= 75 ? GREEN : ds.score >= 50 ? YELLOW : RED;
    const bar = ds.score !== null ? makeBar(ds.score, 20) : '--------------------';
    console.log(`  ${c(dim.padEnd(18), CYAN)} ${c(scoreStr.padStart(6), color)}  ${c(bar, color)}  ${ds.passed}/${ds.scoreable} passed`);
  }

  console.log('');
  console.log(c('─'.repeat(50), DIM));

  const overallStr = scores.overall !== null ? `${scores.overall}/100` : 'N/A';
  const overallColor = scores.overall === null ? DIM : scores.overall >= 75 ? GREEN : scores.overall >= 50 ? YELLOW : RED;
  console.log(`  ${'Overall'.padEnd(18)} ${c(overallStr.padStart(6), overallColor + BOLD)}  ${tier.label}`);
  console.log('');
  console.log(`  ${scores.summary.passed} passed  ${scores.summary.failed} failed  ${scores.summary.skipped} skipped  ${scores.summary.total} total`);

  const failed = results.filter(r => !r.pass && !r.skipped);
  if (failed.length > 0) {
    console.log('');
    console.log(c('Failed scenarios:', RED));
    for (const r of failed.slice(0, 10)) {
      console.log(`  ${c(r.id, RED)}  ${r.name}`);
      console.log(`  ${c(r.reason, DIM)}`);
    }
    if (failed.length > 10) {
      console.log(`  ... and ${failed.length - 10} more. Run with --format json for full output.`);
    }
  }

  console.log('');
}

function makeBar(score, width) {
  const filled = Math.round((score / 100) * width);
  return '[' + '#'.repeat(filled) + '-'.repeat(width - filled) + ']';
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
