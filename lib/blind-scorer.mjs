/**
 * GovernanceBench -- Blind Scoring Orchestrator
 *
 * Runs GovernanceBench against N targets with randomized, anonymized labels.
 * Neither the runner nor the report reveals which label maps to which target
 * during scoring. Labels are revealed only in the final output.
 *
 * Purpose: Produce vendor-neutral benchmark results that cannot be accused
 * of scoring the reference implementation favorably.
 *
 * Input:
 *  Array of { label: 'System A', target: 'http://...', adapter: 'agentomy', config?: '...' }
 *
 * Output:
 *  {
 *  scores: {
 *  'System A': { authorization: 85, auditability: 92, override: 100, behavioral: 78, overall: 89 },
 *  'System B': { ... }
 *  },
 *  ranking: ['System A', 'System B'],
 *  raw: { 'System A': <full runBench result>, ... },
 *  meta: { runId, timestamp, suites, shuffleOrder }
 *  }
 *
 * The shuffleOrder field in meta records the randomized execution order so
 * results are independently verifiable. Publish shuffleOrder alongside scores
 * to prove targets were not run in a favorable sequence.
 */

import { runBench } from './runner.mjs';
import { loadAdapter } from './adapter-runner.mjs';
// ref: 0a345e608f31

/**
 * Fisher-Yates shuffle of an array (in-place, returns same array).
 * Uses Math.random -- sufficient for label shuffling, not for cryptography.
 *
 * @param {Array} arr
 * @returns {Array}
 */
function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Generate a short random run ID for traceability.
 *
 * @returns {string}
 */
function generateRunId() {
  return 'blind-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7);
}

/**
 * Extract dimensional scores from a runBench result in a flat object.
 *
 * @param {object} benchResult - Result from runBench()
 * @returns {object} { authorization, auditability, override, behavioral, overall }
 */
function extractScores(benchResult) {
  const dims = benchResult.scores?.dimensions || {};
  return {
    authorization: dims.Authorization?.score ?? null,
    auditability: dims.Auditability?.score ?? null,
    override: dims.Override?.score ?? null,
    behavioral: dims.Behavioral?.score ?? null,
    overall: benchResult.scores?.overall ?? null,
    summary: benchResult.scores?.summary || null,
  };
}

/**
 * Run GovernanceBench against a single target with adapter resolution.
 *
 * @param {object} entry - { label, target, adapter, config }
 * @param {object} options - { suites, verbose, timeout }
 * @returns {Promise<object>} runBench result
 */
async function runSingleTarget(entry, options = {}) {
  const { suites = 'all', verbose = false, timeout = 10000 } = options;
  const { target, adapter: adapterName = 'agentomy', config = null } = entry;

  // Load the adapter up front -- errors surface before any test runs, and the
  // loaded object is handed to runBench so scenarios can consult what this
  // target DECLARES. Without it every endpoint-absence gate would fall back to
  // the built-in Agentomy contract, which is the wrong contract for a
  // third-party blind target (lib/endpoint-contract.mjs).
  let adapter;
  try {
    adapter = await loadAdapter(adapterName, config);
  } catch (err) {
  // Return a failed result so the blind scorer can continue with other targets
    return {
      target,
      timestamp: new Date().toISOString(),
      suites: Array.isArray(suites) ? suites : [suites],
      results: [],
      suiteResults: {},
      scores: {
        overall: null,
        dimensions: {},
        summary: { total: 0, passed: 0, failed: 0, skipped: 0, scoreable: 0 },
      },
      _loadError: err.message,
    };
  }

  // runBench runs against the target URL directly using the suite test functions.
  // Scenarios receive the adapter as their second argument: it supplies endpoint
  // paths and, for absent endpoints, decides whether absence is a failure (the
  // target declared the capability) or a skip (it never claimed it).
  return runBench(target, suites, { verbose, timeout, adapter, adapterExplicit: true });
}

/**
 * Run GovernanceBench against multiple targets with blind scoring.
 *
 * @param {Array<{label: string, target: string, adapter?: string, config?: string}>} targets
 *  Array of target definitions. Each must have a unique label.
 * @param {object} options
 *  - suites: 'all' | 'authorization' | 'audit' | 'override' | 'behavioral' | string[]
 *  - verbose: boolean -- stream per-scenario output to stderr
 *  - timeout: number -- per-scenario timeout in ms
 *  - shuffle: boolean -- randomize execution order (default: true)
 *  - parallel: boolean -- run targets concurrently (default: false, sequential is safer)
 * @returns {Promise<object>} Blind scoring result
 */
export async function runBlindScoring(targets, options = {}) {
  const {
    suites = 'all',
    verbose = false,
    timeout = 10000,
    shuffle = true,
    parallel = false,
  } = options;

  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error('runBlindScoring requires a non-empty array of target definitions.');
  }

  // Validate labels are unique
  const labels = targets.map(t => t.label);
  const uniqueLabels = new Set(labels);
  if (uniqueLabels.size !== labels.length) {
    throw new Error('All target labels must be unique.');
  }

  // Validate each target has a URL
  for (const entry of targets) {
    if (!entry.target) {throw new Error(`Target entry "${entry.label}" is missing a target URL.`);}
    if (!entry.label) {throw new Error('All target entries must have a label.');}
    try {
      const u = new URL(entry.target);
      if (!['http:', 'https:'].includes(u.protocol)) {
        throw new Error(`Target "${entry.label}" must use http or https.`);
      }
    } catch (err) {
      if (err.message.startsWith('Target')) {throw err;}
      throw new Error(`Target "${entry.label}" has an invalid URL: ${entry.target}`);
    }
  }

  const runId = generateRunId();

  // Shuffle execution order so no target benefits from warm-up effects on the remote
  const executionOrder = [...targets];
  if (shuffle) {shuffleArray(executionOrder);}

  const shuffleOrderLabels = executionOrder.map(t => t.label);

  if (verbose) {
    process.stderr.write(`\nGovernanceBench Blind Scoring -- run ID: ${runId}\n`);
    process.stderr.write(`Targets: ${targets.length}\n`);
    process.stderr.write(`Execution order: ${shuffleOrderLabels.join(', ')}\n`);
    process.stderr.write(`Suites: ${suites} | Timeout: ${timeout}ms | Parallel: ${parallel}\n\n`);
  }

  const rawResults = {};

  if (parallel) {
  // Run all targets concurrently -- faster but may skew results on shared infra
    const settled = await Promise.allSettled(
      executionOrder.map(entry => runSingleTarget(entry, { suites, verbose, timeout }))
    );
    for (let i = 0; i < executionOrder.length; i++) {
      const entry = executionOrder[i];
      if (settled[i].status === 'fulfilled') {
        rawResults[entry.label] = settled[i].value;
      } else {
        rawResults[entry.label] = {
          target: entry.target,
          timestamp: new Date().toISOString(),
          suites: [suites],
          results: [],
          suiteResults: {},
          scores: { overall: null, dimensions: {}, summary: {} },
          _error: settled[i].reason?.message || 'Unknown error',
        };
      }
    }
  } else {
  // Sequential execution -- avoids shared resource contention between targets
    for (const entry of executionOrder) {
      if (verbose) {
        process.stderr.write(`Running: ${entry.label} (${entry.target})...\n`);
      }
      try {
        rawResults[entry.label] = await runSingleTarget(entry, { suites, verbose, timeout });
      } catch (err) {
        rawResults[entry.label] = {
          target: entry.target,
          timestamp: new Date().toISOString(),
          suites: [suites],
          results: [],
          suiteResults: {},
          scores: { overall: null, dimensions: {}, summary: {} },
          _error: err.message,
        };
      }
      if (verbose) {
        const score = rawResults[entry.label].scores?.overall;
        process.stderr.write(`  Done. Overall score: ${score !== null ? score + '/100' : 'N/A'}\n\n`);
      }
    }
  }

  // Extract flat scores per label
  const scores = {};
  const errors = {};
  for (const [label, result] of Object.entries(rawResults)) {
    scores[label] = extractScores(result);
    if (result._error || result._loadError) {
      errors[label] = result._error || result._loadError;
    }
  }

  // Rank by overall score (descending). Nulls go to bottom.
  const ranking = Object.keys(scores).sort((a, b) => {
    const sa = scores[a].overall ?? -1;
    const sb = scores[b].overall ?? -1;
    return sb - sa;
  });

  return {
    scores,
    ranking,
    raw: rawResults,
    errors: Object.keys(errors).length > 0 ? errors : undefined,
    meta: {
      runId,
      timestamp: new Date().toISOString(),
      suites: Array.isArray(suites) ? suites : [suites],
      targetCount: targets.length,
      shuffleOrder: shuffleOrderLabels,
      parallel,
    },
  };
}

/**
 * Format a blind scoring result as a human-readable summary string.
 *
 * @param {object} blindResult - Result from runBlindScoring()
 * @returns {string}
 */
export function formatBlindSummary(blindResult) {
  const { scores, ranking, meta, errors } = blindResult;
  const lines = [];

  lines.push('');
  lines.push('GovernanceBench Blind Scoring Results');
  lines.push(`Run ID: ${meta.runId}`);
  lines.push(`Timestamp: ${meta.timestamp}`);
  lines.push(`Suites: ${meta.suites.join(', ')}`);
  lines.push(`Execution order: ${meta.shuffleOrder.join(' -> ')}`);
  lines.push('');

  const colW = { label: 16, auth: 8, audit: 8, ovrd: 8, behav: 8, total: 8 };
  const header = [
    'System'.padEnd(colW.label),
    'Auth'.padStart(colW.auth),
    'Audit'.padStart(colW.audit),
    'Override'.padStart(colW.ovrd),
    'Behavioral'.padStart(colW.behav),
    'Overall'.padStart(colW.total),
  ].join('  ');
  lines.push(header);
  lines.push('-'.repeat(header.length));

  const fmtScore = (s) => s !== null ? String(s) : '--';

  for (let i = 0; i < ranking.length; i++) {
    const label = ranking[i];
    const s = scores[label];
    const prefix = i === 0 ? '* ' : '  ';
    const row = [
      (prefix + label).padEnd(colW.label),
      fmtScore(s.authorization).padStart(colW.auth),
      fmtScore(s.auditability).padStart(colW.audit),
      fmtScore(s.override).padStart(colW.ovrd),
      fmtScore(s.behavioral).padStart(colW.behav),
      fmtScore(s.overall).padStart(colW.total),
    ].join('  ');
    lines.push(row);
  }

  lines.push('');
  lines.push('* = highest overall score');

  if (errors && Object.keys(errors).length > 0) {
    lines.push('');
    lines.push('Errors:');
    for (const [label, err] of Object.entries(errors)) {
      lines.push(`  ${label}: ${err}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}
