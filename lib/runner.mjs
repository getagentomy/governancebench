/**
 * GovernanceBench -- Test Runner
 *
 * Runs all scenarios in a suite sequentially.
 * Tracks pass/fail/skip per scenario.
 * Computes GovernanceBench score across 5 dimensions.
 */

import { createRequire } from 'module';
import { detectAdapter } from './auto-detect.mjs';
const require = createRequire(import.meta.url);
const integrity = require('./integrity.cjs');

const SUITE_TO_DIMENSION = {
// ref: 61e34f422589
  authorization: 'Authorization',
  audit: 'Auditability',
  override: 'Override',
  behavioral: 'Behavioral',
  owasp: 'OWASP Coverage',
};

const DIMENSION_WEIGHT = {
  Authorization: 20,
  Auditability: 20,
  Override: 20,
  Behavioral: 20,
  'OWASP Coverage': 20,
};

/**
 * Run a single scenario and return a structured result.
 */
async function runScenario(scenario, target, options = {}) {
  const { verbose = false, timeout = 10000, adapter = null } = options;
  const start = Date.now();

  let pass = false;
  let reason = '';
  let detail = null;
  let skipped = false;
  let observational = false;
  let error = null;

  try {
    // F5a adapter v2: scenarios that accept (target, adapter) get the loaded
    // adapter object; scenarios with single-arg (target) signature stay
    // backward-compatible and continue to use literal /api/claw/* paths.
    const result = await Promise.race([
      scenario.test(target, adapter),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Scenario timeout after ${timeout}ms`)), timeout)
      ),
    ]);

    pass = result.pass === true;
    reason = result.reason || (pass ? 'Passed' : 'Failed');
    detail = result.detail || null;

    // Detect skip: reason includes 'skipped' and pass=true
    if (pass && reason.toLowerCase().includes('skipped')) {
      skipped = true;
    }

    // OBSERVATIONAL outcome. Some scenarios deliberately record what the platform
    // did without asserting it -- e.g. behavioural detection that cannot be asserted
    // without an established baseline. Those are legitimate probes, but counting them
    // as PASSES inflates the score with scenarios that were never able to fail: the
    // reported number then describes the suite's structure rather than the platform's
    // behaviour. An observational scenario is excluded from scoring exactly like a
    // skip, and is reported separately so it stays visible instead of silently
    // padding the denominator or the numerator.
    if (result.observational === true) {
      observational = true;
      skipped = true; // excluded from scoring via the existing scoreable calculation
    }
  } catch (err) {
    pass = false;
    reason = `Error: ${err.message}`;
    error = err.message;
  }

  const elapsed = Date.now() - start;

  if (verbose) {
    const _status = observational ? 'OBS' : skipped ? 'SKIP' : pass ? 'PASS' : 'FAIL';
    const prefix = observational ? '  ..' : skipped ? '  --' : pass ? '  ok' : '  FAIL';
    process.stderr.write(`${prefix} [${scenario.id}] ${scenario.name} (${elapsed}ms)\n`);
    if (!pass && !skipped) {
      process.stderr.write(`  ${reason}\n`);
    }
  }

  return {
    id: scenario.id,
    name: scenario.name,
    suite: scenario.suite,
    pass,
    skipped,
    observational,
    reason,
    detail,
    error,
    elapsed,
  };
}

/**
 * Compute dimensional and overall GovernanceBench scores.
 *
 * Scoring rules:
 *  - Skipped tests are excluded from numerator and denominator
 *  - Each dimension: (passed / (total - skipped)) * 100
 *  - Dimensions with no scoreable tests are excluded from overall
 *  - Overall: weighted average of non-empty dimensions
 */
function computeScores(results) {
  const dimensions = {};

  for (const result of results) {
    const dim = SUITE_TO_DIMENSION[result.suite] || result.suite;
    if (!dimensions[dim]) {
      dimensions[dim] = { passed: 0, failed: 0, skipped: 0, total: 0 };
    }
    dimensions[dim].total++;
    if (result.skipped) {
      dimensions[dim].skipped++;
    } else if (result.pass) {
      dimensions[dim].passed++;
    } else {
      dimensions[dim].failed++;
    }
  }

  const dimensionScores = {};
  for (const [dim, counts] of Object.entries(dimensions)) {
    const scoreable = counts.total - counts.skipped;
    dimensionScores[dim] = {
      score: scoreable > 0 ? Math.round((counts.passed / scoreable) * 100) : null,
      passed: counts.passed,
      failed: counts.failed,
      skipped: counts.skipped,
      total: counts.total,
      scoreable,
    };
  }

  // Overall: weighted average across dimensions with scoreable tests
  let weightedSum = 0;
  let totalWeight = 0;
  for (const [dim, ds] of Object.entries(dimensionScores)) {
    if (ds.score !== null) {
      const weight = DIMENSION_WEIGHT[dim] || 25;
      weightedSum += ds.score * weight;
      totalWeight += weight;
    }
  }

  const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : null;

  // Summary counts
  const totalPassed = results.filter(r => r.pass && !r.skipped).length;
  const totalFailed = results.filter(r => !r.pass && !r.skipped).length;
  const totalSkipped = results.filter(r => r.skipped && !r.observational).length;
  const totalObservational = results.filter(r => r.observational).length;
  const totalScenarios = results.length;

  return {
    overall: overallScore,
    dimensions: dimensionScores,
    summary: {
      total: totalScenarios,
      passed: totalPassed,
      failed: totalFailed,
      skipped: totalSkipped,
      observational: totalObservational,
      scoreable: totalScenarios - totalSkipped - totalObservational,
    },
  };
}

/**
 * Load a suite by name.
 */
async function loadSuite(suiteName) {
  const suiteMap = {
    authorization: () => import('../suites/authorization.mjs').then(m => m.authorizationSuite),
    audit: () => import('../suites/audit.mjs').then(m => m.auditSuite),
    override: () => import('../suites/override.mjs').then(m => m.overrideSuite),
    behavioral: () => import('../suites/behavioral.mjs').then(m => m.behavioralSuite),
    owasp: () => import('../suites/owasp.mjs').then(m => m.owaspSuite),
    'override-integrity': () => import('../suites/override-integrity.mjs').then(m => m.overrideIntegritySuite),
    'rpa-governance': () => import('../suites/rpa-governance.mjs').then(m => m.rpaGovernanceSuite),
    'algo-trading': () => import('../suites/algo-trading.mjs').then(m => m.algoTradingSuite),
    'medical-device': () => import('../suites/medical-device.mjs').then(m => m.medicalDeviceSuite),
    'av-fleet': () => import('../suites/av-fleet.mjs').then(m => m.avFleetSuite),
    'industrial-iot': () => import('../suites/industrial-iot.mjs').then(m => m.industrialIoTSuite),
    'breach-reproduction': () => import('../suites/breach-reproduction.mjs').then(m => m.breachReproductionSuite),
    'cloud-infrastructure': () => import('../suites/cloud-infrastructure.mjs').then(m => m.cloudInfrastructureSuite),
    // Phase 10D (2026-05-31): skill-governance suite for skill registry + attestation contracts
    'skill-governance': () => import('../suites/skill-governance.mjs').then(m => m.skillGovernanceSuite),
    // Phase 1.5 (2026-06-18): IPI / agentjacking defense suite (Tenet Security disclosure)
    // exercises /api/ingest/adjudicate + /api/attestation/* server-side wrappers
    // Agent-message governance. Deliberately NOT in the 'all' core set: it was authored
    // BEFORE the runtime class it tests, to measure whether the threat is real rather than
    // to describe a feature. Scenarios in it are expected to fail until that class exists,
    // and a failing measurement in the core set would be indistinguishable from a regression.
    'message-governance': () => import('../suites/message-governance.mjs').then(m => m.messageGovernanceSuite),
    // Substrate properties: is the RECORD inspectable, addressed, ordered and
    // independently checkable, as distinct from whether a decision was correct.
    'substrate-governance': () => import('../suites/substrate-governance.mjs').then(m => m.substrateGovernanceSuite),
    ipi: () => import('../suites/ipi.mjs').then(m => m.ipiSuite),
  };

  if (!suiteMap[suiteName]) {
    throw new Error(`Unknown suite: "${suiteName}". Available: ${Object.keys(suiteMap).join(', ')}`);
  }

  return suiteMap[suiteName]();
}

/**
 * Run one or more suites against a target.
 *
 * @param {string} target - Base URL of governance platform
 * @param {string|string[]} suites - Suite name(s) or 'all'
 * @param {object} options - { verbose, timeout, onProgress }
 * @returns {object} Structured results
 */
export async function runBench(target, suites, options = {}) {
  const { verbose = false, timeout = 10000, onProgress = null, adapterExplicit = false, adapter = null } = options;

  // Integrity check
  const suitesDir = new URL('../suites/', import.meta.url).pathname;
  const integrityResult = integrity.verifyIntegrity(suitesDir.replace(/^\/([A-Z]:)/, '$1'), null);
  if (verbose) process.stderr.write(`Integrity: ${integrityResult.valid ? 'PASS' : 'WARN (first run or files changed)'}\n`);

  // Normalize target
  // Strip trailing /api or /api/ from target -- suites already prefix paths with /api/
  const normalizedTarget = target.replace(/\/api\/?$/, '').replace(/\/$/, '');

  // Resolve suites
  const suiteNames = suites === 'all' || suites === ['all']
    ? ['authorization', 'audit', 'override', 'behavioral', 'owasp']
    : Array.isArray(suites)
      ? suites
      : [suites];

  if (verbose) {
    process.stderr.write(`\nGovernanceBench -- target: ${normalizedTarget}\n`);
    process.stderr.write(`Suites: ${suiteNames.join(', ')}\n`);
    process.stderr.write(`Timeout: ${timeout}ms per scenario\n\n`);
  }

  const allResults = [];
  const suiteResults = {};

  for (const suiteName of suiteNames) {
    let scenarios;
    try {
      scenarios = await loadSuite(suiteName);
    } catch (err) {
      allResults.push({
        id: `${suiteName.toUpperCase()}-LOAD-FAIL`,
        name: `Suite load failed: ${suiteName}`,
        suite: suiteName,
        pass: false,
        skipped: false,
        reason: err.message,
        detail: null,
        error: err.message,
        elapsed: 0,
      });
      continue;
    }

    if (verbose) {
      process.stderr.write(`--- Suite: ${suiteName} (${scenarios.length} scenarios) ---\n`);
    }

    const results = [];
    for (const scenario of scenarios) {
      const result = await runScenario(scenario, normalizedTarget, { verbose, timeout, adapter });
      results.push(result);
      allResults.push(result);
      if (onProgress) {onProgress(result, suiteName);}
    }

    const scores = computeScores(results);
    suiteResults[suiteName] = {
      scenarios: results,
      scores,
    };

    if (verbose) {
      const dim = SUITE_TO_DIMENSION[suiteName];
      const ds = scores.dimensions[dim];
      if (ds) {
        process.stderr.write(`\n${suiteName}: ${ds.passed}/${ds.scoreable} passed`);
        process.stderr.write(ds.score !== null ? ` -- ${dim} score: ${ds.score}/100\n\n` : '\n\n');
      }
    }
  }

  const scores = computeScores(allResults);

  // Auto-detect adapter if none was explicitly specified
  let detectedAdapter = null;
  if (!adapterExplicit) {
    detectedAdapter = await detectAdapter(normalizedTarget);
  }

  if (verbose) {
    process.stderr.write('=== GovernanceBench Results ===\n');
    for (const [dim, ds] of Object.entries(scores.dimensions)) {
      const scoreStr = ds.score !== null ? `${ds.score}/100` : 'N/A';
      process.stderr.write(`  ${dim.padEnd(16)}: ${scoreStr} (${ds.passed}/${ds.scoreable} passed, ${ds.skipped} skipped)\n`);
    }
    process.stderr.write(`  ${'Overall'.padEnd(16)}: ${scores.overall !== null ? `${scores.overall}/100` : 'N/A'}\n`);
    process.stderr.write('\n');
  }

  // Improved messaging for zero-score and low-score results
  if (scores.overall === 0 && !adapterExplicit) {
    process.stderr.write('\n');
    process.stderr.write('--- No governance endpoints detected ---\n');
    process.stderr.write('The target returned no valid governance responses.\n');
    process.stderr.write('\nDimension breakdown (what is missing):\n');
    for (const [dim, ds] of Object.entries(scores.dimensions)) {
      process.stderr.write(`  ${dim.padEnd(16)}: 0/${ds.scoreable} passed -- no endpoints responded\n`);
    }
    process.stderr.write('\nGet started (works standalone, no infrastructure needed):\n');
    process.stderr.write('  npm install agentomy-agent\n');
    process.stderr.write('  → 2/5 governance immediately, 5/5 with platform\n');
    process.stderr.write('\nDocs: https://github.com/getagentomy/governancebench\n');
    process.stderr.write('\n');
  } else if (scores.overall !== null && scores.overall < 50) {
    process.stderr.write('\n');
    process.stderr.write('Improve your score: npm install agentomy-agent (standalone, no infrastructure needed)\n');
    process.stderr.write('\n');
  }

  return {
    target: normalizedTarget,
    timestamp: new Date().toISOString(),
    suites: suiteNames,
    results: allResults,
    suiteResults,
    scores,
    detectedAdapter,
  };
}

/**
 * Run a specific set of scenarios (for targeted use).
 */
export async function runScenarios(scenarios, target, options = {}) {
  const results = [];
  for (const scenario of scenarios) {
    const result = await runScenario(scenario, target.replace(/\/$/, ''), options);
    results.push(result);
  }
  return results;
}

export { computeScores, SUITE_TO_DIMENSION, DIMENSION_WEIGHT };
