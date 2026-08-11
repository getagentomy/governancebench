/**
 * GovernanceBench -- Test Runner
 *
 * Runs all scenarios in a suite sequentially.
 * Tracks pass/fail/skip per scenario.
 * Computes GovernanceBench score across 6 dimensions.
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
  'message-governance': 'Message Governance',
};

// Equal weight per dimension, DERIVED rather than written out.
//
// It was five hardcoded 20s. Promoting message-governance into the core set on 2026-08-10 made that a
// trap: a sixth dimension with no entry here scores as weight zero, so the suite would run,
// pass, be counted in the scenario total, and contribute nothing to the score -- a capability
// present in the product, counted in the headline, and invisible in the number. Deriving the
// weight means adding a dimension can never again silently fail to move the score.
//
// Equal weighting is the model this benchmark already used: Authorization carries 51 scenarios
// and OWASP Coverage 15, and both were weighted 20. That is deliberate -- a dimension is a
// governance PROPERTY, and a property is not more important because it took more scenarios to
// test.
//
// NOTE ON COMPARABILITY: third-party scores published before this date (Microsoft AGT 57/100,
// bare n8n 56/100) were measured under the five-dimension model. They remain valid for the
// instrument that produced them and are NOT directly comparable to a six-dimension score.
const DIMENSION_WEIGHT = Object.fromEntries(
  [...new Set(Object.values(SUITE_TO_DIMENSION))].map(
    (d, _i, all) => [d, 100 / all.length]));

// The set the weight map is derived FROM, so "is this a core dimension" and "does it have a
// weight" are answered by the same source rather than by two lists that can drift apart.
const CORE_DIMENSIONS = new Set(Object.values(SUITE_TO_DIMENSION));

// Optional and vertical suites are scored standalone and are not core dimensions. They take
// the identical per-dimension weight, which keeps `overall` a plain mean in every run.
const UNIFORM_DIMENSION_WEIGHT = 100 / CORE_DIMENSIONS.size;

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
    // `suite` first, then `category`. Core suites declare `suite`; most optional and
    // vertical suites declare only `category`, and computeScores reads `result.suite`.
    // That divergence put message-governance under a dimension literally named `undefined`
    // when it was promoted on 2026-08-10, and the same divergence silently mis-scored every
    // optional suite for as long as the weight lookup had a `|| 25` default to fall into.
    // Reading both here fixes the class rather than the suite that happened to surface it.
    suite: scenario.suite || scenario.category,
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
      // No `|| 25` default, and no blanket fallback either. Two distinct cases:
      //
      // A CORE dimension with no weight means DIMENSION_WEIGHT and SUITE_TO_DIMENSION have
      // been decoupled, and a default would publish a score weighted by a number nobody
      // chose. That is the failure this file already had: five hardcoded 20s, so the sixth
      // dimension weighed zero, ran, passed, counted in the total and moved the score not at
      // all. Refuse.
      //
      // An OPTIONAL or vertical suite is not a core dimension and legitimately has no entry.
      // Every weight here is equal, so overall is the mean of the dimensions present in the
      // run and the weight VALUE cannot affect it; what would corrupt the mean is one
      // dimension getting a DIFFERENT number. So an unmapped suite takes the same uniform
      // weight rather than an invented one.
      //
      // The `|| 25` this replaced was not merely inelegant. It silently absorbed a second
      // defect: most optional suites declare `category` and not `suite`, so every one of
      // them scored under a dimension named `undefined` at a weight of 25 for as long as
      // that default existed. Fixed at the source, where `suite` is now read from either.
      const weight = CORE_DIMENSIONS.has(dim) ? DIMENSION_WEIGHT[dim] : UNIFORM_DIMENSION_WEIGHT;
      if (weight === undefined) {
        throw new Error(
          `governancebench: core dimension ${JSON.stringify(dim)} has no weight. DIMENSION_WEIGHT is derived from ` +
          `SUITE_TO_DIMENSION; a core dimension reaching scoring without an entry means scoring and ` +
          `weighting no longer read the same map.`);
      }
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
    // Agent-message governance. PROMOTED INTO THE CORE SET 2026-08-10.
    //
    // It was authored BEFORE the runtime class it tests -- to measure whether the threat was
    // real rather than to describe a feature -- so it sat outside 'all' on the grounds that
    // its scenarios were expected to fail and a failing measurement in the core set would be
    // indistinguishable from a regression. That premise held when it was written and no
    // longer does: the suite passes 8/8 against this build, including AGB-MSG-008, the guard
    // scenario that fails any platform which satisfies the suite by refusing everything. So
    // the pass is not vacuous by the suite's own test.
    //
    // Keeping it out once it passes is the mirror of the defect this benchmark exists to
    // catch: a capability the product has and the published score does not count. Core total
    // moves 224 -> 232.
    'message-governance': () => import('../suites/message-governance.mjs').then(m => m.messageGovernanceSuite),
    // Substrate properties: is the RECORD inspectable, addressed, ordered and
    // independently checkable, as distinct from whether a decision was correct.
    'substrate-governance': () => import('../suites/substrate-governance.mjs').then(m => m.substrateGovernanceSuite),
    'agent-collective': () => import('../suites/agent-collective.mjs').then(m => m.agentCollectiveSuite),
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
    ? ['authorization', 'audit', 'override', 'behavioral', 'owasp', 'message-governance']
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
