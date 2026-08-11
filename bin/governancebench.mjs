#!/usr/bin/env node

/**
 * GovernanceBench CLI
 *
 * The open governance benchmark for AI agent platforms.
 * Tests any governance platform against 6 dimensions: Authorization,
 * Auditability, Override, and Behavioral Monitoring.
 *
 * Usage:
 *  governancebench run --target http://localhost:3000
 *  governancebench run --target http://target:3000 --suite authorization
 *  governancebench report --format markdown
 */

import { createRequire } from 'module';
import { Command } from 'commander';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

import { runBench } from '../lib/runner.mjs';
import { generateJsonReport, generateMarkdownReport, printSummary } from '../lib/reporter.mjs';
import { generateHtmlReport } from '../lib/html-reporter.js';
import { loadAdapter } from '../lib/adapter-runner.mjs';
import { runBlindScoring, formatBlindSummary } from '../lib/blind-scorer.mjs';
import { setApiKey } from '../lib/bench-config.mjs';
import { detectAdapter } from '../lib/auto-detect.mjs';

const require = createRequire(import.meta.url);
// ref: 07466a5fd467
let version = '1.0.1';
try {
  const pkg = require('../package.json');
  version = pkg.version;
} catch {
  // fall back to default version
}

// Temp file for persisting last run result
const LAST_RUN_FILE = join(tmpdir(), '.governancebench-last-run.json');

function loadLastRun() {
  try {
    if (existsSync(LAST_RUN_FILE)) {
      return JSON.parse(readFileSync(LAST_RUN_FILE, 'utf8'));
    }
  } catch {
  // ignore
  }
  return null;
}

function saveLastRun(result) {
  try {
    writeFileSync(LAST_RUN_FILE, JSON.stringify(result, null, 2), 'utf8');
  } catch {
  // ignore write failures
  }
}

const VALID_SUITES = ['all', 'authorization', 'audit', 'override', 'behavioral', 'owasp', 'override-integrity', 'rpa-governance', 'algo-trading', 'medical-device', 'av-fleet', 'industrial-iot', 'breach-reproduction', 'cloud-infrastructure', 'skill-governance', 'ipi', 'message-governance', 'substrate-governance', 'agent-collective'];
const VALID_ADAPTERS = ['agentomy', 'generic', 'microsoft-agt', 'openai-agentkit', 'n8n'];

const program = new Command();

program
  .name('governancebench')
  .description(
    'GovernanceBench -- The open governance benchmark for AI agent platforms.\n' +
  'Tests any governance API across 6 dimensions: Authorization, Auditability, Override, Behavioral, OWASP Coverage, Message Governance.'
  )
  .version(version, '-v, --version', 'Print GovernanceBench version')
  .addHelpText('after', `
Dimensions:
  authorization  Permission tier enforcement and escalation blocking
  audit  Tamper-evident audit trail integrity and completeness
  override  Kill switch reliability and operator validation
  behavioral  Anomaly detection, quarantine mechanics, false positive rate
  owasp  OWASP Agentic Top 10 coverage (ASI-01 through ASI-10, Kevlar harness)

Examples:
  governancebench run --target http://localhost:3000
  governancebench run --target http://localhost:3000 --api-key YOUR_KEY
  governancebench run --target http://target:3000 --suite authorization
  governancebench run --target http://target:3000 --suite all --verbose --format markdown
  governancebench run --target http://external.example.com --adapter microsoft-agt
  governancebench run --target http://external.example.com --adapter generic --config ./my-adapter.json
  governancebench report --format json
  governancebench report --format markdown > report.md
  governancebench blind --targets targets.json

Scoring:
  Each dimension is scored 0-100 based on pass/fail of scoreable scenarios.
  Skipped scenarios (endpoint not implemented) are excluded from scoring.
  Overall score is the equally weighted average of all 6 dimensions.

  Excellent: 90+  Good: 75+  Adequate: 60+  Insufficient: 40+  Critical: <40

Adapters:
  agentomy  Default. Maps to Agentomy /api/claw/* endpoints.
  microsoft-agt  Microsoft Agent Governance Toolkit adapter.
  openai-agentkit OpenAI AgentKit guardrails adapter.
  n8n  n8n workflow runtime adapter (v1 public API). Stock n8n scores low on
        agent-shape governance dimensions (~10-20/100); use WorkflowBench
        (cli/workflowbench/) for the workflow-shape surface.
  generic  Load endpoint mapping from a JSON config file (requires --config).
`);

// ─── run command ─────────────────────────────────────────────────────────────

program
  .command('run')
  .description('Run GovernanceBench against a target governance platform')
  .requiredOption('--target <url>', 'Base URL of the governance platform (e.g. http://localhost:3000)')
  .option(
    '--suite <name>',
    `Suite to run: ${VALID_SUITES.join(' | ')}`,
    'all'
  )
  .option('--timeout <ms>', 'Timeout per scenario in milliseconds', '10000')
  .option('--verbose', 'Stream pass/fail per scenario to stderr', false)
  .option(
    '--format <fmt>',
    'Output format: summary | json | markdown | html',
    'summary'
  )
  .option('--output <file>', 'Write report to file instead of stdout')
  .option(
    '--adapter <name>',
    `Endpoint adapter: ${VALID_ADAPTERS.join(' | ')}`,
    'agentomy'
  )
  .option('--config <path>', 'Path to JSON adapter config (required when --adapter generic)')
  .option('--api-key <key>', 'API key sent as X-API-Key header on every HTTP request')
  .addHelpText('after', `
Examples:
  governancebench run --target http://localhost:3000
  governancebench run --target http://localhost:3000 --api-key my-secret-key
  governancebench run --target http://localhost:3000 --suite authorization --verbose
  governancebench run --target http://localhost:3000 --suite all --format json > results.json
  governancebench run --target http://localhost:3000 --format markdown --output report.md
  governancebench run --target https://external-governance-endpoint.com --adapter microsoft-agt
  governancebench run --target https://external-governance-endpoint.com --adapter generic --config ./adapter.json
`)
  .action(async (opts, cmd) => {
    const { target, suite, verbose, format, output, adapter: adapterName, config: configPath, apiKey } = opts;
    const timeout = parseInt(opts.timeout, 10) || 10000;

    // Determine if --adapter was explicitly passed by the user
    const adapterExplicit = cmd.getOptionValueSource('adapter') === 'cli';

    // Store API key so all suite HTTP helpers include it
    if (apiKey) {
      setApiKey(apiKey);
    }

    // Validate target URL
    try {
      const url = new URL(target);
      if (!['http:', 'https:'].includes(url.protocol)) {
        console.error(`ERR Target must use http or https: ${target}`);
        process.exit(1);
      }
    } catch {
      console.error(`ERR Invalid target URL: ${target}`);
      process.exit(1);
    }

    // Validate suite
    const suiteArg = suite.toLowerCase();
    if (!VALID_SUITES.includes(suiteArg)) {
      console.error(`ERR Unknown suite: "${suite}". Valid options: ${VALID_SUITES.join(', ')}`);
      process.exit(1);
    }

    // Auto-detect adapter if not explicitly specified
    let adapterKey;
    if (!adapterExplicit) {
      const detected = await detectAdapter(target);
      if (detected) {
        adapterKey = detected;
        process.stderr.write(`Auto-detected platform: ${adapterKey}\n`);
      } else {
        adapterKey = 'agentomy';
      }
    } else {
      adapterKey = (adapterName || 'agentomy').toLowerCase();
    }

    // Validate adapter
    if (!VALID_ADAPTERS.includes(adapterKey)) {
      console.error(`ERR Unknown adapter: "${adapterKey}". Valid options: ${VALID_ADAPTERS.join(', ')}`);
      process.exit(1);
    }
    if (adapterKey === 'generic' && !configPath) {
      console.error('ERR --adapter generic requires --config <path> to a JSON adapter config file.');
      process.exit(1);
    }

    let adapter;
    try {
      adapter = await loadAdapter(adapterKey, configPath || null);
    } catch (err) {
      console.error(`ERR Failed to load adapter "${adapterKey}": ${err.message}`);
      process.exit(1);
    }

    if (!verbose) {
      process.stderr.write(`GovernanceBench v${version} -- target: ${target}\n`);
      process.stderr.write(`Suite: ${suiteArg} | Adapter: ${adapter.name} | Timeout: ${timeout}ms\n`);
      process.stderr.write('Running...\n');
    }

    let benchResult;
    try {
      benchResult = await runBench(target, suiteArg, { verbose, timeout, adapterExplicit, adapter });
      // Attach adapter info to result for report metadata
      benchResult._adapter = adapter.name;
    } catch (err) {
      console.error(`ERR Benchmark failed: ${err.message}`);
      process.exit(1);
    }

    // Persist last run
    saveLastRun(benchResult);

    // Generate output
    let output_content;
    if (format === 'json') {
      const report = generateJsonReport(benchResult);
      output_content = JSON.stringify(report, null, 2);
    } else if (format === 'markdown') {
      output_content = generateMarkdownReport(benchResult);
    } else if (format === 'html') {
      output_content = generateHtmlReport(benchResult);
      if (output) {
        writeFileSync(output, output_content, 'utf8');
        process.stderr.write(`HTML report saved to ${output}\n`);
      } else {
        const defaultPath = 'governancebench-report.html';
        writeFileSync(defaultPath, output_content, 'utf8');
        process.stderr.write(`HTML report saved to ${defaultPath}\n`);
      }
      printSummary(benchResult);
      const score = benchResult.scores.overall;
      process.exit(score !== null && score >= 60 ? 0 : 1);
      return;
    } else {
      // summary: print to console, no file
      printSummary(benchResult);
      if (output) {
        const jsonReport = generateJsonReport(benchResult);
        writeFileSync(output, JSON.stringify(jsonReport, null, 2), 'utf8');
        process.stderr.write(`Report saved to ${output}\n`);
      }
      // Exit code based on overall score
      const score = benchResult.scores.overall;
      process.exit(score !== null && score >= 60 ? 0 : 1);
      return;
    }

    if (output) {
      writeFileSync(output, output_content, 'utf8');
      process.stderr.write(`Report saved to ${output}\n`);
      printSummary(benchResult);
    } else {
      console.log(output_content);
      if (format !== 'json') {
        printSummary(benchResult);
      }
    }

    // Exit code: 0 if adequate (60+), 1 if insufficient
    const score = benchResult.scores.overall;
    process.exit(score !== null && score >= 60 ? 0 : 1);
  });

// ─── report command ───────────────────────────────────────────────────────────

program
  .command('report')
  .description('Generate a report from the last GovernanceBench run')
  .option('--format <fmt>', 'Output format: json | markdown | html | summary', 'summary')
  .option('--output <file>', 'Write report to file instead of stdout')
  .addHelpText('after', `
Examples:
  governancebench report
  governancebench report --format json
  governancebench report --format markdown > report.md
  governancebench report --format markdown --output report.md
  governancebench report --format html --output report.html
`)
  .action((opts) => {
    const { format, output } = opts;

    const lastRun = loadLastRun();
    if (!lastRun) {
      console.error('ERR No previous run found. Run `governancebench run --target <url>` first.');
      process.exit(1);
    }

    let output_content;
    if (format === 'json') {
      const report = generateJsonReport(lastRun);
      output_content = JSON.stringify(report, null, 2);
    } else if (format === 'markdown') {
      output_content = generateMarkdownReport(lastRun);
    } else if (format === 'html') {
      output_content = generateHtmlReport(lastRun);
      if (output) {
        writeFileSync(output, output_content, 'utf8');
        process.stderr.write(`HTML report saved to ${output}\n`);
      } else {
        const defaultPath = 'governancebench-report.html';
        writeFileSync(defaultPath, output_content, 'utf8');
        process.stderr.write(`HTML report saved to ${defaultPath}\n`);
      }
      return;
    } else {
      printSummary(lastRun);
      if (output) {
        const jsonReport = generateJsonReport(lastRun);
        writeFileSync(output, JSON.stringify(jsonReport, null, 2), 'utf8');
        process.stderr.write(`Report saved to ${output}\n`);
      }
      return;
    }

    if (output) {
      writeFileSync(output, output_content, 'utf8');
      process.stderr.write(`Report saved to ${output}\n`);
    } else {
      console.log(output_content);
    }
  });

// ─── list command ─────────────────────────────────────────────────────────────

program
  .command('list')
  .description('List all available test scenarios')
  .option('--suite <name>', 'Filter by suite', 'all')
  .option('--format <fmt>', 'Output format: table | json', 'table')
  .action(async (opts) => {
    const suiteArg = (opts.suite || 'all').toLowerCase();

    const suitesToLoad = suiteArg === 'all'
      ? ['authorization', 'audit', 'override', 'behavioral', 'owasp']
      : [suiteArg];

    const allScenarios = [];
    for (const name of suitesToLoad) {
      try {
        let scenarios;
        if (name === 'authorization') {
          ({ authorizationSuite: scenarios } = await import('../suites/authorization.mjs'));
        } else if (name === 'audit') {
          ({ auditSuite: scenarios } = await import('../suites/audit.mjs'));
        } else if (name === 'override') {
          ({ overrideSuite: scenarios } = await import('../suites/override.mjs'));
        } else if (name === 'behavioral') {
          ({ behavioralSuite: scenarios } = await import('../suites/behavioral.mjs'));
        } else if (name === 'owasp') {
          ({ owaspSuite: scenarios } = await import('../suites/owasp.mjs'));
        } else {
          console.error(`ERR Unknown suite: ${name}`);
          continue;
        }
        allScenarios.push(...scenarios);
      } catch (err) {
        console.error(`ERR Loading ${name}: ${err.message}`);
      }
    }

    if (opts.format === 'json') {
      console.log(JSON.stringify(allScenarios.map(s => ({ id: s.id, name: s.name, suite: s.suite })), null, 2));
    } else {
      const suiteCounts = {};
      for (const s of allScenarios) {
        suiteCounts[s.suite] = (suiteCounts[s.suite] || 0) + 1;
      }
      console.log(`\nGovernanceBench scenarios (${allScenarios.length} total)\n`);
      for (const [suite, count] of Object.entries(suiteCounts)) {
        console.log(`  ${suite}: ${count} scenarios`);
      }
      console.log('');
      for (const s of allScenarios) {
        console.log(`  ${s.id.padEnd(12)}  ${s.suite.padEnd(16)}  ${s.name}`);
      }
      console.log('');
    }
  });

// ─── blind command ────────────────────────────────────────────────────────────

program
  .command('blind')
  .description('Run GovernanceBench against multiple targets with blind scoring')
  .requiredOption(
    '--targets <file>',
    'Path to a JSON file containing an array of target definitions'
  )
  .option(
    '--suite <name>',
    `Suite to run: ${VALID_SUITES.join(' | ')}`,
    'all'
  )
  .option('--timeout <ms>', 'Timeout per scenario in milliseconds', '10000')
  .option('--verbose', 'Stream per-scenario output to stderr', false)
  .option('--no-shuffle', 'Disable randomized execution order')
  .option('--parallel', 'Run all targets concurrently (default: sequential)', false)
  .option('--format <fmt>', 'Output format: summary | json', 'summary')
  .option('--output <file>', 'Write result to file instead of stdout')
  .option('--api-key <key>', 'API key sent as X-API-Key header on every HTTP request')
  .addHelpText('after', `
Targets file format (JSON array):
  [
  { "label": "System A", "target": "http://host-a:3000", "adapter": "agentomy" },
  { "label": "System B", "target": "http://host-b:3000", "adapter": "microsoft-agt" },
  { "label": "System C", "target": "http://host-c:3000", "adapter": "generic", "config": "./c-adapter.json" }
  ]

  Required fields: label (unique), target (URL)
  Optional fields: adapter (default: agentomy), config (path, required for generic adapter)

Examples:
  governancebench blind --targets targets.json
  governancebench blind --targets targets.json --suite authorization --verbose
  governancebench blind --targets targets.json --format json --output blind-results.json
  governancebench blind --targets targets.json --api-key my-secret-key
`)
  .action(async (opts) => {
    const { suite, verbose, format, output, parallel, apiKey } = opts;
    const timeout = parseInt(opts.timeout, 10) || 10000;
    const shuffle = opts.shuffle !== false; // --no-shuffle sets opts.shuffle to false

    // Store API key so all suite HTTP helpers include it
    if (apiKey) {
      setApiKey(apiKey);
    }

    // Load targets file
    let targetsRaw;
    try {
      const { readFileSync } = await import('fs');
      targetsRaw = readFileSync(opts.targets, 'utf-8');
    } catch (err) {
      console.error(`ERR Cannot read targets file "${opts.targets}": ${err.message}`);
      process.exit(1);
    }

    let targets;
    try {
      targets = JSON.parse(targetsRaw);
    } catch (err) {
      console.error(`ERR Invalid JSON in targets file: ${err.message}`);
      process.exit(1);
    }

    if (!Array.isArray(targets) || targets.length === 0) {
      console.error('ERR Targets file must contain a non-empty JSON array.');
      process.exit(1);
    }

    // Validate suite
    const suiteArg = suite.toLowerCase();
    if (!VALID_SUITES.includes(suiteArg)) {
      console.error(`ERR Unknown suite: "${suite}". Valid options: ${VALID_SUITES.join(', ')}`);
      process.exit(1);
    }

    if (!verbose) {
      process.stderr.write(`GovernanceBench v${version} -- blind scoring\n`);
      process.stderr.write(`Targets: ${targets.length} | Suite: ${suiteArg} | Timeout: ${timeout}ms\n`);
      process.stderr.write(`Shuffle: ${shuffle} | Parallel: ${parallel}\n`);
      process.stderr.write('Running...\n\n');
    }

    let blindResult;
    try {
      blindResult = await runBlindScoring(targets, { suites: suiteArg, verbose, timeout, shuffle, parallel });
    } catch (err) {
      console.error(`ERR Blind scoring failed: ${err.message}`);
      process.exit(1);
    }

    let outputContent;
    if (format === 'json') {
      outputContent = JSON.stringify(blindResult, null, 2);
    } else {
      outputContent = formatBlindSummary(blindResult);
    }

    if (output) {
      writeFileSync(output, outputContent, 'utf8');
      process.stderr.write(`Blind scoring result saved to ${output}\n`);
      if (format !== 'json') {
        process.stdout.write(outputContent + '\n');
      }
    } else {
      process.stdout.write(outputContent + '\n');
    }

    // Exit 0 if any target scored >= 60, 1 if all failed or no scores
    const overallScores = Object.values(blindResult.scores).map(s => s.overall).filter(s => s !== null);
    const anyAdequate = overallScores.some(s => s >= 60);
    process.exit(anyAdequate ? 0 : 1);
  });

// ─── Unknown command handler ──────────────────────────────────────────────────

program.on('command:*', (operands) => {
  console.error(`ERR Unknown command: ${operands[0]}`);
  console.error('Run `governancebench --help` to see available commands.');
  process.exit(1);
});

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.help();
}
