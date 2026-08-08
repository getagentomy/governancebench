/**
 * GovernanceBench -- Evaluator Integrity Verification
 *
 * Self-integrity checks before scoring. Ensures evaluator files
 * have not been tampered with and test cases are rotated so
 * agents cannot memorize answers.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * SHA-256 hash of a file's contents.
 * @param {string} filePath
 * @returns {string} hex digest
 */
function computeFileHash(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Hash all .mjs files in a suites directory.
 * @param {string} suitesDir
 * @returns {{ files: Record<string, string>, combinedHash: string }}
 */
function computeSuiteHashes(suitesDir) {
  const entries = fs.readdirSync(suitesDir)
    .filter(f => f.endsWith('.mjs'))
    .sort();

  const files = {};
  for (const entry of entries) {
    files[entry] = computeFileHash(path.join(suitesDir, entry));
  }

  const combined = crypto.createHash('sha256')
    .update(Object.values(files).join(''))
    .digest('hex');

  return { files, combinedHash: combined };
}

/**
 * Compare current suite hashes against known-good hashes.
 *
 * If knownHashes is null/undefined, generates and returns current
 * hashes as a first-run baseline (valid: true, no mismatches).
 *
 * @param {string} suitesDir
 * @param {Record<string, string>|null} knownHashes - filename -> expected hash
 * @returns {{ valid: boolean, mismatches: Array<{file: string, expected: string, actual: string}>, newFiles: string[], missingFiles: string[] }}
 */
function verifyIntegrity(suitesDir, knownHashes) {
  const current = computeSuiteHashes(suitesDir);

  // First-run baseline
  if (knownHashes == null) {
    return {
      valid: true,
      mismatches: [],
      newFiles: Object.keys(current.files),
      missingFiles: [],
    };
  }

  const mismatches = [];
  const newFiles = [];
  const missingFiles = [];

  const knownSet = new Set(Object.keys(knownHashes));
  const currentSet = new Set(Object.keys(current.files));

  // Check for mismatches and new files
  for (const [file, hash] of Object.entries(current.files)) {
    if (!knownSet.has(file)) {
      newFiles.push(file);
    } else if (knownHashes[file] !== hash) {
      mismatches.push({ file, expected: knownHashes[file], actual: hash });
    }
  }

  // Check for missing files
  for (const file of knownSet) {
    if (!currentSet.has(file)) {
      missingFiles.push(file);
    }
  }

  const valid = mismatches.length === 0 && newFiles.length === 0 && missingFiles.length === 0;

  return { valid, mismatches, newFiles, missingFiles };
}

/**
 * Seeded pseudo-random number generator (mulberry32).
 * @param {number} seed
 * @returns {function(): number} returns 0..1
 */
function seededRng(seed) {
  let s = seed | 0;
  return function () {
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Fisher-Yates shuffle with deterministic seed, return subset.
 *
 * @param {Array} scenarios - full scenario array
 * @param {object} [options]
 * @param {number} [options.rotationSeed] - deterministic seed (default: Date.now())
 * @param {number} [options.coverageTarget] - fraction to include (default: 0.8)
 * @returns {{ selected: Array, seed: number, total: number, selectedCount: number }}
 */
function rotateTestCases(scenarios, options = {}) {
  const seed = options.rotationSeed != null ? options.rotationSeed : Date.now();
  const coverageTarget = options.coverageTarget != null ? options.coverageTarget : 0.8;

  const arr = scenarios.slice(); // defensive copy
  const rng = seededRng(seed);

  // Fisher-Yates
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }

  const count = Math.max(1, Math.round(arr.length * coverageTarget));
  const selected = arr.slice(0, count);

  return { selected, seed, total: scenarios.length, selectedCount: selected.length };
}

/**
 * Generate a blind evaluation ID that does not reveal the framework under test.
 * @returns {string} Format: eval-<16 hex chars>
 */
function generateBlindId() {
  return `eval-${crypto.randomBytes(8).toString('hex')}`;
}

/**
 * Combine integrity and rotation results into an audit-ready report.
 *
 * @param {{ valid: boolean, mismatches: Array, newFiles: Array, missingFiles: Array }} verificationResult
 * @param {{ selected: Array, seed: number, total: number, selectedCount: number }} rotationResult
 * @returns {object}
 */
function createIntegrityReport(verificationResult, rotationResult) {
  return {
    timestamp: new Date().toISOString(),
    integrityValid: verificationResult.valid,
    filesChecked: verificationResult.mismatches.length
      + verificationResult.newFiles.length
      + verificationResult.missingFiles.length
      + (verificationResult.valid ? verificationResult.newFiles.length : 0),
    rotationSeed: rotationResult.seed,
    scenariosTotal: rotationResult.total,
    scenariosSelected: rotationResult.selectedCount,
    evaluationId: generateBlindId(),
  };
}

module.exports = {
  computeFileHash,
  computeSuiteHashes,
  verifyIntegrity,
  rotateTestCases,
  generateBlindId,
  createIntegrityReport,
};
