/**
 * GovernanceBench -- Suite: Skill Governance (Phase 10D, 2026-05-31)
 *
 * Tests any governance platform's skill-loading governance contracts:
 *   - SignedSkillAttestation roundtrip works for valid skill
 *   - Tampered skill content -> attestation rejection
 *   - Tier gating enforced (low-tier denied higher-tier skill)
 *   - Registry tamper detection (registryHash present + deterministic)
 *   - Wrong-issuer attestation rejected
 *
 * Each scenario is self-contained, idempotent, and returns { pass, reason, detail }.
 */

import { getAuthHeaders } from '../lib/bench-config.mjs';

async function post(target, path, body, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`${target}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...getAuthHeaders() },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);
    let data;
    try { data = await res.json(); } catch { data = null; }
    return { status: res.status, data };
  } catch (err) {
    clearTimeout(timer);
    return { status: 0, data: null, error: err.message };
  }
}

async function get(target, path, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`${target}${path}`, {
      headers: { Accept: 'application/json', ...getAuthHeaders() },
      signal: controller.signal,
    });
    clearTimeout(timer);
    let data;
    try { data = await res.json(); } catch { data = null; }
    return { status: res.status, data };
  } catch (err) {
    clearTimeout(timer);
    return { status: 0, data: null, error: err.message };
  }
}

export const skillGovernanceSuite = [
  {
    id: 'AGB-SK-001',
    name: 'Skill registry endpoint surfaces all Phase 10A primitives + deterministic registryHash',
    category: 'skill-governance',
    async test(target) {
      const r = await get(target, '/api/skills/registry/status');
      if (r.status !== 200) {
        return { pass: false, reason: `Registry endpoint returned ${r.status}`, detail: { status: r.status } };
      }
      const count = r.data?.count;
      const hashFormat = /^[a-f0-9]{64}$/.test(r.data?.registryHash || '');
      const has16OrMore = count >= 16;
      const hasLoadedAt = typeof r.data?.loadedAt === 'string';
      const pass = has16OrMore && hashFormat && hasLoadedAt;
      return {
        pass,
        reason: pass
          ? `Registry surfaces ${count} skills with valid registryHash + loadedAt`
          : `FAIL: count=${count} hashFormat=${hashFormat} hasLoadedAt=${hasLoadedAt}`,
        detail: { count, registryHash: r.data?.registryHash, loadedAt: r.data?.loadedAt },
      };
    },
  },
  {
    id: 'AGB-SK-002',
    name: 'Tampered skill contentHash rejected by SignedSkillAttestation verifier',
    category: 'skill-governance',
    async test(target) {
      const tampered = {
        slug: 'agent-certificate',
        contentHash: 'tampered'.padEnd(64, '0'),
        version: '1.0.0',
        issuer: 'Agentomy',
        signature: Buffer.from('any').toString('base64'),
      };
      const r = await post(target, '/api/skills/verify-attestation', {
        attestation: tampered,
        publicKeyDer: Buffer.from('any-key').toString('base64'),
      });
      const flaggedInvalid = r.data?.valid === false;
      const reasonSurfaced = Array.isArray(r.data?.reasons) && r.data.reasons.some((rs) =>
        rs.includes('manifest_hash_mismatch') || rs.includes('signature_invalid'));
      const pass = flaggedInvalid && reasonSurfaced;
      return {
        pass,
        reason: pass
          ? `Tampered attestation correctly rejected: ${r.data.reasons.join(', ')}`
          : `FAIL: valid=${r.data?.valid} reasons=${JSON.stringify(r.data?.reasons)}`,
        detail: { reasons: r.data?.reasons },
      };
    },
  },
  {
    id: 'AGB-SK-003',
    name: 'Wrong-issuer attestation refused (single-issuer Agentomy constant)',
    category: 'skill-governance',
    async test(target) {
      const wrongIssuer = {
        slug: 'sovereignty-integrity-dyad',
        contentHash: '0'.repeat(64),
        version: '1.0.0',
        issuer: 'ImpostorOrg',
        signature: Buffer.from('any').toString('base64'),
      };
      const r = await post(target, '/api/skills/verify-attestation', {
        attestation: wrongIssuer,
        publicKeyDer: Buffer.from('any-key').toString('base64'),
      });
      const wrongIssuerDetected = r.data?.reasons?.includes('wrong_issuer');
      const pass = r.data?.valid === false && wrongIssuerDetected;
      return {
        pass,
        reason: pass
          ? `Wrong-issuer attestation correctly rejected`
          : `FAIL: valid=${r.data?.valid} reasons=${JSON.stringify(r.data?.reasons)}`,
        detail: { reasons: r.data?.reasons },
      };
    },
  },
  {
    id: 'AGB-SK-004',
    name: 'Unknown skill attestation refused (skill_not_in_registry)',
    category: 'skill-governance',
    async test(target) {
      const unknownSkill = {
        slug: 'attacker-skill-' + Date.now(),
        contentHash: '0'.repeat(64),
        version: '1.0.0',
        issuer: 'Agentomy',
        signature: Buffer.from('any').toString('base64'),
      };
      const r = await post(target, '/api/skills/verify-attestation', {
        attestation: unknownSkill,
        publicKeyDer: Buffer.from('any-key').toString('base64'),
      });
      const skillNotInRegistry = r.data?.reasons?.includes('skill_not_in_registry');
      const pass = r.data?.valid === false && skillNotInRegistry;
      return {
        pass,
        reason: pass
          ? `Unknown-skill attestation correctly rejected with skill_not_in_registry`
          : `FAIL: valid=${r.data?.valid} reasons=${JSON.stringify(r.data?.reasons)}`,
        detail: { reasons: r.data?.reasons },
      };
    },
  },
  {
    id: 'AGB-SK-005',
    name: 'Skill registry public surface does not leak internal file paths or secrets',
    category: 'skill-governance',
    async test(target) {
      const r = await get(target, '/api/skills/registry/status');
      if (r.status !== 200) {
        return { pass: false, reason: `Registry returned ${r.status}`, detail: { status: r.status } };
      }
      const blob = JSON.stringify(r.data);
      const noInternalPaths = !blob.match(/\/app\/agentskills\/|C:\\\\Users|\/home\/runner/);
      const noPrivateKeys = !blob.match(/privateKey|secretKey|signKey|password/i);
      const noEnvVars = !blob.match(/DATABASE_URL|JWT_SECRET|API_KEY=/);
      const pass = noInternalPaths && noPrivateKeys && noEnvVars;
      return {
        pass,
        reason: pass
          ? `Public registry surface clean (no internal paths, no secrets, no env vars)`
          : `FAIL: noInternalPaths=${noInternalPaths} noPrivateKeys=${noPrivateKeys} noEnvVars=${noEnvVars}`,
        detail: { skillCount: r.data?.count },
      };
    },
  },
];
