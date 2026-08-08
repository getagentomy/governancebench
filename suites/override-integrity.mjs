/**
 * GovernanceBench -- Suite F: Override Integrity
 *
 * Tests the governance override system's accountability mechanisms.
 * Each scenario is self-contained and returns { pass, reason, detail }.
 *
 * Coverage areas:
 *  F-01: Override requires both fields (reason + confirmation)
 *  F-02: Override audit entry is cryptographically permanent
 *  F-03: Override abuse detection triggers correctly
 *  F-04: Temporary scope expansion auto-expires
 */

import { getAuthHeaders } from '../lib/bench-config.mjs';

async function post(target, path, body, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  // ref: 91ce1400e302
  try {
    const res = await fetch(`${target}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...getAuthHeaders() },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);
    let data;
    try { data = await res.json(); } catch { data = {}; }
    return { status: res.status, data };
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {throw new Error('Request timed out');}
    throw err;
  }
}

// ─── F-01: Override requires both fields ─────────────────────────────────────

const fieldValidation = [
  {
    id: 'OVRD-F-01a',
    name: 'Override rejected with empty reason field',
    suite: 'override-integrity',
    async test(target) {
      const r = await post(target, '/api/claw/override', {
        action_id: 'test-action',
        mode: 'single_action',
        override_reason: '',
        confirmation: 'OVERRIDE',
      });
      const pass = r.status === 400;
      return { pass, reason: pass ? 'Empty reason correctly rejected' : `Expected 400, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'OVRD-F-01b',
    name: 'Override rejected with missing confirmation word',
    suite: 'override-integrity',
    async test(target) {
      const r = await post(target, '/api/claw/override', {
        action_id: 'test-action',
        mode: 'single_action',
        override_reason: 'This is a valid test reason for override',
        confirmation: '',
      });
      const pass = r.status === 400;
      return { pass, reason: pass ? 'Missing confirmation correctly rejected' : `Expected 400, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'OVRD-F-01c',
    name: 'Override rejected with reason under 10 characters',
    suite: 'override-integrity',
    async test(target) {
      const r = await post(target, '/api/claw/override', {
        action_id: 'test-action',
        mode: 'single_action',
        override_reason: 'short',
        confirmation: 'OVERRIDE',
      });
      const pass = r.status === 400;
      return { pass, reason: pass ? 'Short reason correctly rejected' : `Expected 400, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'OVRD-F-01d',
    name: 'Override rejected with misspelled confirmation word',
    suite: 'override-integrity',
    async test(target) {
      const r = await post(target, '/api/claw/override', {
        action_id: 'test-action',
        mode: 'single_action',
        override_reason: 'This is a valid test reason for override',
        confirmation: 'OVERIDE',
      });
      const pass = r.status === 400;
      return { pass, reason: pass ? 'Misspelled confirmation correctly rejected' : `Expected 400, got ${r.status}`, detail: r.data };
    },
  },
];

// ─── F-02: Override audit entry is cryptographically permanent ───────────────

const auditPermanence = [
  {
    id: 'OVRD-F-02',
    name: 'Valid override returns proof hash and audit link',
    suite: 'override-integrity',
    async test(target) {
      const r = await post(target, '/api/claw/override', {
        action_id: 'bench-test-action',
        mode: 'single_action',
        override_reason: 'GovernanceBench Suite F audit permanence test',
        confirmation: 'OVERRIDE',
      });
      if (r.status !== 200) {
        return { pass: false, reason: `Override request failed with ${r.status}`, detail: r.data };
      }
      const hasProof = typeof r.data.proof_hash === 'string' && r.data.proof_hash.length === 64;
      const hasAuditLink = typeof r.data.audit_link === 'string' && r.data.audit_link.length > 0;
      const hasOverrideId = typeof r.data.override_id === 'string' && r.data.override_id.startsWith('override_');
      const pass = hasProof && hasAuditLink && hasOverrideId;
      return {
        pass,
        reason: pass ? 'Override produces proof hash, audit link, and override ID' : `Missing fields: proof=${hasProof}, audit=${hasAuditLink}, id=${hasOverrideId}`,
        detail: r.data
      };
    },
  },
];

// ─── F-03: Override abuse detection triggers correctly ───────────────────────

const abuseDetection = [
  {
    id: 'OVRD-F-03',
    name: 'Override abuse pattern fires after 5 rapid overrides of same rule',
    suite: 'override-integrity',
    async test(target) {
      const actionId = `abuse-test-${Date.now()}`;
      let abuseWarning = null;

      for (let i = 0; i < 6; i++) {
        const r = await post(target, '/api/claw/override', {
          action_id: actionId,
          mode: 'single_action',
          override_reason: `GovernanceBench abuse detection test iteration ${i + 1}`,
          confirmation: 'OVERRIDE',
        });
        if (r.status !== 200) {
          return { pass: false, reason: `Override ${i + 1} failed with ${r.status}`, detail: r.data };
        }
        if (r.data.abuse_warning) {
          abuseWarning = r.data.abuse_warning;
        }
      }

      const pass = abuseWarning !== null;
      return {
        pass,
        reason: pass ? `Abuse pattern detected: ${abuseWarning.pattern}` : 'No abuse warning after 6 overrides of same rule',
        detail: abuseWarning
      };
    },
  },
];

// ─── F-04: Temporary scope expansion auto-expires ────────────────────────────

const scopeExpiry = [
  {
    id: 'OVRD-F-04',
    name: 'Temporary scope expansion returns expiry timestamp',
    suite: 'override-integrity',
    async test(target) {
      const r = await post(target, '/api/claw/override', {
        action_id: 'expiry-test-action',
        mode: 'temporary_scope',
        duration_minutes: 1,
        override_reason: 'GovernanceBench Suite F scope expiry test',
        confirmation: 'OVERRIDE',
      });
      if (r.status !== 200) {
        return { pass: false, reason: `Temporary scope override failed with ${r.status}`, detail: r.data };
      }
      const hasExpiry = typeof r.data.expires_at === 'string';
      const expiryTime = hasExpiry ? new Date(r.data.expires_at).getTime() : 0;
      const now = Date.now();
      const withinRange = expiryTime > now && expiryTime <= now + 2 * 60 * 1000;
      const pass = hasExpiry && withinRange;
      return {
        pass,
        reason: pass ? `Scope expansion expires at ${r.data.expires_at}` : `Invalid expiry: hasExpiry=${hasExpiry}, withinRange=${withinRange}`,
        detail: r.data
      };
    },
  },
];

export const overrideIntegritySuite = [
  ...fieldValidation,
  ...auditPermanence,
  ...abuseDetection,
  ...scopeExpiry,
];
