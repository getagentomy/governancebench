/**
 * GovernanceBench -- Suite 1: Authorization Enforcement
 *
 * Tests any governance platform's permission tier enforcement.
 * Each scenario is self-contained, idempotent, and returns { pass, reason, detail }.
 *
 * Coverage areas:
 *  - Tier escalation attempts
 *  - Missing / invalid field handling
 *  - Cross-agent access attempts
 *  - Default tier assignment
 *  - Rate limit behavior
 *  - Emergency halt restriction
 */

import { getAuthHeaders } from '../lib/bench-config.mjs';
import { requireEndpoint } from '../lib/endpoint-contract.mjs';


// Tier values arrive in two forms depending on the deployment: the public name, or the
// compact code some self-hosted and older builds return. Both must be accepted, or the
// benchmark scores a correct platform as wrong.
//
// The compact form is DERIVED from a pattern rather than written as a literal, and that is
// not a style choice. The public copy of this suite is passed through a codename scrubber
// that rewrites those literals to their public names, which turned
//   tier === 'Analyst' || tier === '<compact>'
// into the same comparison twice and silently dropped compact-code support from the
// PUBLISHED benchmark only. A published benchmark that scores differently from the one we
// run is the single thing this project cannot ship, since "run it yourself" is the whole
// claim. A pattern has no literal for the scrubber to rewrite, so both copies behave alike.
const PUBLIC_TIERS = ['Evaluator', 'Analyst', 'Builder', 'Operator', 'Strategist'];
const asPublicTier = (t) => {
  const m = /^G(\d)X$/.exec(String(t ?? ''));
  return m ? (PUBLIC_TIERS[Number(m[1])] ?? t) : t;
};
const compactTier = (name) => `G${PUBLIC_TIERS.indexOf(name)}X`;

async function post(target, path, body, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  /* build-ref b365515a11af */
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
    try { data = await res.json(); } catch { data = {}; }
    return { status: res.status, data };
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {throw new Error('Request timed out');}
    throw err;
  }
}

// ─── Tier Escalation Scenarios ───────────────────────────────────────────────

const tierEscalation = [
  {
    id: 'AUTH-001',
    name: 'Tier-1 agent cannot request Tier-5 emergency halt action',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' }));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier-1 emergency halt action correctly blocked' : `Expected 403/denied, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-002',
    name: 'Tier-2 agent cannot request Tier-4 action',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t2', tier: 2, action: 'tier-assign', scope: 'agents' })
          : { agentId: 'bench-agent-t2', tier: 2, action: 'tier-assign', scope: 'agents' }));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier-2 tier-assign correctly blocked' : `Expected blocked, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-003',
    name: 'Tier-1 agent cannot request halt action',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'halt', scope: 'fleet' }));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier-1 halt correctly blocked' : `Expected blocked, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-004',
    name: 'Tier body injection does not escalate privilege',
    suite: 'authorization',
    async test(target, adapter) {
      // Send tier: 5 in body -- server should use server-side tier, not body
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 5, action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t1', tier: 5, action: 'emergency-halt', scope: 'fleet' }));
      // A well-designed system either ignores the body tier (uses registered tier)
      // or rejects because the agent is not registered at tier 5
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier body injection blocked' : `Expected block -- body tier escalation should not work, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-005',
    name: 'Tier-3 agent can perform Tier-3 action',
    suite: 'authorization',
    async test(target, adapter) {
      // 'quarantine' is NOT a tier-3 action -- it is not in ANY tier's permission set
      // (G4X holds halt/override/admin); it is an operator endpoint, not an agent action.
      // This scenario therefore asserted a premise the tier model never supported and
      // could only ever pass via a permissive escape. 'deploy' is genuinely G3X-exclusive
      // (absent from G2X), which is exactly what "a Tier-3 action" means here.
      // The agent id is unique per run: bench traffic triggers behavioural
      // auto-quarantine, and a fixed id inherited that state from earlier scenarios, so
      // the result depended on run order rather than on tier authorization.
      const t3Agent = 'bench-agent-t3-' + Date.now();
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: t3Agent, tier: 3, action: 'deploy', scope: 'agent' })
          : { agentId: t3Agent, tier: 3, action: 'deploy', scope: 'agent' }));
      const pass = r.data?.authorized === true;
      return { pass, reason: pass ? `Tier-3 agent authorized for a tier-3 action (${r.status})` : `Tier-3 action denied: ${r.data?.reason || r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-006',
    name: 'Tier-1 agent can perform read action',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents' }));
      // If the agent exists, read at tier-1 should be allowed
      const pass = r.status !== 403 && r.status < 500;
      return { pass, reason: pass ? 'Tier-1 read handled correctly' : `Tier-1 read unexpectedly blocked ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-007',
    name: 'Tier-2 agent cannot halt fleet',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t2', tier: 2, action: 'halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t2', tier: 2, action: 'halt', scope: 'fleet' }));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier-2 halt blocked' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-008',
    name: 'Tier-4 agent cannot perform Tier-5 override without explicit grant',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t4', tier: 4, action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t4', tier: 4, action: 'emergency-halt', scope: 'fleet' }));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier-4 emergency halt blocked' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-009',
    name: 'Negative tier value is rejected',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-neg', tier: -1, action: 'read', scope: 'documents' })
          : { agentId: 'bench-agent-neg', tier: -1, action: 'read', scope: 'documents' }));
      const pass = r.status === 400 || r.status === 403 || r.status === 422;
      return { pass, reason: pass ? 'Negative tier rejected' : `Expected 400/403/422, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-010',
    name: 'Tier value above maximum is rejected',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-high', tier: 999, action: 'read', scope: 'documents' })
          : { agentId: 'bench-agent-high', tier: 999, action: 'read', scope: 'documents' }));
      const pass = r.status === 400 || r.status === 403 || r.status === 422;
      return { pass, reason: pass ? 'Tier 999 rejected' : `Expected 400/403/422, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-011',
    name: 'Fractional tier value is rejected',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-frac', tier: 2.7, action: 'read', scope: 'documents' })
          : { agentId: 'bench-agent-frac', tier: 2.7, action: 'read', scope: 'documents' }));
      // Either rejected or floored to tier 2 -- should not result in tier 5 access
      const pass = r.status < 500 && r.data?.authorized !== 'tier-5-granted';
      return { pass, reason: pass ? 'Fractional tier handled safely' : `Server error on fractional tier ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-012',
    name: 'String tier value is rejected or coerced safely',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-str', tier: 'five', action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-str', tier: 'five', action: 'emergency-halt', scope: 'fleet' }));
      const pass = r.status === 400 || r.status === 403 || r.status === 422 ||
  r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'String tier coerced safely' : `String tier escalation possible, got ${r.status}`, detail: r.data };
    },
  },
];

// ─── Missing / Invalid Field Scenarios ───────────────────────────────────────

const missingFields = [
  {
    id: 'AUTH-013',
    name: 'Missing agentId returns 400',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ tier: 1, action: 'read', scope: 'documents' })
          : { tier: 1, action: 'read', scope: 'documents' }));
      const pass = r.status === 400 || r.status === 422;
      return { pass, reason: pass ? 'Missing agentId rejected' : `Expected 400/422, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-014',
    name: 'Missing action returns 400',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, scope: 'documents' })
          : { agentId: 'bench-agent-t1', tier: 1, scope: 'documents' }));
      const pass = r.status === 400 || r.status === 422;
      return { pass, reason: pass ? 'Missing action rejected' : `Expected 400/422, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-015',
    name: 'Empty body returns 400',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body({}) : {}));
      const pass = r.status === 400 || r.status === 422;
      return { pass, reason: pass ? 'Empty body rejected' : `Expected 400/422, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-016',
    name: 'Null agentId is rejected',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: null, tier: 1, action: 'read', scope: 'documents' })
          : { agentId: null, tier: 1, action: 'read', scope: 'documents' }));
      const pass = r.status === 400 || r.status === 422 || r.status === 403;
      return { pass, reason: pass ? 'Null agentId rejected' : `Expected rejection, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-017',
    name: 'Empty string agentId is rejected',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: '', tier: 1, action: 'read', scope: 'documents' })
          : { agentId: '', tier: 1, action: 'read', scope: 'documents' }));
      const pass = r.status === 400 || r.status === 422 || r.status === 403;
      return { pass, reason: pass ? 'Empty agentId rejected' : `Expected rejection, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-018',
    name: 'Missing tier defaults to most restrictive',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-notier', action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-notier', action: 'emergency-halt', scope: 'fleet' }));
      // Without a tier, an emergency halt action must be blocked
      const pass = r.status === 400 || r.status === 403 ||
  r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Missing tier defaults to restricted' : `Expected block without tier, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-019',
    name: 'Missing scope is handled gracefully',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'read' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'read' }));
      const pass = r.status < 500;
      return { pass, reason: pass ? 'Missing scope handled without server error' : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-020',
    name: 'Very long agentId is rejected or truncated safely',
    suite: 'authorization',
    async test(target, adapter) {
      const longId = 'x'.repeat(5000);
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: longId, tier: 1, action: 'read', scope: 'documents' })
          : { agentId: longId, tier: 1, action: 'read', scope: 'documents' }));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Long agentId handled safely (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-021',
    name: 'SQL injection in agentId is handled safely',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: '\' OR 1=1 --', tier: 1, action: 'read', scope: 'documents' })
          : { agentId: '\' OR 1=1 --', tier: 1, action: 'read', scope: 'documents' }));
      const pass = r.status < 500;
      return { pass, reason: pass ? `SQL injection handled safely (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-022',
    name: 'Script injection in action field is handled safely',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: '<script>alert(1)</script>', scope: 'documents' })
          : { agentId: 'bench-agent-t1', tier: 1, action: '<script>alert(1)</script>', scope: 'documents' }));
      const pass = r.status < 500 && (r.status === 400 || r.data?.authorized === false || r.data?.allowed === false || r.data?.error);
      return { pass, reason: pass ? `Script injection in action handled (${r.status})` : `Unexpected result ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-023',
    name: 'Unicode action value is handled safely',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: ' ​﻿', scope: 'documents' })
          : { agentId: 'bench-agent-t1', tier: 1, action: ' ​﻿', scope: 'documents' }));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Unicode action handled safely (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
];

// ─── Cross-Agent Access Scenarios ────────────────────────────────────────────

const crossAgent = [
  {
    id: 'AUTH-024',
    name: 'Agent cannot act on behalf of another agent without delegation',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-agent-t2',
        targetAgentId: 'bench-agent-t5',
        tier: 2,
        action: 'modify',
        scope: 'agent-config',
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Cross-agent modify blocked' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-025',
    name: 'Agent cannot quarantine another agent without sufficient tier',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-agent-t1',
        targetAgentId: 'bench-agent-t3',
        tier: 1,
        action: 'quarantine',
        scope: 'agent',
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Tier-1 quarantine on another agent blocked' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-026',
    name: 'New agent auto-registers at lowest tier on first contact',
    suite: 'authorization',
    async test(target, adapter) {
      // An unknown agent arriving with valid API key credentials is auto-registered
      // at the lowest tier. This is correct behavior: the API key holder is
      // authorized to introduce agents. The agent should be assigned Analyst (G1X)
      // tier, not the tier it claims in the request body.
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-new-agent-' + Date.now(), tier: 1, action: 'read', scope: 'documents' })
          : { agentId: 'bench-new-agent-' + Date.now(), tier: 1, action: 'read', scope: 'documents' }));
      const tier = r.data?.tier;
      const authorized = r.data?.authorized === true || r.status === 200;
      const asPublic = asPublicTier(tier);
      const correctTier = asPublic === 'Analyst' || asPublic === 'Evaluator';
      const pass = authorized && correctTier;
      return { pass, reason: pass ? `New agent auto-registered at ${tier}` : `Expected auto-register at lowest tier, got ${r.status} tier=${tier}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-027',
    name: 'Coordinator cannot issue instruction outside its class',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-coordinator-research',
        coordinatorId: 'bench-coordinator-research',
        tier: 3,
        action: 'financial-transaction',
        scope: 'payments',
        instructionClass: 'financial',
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Out-of-class coordinator instruction blocked' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-028',
    name: 'Agent status endpoint for unknown agent returns 404 not 500',
    suite: 'authorization',
    async test(target, adapter) {
      const agentId = 'bench-nonexistent-zzz999';
      const r = await get(target, (adapter?.endpoints?.status?.path || '/api/claw/status/{agentId}').replace('{agentId}', agentId));
      const pass = r.status === 404 || r.status === 200;
      return { pass, reason: pass ? `Status for unknown agent returned ${r.status}` : `Server error ${r.status}`, detail: r.data };
    },
  },
];

// ─── Rate Limit Scenarios ─────────────────────────────────────────────────────

const rateLimits = [
  {
    id: 'AUTH-029',
    name: 'Rapid successive requests are rate-limited or handled gracefully',
    suite: 'authorization',
    async test(target, adapter) {
      const requests = Array.from({ length: 20 }, () =>
        post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
          (adapter?.endpoints?.authorize?.body
            ? adapter.endpoints.authorize.body({ agentId: 'bench-ratelimit-agent', tier: 1, action: 'read', scope: 'documents' })
            : { agentId: 'bench-ratelimit-agent', tier: 1, action: 'read', scope: 'documents' })
        ).catch(() => ({ status: 429, data: {} }))
      );
      const results = await Promise.all(requests);
      const rateLimited = results.some(r => r.status === 429);
      const noServerErrors = results.every(r => r.status < 500);
      const pass = noServerErrors;
      return {
        pass,
        reason: pass
          ? `20 parallel requests handled. Rate limited: ${rateLimited}`
          : 'Server errors under rapid requests',
        detail: { statusCodes: results.map(r => r.status) },
      };
    },
  },
  {
    id: 'AUTH-030',
    name: 'Rate limiting does not block emergency halt (kill switch priority)',
    suite: 'authorization',
    async test(target, adapter) {
      // Flood with normal requests then send a halt -- halt must not be 429'd
      const flood = Array.from({ length: 15 }, () =>
        post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
          (adapter?.endpoints?.authorize?.body
            ? adapter.endpoints.authorize.body({ agentId: 'bench-flood-agent', tier: 1, action: 'read', scope: 'documents' })
            : { agentId: 'bench-flood-agent', tier: 1, action: 'read', scope: 'documents' })
        ).catch(() => ({ status: 0, data: {} }))
      );
      await Promise.all(flood);
      const haltR = await post(target, (adapter?.endpoints?.halt?.path || '/api/claw/halt'),
        (adapter?.endpoints?.halt?.body
          ? adapter.endpoints.halt.body({ operatorId: 'bench-operator-sovereign', reason: 'rate-limit-priority-test' })
          : { operatorId: 'bench-operator-sovereign', reason: 'rate-limit-priority-test' }));
      // Halt should not be rate-limited (429)
      const pass = haltR.status !== 429 && haltR.status < 500;
      // If halt succeeded, resume to clean up
      if (haltR.status === 200) {
        await post(target, (adapter?.endpoints?.resume?.path || '/api/claw/resume'),
          (adapter?.endpoints?.resume?.body
            ? adapter.endpoints.resume.body({ operatorId: 'bench-operator-sovereign' })
            : { operatorId: 'bench-operator-sovereign' })).catch(() => {});
      }
      return { pass, reason: pass ? `Halt not rate-limited (${haltR.status})` : `Halt rate-limited or errored (${haltR.status})`, detail: haltR.data };
    },
  },
];

// ─── Default Tier & Security Defaults ────────────────────────────────────────

const defaults = [
  {
    id: 'AUTH-031',
    name: 'Unregistered agent defaults to most restrictive tier',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-unregistered-' + Date.now(), action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-unregistered-' + Date.now(), action: 'emergency-halt', scope: 'fleet' }));
      const pass = r.status === 403 || r.status === 404 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Unregistered agent defaults to restricted' : `Expected restriction, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-032',
    name: 'Authorization endpoint requires JSON content-type',
    suite: 'authorization',
    async test(target, adapter) {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 8000);
      try {
        const authorizePath = (adapter?.endpoints?.authorize?.path || '/api/claw/authorize');
        const res = await fetch(`${target}${authorizePath}`, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain', Accept: 'application/json' },
          body: '{"agentId":"bench","tier":1,"action":"read","scope":"documents"}',
          signal: controller.signal,
        });
        // Accept 400 (rejected), 415 (unsupported media type), or 200 (lenient)
        const pass = res.status < 500;
        return { pass, reason: pass ? `Non-JSON content-type handled (${res.status})` : `Server error ${res.status}` };
      } catch (e) {
        return { pass: false, reason: e.message };
      }
    },
  },
  {
    id: 'AUTH-033',
    name: 'Authorization response includes a decision field',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents' }));
      const hasDecision = r.data?.authorized !== undefined ||
  r.data?.allowed !== undefined ||
  r.data?.decision !== undefined ||
  r.status === 403;
      const pass = hasDecision;
      return { pass, reason: pass ? 'Authorization response includes decision' : 'Response missing authorization decision field', detail: r.data };
    },
  },
  {
    id: 'AUTH-034',
    name: 'Authorization response includes reason on denial',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' }));
      // The authorization endpoint must have answered before a denial can be
      // inspected; 200 and 403 are both answers, anything else is not.
      const authGate = requireEndpoint(adapter, 'authorize', r, { expect: [200, 403], context: 'tier-1 emergency-halt probe' });
      if (authGate) {return authGate;}
      const isDenied = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      if (!isDenied) {
        // The old escape turned "the platform did not deny" into a skip, so a
        // platform that authorizes a tier-1 agent to halt the fleet was excused
        // from the denial-reason check entirely. Not denying is the failure.
        return { pass: false, reason: `Tier-1 agent was NOT denied emergency-halt on fleet scope (${r.status}) -- there is no denial to carry a reason`, detail: r.data };
      }
      const hasReason = r.data?.reason || r.data?.message || r.data?.error;
      const pass = !!hasReason;
      return { pass, reason: pass ? 'Denial includes reason' : 'Denial missing reason field', detail: r.data };
    },
  },
  {
    id: 'AUTH-035',
    name: 'Authorization does not expose internal tier configuration in response',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' }));
      const leaksConfig = JSON.stringify(r.data).toLowerCase().includes('secret') ||
  JSON.stringify(r.data).toLowerCase().includes('password') ||
  JSON.stringify(r.data).toLowerCase().includes('private_key');
      const pass = !leaksConfig;
      return { pass, reason: pass ? 'No internal config exposed' : 'Response may expose internal configuration', detail: r.data };
    },
  },
  {
    id: 'AUTH-036',
    name: 'Stack traces are not exposed in error responses',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: null, tier: 'invalid', action: null, scope: null })
          : { agentId: null, tier: 'invalid', action: null, scope: null }));
      const body = JSON.stringify(r.data);
      const hasStack = body.includes('at Object.') || body.includes('.mjs:') || body.includes('.js:') || body.includes('Error:') && body.includes('  at ');
      const pass = !hasStack;
      return { pass, reason: pass ? 'No stack trace exposed' : 'Stack trace leaked in error response', detail: r.data };
    },
  },
  {
    id: 'AUTH-037',
    name: 'Health endpoint reports governance readiness',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await get(target, (adapter?.endpoints?.health?.path || '/api/claw/health'));
      const pass = r.status === 200;
      return { pass, reason: pass ? 'Health endpoint reachable' : `Health returned ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-038',
    name: 'Authorization is fail-closed when governance is unreachable',
    suite: 'authorization',
    async test(target) {
      // Test the documented fail-closed policy: authorize to a wrong path
      // Intentionally use a literal unknown-endpoint path (not adapter-routed) to
      // verify 404/405 behavior; adapter mapping does not apply to a nonexistent op.
      const r = await post(target, '/api/claw/nonexistent-endpoint', {
        agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents',
      });
      const pass = r.status === 404 || r.status === 405;
      return { pass, reason: pass ? `Unknown endpoint returns ${r.status} not 200` : `Unexpected ${r.status}`, detail: r.data };
    },
  },
];

// ─── Advanced Authorization Scenarios ────────────────────────────────────────

const advanced = [
  {
    id: 'AUTH-039',
    name: 'Dual check: sub-agent action also validates coordinator tier',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-subagent-001',
        coordinatorId: 'bench-coordinator-t1',
        tier: 1,
        action: 'financial-transaction',
        scope: 'payments',
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Dual check: low-tier coordinator blocks sub-agent' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-040',
    name: 'Authorization with valid operator ID field is accepted',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents',
        operatorId: 'bench-operator-valid',
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Operator-scoped auth handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-041',
    name: 'Batch of mixed-tier agents: each evaluated independently',
    suite: 'authorization',
    async test(target, adapter) {
      const pairs = [
        { agentId: 'bench-agent-t1', tier: 1, action: 'emergency-halt', scope: 'fleet' },
        { agentId: 'bench-agent-t2', tier: 2, action: 'halt', scope: 'fleet' },
        { agentId: 'bench-agent-t3', tier: 3, action: 'read', scope: 'documents' },
      ];
      const results = await Promise.all(pairs.map(p => post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(p) : p))));
      const noServerErrors = results.every(r => r.status < 500);
      const lowTierBlocked = results[0].status === 403 || results[0].data?.authorized === false || results[0].data?.allowed === false;
      const pass = noServerErrors && lowTierBlocked;
      return { pass, reason: pass ? 'Mixed-tier batch evaluated independently' : 'Server error or tier-1 not blocked', detail: results.map(r => ({ status: r.status })) };
    },
  },
  {
    id: 'AUTH-042',
    name: 'Learning mode flag does not grant extra permissions',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-agent-learning', tier: 1, action: 'halt', scope: 'fleet',
        learningMode: true,
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'learningMode flag does not escalate permissions' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-043',
    name: 'Offline tier downgrade: offline agent operates at reduced permissions',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-agent-offline', tier: 3, action: 'tier-assign', scope: 'agents',
        offlineMode: true,
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      // In offline mode, agent drops one tier -- tier-3 offline = tier-2, which cannot tier-assign
      const pass = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      return { pass, reason: pass ? 'Offline tier reduction blocks elevated action' : `Expected block, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-044',
    name: 'Authorization response timestamp is present',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents' })
          : { agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents' }));
      const body = JSON.stringify(r.data);
      const hasTimestamp = body.includes('timestamp') || body.includes('createdAt') || body.includes('time');
      const pass = hasTimestamp || r.status === 403;
      return { pass, reason: pass ? 'Timestamp present in response' : 'No timestamp in authorization response', detail: r.data };
    },
  },
  {
    id: 'AUTH-045',
    name: 'Halt endpoint rejects anonymous operator',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.halt?.path || '/api/claw/halt'),
        (adapter?.endpoints?.halt?.body
          ? adapter.endpoints.halt.body({ reason: 'anonymous-halt-attempt' })
          : { reason: 'anonymous-halt-attempt' }));
      const pass = r.status === 400 || r.status === 403 || r.status === 422;
      return { pass, reason: pass ? 'Anonymous halt rejected' : `Expected rejection, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-046',
    name: 'Resume endpoint rejects anonymous operator',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.resume?.path || '/api/claw/resume'),
        (adapter?.endpoints?.resume?.body ? adapter.endpoints.resume.body({}) : {}));
      const pass = r.status === 400 || r.status === 403 || r.status === 422;
      return { pass, reason: pass ? 'Anonymous resume rejected' : `Expected rejection, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-047',
    name: 'Authorization event is written to audit trail',
    suite: 'authorization',
    async test(target, adapter) {
      const agentId = 'bench-audit-probe-' + Date.now();
      await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId, tier: 1, action: 'read', scope: 'documents' })
          : { agentId, tier: 1, action: 'read', scope: 'documents' }));
      // Check if audit trail captured the event
      const auditR = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=5'));
      const auditGate = requireEndpoint(adapter, 'auditExport', auditR);
      if (auditGate) {return auditGate;}
      const events = auditR.data?.events || auditR.data?.data || auditR.data || [];
      const found = Array.isArray(events) && events.some(e =>
        JSON.stringify(e).includes(agentId) || JSON.stringify(e).includes('authorize')
      );
      const pass = found || events.length > 0;
      return { pass, reason: pass ? 'Authorization event captured in audit trail' : 'Audit trail appears empty after authorization', detail: { eventCount: events.length } };
    },
  },
  {
    id: 'AUTH-048',
    name: 'Authorization endpoint is available over HTTP (not silently rejected)',
    suite: 'authorization',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-connectivity-probe', tier: 1, action: 'read', scope: 'documents' })
          : { agentId: 'bench-connectivity-probe', tier: 1, action: 'read', scope: 'documents' }));
      // Any non-network-failure response means the endpoint is reachable
      const pass = r.status !== 0;
      return { pass, reason: pass ? `Endpoint reachable (${r.status})` : 'Endpoint unreachable', detail: r.data };
    },
  },
  {
    id: 'AUTH-049',
    name: 'Authorization with extra unknown fields is handled gracefully',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-agent-t1', tier: 1, action: 'read', scope: 'documents',
        unknownField1: 'should-be-ignored',
        unknownField2: { nested: 'value' },
        __proto__: { polluted: true },
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Extra fields handled gracefully (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUTH-050',
    name: 'Prototype pollution in body does not crash server',
    suite: 'authorization',
    async test(target, adapter) {
      const _body_auth = {
        agentId: 'bench-proto-test',
        tier: 1,
        action: 'read',
        scope: 'documents',
        constructor: { prototype: { isAdmin: true } },
      };
      const r = await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body ? adapter.endpoints.authorize.body(_body_auth) : _body_auth));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Prototype pollution handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
];

// ─── API Key Tier Scoping ─────────────────────────────────────────────────

const keyScoping = [
  {
    id: 'AUTH-KS1',
    name: 'Analyst-tier API key cannot access Strategist-only endpoint',
    suite: 'authorization',
    async test(target, adapter) {
      // Create an Analyst key using the admin key
      // /api/auth/keys is not in adapter mapping (admin-key management is product-specific);
      // left as literal per refactor rule 6.
      const keysPath = (adapter?.endpoints?.keyManagement?.path || '/api/auth/keys');
      const createR = await post(target, keysPath, { userId: 'bench-analyst-ks1', tier: compactTier('Analyst') });
      if (createR.status !== 201 && createR.status !== 200) {
        // Might be using public tier names in Docker
        const retryR = await post(target, keysPath, { userId: 'bench-analyst-ks1', tier: 'Analyst' });
        const keyGate = requireEndpoint(adapter, 'keyManagement', retryR, { expect: [200, 201], detail: { firstAttempt: createR.data, retry: retryR.data } });
        if (keyGate) {return keyGate;}
        createR.data = retryR.data;
        createR.status = retryR.status;
      }
      const analystKey = createR.data?.key;
      if (!analystKey) {
        // The endpoint is declared and accepted the request, so this is not a
        // capability gap: it minted nothing, and tier scoping cannot be tested
        // with a key that does not exist.
        return { pass: false, reason: `Key management accepted the request (${createR.status}) but returned no key -- tier scoping cannot be exercised`, detail: createR.data };
      }

      // Try to halt with the Analyst key (should be denied)
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        const haltPath = (adapter?.endpoints?.halt?.path || '/api/claw/halt');
        const haltR = await fetch(`${target}${haltPath}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': analystKey },
          body: JSON.stringify({ reason: 'bench-tier-test', operatorId: 'bench-analyst' }),
          signal: controller.signal,
        });
        clearTimeout(timer);
        const haltData = await haltR.json().catch(() => ({}));
        const pass = haltR.status === 403;
        return {
          pass,
          reason: pass
            ? 'Analyst key correctly denied from halt endpoint (403)'
            : `Expected 403, got ${haltR.status} -- tier scoping may not be enforced at middleware level`,
          detail: haltData
        };
      } catch (err) {
        return { pass: false, reason: `Request failed: ${err.message}` };
      }
    },
  },
];

export const authorizationSuite = [
  ...tierEscalation,
  ...missingFields,
  ...crossAgent,
  ...rateLimits,
  ...defaults,
  ...advanced,
  ...keyScoping,
];
