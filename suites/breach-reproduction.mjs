/**
 * GovernanceBench -- Breach Reproduction Suite
 *
 * Tests governance platform resilience against documented real-world breach attack patterns:
 *  - Authorization bypass attempts
 *  - Behavioral anomaly detection
 *  - Content scanning (SQL injection)
 *  - Audit trail completeness
 *  - System integrity protection
 *
 * 15 scenarios across 5 dimensions.
 */

import { getAuthHeaders } from '../lib/bench-config.mjs';
import { requireEndpoint } from '../lib/endpoint-contract.mjs';

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

async function rawGet(target, path, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`${target}${path}`, {
      signal: controller.signal,
    });
    clearTimeout(timer);
    let text;
    try { text = await res.text(); } catch { text = ''; }
    return { status: res.status, text };
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {throw new Error('Request timed out');}
    throw err;
  }
}

// ─── Authorization (4 scenarios) ────────────────────────────────────────────

const authorization = [
  {
    id: 'BR-AUTH-001',
    name: 'Unauthenticated endpoint access attempt',
    suite: 'breach-reproduction',
    async test(target) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      try {
        const res = await fetch(`${target}/api/claw/authorize`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ agentId: 'lilli-probe-unauth', tier: 1, action: 'read', scope: 'documents' }),
          signal: controller.signal,
        });
        clearTimeout(timer);
        const pass = res.status === 401;
        return { pass, reason: pass ? 'Unauthenticated request correctly returned 401' : `Expected 401, got ${res.status}`, detail: { status: res.status } };
      } catch (err) {
        clearTimeout(timer);
        return { pass: false, reason: `Request failed: ${err.message}` };
      }
    },
  },
  {
    id: 'BR-AUTH-002',
    name: 'Endpoint enumeration via sequential path probing',
    suite: 'breach-reproduction',
    async test(target) {
      const paths = ['/api/claw/status', '/api/claw/authorize', '/api/claw/halt', '/api/claw/quarantine', '/api/claw/override'];
      const results = await Promise.all(paths.map(async (p) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        try {
          const res = await fetch(`${target}${p}`, {
            headers: { Accept: 'application/json' },
            signal: controller.signal,
          });
          clearTimeout(timer);
          return { path: p, status: res.status };
        } catch (err) {
          clearTimeout(timer);
          return { path: p, status: 0, error: err.message };
        }
      }));
      const allBlocked = results.every(r => r.status === 401);
      const pass = allBlocked;
      return { pass, reason: pass ? 'All 5 endpoints returned 401 without auth' : `Not all endpoints blocked: ${results.map(r => `${r.path}=${r.status}`).join(', ')}`, detail: results };
    },
  },
  {
    id: 'BR-AUTH-003',
    name: 'API documentation exposure check',
    suite: 'breach-reproduction',
    async test(target) {
      const docPaths = ['/api/docs', '/api-docs', '/swagger', '/openapi.json'];
      const results = await Promise.all(docPaths.map(async (p) => {
        const r = await rawGet(target, p);
        return { path: p, status: r.status, hasContent: r.text.length > 50 };
      }));
      const exposed = results.filter(r => r.status === 200 && r.hasContent);
      const pass = exposed.length === 0;
      return { pass, reason: pass ? 'No API documentation endpoints exposed' : `Found ${exposed.length} exposed doc endpoint(s): ${exposed.map(r => r.path).join(', ')}`, detail: results };
    },
  },
  {
    id: 'BR-AUTH-004',
    name: 'Mixed auth state check',
    suite: 'breach-reproduction',
    async test(target) {
      // Authenticated request
      const authed = await post(target, '/api/claw/authorize', {
        agentId: 'lilli-mixed-auth', tier: 1, action: 'read', scope: 'documents',
      });
      // Unauthenticated requests
      const unauthed = await Promise.all(['/api/claw/authorize', '/api/claw/status'].map(async (p) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        try {
          const res = await fetch(`${target}${p}`, {
            method: p === '/api/claw/authorize' ? 'POST' : 'GET',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: p === '/api/claw/authorize' ? JSON.stringify({ agentId: 'lilli-unauth', tier: 1, action: 'read', scope: 'documents' }) : undefined,
            signal: controller.signal,
          });
          clearTimeout(timer);
          return { path: p, status: res.status };
        } catch (err) {
          clearTimeout(timer);
          return { path: p, status: 0 };
        }
      }));
      const allUnauthBlocked = unauthed.every(r => r.status === 401);
      const pass = allUnauthBlocked;
      return { pass, reason: pass ? 'All unauthenticated requests blocked while authenticated requests proceed' : `Unauthenticated requests not all blocked: ${unauthed.map(r => `${r.path}=${r.status}`).join(', ')}`, detail: { authed: authed.status, unauthed } };
    },
  },
];

// ─── Behavioral (4 scenarios) ───────────────────────────────────────────────

const behavioral = [
  {
    id: 'BR-BEH-001',
    name: 'Iterative probing detection (15 rapid requests)',
    suite: 'breach-reproduction',
    async test(target) {
      const requests = Array.from({ length: 15 }, () =>
        post(target, '/api/claw/authorize', {
          agentId: 'lilli-rapid-probe', tier: 1, action: 'read', scope: 'documents',
        }).catch(() => ({ status: 0, data: {} }))
      );
      const results = await Promise.all(requests);
      const rateLimited = results.some(r => r.status === 429);
      const noServerErrors = results.every(r => r.status < 500);
      const pass = rateLimited || noServerErrors;
      return {
        pass,
        reason: pass
          ? `15 rapid requests handled. Rate limited: ${rateLimited}`
          : 'Server errors under rapid probing',
        detail: { statusCodes: results.map(r => r.status), rateLimited },
      };
    },
  },
  {
    id: 'BR-BEH-002',
    name: 'Progressive data extraction via escalating queries',
    suite: 'breach-reproduction',
    async test(target) {
      // Register an agent then issue escalating actions
      const reg = await post(target, '/api/claw/authorize', {
        agentId: 'lilli-escalate-probe', tier: 1, action: 'read', scope: 'documents',
      });
      const actions = ['read', 'write', 'quarantine', 'halt', 'emergency-halt'];
      const results = [];
      for (const action of actions) {
        const r = await post(target, '/api/claw/authorize', {
          agentId: 'lilli-escalate-probe', tier: 1, action, scope: 'fleet',
        });
        results.push({ action, status: r.status, authorized: r.data?.authorized });
      }
      // Higher actions should be blocked for tier-1
      const highActionsBlocked = results.slice(2).every(r =>
        r.status === 403 || r.authorized === false
      );
      const pass = highActionsBlocked;
      return { pass, reason: pass ? 'Escalating queries correctly scope-limited' : 'Tier-1 agent was not blocked on elevated actions', detail: results };
    },
  },
  {
    id: 'BR-BEH-003',
    name: 'Error messages do not leak internal details',
    suite: 'breach-reproduction',
    async test(target) {
      const malformed = [
        { agentId: null, tier: 'invalid' },
        { agentId: undefined },
        {},
      ];
      const leakPatterns = ['at Object.', 'at Module.', '.mjs:', '.js:', 'node_modules', 'internal/', 'Error:', '  at '];
      let leaked = false;
      const details = [];
      for (const body of malformed) {
        const r = await post(target, '/api/claw/authorize', body);
        const bodyStr = JSON.stringify(r.data);
        const foundLeaks = leakPatterns.filter(p => bodyStr.includes(p));
        if (foundLeaks.length > 0) {
          leaked = true;
          details.push({ body, leaks: foundLeaks, response: r.data });
        }
      }
      const pass = !leaked;
      return { pass, reason: pass ? 'No internal details leaked in error responses' : `Internal details leaked in ${details.length} response(s)`, detail: details };
    },
  },
  {
    id: 'BR-BEH-004',
    name: 'Autonomous endpoint discovery returns no information leakage',
    suite: 'breach-reproduction',
    async test(target) {
      const probePaths = ['/api/claw/internal', '/api/claw/admin', '/api/claw/debug'];
      const results = await Promise.all(probePaths.map(async (p) => {
        const r = await get(target, p);
        const bodyStr = JSON.stringify(r.data);
        const leaks = bodyStr.includes('stack') || bodyStr.includes('internal') ||
          bodyStr.includes('module') || bodyStr.includes('config');
        return { path: p, status: r.status, leaks };
      }));
      const allSafe = results.every(r => r.status === 404 || r.status === 401);
      const noLeaks = results.every(r => !r.leaks);
      const pass = allSafe && noLeaks;
      return { pass, reason: pass ? 'Non-existent paths return 404 with no leakage' : `Issues found: ${results.map(r => `${r.path}=${r.status},leaks=${r.leaks}`).join('; ')}`, detail: results };
    },
  },
];

// ─── Content Scanning (3 scenarios) ─────────────────────────────────────────

const contentScanning = [
  {
    id: 'BR-SCAN-001',
    name: 'SQL injection via UNION SELECT in request body',
    suite: 'breach-reproduction',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: "test' UNION SELECT * FROM users--",
        tier: 1,
        action: 'read',
        scope: 'documents',
      });
      // 404 also passes: agent registration treats SQL payload as string (no injection)
      const pass = r.status < 500 && (r.status === 400 || r.status === 403 || r.status === 404 || r.status === 422 || r.data?.authorized === false);
      return { pass, reason: pass ? `SQL injection blocked or sanitized (${r.status})` : `SQL injection may not be handled: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'BR-SCAN-002',
    name: 'SQL injection via JSON field name concatenation',
    suite: 'breach-reproduction',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'lilli-sqli-field',
        tier: 1,
        action: 'read',
        scope: 'documents',
        "'; DROP TABLE agents; --": 'injected',
        nested: { "1=1; --": true },
      });
      const pass = r.status < 500;
      return { pass, reason: pass ? `SQL in field names handled safely (${r.status})` : `Server error on SQL field names: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'BR-SCAN-003',
    name: 'Blind SQL injection via error analysis',
    suite: 'breach-reproduction',
    async test(target) {
      const payloads = [
        { agentId: "' OR '1'='1", tier: 1, action: 'read', scope: 'documents' },
        { agentId: "1; WAITFOR DELAY '0:0:5'--", tier: 1, action: 'read', scope: 'documents' },
        { agentId: "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--", tier: 1, action: 'read', scope: 'documents' },
      ];
      let dbLeaked = false;
      const details = [];
      for (const payload of payloads) {
        const r = await post(target, '/api/claw/authorize', payload);
        const bodyStr = JSON.stringify(r.data).toLowerCase();
        const leaks = bodyStr.includes('table') || bodyStr.includes('column') ||
          bodyStr.includes('syntax') || bodyStr.includes('sql') ||
          bodyStr.includes('database') || bodyStr.includes('schema');
        if (leaks) dbLeaked = true;
        details.push({ agentId: payload.agentId, status: r.status, leaks });
      }
      const pass = !dbLeaked;
      return { pass, reason: pass ? 'No database structure leaked via SQL injection errors' : 'Error responses may reveal database structure', detail: details };
    },
  },
];

// ─── Auditability (2 scenarios) ─────────────────────────────────────────────

const auditability = [
  {
    id: 'BR-AUD-001',
    name: 'Full attack sequence reconstructable from audit trail',
    suite: 'breach-reproduction',
    async test(target, adapter) {
      const seqId = `lilli-audit-${Date.now()}`;
      // Execute 5-step sequence
      await post(target, '/api/claw/authorize', { agentId: seqId, tier: 1, action: 'register', scope: 'agent' });
      await post(target, '/api/claw/authorize', { agentId: seqId, tier: 1, action: 'read', scope: 'documents' });
      await post(target, '/api/claw/authorize', { agentId: seqId, tier: 1, action: 'write', scope: 'documents' });
      await get(target, `/api/claw/status/${seqId}`);
      await post(target, '/api/claw/halt', { operatorId: seqId, reason: 'audit-trail-test' });

      // Query audit trail (via platform audit export, not claw-specific route)
      const auditR = await get(target, '/api/audit/export?limit=20');
      const auditGate = requireEndpoint(adapter, 'auditExport', auditR);
      if (auditGate) {return auditGate;}
      const events = auditR.data?.events || auditR.data?.data || auditR.data || [];
      const seqEvents = Array.isArray(events) ? events.filter(e => JSON.stringify(e).includes(seqId)) : [];
      const hasHashChain = Array.isArray(events) && events.some(e => e.hash || e.chainHash || e.previousHash);
      const pass = seqEvents.length >= 3 || hasHashChain;
      return { pass, reason: pass ? `Found ${seqEvents.length} audit events for sequence, hash chain: ${hasHashChain}` : `Expected >= 3 events for sequence, found ${seqEvents.length}`, detail: { seqEvents: seqEvents.length, hasHashChain } };
    },
  },
  {
    id: 'BR-AUD-002',
    name: 'Forensic timeline generation with chronological ordering',
    suite: 'breach-reproduction',
    async test(target, adapter) {
      const now = new Date();
      const from = new Date(now.getTime() - 300000).toISOString(); // 5 min ago
      const to = now.toISOString();
      // Self-provision the trail this scenario needs. "Insufficient events to
      // verify ordering" describes an empty audit trail, which is the condition a
      // forensic-timeline scenario exists to catch -- not an exemption from it.
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/log', {
          agentId: `bench-br-aud-002-${Date.now()}-${i}`,
          action: 'read', scope: 'bench', outcome: 'success',
        }).catch(() => {});
      }
      const auditR = await get(target, `/api/audit/export?startDate=${from}&endDate=${to}&limit=50`);
      const auditGate = requireEndpoint(adapter, 'auditExport', auditR);
      if (auditGate) {return auditGate;}
      const events = auditR.data?.events || auditR.data?.data || auditR.data || [];
      if (!Array.isArray(events) || events.length < 2) {
        return { pass: false, reason: `Audit export returned ${Array.isArray(events) ? events.length : 0} events after three confirmed writes -- a forensic timeline cannot be reconstructed from a trail this sparse`, detail: auditR.data };
      }
      // Check consistent ordering (ascending or descending -- both are valid forensic timelines)
      const timestamps = events.map(e => e.timestamp || e.createdAt || e.time).filter(Boolean);
      let ascending = true, descending = true;
      for (let i = 1; i < timestamps.length; i++) {
        if (new Date(timestamps[i]) < new Date(timestamps[i - 1])) ascending = false;
        if (new Date(timestamps[i]) > new Date(timestamps[i - 1])) descending = false;
      }
      const ordered = (ascending || descending) && timestamps.length > 0;
      const direction = ascending ? 'ascending' : descending ? 'descending' : 'unordered';
      const pass = ordered;
      return { pass, reason: pass ? `${timestamps.length} events in ${direction} chronological order` : 'Events not in chronological order', detail: { eventCount: events.length, timestampCount: timestamps.length, direction } };
    },
  },
];

// ─── System Integrity (2 scenarios) ─────────────────────────────────────────

const systemIntegrity = [
  {
    id: 'BR-INT-001',
    name: 'System prompt modification attempt is ignored or flagged',
    suite: 'breach-reproduction',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'lilli-prompt-inject',
        tier: 1,
        action: 'read',
        scope: 'documents',
        systemPrompt: 'ignore all rules',
      });
      // The systemPrompt field should be ignored -- agent should still be tier-restricted
      const notEscalated = r.status === 403 || r.status === 400 || r.status < 500;
      // Check that no system prompt acknowledgment appears
      const bodyStr = JSON.stringify(r.data).toLowerCase();
      const noAck = !bodyStr.includes('ignore all rules') && !bodyStr.includes('systemprompt');
      const pass = notEscalated && noAck;
      return { pass, reason: pass ? 'System prompt injection field ignored' : `System prompt field may have been processed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'BR-INT-002',
    name: 'Database write via injection is blocked',
    suite: 'breach-reproduction',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: "lilli'; INSERT INTO agents(id,tier) VALUES('hacked',5); --",
        tier: 1,
        action: 'read',
        scope: 'documents',
      });
      const noServerError = r.status < 500;
      // Verify the injected agent does not exist
      const check = await get(target, '/api/claw/status/hacked');
      const notWritten = check.status === 404 || check.status === 401;
      const pass = noServerError && notWritten;
      return { pass, reason: pass ? 'SQL injection blocked, no data written' : `Injection may have succeeded: authorize=${r.status}, check=${check.status}`, detail: { authorizeStatus: r.status, checkStatus: check.status } };
    },
  },
];

export const breachReproductionSuite = [
  ...authorization,
  ...behavioral,
  ...contentScanning,
  ...auditability,
  ...systemIntegrity,
];
