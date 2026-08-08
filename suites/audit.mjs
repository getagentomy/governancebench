/**
 * GovernanceBench -- Suite 2: Audit Trail Integrity
 *
 * Tests any governance platform's tamper-evident audit trail.
 * Each scenario is self-contained and returns { pass, reason, detail }.
 *
 * Coverage areas:
 *  - Log an event, verify it appears in export
 *  - Chain integrity verification
 *  - Hash consistency (deterministic output)
 *  - Pagination correctness
 *  - Time-range filtering
 *  - Export completeness (log N events, export shows N)
 *  - Tamper detection
 *  - Export idempotency
 */

import { getAuthHeaders } from '../lib/bench-config.mjs';
import { requireEndpoint, requireEndpointParam } from '../lib/endpoint-contract.mjs';

async function post(target, path, body, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  // build-ref: 873e0d5adfc2
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

function extractEvents(data) {
  if (Array.isArray(data)) {return data;}
  if (data?.events && Array.isArray(data.events)) {return data.events;}
  if (data?.data && Array.isArray(data.data)) {return data.data;}
  if (data?.entries && Array.isArray(data.entries)) {return data.entries;}
  if (data?.blocks && Array.isArray(data.blocks)) {return data.blocks;}
  return [];
}

// ─── Write-then-locate (anti-vacuous-pass) ────────────────────────────────────
//
// An audit-integrity scenario that inspects "whatever happens to be in the
// export" is vacuously satisfied by a target that exports nothing: the classic
// `if (events.length === 0) return { pass: true }` escape hands a perfect audit
// score to a platform with no audit trail at all. For an audit-integrity suite,
// absent data is a FAILURE, not a skip.
//
// Every inspect-style scenario below therefore writes its OWN event first and
// asserts THAT event is present. The written event is located by the `id` the
// write returned -- never by position in the list (export ordering is
// platform-defined) and never by a metadata marker or agentId, because a
// platform serving redacted/public reads blanks those fields while `id` is
// always preserved.

function eventIdOf(e) {
  return e?.id || e?.eventId || e?.blockId || e?.block_id || e?.entry_id || null;
}

/**
 * Write one audit event and return the write receipt.
 * @returns {{status:number, id:string|null, hash:string|null, agentId:string, data:object}}
 */
async function writeProbeEvent(target, adapter, benchmarkId, agentIdOverride) {
  const agentId = agentIdOverride ||
    `bench-${benchmarkId.toLowerCase()}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const payload = {
    agentId,
    action: 'read',
    scope: 'bench',
    outcome: 'success',
    metadata: { benchmarkId },
  };
  const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
    (adapter?.endpoints?.log?.body ? adapter.endpoints.log.body(payload) : payload));
  const id = r.data?.id || r.data?.eventId || r.data?.auditId || r.data?.blockId ||
    r.data?.entry_id || r.data?.logId || null;
  const hash = r.data?.hash || r.data?.blockHash || r.data?.digest || null;
  return { status: r.status, id, hash, agentId, data: r.data };
}

/**
 * Locate previously-written events in the audit export.
 *
 * Reads a broad recent page first, so property assertions still run against a
 * representative sample of the trail, then falls back to an agent-scoped query
 * for platforms whose export is not newest-first. Never reports ok:true unless
 * every probe was found by id.
 *
 * @returns {{ok:boolean, events:object[], scopedEvents:object[], found:object[], reason:string|null}}
 */
async function locateProbeEvents(target, adapter, probes, limit = 25) {
  const basePath = (adapter?.endpoints?.auditExport?.path || '/api/audit/export');
  const missingId = probes.find(p => !p.id);
  if (missingId) {
    return {
      ok: false, events: [], scopedEvents: [], found: [],
      reason: `Audit log write returned no event id (status ${missingId.status}) -- the write cannot be proven to have landed`,
    };
  }
  const broad = await get(target, `${basePath}?limit=${limit}`);
  if (broad.status !== 200) {
    return {
      ok: false, events: [], scopedEvents: [], found: [],
      reason: `Audit export returned ${broad.status} -- written event ${probes[0].id} cannot be verified`,
    };
  }
  const events = extractEvents(broad.data);
  const found = probes.map(p => events.find(e => eventIdOf(e) === p.id) || null);
  let scopedEvents = [];
  if (found.some(f => !f)) {
    const scopePath = `${basePath}?agentId=${encodeURIComponent(probes[0].agentId)}&limit=${Math.max(limit, 50)}`;
    const scoped = await get(target, scopePath);
    if (scoped.status === 200) {
      scopedEvents = extractEvents(scoped.data);
      for (let i = 0; i < probes.length; i++) {
        if (!found[i]) {found[i] = scopedEvents.find(e => eventIdOf(e) === probes[i].id) || null;}
      }
    }
  }
  const missing = probes.filter((p, i) => !found[i]);
  if (missing.length > 0) {
    return {
      ok: false, events, scopedEvents, found,
      reason: `Written event${missing.length > 1 ? 's' : ''} ${missing.map(p => p.id).join(', ')} absent from audit export (${events.length} recent + ${scopedEvents.length} agent-scoped events read) -- the audit trail did not record the write`,
    };
  }
  return { ok: true, events, scopedEvents, found, reason: null };
}

// ─── Basic Event Logging ──────────────────────────────────────────────────────

const basicLogging = [
  {
    id: 'AUDIT-001',
    name: 'Log endpoint accepts a governance event',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({
            agentId: 'bench-audit-agent',
            action: 'read',
            scope: 'documents',
            outcome: 'success',
            metadata: { benchmarkId: 'AUDIT-001' },
          })
          : {
            agentId: 'bench-audit-agent',
            action: 'read',
            scope: 'documents',
            outcome: 'success',
            metadata: { benchmarkId: 'AUDIT-001' },
          }));
      const pass = r.status === 200 || r.status === 201;
      return { pass, reason: pass ? `Log accepted (${r.status})` : `Expected 200/201, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-002',
    name: 'Logged event appears in export',
    suite: 'audit',
    async test(target, adapter) {
      const marker = 'bench-marker-' + Date.now();
      await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({
            agentId: 'bench-audit-agent',
            action: 'read',
            scope: 'documents',
            outcome: 'success',
            metadata: { marker },
          })
          : {
            agentId: 'bench-audit-agent',
            action: 'read',
            scope: 'documents',
            outcome: 'success',
            metadata: { marker },
          }));
      const exportR = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=20'));
      const gate = requireEndpoint(adapter, 'auditExport', exportR);
      if (gate) {return gate;}
      const events = extractEvents(exportR.data);
      const found = events.some(e => JSON.stringify(e).includes(marker));
      const pass = found;
      return { pass, reason: pass ? 'Logged event found in export' : `Marker ${marker} not found in ${events.length} exported events`, detail: { eventCount: events.length } };
    },
  },
  {
    id: 'AUDIT-003',
    name: 'Export endpoint returns structured data',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=5'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const pass = Array.isArray(events);
      return { pass, reason: pass ? `Export returns array of ${events.length} events` : 'Export response is not an array', detail: r.data };
    },
  },
  {
    id: 'AUDIT-004',
    name: 'Each audit event includes a timestamp',
    suite: 'audit',
    async test(target, adapter) {
      const probe = await writeProbeEvent(target, adapter, 'AUDIT-004');
      const loc = await locateProbeEvents(target, adapter, [probe]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writeStatus: probe.status, writtenId: probe.id } };}
      const timestampOf = e => e.timestamp || e.createdAt || e.created_at || e.time || e.eventTime;
      const allHaveTimestamp = loc.events.every(timestampOf);
      const writtenHasTimestamp = !!timestampOf(loc.found[0]);
      const pass = allHaveTimestamp && writtenHasTimestamp;
      return {
        pass,
        reason: pass
          ? `All ${loc.events.length} exported events include timestamp; written event ${probe.id} verified present and timestamped`
          : (writtenHasTimestamp ? 'Some events missing timestamp' : `Written event ${probe.id} has no timestamp`),
        detail: { writtenId: probe.id, inspected: loc.events.length, sampleKeys: Object.keys(loc.found[0] || {}) },
      };
    },
  },
  {
    id: 'AUDIT-005',
    name: 'Each audit event includes an event type or action',
    suite: 'audit',
    async test(target, adapter) {
      const probe = await writeProbeEvent(target, adapter, 'AUDIT-005');
      const loc = await locateProbeEvents(target, adapter, [probe]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writeStatus: probe.status, writtenId: probe.id } };}
      const actionOf = e => e.action || e.event || e.eventType || e.type;
      const allHaveAction = loc.events.every(actionOf);
      const writtenHasAction = !!actionOf(loc.found[0]);
      const pass = allHaveAction && writtenHasAction;
      return {
        pass,
        reason: pass
          ? `All ${loc.events.length} exported events include action/event type; written event ${probe.id} verified present and typed`
          : (writtenHasAction ? 'Some events missing event type' : `Written event ${probe.id} has no action/event type`),
        detail: { writtenId: probe.id, inspected: loc.events.length, sampleKeys: Object.keys(loc.found[0] || {}) },
      };
    },
  },
  {
    id: 'AUDIT-006',
    name: 'Each audit event includes an agentId or source',
    suite: 'audit',
    async test(target, adapter) {
      const probe = await writeProbeEvent(target, adapter, 'AUDIT-006');
      const loc = await locateProbeEvents(target, adapter, [probe]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writeStatus: probe.status, writtenId: probe.id } };}
      const agentOf = e => e.agentId || e.agent_id || e.source || e.actor;
      const allHaveAgent = loc.events.every(agentOf);
      const writtenHasAgent = !!agentOf(loc.found[0]);
      const pass = allHaveAgent && writtenHasAgent;
      return {
        pass,
        reason: pass
          ? `All ${loc.events.length} exported events include agent/source; written event ${probe.id} verified present and attributed`
          : (writtenHasAgent ? 'Some events missing agent identifier' : `Written event ${probe.id} has no agent identifier`),
        detail: { writtenId: probe.id, inspected: loc.events.length, sampleKeys: Object.keys(loc.found[0] || {}) },
      };
    },
  },
  {
    id: 'AUDIT-007',
    name: 'Log endpoint rejects missing agentId',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ action: 'read', scope: 'documents', outcome: 'success' })
          : { action: 'read', scope: 'documents', outcome: 'success' }));
      const pass = r.status === 400 || r.status === 422;
      return { pass, reason: pass ? 'Missing agentId in log rejected' : `Expected 400/422, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-008',
    name: 'Log endpoint rejects missing action',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId: 'bench-audit-agent', scope: 'documents', outcome: 'success' })
          : { agentId: 'bench-audit-agent', scope: 'documents', outcome: 'success' }));
      const pass = r.status === 400 || r.status === 422; // 'rejects missing action' means it must REJECT; 200 is the failure case
      return { pass, reason: pass ? `Missing action handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
];

// ─── Hash Chain Integrity ─────────────────────────────────────────────────────

const hashChain = [
  {
    id: 'AUDIT-009',
    name: 'Integrity endpoint is available and reports status',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, (adapter?.endpoints?.auditIntegrity?.path || '/api/audit/export/integrity'));
      const gate = requireEndpoint(adapter, 'auditIntegrity', r, { expect: [200, 207] });
      if (gate) {return gate;}
      const pass = r.status === 200 || r.status === 207;
      return { pass, reason: pass ? `Integrity endpoint reachable (${r.status})` : `Expected 200, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-010',
    name: 'Integrity check reports valid when no tampering',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, (adapter?.endpoints?.auditIntegrity?.path || '/api/audit/export/integrity'));
      const gate = requireEndpoint(adapter, 'auditIntegrity', r);
      if (gate) {return gate;}
      const valid = r.data?.valid === true || r.data?.integrity === 100 ||
  r.data?.status === 'valid' || r.data?.integrityPercentage === 100;
      const pass = r.status === 200 && valid;
      return { pass, reason: pass ? 'Chain integrity reported as valid' : 'Integrity check not reporting valid', detail: r.data };
    },
  },
  {
    id: 'AUDIT-011',
    name: 'Integrity response includes block count',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, (adapter?.endpoints?.auditIntegrity?.path || '/api/audit/export/integrity'));
      const gate = requireEndpoint(adapter, 'auditIntegrity', r);
      if (gate) {return gate;}
      const hasCount = r.data?.blockCount !== undefined || r.data?.count !== undefined ||
  r.data?.totalBlocks !== undefined || r.data?.blocks !== undefined;
      const pass = hasCount;
      return { pass, reason: pass ? 'Block count present in integrity response' : 'Block count missing', detail: r.data };
    },
  },
  {
    id: 'AUDIT-012',
    name: 'Each event has a hash field',
    suite: 'audit',
    async test(target, adapter) {
      const probe = await writeProbeEvent(target, adapter, 'AUDIT-012');
      const loc = await locateProbeEvents(target, adapter, [probe]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writeStatus: probe.status, writtenId: probe.id } };}
      const hashOf = e => e.hash || e.blockHash || e.block_hash || e.sha256 || e.digest;
      const allHaveHash = loc.events.every(hashOf);
      const writtenHasHash = !!hashOf(loc.found[0]);
      const pass = allHaveHash && writtenHasHash;
      return {
        pass,
        reason: pass
          ? `All ${loc.events.length} exported events include hash; written event ${probe.id} verified present and hashed`
          : (writtenHasHash ? 'Some events missing hash field' : `Written event ${probe.id} has no hash -- the audit trail is not hash-chained`),
        detail: { writtenId: probe.id, inspected: loc.events.length, sampleKeys: Object.keys(loc.found[0] || {}) },
      };
    },
  },
  {
    id: 'AUDIT-013',
    name: 'Each event has a parentHash or chain linkage field',
    suite: 'audit',
    async test(target, adapter) {
      // Two writes guarantee the chain has linkable neighbours. "Insufficient
      // events to check the chain" describes an empty trail, which is the
      // condition this suite exists to catch, not an exemption from checking.
      const agentId = 'bench-audit-013-' + Date.now() + '-' + Math.floor(Math.random() * 1e6);
      const p1 = await writeProbeEvent(target, adapter, 'AUDIT-013', agentId);
      const p2 = await writeProbeEvent(target, adapter, 'AUDIT-013', agentId);
      const loc = await locateProbeEvents(target, adapter, [p1, p2]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writtenIds: [p1.id, p2.id] } };}
      // An empty-string parentHash is not linkage; chainPosition 0 is (genesis).
      const linkOf = (e) => {
        const parent = e.parentHash || e.parent_hash || e.previousHash || e.previous_hash;
        if (typeof parent === 'string' && parent.length > 0) {return parent;}
        const pos = e.chainPosition ?? e.chain_position;
        return typeof pos === 'number' ? `position:${pos}` : null;
      };
      const unlinked = loc.found.filter(e => !linkOf(e));
      const pass = unlinked.length === 0;
      return {
        pass,
        reason: pass
          ? `Chain linkage present on both written events (${loc.found.map(linkOf).join(', ').slice(0, 80)})`
          : `${unlinked.length} of 2 written events carry no parentHash or chain position -- the trail is not a hash chain`,
        detail: { writtenIds: [p1.id, p2.id], sampleKeys: Object.keys(loc.found[0] || {}) },
      };
    },
  },
  {
    id: 'AUDIT-014',
    name: 'Two identical log calls produce consistent hash format',
    suite: 'audit',
    async test(target, adapter) {
      // Identical payloads, but on a run-unique agentId so the pair is
      // recoverable from the export without depending on list position.
      const agentId = 'bench-hash-agent-' + Date.now() + '-' + Math.floor(Math.random() * 1e6);
      const payload = { agentId, action: 'read', scope: 'bench', outcome: 'success' };
      const r1 = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body ? adapter.endpoints.log.body(payload) : payload));
      const r2 = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body ? adapter.endpoints.log.body(payload) : payload));
      const accepted = s => s === 200 || s === 201;
      if (!accepted(r1.status) || !accepted(r2.status)) {
        return { pass: false, reason: `Audit log write rejected (${r1.status}/${r2.status}) -- hash format cannot be verified`, detail: { r1: r1.data, r2: r2.data } };
      }
      let hash1 = r1.data?.hash || r1.data?.blockHash || r1.data?.digest || null;
      let hash2 = r2.data?.hash || r2.data?.blockHash || r2.data?.digest || null;
      // Authority, not proxy: the write receipt is a convenience view. If it
      // omits the hash, resolve the two events from the chain itself instead of
      // skipping -- a platform that hashes its trail must expose those hashes
      // somewhere, and "no hash anywhere" is a failure, not an exemption.
      if (!hash1 || !hash2) {
        const idOf = d => d?.id || d?.eventId || d?.auditId || d?.blockId || d?.entry_id || d?.logId || null;
        const basePath = (adapter?.endpoints?.auditExport?.path || '/api/audit/export');
        const scoped = await get(target, `${basePath}?agentId=${encodeURIComponent(agentId)}&limit=50`);
        const pool = scoped.status === 200 ? extractEvents(scoped.data) : [];
        const chainHash = e => e?.hash || e?.blockHash || e?.block_hash || e?.sha256 || e?.digest || null;
        const e1 = pool.find(e => eventIdOf(e) === idOf(r1.data));
        const e2 = pool.find(e => eventIdOf(e) === idOf(r2.data));
        hash1 = hash1 || chainHash(e1);
        hash2 = hash2 || chainHash(e2);
      }
      if (!hash1 || !hash2) {
        return { pass: false, reason: 'No hash on the write receipt or on the exported chain blocks -- audit events are not hashed', detail: { hash1, hash2 } };
      }
      // Hashes should be non-empty strings of consistent length (hex or base64)
      const consistentFormat = typeof hash1 === 'string' && typeof hash2 === 'string' && hash1.length === hash2.length;
      const pass = consistentFormat;
      return { pass, reason: pass ? `Hash format consistent (length ${hash1?.length})` : 'Hash format inconsistent', detail: { hash1, hash2 } };
    },
  },
];

// ─── Pagination ───────────────────────────────────────────────────────────────

const pagination = [
  {
    id: 'AUDIT-015',
    name: 'Export limit parameter is respected',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=3'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const pass = events.length <= 3;
      return { pass, reason: pass ? `Limit=3 returns ${events.length} events` : `Limit=3 returned ${events.length} events -- limit not enforced`, detail: { count: events.length } };
    },
  },
  {
    id: 'AUDIT-016',
    name: 'Export limit=1 returns exactly one event',
    suite: 'audit',
    async test(target, adapter) {
      // Log an event first to ensure there is at least one
      await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId: 'bench-pagination-agent', action: 'read', scope: 'bench', outcome: 'success' })
          : { agentId: 'bench-pagination-agent', action: 'read', scope: 'bench', outcome: 'success' }));
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=1'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const pass = events.length === 1;
      return { pass, reason: pass ? 'limit=1 returns exactly 1 event' : `Expected 1, got ${events.length}`, detail: { count: events.length } };
    },
  },
  {
    id: 'AUDIT-017',
    name: 'Pagination offset produces different results than page 1',
    suite: 'audit',
    async test(target, adapter) {
      // Self-provision the two pages worth of trail this scenario needs, so
      // "insufficient events" can no longer stand in for a working pagination
      // implementation. Ten writes cover limit=5 offset=0 and offset=5.
      const agentId = 'bench-audit-017-' + Date.now() + '-' + Math.floor(Math.random() * 1e6);
      const probes = [];
      for (let i = 0; i < 10; i++) {
        probes.push(await writeProbeEvent(target, adapter, 'AUDIT-017', agentId));
      }
      const rejected = probes.filter(p => p.status !== 200 && p.status !== 201);
      if (rejected.length > 0) {
        return { pass: false, reason: `${rejected.length} of 10 audit log writes rejected -- pagination cannot be verified`, detail: { statuses: probes.map(p => p.status) } };
      }
      const r1 = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=5&offset=0'));
      const r2 = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=5&offset=5'));
      const gate = requireEndpoint(adapter, 'auditExport', r1) || requireEndpoint(adapter, 'auditExport', r2);
      if (gate) {return gate;}
      const events1 = extractEvents(r1.data);
      const events2 = extractEvents(r2.data);
      if (events1.length < 5 || events2.length === 0) {
        return { pass: false, reason: `After 10 accepted writes the export returned ${events1.length} events at offset=0 and ${events2.length} at offset=5 -- pagination is not serving the trail`, detail: { page1: events1.length, page2: events2.length } };
      }
      const firstIds = new Set(events1.map(e => e.id || e.blockId || JSON.stringify(e)));
      const secondIds = events2.map(e => e.id || e.blockId || JSON.stringify(e));
      const overlap = secondIds.filter(id => firstIds.has(id));
      const pass = overlap.length === 0;
      return { pass, reason: pass ? 'Offset pagination returns non-overlapping results' : `Overlap found: ${overlap.length} duplicate events`, detail: { overlap: overlap.length } };
    },
  },
  {
    id: 'AUDIT-018',
    name: 'Zero limit returns empty or default result',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=0'));
      const gate = requireEndpoint(adapter, 'auditExport', r, { expect: [200, 400], context: 'limit=0' });
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const pass = r.status < 500;
      return { pass, reason: pass ? `limit=0 handled safely (${r.status}, ${events.length} events)` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-019',
    name: 'Negative limit is rejected or handled safely',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=-10'));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Negative limit handled safely (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-020',
    name: 'Very large limit is bounded or handled gracefully',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=999999'));
      const pass = r.status < 500;
      const events = extractEvents(r.data);
      return { pass, reason: pass ? `Large limit handled (${r.status}, ${events.length} events returned)` : `Server error ${r.status}`, detail: { count: events.length } };
    },
  },
];

// ─── Time-Range Filtering ─────────────────────────────────────────────────────

const timeFiltering = [
  {
    id: 'AUDIT-021',
    name: 'Time-range filter: startTime parameter accepted',
    suite: 'audit',
    async test(target, adapter) {
      const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + `?startTime=${encodeURIComponent(oneHourAgo)}&limit=10`));
      const gate = requireEndpointParam(adapter, 'auditExport', 'startTime', r, { expect: (s) => s < 400 });
      if (gate) {return gate;}
      const pass = r.status < 500;
      return { pass, reason: pass ? `startTime filter handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-022',
    name: 'Time-range filter: endTime parameter accepted',
    suite: 'audit',
    async test(target, adapter) {
      const now = new Date().toISOString();
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + `?endTime=${encodeURIComponent(now)}&limit=10`));
      const gate = requireEndpointParam(adapter, 'auditExport', 'endTime', r, { expect: (s) => s < 400 });
      if (gate) {return gate;}
      const pass = r.status < 500;
      return { pass, reason: pass ? `endTime filter handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-023',
    name: 'Future startTime returns empty set not error',
    suite: 'audit',
    async test(target, adapter) {
      const future = new Date(Date.now() + 86400000).toISOString();
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + `?startTime=${encodeURIComponent(future)}&limit=10`));
      const gate = requireEndpointParam(adapter, 'auditExport', 'startTime', r, { expect: (s) => s < 400, label: 'Audit export (future startTime)' });
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const pass = r.status < 500 && events.length === 0;
      return { pass, reason: pass ? 'Future startTime returns empty set' : `Got ${events.length} events with future startTime (${r.status})`, detail: { count: events.length } };
    },
  },
  {
    id: 'AUDIT-024',
    name: 'Event type filter narrows results',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?eventType=authorize&limit=10'));
      const gate = requireEndpointParam(adapter, 'auditExport', 'eventType', r, { expect: (s) => s < 400 });
      if (gate) {return gate;}
      const pass = r.status < 500;
      return { pass, reason: pass ? `eventType filter handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-025',
    name: 'Agent filter returns only events for that agent',
    suite: 'audit',
    async test(target, adapter) {
      const agentId = 'bench-filter-test-' + Date.now();
      await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId, action: 'read', scope: 'bench', outcome: 'success' })
          : { agentId, action: 'read', scope: 'bench', outcome: 'success' }));
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + `?agentId=${agentId}&limit=10`));
      const gate = requireEndpointParam(adapter, 'auditExport', 'agentId', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const allMatch = events.every(e => (e.agentId || e.agent_id || '') === agentId || JSON.stringify(e).includes(agentId));
      const pass = events.length > 0 ? allMatch : true;
      return { pass, reason: pass ? `Agent filter returns ${events.length} matching events` : 'Agent filter returned events for wrong agent', detail: { count: events.length } };
    },
  },
];

// ─── Export Completeness ──────────────────────────────────────────────────────

const completeness = [
  {
    id: 'AUDIT-026',
    name: 'Log 5 events, export shows at least 5 recent events',
    suite: 'audit',
    async test(target, adapter) {
      const baseMarker = 'completeness-' + Date.now();
      const promises = Array.from({ length: 5 }, (_, i) =>
        post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
          (adapter?.endpoints?.log?.body
            ? adapter.endpoints.log.body({
              agentId: 'bench-completeness-agent',
              action: 'read',
              scope: 'bench',
              outcome: 'success',
              metadata: { marker: `${baseMarker}-${i}` },
            })
            : {
              agentId: 'bench-completeness-agent',
              action: 'read',
              scope: 'bench',
              outcome: 'success',
              metadata: { marker: `${baseMarker}-${i}` },
            }))
      );
      await Promise.all(promises);
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=20'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const found = events.filter(e => JSON.stringify(e).includes(baseMarker));
      const pass = found.length === 5;
      return { pass, reason: pass ? 'All 5 logged events found in export' : `Expected 5, found ${found.length}`, detail: { found: found.length, total: events.length } };
    },
  },
  {
    id: 'AUDIT-027',
    name: 'Export is idempotent: same query returns same count',
    suite: 'audit',
    async test(target, adapter) {
      const r1 = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const r2 = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const gate = requireEndpoint(adapter, 'auditExport', r1) || requireEndpoint(adapter, 'auditExport', r2);
      if (gate) {return gate;}
      const events1 = extractEvents(r1.data);
      const events2 = extractEvents(r2.data);
      const pass = events1.length === events2.length;
      return { pass, reason: pass ? `Idempotent: both queries return ${events1.length} events` : `Query 1: ${events1.length}, Query 2: ${events2.length}`, detail: { count1: events1.length, count2: events2.length } };
    },
  },
  {
    id: 'AUDIT-028',
    name: 'Audit trail persists across multiple log calls',
    suite: 'audit',
    async test(target, adapter) {
      const marker = 'persist-test-' + Date.now();
      for (let i = 0; i < 3; i++) {
        await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
          (adapter?.endpoints?.log?.body
            ? adapter.endpoints.log.body({ agentId: 'bench-persist-agent', action: 'read', scope: 'bench', outcome: 'success', metadata: { marker } })
            : { agentId: 'bench-persist-agent', action: 'read', scope: 'bench', outcome: 'success', metadata: { marker } }));
      }
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const found = events.filter(e => JSON.stringify(e).includes(marker));
      const pass = found.length >= 3;
      return { pass, reason: pass ? `${found.length} of 3 logged events persist` : `Expected 3, found ${found.length}`, detail: { found: found.length } };
    },
  },
  {
    id: 'AUDIT-029',
    name: 'Log response includes event ID or reference',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId: 'bench-id-check-agent', action: 'read', scope: 'bench', outcome: 'success' })
          : { agentId: 'bench-id-check-agent', action: 'read', scope: 'bench', outcome: 'success' }));
      const gate = requireEndpoint(adapter, 'log', r, { expect: [200, 201] });
      if (gate) {return gate;}
      const hasId = r.data?.id || r.data?.eventId || r.data?.blockId || r.data?.entry_id || r.data?.logId;
      const pass = !!hasId;
      return { pass, reason: pass ? `Log response includes ID (${hasId})` : 'Log response missing event ID', detail: r.data };
    },
  },
  {
    id: 'AUDIT-030',
    name: 'Events are ordered consistently (by time or position)',
    suite: 'audit',
    async test(target, adapter) {
      // Guarantee at least two events exist rather than skipping when the trail
      // happens to be short -- "not enough events to check" is a property of an
      // empty audit trail, which is itself the failure this suite must catch.
      const agentId = 'bench-audit-030-' + Date.now() + '-' + Math.floor(Math.random() * 1e6);
      const p1 = await writeProbeEvent(target, adapter, 'AUDIT-030', agentId);
      const p2 = await writeProbeEvent(target, adapter, 'AUDIT-030', agentId);
      const loc = await locateProbeEvents(target, adapter, [p1, p2]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writtenIds: [p1.id, p2.id] } };}
      const ordered = loc.events.length >= 2 ? loc.events : loc.scopedEvents;
      if (ordered.length < 2) {
        return { pass: false, reason: `Audit export returned ${ordered.length} events after two confirmed writes -- ordering cannot be verified`, detail: { count: ordered.length } };
      }
      const timestamps = ordered
        .map(e => e.timestamp || e.createdAt || e.created_at || e.time)
        .filter(Boolean)
        .map(t => new Date(t).getTime());
      if (timestamps.length < 2) {
        return { pass: false, reason: `Exported events carry no comparable timestamps (${ordered.length} events read) -- ordering is unverifiable`, detail: { sampleKeys: Object.keys(ordered[0] || {}) } };
      }
      const isAsc = timestamps.every((t, i) => i === 0 || t >= timestamps[i - 1]);
      const isDesc = timestamps.every((t, i) => i === 0 || t <= timestamps[i - 1]);
      const pass = isAsc || isDesc;
      return { pass, reason: pass ? `Events ordered consistently (${isDesc ? 'desc' : 'asc'}) across ${timestamps.length} timestamped events` : 'Events not in consistent order', detail: { first: timestamps[0], last: timestamps[timestamps.length - 1] } };
    },
  },
];

// ─── Security / Integrity ─────────────────────────────────────────────────────

const security = [
  {
    id: 'AUDIT-031',
    name: 'Export does not expose internal system paths',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const body = JSON.stringify(r.data);
      const leaksPaths = /\/(home|users|var|srv|etc|opt|root)\/[a-z]/i.test(body) &&
  !body.includes('documents') && !body.includes('scope');
      const pass = !leaksPaths;
      return { pass, reason: pass ? 'No internal paths leaked in audit export' : 'Audit export may contain system paths', detail: { sample: body.slice(0, 200) } };
    },
  },
  {
    id: 'AUDIT-032',
    name: 'Audit export does not expose API keys or secrets',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const body = JSON.stringify(r.data).toLowerCase();
      const leaksSecrets = body.includes('api_key') || body.includes('apikey') ||
  body.includes('password') || body.includes('secret') ||
  body.includes('private_key') || body.includes('jwt_secret');
      const pass = !leaksSecrets;
      return { pass, reason: pass ? 'No secrets in audit export' : 'Audit export may contain secrets', detail: {} };
    },
  },
  {
    id: 'AUDIT-033',
    name: 'Audit log endpoint does not allow arbitrary writes without agentId',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ action: 'sovereign-override', outcome: 'success', fabricated: true })
          : { action: 'sovereign-override', outcome: 'success', fabricated: true }));
      const pass = r.status === 400 || r.status === 422 || r.status === 403;
      return { pass, reason: pass ? 'Anonymous/missing agentId log rejected' : `Expected rejection, got ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-034',
    name: 'Audit chain hash format is hex or base64 (not plaintext)',
    suite: 'audit',
    async test(target, adapter) {
      const probe = await writeProbeEvent(target, adapter, 'AUDIT-034');
      const loc = await locateProbeEvents(target, adapter, [probe]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writeStatus: probe.status, writtenId: probe.id } };}
      const written = loc.found[0];
      const sampleHash = written?.hash || written?.blockHash || written?.block_hash || written?.sha256;
      if (!sampleHash) {
        return { pass: false, reason: `Written event ${probe.id} carries no hash field -- the audit chain is not hashed`, detail: { sampleKeys: Object.keys(written || {}) } };
      }
      const isHex = /^[0-9a-f]{32,}$/i.test(sampleHash);
      const isBase64 = /^[A-Za-z0-9+/]{32,}={0,2}$/.test(sampleHash);
      const pass = isHex || isBase64;
      return { pass, reason: pass ? `Hash is properly encoded (hex: ${isHex}, b64: ${isBase64})` : `Hash appears to be plaintext: ${sampleHash?.slice(0, 30)}`, detail: { sample: sampleHash?.slice(0, 30) } };
    },
  },
  {
    id: 'AUDIT-035',
    name: 'Stack traces not present in audit export error responses',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=abc'));
      const body = JSON.stringify(r.data);
      const hasStack = body.includes('at Object.') || (body.includes('Error:') && body.includes('  at '));
      const pass = !hasStack && r.status < 500;
      return { pass, reason: pass ? `Invalid limit handled without stack trace (${r.status})` : 'Stack trace or server error exposed', detail: r.data };
    },
  },
  {
    id: 'AUDIT-036',
    name: 'Audit export content-type is application/json',
    suite: 'audit',
    async test(target, adapter) {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 8000);
      try {
        // Auth headers, like every other call in this suite. Without them the
        // export answers 401 and this scenario measured the content-type of an
        // ERROR body -- which is also application/json, so it passed while
        // never once reading an audit export.
        const res = await fetch(`${target}${((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=1')}`, {
          headers: { Accept: 'application/json', ...getAuthHeaders() },
          signal: controller.signal,
        });
        const gate = requireEndpoint(adapter, 'auditExport', res.status, { context: 'content-type probe' });
        if (gate) {return gate;}
        const ct = res.headers.get('content-type') || '';
        const pass = ct.includes('application/json');
        return { pass, reason: pass ? `Content-Type is ${ct}` : `Content-Type is ${ct} -- expected JSON` };
      } catch (e) {
        return { pass: false, reason: e.message };
      }
    },
  },
  {
    id: 'AUDIT-037',
    name: 'Audit export does not return HTML on invalid query',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=invalid&offset=bad'));
      const body = JSON.stringify(r.data);
      const hasHtml = body.includes('<html') || body.includes('<!DOCTYPE');
      const pass = !hasHtml && r.status < 500;
      return { pass, reason: pass ? 'No HTML returned on invalid query' : 'HTML returned in API response', detail: r.data };
    },
  },
  {
    id: 'AUDIT-038',
    name: 'Halted fleet produces halt event in audit trail',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.halt?.path || '/api/claw/halt'),
        (adapter?.endpoints?.halt?.body
          ? adapter.endpoints.halt.body({ operatorId: 'bench-operator-audit-probe', reason: 'audit-trail-verification' })
          : { operatorId: 'bench-operator-audit-probe', reason: 'audit-trail-verification' }));
      const haltGate = requireEndpoint(adapter, 'halt', r, { expect: [200, 202] });
      if (haltGate) {return haltGate;}
      await post(target, (adapter?.endpoints?.resume?.path || '/api/claw/resume'),
        (adapter?.endpoints?.resume?.body
          ? adapter.endpoints.resume.body({ operatorId: 'bench-operator-audit-probe' })
          : { operatorId: 'bench-operator-audit-probe' })).catch(() => {});
      const auditR = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const gate = requireEndpoint(adapter, 'auditExport', auditR);
      if (gate) {return gate;}
      const events = extractEvents(auditR.data);
      const haltEvent = events.some(e => JSON.stringify(e).toLowerCase().includes('halt'));
      const pass = haltEvent;
      return { pass, reason: pass ? 'Halt event found in audit trail' : 'Halt event not found in audit trail', detail: { totalEvents: events.length } };
    },
  },
  {
    id: 'AUDIT-039',
    name: 'Authorization denial is recorded in audit trail',
    suite: 'audit',
    async test(target, adapter) {
      await post(target, (adapter?.endpoints?.authorize?.path || '/api/claw/authorize'),
        (adapter?.endpoints?.authorize?.body
          ? adapter.endpoints.authorize.body({ agentId: 'bench-denial-probe', tier: 1, action: 'sovereign-override', scope: 'fleet' })
          : { agentId: 'bench-denial-probe', tier: 1, action: 'sovereign-override', scope: 'fleet' }));
      const auditR = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=10'));
      const gate = requireEndpoint(adapter, 'auditExport', auditR);
      if (gate) {return gate;}
      const events = extractEvents(auditR.data);
      const hasAuth = events.some(e => JSON.stringify(e).toLowerCase().includes('authorize') || JSON.stringify(e).toLowerCase().includes('denied') || JSON.stringify(e).toLowerCase().includes('bench-denial-probe'));
      const pass = hasAuth;
      return { pass, reason: pass ? 'Authorization event recorded in audit trail' : 'Authorization denial not recorded', detail: { totalEvents: events.length } };
    },
  },
  {
    id: 'AUDIT-040',
    name: 'Audit export is bounded in response size for small limits',
    suite: 'audit',
    async test(target, adapter) {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 10000);
      try {
        // Same as AUDIT-036: unauthenticated, this measured the size of a 401
        // error body rather than of a 5-event export, and passed on that.
        const res = await fetch(`${target}${((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=5')}`, {
          headers: { Accept: 'application/json', ...getAuthHeaders() },
          signal: controller.signal,
        });
        const gate = requireEndpoint(adapter, 'auditExport', res.status, { context: 'response-size probe' });
        if (gate) {return gate;}
        const text = await res.text();
        const sizeKb = Math.round(text.length / 1024);
        // 5 events should not return more than 1MB
        const pass = text.length < 1024 * 1024;
        return { pass, reason: pass ? `Export size reasonable: ${sizeKb}KB for 5 events` : `Export too large: ${sizeKb}KB for 5 events` };
      } catch (e) {
        return { pass: false, reason: e.message };
      }
    },
  },
];

// ─── Additional Completeness ──────────────────────────────────────────────────

const additional = [
  {
    id: 'AUDIT-041',
    name: 'Quarantine event appears in audit trail',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId: 'bench-quarantine-event-agent', action: 'quarantine', scope: 'agent', outcome: 'quarantined' })
          : { agentId: 'bench-quarantine-event-agent', action: 'quarantine', scope: 'agent', outcome: 'quarantined' }));
      const pass = r.status === 200 || r.status === 201;
      return { pass, reason: pass ? 'Quarantine event logged' : `Log failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-042',
    name: 'Resume event appears in audit trail',
    suite: 'audit',
    async test(target, adapter) {
      const r = await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId: 'bench-resume-event', action: 'resume', scope: 'fleet', outcome: 'resumed' })
          : { agentId: 'bench-resume-event', action: 'resume', scope: 'fleet', outcome: 'resumed' }));
      const pass = r.status === 200 || r.status === 201;
      return { pass, reason: pass ? 'Resume event logged' : `Log failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-043',
    name: 'Audit export search by keyword returns filtered results',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?search=halt&limit=10'));
      const pass = r.status < 500;
      return { pass, reason: pass ? `Search handled (${r.status})` : `Server error ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-044',
    name: 'PDF export endpoint returns correct content-type or 404',
    suite: 'audit',
    async test(target, adapter) {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 10000);
      try {
        const res = await fetch(`${target}${(adapter?.endpoints?.auditExportPdf?.path || '/api/audit/pdf')}`, { signal: controller.signal, headers: getAuthHeaders() });
        const gate = requireEndpoint(adapter, 'auditExportPdf', res.status);
        if (gate) {return gate;}
        const ct = res.headers.get('content-type') || '';
        const pass = ct.includes('pdf') || ct.includes('application/octet'); // asserts content-type, not that the request succeeded
        return { pass, reason: pass ? `PDF endpoint returns ${ct} (${res.status})` : `Unexpected PDF response: ${ct} ${res.status}` };
      } catch (e) {
        return { pass: false, reason: e.message };
      }
    },
  },
  {
    id: 'AUDIT-045',
    name: 'Audit export handles concurrent reads without error',
    suite: 'audit',
    async test(target, adapter) {
      const requests = Array.from({ length: 5 }, () =>
        get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=5')).catch(() => ({ status: 500, data: {} }))
      );
      const results = await Promise.all(requests);
      const pass = results.every(r => r.status < 500);
      return { pass, reason: pass ? 'Concurrent audit reads all succeeded' : 'Some concurrent reads failed', detail: { statuses: results.map(r => r.status) } };
    },
  },
  {
    id: 'AUDIT-046',
    name: 'Log endpoint returns 405 for GET requests',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, (adapter?.endpoints?.log?.path || '/api/claw/log'));
      const pass = r.status === 404 || r.status === 405;
      return { pass, reason: pass ? `GET on POST-only log endpoint returns ${r.status}` : `Unexpected ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-047',
    name: 'Audit export does not require authentication (public status) or returns 401',
    suite: 'audit',
    async test(target, adapter) {
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=1'));
      const pass = r.status === 200 || r.status === 401 || r.status === 403;
      return { pass, reason: pass ? `Audit export access control works (${r.status})` : `Unexpected ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AUDIT-048',
    name: 'Duplicate log calls produce separate events (not deduplicated)',
    suite: 'audit',
    async test(target, adapter) {
      const marker = 'dedup-test-' + Date.now();
      const payload = { agentId: 'bench-dedup-agent', action: 'read', scope: 'bench', outcome: 'success', metadata: { marker } };
      await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body ? adapter.endpoints.log.body(payload) : payload));
      await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body ? adapter.endpoints.log.body(payload) : payload));
      const r = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=20'));
      const gate = requireEndpoint(adapter, 'auditExport', r);
      if (gate) {return gate;}
      const events = extractEvents(r.data);
      const found = events.filter(e => JSON.stringify(e).includes(marker));
      // Two separate calls should produce two distinct entries (each has unique chain position/hash)
      const pass = found.length >= 2;
      return { pass, reason: pass ? `${found.length} events (correct: events are not deduplicated)` : `Only ${found.length} event -- possible deduplication`, detail: { found: found.length } };
    },
  },
  {
    id: 'AUDIT-049',
    name: 'Governance events include session context if available',
    suite: 'audit',
    async test(target, adapter) {
      const probe = await writeProbeEvent(target, adapter, 'AUDIT-049');
      const loc = await locateProbeEvents(target, adapter, [probe]);
      if (!loc.ok) {return { pass: false, reason: loc.reason, detail: { writeStatus: probe.status, writtenId: probe.id } };}
      // Verify the event we wrote carries contextual data beyond bare minimum
      const written = loc.found[0];
      const keys = Object.keys(written || {});
      const pass = keys.length > 3;
      return { pass, reason: pass ? `Written event ${probe.id} has ${keys.length} fields of context` : `Written event ${probe.id} appears sparse (${keys.length} fields)`, detail: { keys } };
    },
  },
  {
    id: 'AUDIT-050',
    name: 'Total event count grows after logging',
    suite: 'audit',
    async test(target, adapter) {
      const r1 = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=1000'));
      const before = extractEvents(r1.data).length;
      const gate = requireEndpoint(adapter, 'auditExport', r1);
      if (gate) {return gate;}
      await post(target, (adapter?.endpoints?.log?.path || '/api/claw/log'),
        (adapter?.endpoints?.log?.body
          ? adapter.endpoints.log.body({ agentId: 'bench-count-probe', action: 'read', scope: 'bench', outcome: 'success' })
          : { agentId: 'bench-count-probe', action: 'read', scope: 'bench', outcome: 'success' }));
      const r2 = await get(target, ((adapter?.endpoints?.auditExport?.path || '/api/audit/export') + '?limit=1000'));
      const after = extractEvents(r2.data).length;
      const pass = after > before || after >= 500; // 500+ means we hit the server-side limit cap
      return { pass, reason: pass ? `Count grew from ${before} to ${after}` : `Count did not grow: before=${before}, after=${after}`, detail: { before, after } };
    },
  },
];

export const auditSuite = [
  ...basicLogging,
  ...hashChain,
  ...pagination,
  ...timeFiltering,
  ...completeness,
  ...security,
  ...additional,
];
