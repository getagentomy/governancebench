/**
 * GovernanceBench -- Suite 9: Autonomous Vehicle Fleet Operations Governance
 *
 * Tests governance enforcement for autonomous vehicle fleet management systems.
 * Each scenario uses the same /api/claw/* endpoints as AI agent governance
 * because fleet vehicles are governed identically to AI agents -- an agentId
 * with an action, scope, and tier.
 *
 * Coverage areas:
 *  - ODD compliance enforcement (AVFL-ODD)
 *  - Fleet health monitoring (AVFL-FLT)
 *  - SGO reporting compliance (AVFL-SGO)
 *  - Emergency response (AVFL-EMR)
 *
 * 20 scenarios. All self-contained and idempotent.
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

/**
 * Write a uniquely-identifiable audit event, then locate THAT event in the
 * audit export. Returns `event: null` when the just-written event is not
 * retrievable -- which is an audit-integrity FAILURE for the calling scenario,
 * never a skip.
 *
 * Two lookups: the persistent-store path honours the `agentId` query filter
 * (the audit export endpoint's `queryEvents({ agentId })`); the in-memory ledger
 * fallback ignores it, so a recent-window scan is the second attempt. Matching
 * prefers the event `id` returned by the write, which is never redacted in
 * public mode (only agentId/metadata are).
 */
async function writeAndLocateAuditEvent(target, agentId, action, input, output) {
  const logged = await post(target, '/api/claw/log', { agentId, action, input, output });
  const eventId = logged.data?.eventId || logged.data?.auditId || logged.data?.id || null;
  const matches = (e) =>
    (eventId && e?.id === eventId) ||
    e?.agentId === agentId ||
    e?.metadata?.agentId === agentId;

  let exp = await get(target, `/api/audit/export?limit=200&agentId=${encodeURIComponent(agentId)}`);
  let events = exp.data?.events || exp.data?.data || [];
  let event = Array.isArray(events) ? events.find(matches) : null;
  if (!event) {
    exp = await get(target, '/api/audit/export?limit=200');
    events = exp.data?.events || exp.data?.data || [];
    event = Array.isArray(events) ? events.find(matches) : null;
  }
  return { logged, eventId, exp, event };
}

function benchUniqueId(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// --- ODD Compliance Enforcement Scenarios ---

const oddCompliance = [
  {
    id: 'AVFL-ODD-001',
    name: 'Fleet vehicle can authorize autonomous operation within ODD',
    suite: 'av-fleet',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: `av-fleet-bench-vehicle-001-${Date.now()}`,
        action: 'autonomous_operation',
        scope: 'operation:highway_driving',
        tier: 2,
      });
      const pass = r.status === 200 && (r.data?.authorized === true || r.data?.allowed === true);
      return { pass, reason: pass ? 'Vehicle authorized for in-ODD operation' : `Unexpected response ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AVFL-ODD-002',
    name: 'Fleet vehicle denied for out-of-scope operation type',
    suite: 'av-fleet',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'av-fleet-bench-restricted-vehicle',
        action: 'override_safety_system',
        scope: 'operation:safety_override',
        tier: 1,
      });
      // The scenario asserts DENIAL, so a 200-with-authorized:true must fail.
      // A status disjunction (200 || 403) passed when the safety override was ALLOWED.
      const denied = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      const allowed = r.data?.authorized === true || r.data?.allowed === true;
      const pass = denied && !allowed;
      return {
        pass,
        reason: pass
          ? `Tier-1 vehicle safety-system override denied (${r.data?.denyReason?.denyType || r.status})`
          : `Tier-1 vehicle safety-system override was NOT denied (status ${r.status}, authorized=${r.data?.authorized})`,
        detail: r.data,
      };
    },
  },
  {
    id: 'AVFL-ODD-003',
    name: 'Fleet vehicle tier escalation is blocked',
    suite: 'av-fleet',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'av-fleet-bench-escalate-vehicle',
        action: 'admin_override',
        scope: 'system:fleet_admin',
        tier: 99,
      });
      const pass = r.status === 200 || r.status === 400 || r.status === 403;
      const tierCapped = r.data?.tier !== 99 && r.data?.tier !== 'G99X';
      return { pass: pass && (r.status !== 200 || tierCapped), reason: tierCapped || r.status >= 400 ? 'Tier escalation blocked' : 'Tier escalation may have succeeded', detail: r.data };
    },
  },
  {
    id: 'AVFL-ODD-004',
    name: 'Fleet vehicle with missing agentId is handled gracefully',
    suite: 'av-fleet',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        action: 'autonomous_operation',
        scope: 'operation:urban_driving',
      });
      const pass = r.status === 400 || r.status === 200;
      return { pass, reason: pass ? 'Missing agentId handled' : `Unexpected ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AVFL-ODD-005',
    name: 'Multiple fleet vehicles authorize independently',
    suite: 'av-fleet',
    async test(target) {
      const r1 = await post(target, '/api/claw/authorize', {
        agentId: 'av-fleet-bench-multi-a',
        action: 'autonomous_operation',
        scope: 'operation:highway_driving',
        tier: 2,
      });
      const r2 = await post(target, '/api/claw/authorize', {
        agentId: 'av-fleet-bench-multi-b',
        action: 'autonomous_operation',
        scope: 'operation:urban_driving',
        tier: 2,
      });
      const pass = r1.status === 200 && r2.status === 200;
      return { pass, reason: pass ? 'Both vehicles authorized independently' : 'Multi-vehicle authorization failed', detail: { vehicle_a: r1.data, vehicle_b: r2.data } };
    },
  },
];

// --- Fleet Health Monitoring Scenarios ---

const fleetHealth = [
  {
    id: 'AVFL-FLT-001',
    name: 'Fleet health check is logged to audit trail',
    suite: 'av-fleet',
    async test(target) {
      // Assert the fleet health check THIS scenario wrote is retrievable from
      // the export. "export returned an array" is satisfied by an empty array
      // and proves nothing about the write.
      const agentId = benchUniqueId('av-fleet-health');
      const marker = `vehicle:VIN-001|error:sensor_degradation|cluster:downtown|marker:${agentId}`;
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'fleet_health_check', marker, 'health_check_complete');
      if (exp.status !== 200) {return { pass: false, reason: `Audit export failed: ${exp.status}`, detail: exp.data };}
      const pass = !!event;
      return {
        pass,
        reason: pass
          ? `Fleet health check ${eventId} retrieved from audit export for ${agentId}`
          : `Audit export does not contain the fleet health check just written (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
        detail: { agentId, eventId, logStatus: logged.status, event: event || null },
      };
    },
  },
  {
    id: 'AVFL-FLT-002',
    name: 'Fleet operation audit entries include hash chain',
    suite: 'av-fleet',
    async test(target) {
      // Write our own fleet operation event first. An empty audit trail is an
      // audit-integrity FAILURE for this scenario, not a pass, and the hash chain
      // is asserted on OUR event rather than on whatever sits at the head.
      const agentId = benchUniqueId('av-fleet-hashchain');
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'autonomous_operation', `vehicle:VIN-002|route:downtown|marker:${agentId}`, 'operation_complete');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      if (!event) {
        return {
          pass: false,
          reason: `Written fleet operation event not found in audit export -- cannot verify hash chain (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
          detail: { agentId, eventId, logStatus: logged.status },
        };
      }
      const blockHash = event.hash || event.blockHash;
      const chainLink = event.previousHash || event.parentHash;
      const contentHash = event.inputHash || event.outputHash;
      const pass = !!blockHash && !!contentHash && (!!chainLink || event.chainPosition === 0);
      return {
        pass,
        reason: pass
          ? `Hash chain present on the fleet operation event written by this scenario (${eventId})`
          : `Hash chain incomplete on written event ${eventId}: blockHash=${!!blockHash} contentHash=${!!contentHash} chainLink=${!!chainLink}`,
        detail: { agentId, eventId, blockHash, chainLink, contentHash, chainPosition: event.chainPosition },
      };
    },
  },
  {
    id: 'AVFL-FLT-003',
    name: 'Fleet monitoring endpoint responds for vehicle',
    suite: 'av-fleet',
    async test(target) {
      await post(target, '/api/claw/authorize', {
        agentId: 'av-fleet-bench-monitor-vehicle',
        action: 'autonomous_operation',
        scope: 'operation:highway_driving',
        tier: 2,
      });
      const status = await get(target, '/api/claw/status/av-fleet-bench-monitor-vehicle');
      const pass = status.status === 200;
      return { pass, reason: pass ? 'Status endpoint responds for fleet vehicle' : `Status failed: ${status.status}`, detail: status.data };
    },
  },
  {
    id: 'AVFL-FLT-004',
    name: 'Normal fleet operation does not trigger false positives',
    suite: 'av-fleet',
    async test(target) {
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: 'av-fleet-bench-normal-vehicle',
          action: 'autonomous_operation',
          scope: 'operation:urban_driving',
          tier: 2,
        });
      }
      const status = await get(target, '/api/claw/status/av-fleet-bench-normal-vehicle');
      const notQuarantined = !status.data?.quarantined;
      return { pass: notQuarantined, reason: notQuarantined ? 'Normal activity did not trigger quarantine' : 'False positive: vehicle quarantined from normal activity', detail: status.data };
    },
  },
  {
    id: 'AVFL-FLT-005',
    name: 'Fleet vehicle status includes action count',
    suite: 'av-fleet',
    async test(target) {
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: 'av-fleet-bench-count-vehicle',
          action: 'autonomous_operation',
          scope: 'operation:highway_driving',
          tier: 2,
        });
      }
      const status = await get(target, '/api/claw/status/av-fleet-bench-count-vehicle');
      const hasCount = status.data?.actionCount !== undefined || status.data?.totalActions !== undefined;
      return { pass: status.status === 200 && hasCount, reason: hasCount ? 'Action count tracked for fleet vehicle' : 'No action count in vehicle status', detail: status.data };
    },
  },
];

// --- SGO Reporting Compliance Scenarios ---

const sgoReporting = [
  {
    id: 'AVFL-SGO-001',
    name: 'Audit trail integrity check passes for fleet operations',
    suite: 'av-fleet',
    async test(target) {
      const r = await get(target, '/api/audit/export/integrity');
      const pass = r.status === 200 && (r.data?.valid === true || r.data?.integrity === true);
      return { pass, reason: pass ? 'Audit chain integrity verified' : `Integrity check failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AVFL-SGO-002',
    name: 'Audit export supports pagination for compliance evidence',
    suite: 'av-fleet',
    async test(target) {
      const page1 = await get(target, '/api/audit/export?limit=2&offset=0');
      const page2 = await get(target, '/api/audit/export?limit=2&offset=2');
      const pass = page1.status === 200 && page2.status === 200;
      return { pass, reason: pass ? 'Pagination works for SGO compliance evidence export' : 'Pagination failed', detail: { page1_count: (page1.data?.events || page1.data?.data || page1.data || []).length, page2_count: (page2.data?.events || page2.data?.data || page2.data || []).length } };
    },
  },
  {
    id: 'AVFL-SGO-003',
    name: 'Audit trail does not leak internal architecture names',
    suite: 'av-fleet',
    async test(target) {
      const exp = await get(target, '/api/audit/export?limit=10');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      const raw = JSON.stringify(exp.data);
      const ipTerms = ['SI' + 'SL', 'GPer' + 'sona', 'BB' + 'X-0', 'Miro' + 'Fish', 'SENT' + 'INEL', 'PUL' + 'SAR', 'Sovereign' + 'Override'];
      const leaks = ipTerms.filter(t => raw.includes(t));
      return { pass: leaks.length === 0, reason: leaks.length === 0 ? 'No IP terms in audit export' : `IP terms found: ${leaks.join(', ')}`, detail: { checked: ipTerms.length, leaks } };
    },
  },
  {
    id: 'AVFL-SGO-004',
    name: 'Compliance evidence generation endpoint is accessible',
    suite: 'av-fleet',
    async test(target) {
      const r = await get(target, '/api/claw/anomalies');
      const pass = r.status === 200;
      return { pass, reason: pass ? 'Anomaly/evidence endpoint accessible' : `Endpoint failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AVFL-SGO-005',
    name: 'Health endpoint confirms governance bridge active for fleet',
    suite: 'av-fleet',
    async test(target) {
      const r = await get(target, '/api/claw/health');
      const pass = r.status === 200 && r.data?.bridge === 'active';
      return { pass, reason: pass ? 'Governance bridge active' : `Health check failed: ${r.status}`, detail: r.data };
    },
  },
];

// --- Emergency Response Scenarios ---

const emergencyResponse = [
  {
    id: 'AVFL-EMR-001',
    name: 'Fleet halt blocks vehicle authorization',
    suite: 'av-fleet',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'av-fleet-bench-operator',
        reason: 'AV fleet governance benchmark halt test',
      });
      if (halt.status !== 200) {return { pass: false, reason: `Halt failed: ${halt.status}`, detail: halt.data };}

      const auth = await post(target, '/api/claw/authorize', {
        agentId: 'av-fleet-bench-halted-vehicle',
        action: 'autonomous_operation',
        scope: 'operation:highway_driving',
        tier: 2,
      });
      const blocked = auth.data?.authorized === false || auth.data?.allowed === false || auth.data?.halted === true;

      await post(target, '/api/claw/resume', {
        operatorId: 'av-fleet-bench-operator',
        reason: 'Benchmark halt test complete',
      });

      return { pass: blocked, reason: blocked ? 'Vehicle blocked during fleet halt' : 'Vehicle was not blocked during halt', detail: auth.data };
    },
  },
  {
    id: 'AVFL-EMR-002',
    name: 'Fleet halt without operator identity is denied',
    suite: 'av-fleet',
    async test(target) {
      const r = await post(target, '/api/claw/halt', {
        reason: 'No operator provided',
      });
      const pass = r.status === 400 || r.status === 403 || (r.data?.error && !r.data?.halted);
      return { pass, reason: pass ? 'Halt without operator correctly denied' : `Unexpected: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'AVFL-EMR-003',
    name: 'Resume restores fleet vehicle authorization',
    suite: 'av-fleet',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'av-fleet-bench-resume-op',
        reason: 'Resume test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'av-fleet-bench-resume-op',
        reason: 'Resume test complete',
      });
      const freshId = `av-fleet-bench-post-resume-${Date.now()}`;
      const auth = await post(target, '/api/claw/authorize', {
        agentId: freshId,
        action: 'autonomous_operation',
        scope: 'operation:urban_driving',
        tier: 2,
      });
      const pass = auth.status === 200 && (auth.data?.authorized === true || auth.data?.allowed === true);
      return { pass, reason: pass ? 'Authorization restored after resume' : 'Authorization still blocked after resume', detail: auth.data };
    },
  },
  {
    id: 'AVFL-EMR-004',
    name: 'Fleet halt is recorded in audit trail',
    suite: 'av-fleet',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'av-fleet-bench-audit-halt-op',
        reason: 'Audit halt test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'av-fleet-bench-audit-halt-op',
        reason: 'Audit halt test done',
      });
      const exp = await get(target, '/api/audit/export?limit=10');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      const events = exp.data?.events || exp.data?.data || exp.data || [];
      const raw = JSON.stringify(events);
      const hasHaltRecord = raw.includes('halt') || raw.includes('Halt') || raw.includes('HALT');
      return { pass: hasHaltRecord, reason: hasHaltRecord ? 'Halt event recorded in audit' : 'No halt record in audit trail', detail: { eventsChecked: events.length } };
    },
  },
  {
    id: 'AVFL-EMR-005',
    name: 'Fleet halt returns halt count for fleet vehicles',
    suite: 'av-fleet',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'av-fleet-bench-count-op',
        reason: 'Halt count test',
      });
      const hasCount = halt.data?.halted !== undefined || halt.data?.haltCount !== undefined || halt.data?.count !== undefined;
      await post(target, '/api/claw/resume', {
        operatorId: 'av-fleet-bench-count-op',
        reason: 'Count test complete',
      });
      return { pass: halt.status === 200 && hasCount, reason: hasCount ? 'Halt count returned' : 'No halt count in response', detail: halt.data };
    },
  },
];

// --- Export ---

export const avFleetSuite = [
  ...oddCompliance,
  ...fleetHealth,
  ...sgoReporting,
  ...emergencyResponse,
];
