/**
 * GovernanceBench -- Suite 10: Industrial IoT / SCADA Governance
 *
 * Tests governance enforcement for industrial control system operations.
 * Each scenario uses the same /api/claw/* endpoints as AI agent governance
 * because controllers are governed identically to AI agents -- an agentId
 * with an action, scope, and tier.
 *
 * Coverage areas:
 *  - Process boundary enforcement (IIOT-PBE)
 *  - Controller integrity monitoring (IIOT-CIM)
 *  - Safety system governance (IIOT-SSG)
 *  - Network perimeter control (IIOT-NPC)
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

// --- Process Boundary Enforcement Scenarios ---

const processBoundary = [
  {
    id: 'IIOT-PBE-001',
    name: 'Controller can authorize process operation within safe range',
    suite: 'industrial-iot',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: `iiot-bench-controller-001-${Date.now()}`,
        action: 'scada_operation',
        scope: 'operation:process_monitoring',
        tier: 2,
      });
      const pass = r.status === 200 && (r.data?.authorized === true || r.data?.allowed === true);
      return { pass, reason: pass ? 'Controller authorized for process operation' : `Unexpected response ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'IIOT-PBE-002',
    name: 'Controller denied for safety override scope',
    suite: 'industrial-iot',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'iiot-bench-restricted-controller',
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
          ? `Tier-1 controller safety-system override denied (${r.data?.denyReason?.denyType || r.status})`
          : `Tier-1 controller safety-system override was NOT denied (status ${r.status}, authorized=${r.data?.authorized})`,
        detail: r.data,
      };
    },
  },
  {
    id: 'IIOT-PBE-003',
    name: 'Controller tier escalation is blocked',
    suite: 'industrial-iot',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'iiot-bench-escalate-controller',
        action: 'admin_override',
        scope: 'system:plant_admin',
        tier: 99,
      });
      const pass = r.status === 200 || r.status === 400 || r.status === 403;
      const tierCapped = r.data?.tier !== 99 && r.data?.tier !== 'G99X';
      return { pass: pass && (r.status !== 200 || tierCapped), reason: tierCapped || r.status >= 400 ? 'Tier escalation blocked' : 'Tier escalation may have succeeded', detail: r.data };
    },
  },
  {
    id: 'IIOT-PBE-004',
    name: 'Controller with missing agentId is handled gracefully',
    suite: 'industrial-iot',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        action: 'scada_operation',
        scope: 'operation:process_monitoring',
      });
      const pass = r.status === 400 || r.status === 200;
      return { pass, reason: pass ? 'Missing agentId handled' : `Unexpected ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'IIOT-PBE-005',
    name: 'Multiple controllers authorize independently',
    suite: 'industrial-iot',
    async test(target) {
      const r1 = await post(target, '/api/claw/authorize', {
        agentId: 'iiot-bench-multi-a',
        action: 'scada_operation',
        scope: 'operation:process_monitoring',
        tier: 2,
      });
      const r2 = await post(target, '/api/claw/authorize', {
        agentId: 'iiot-bench-multi-b',
        action: 'scada_operation',
        scope: 'operation:setpoint_control',
        tier: 2,
      });
      const pass = r1.status === 200 && r2.status === 200;
      return { pass, reason: pass ? 'Both controllers authorized independently' : 'Multi-controller authorization failed', detail: { controller_a: r1.data, controller_b: r2.data } };
    },
  },
];

// --- Controller Integrity Monitoring Scenarios ---

const controllerIntegrity = [
  {
    id: 'IIOT-CIM-001',
    name: 'Controller operation is logged to audit trail',
    suite: 'industrial-iot',
    async test(target) {
      // Assert the controller operation THIS scenario wrote is retrievable from
      // the export. "export returned an array" is satisfied by an empty array
      // and proves nothing about the write.
      const agentId = benchUniqueId('iiot-audit');
      const marker = `controller:PLC-001|hash:abc123|status:verified|marker:${agentId}`;
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'firmware_check', marker, 'integrity_check_complete');
      if (exp.status !== 200) {return { pass: false, reason: `Audit export failed: ${exp.status}`, detail: exp.data };}
      const pass = !!event;
      return {
        pass,
        reason: pass
          ? `Controller operation ${eventId} retrieved from audit export for ${agentId}`
          : `Audit export does not contain the controller operation just written (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
        detail: { agentId, eventId, logStatus: logged.status, event: event || null },
      };
    },
  },
  {
    id: 'IIOT-CIM-002',
    name: 'Controller audit entries include hash chain',
    suite: 'industrial-iot',
    async test(target) {
      // Write our own controller event first. An empty audit trail is an
      // audit-integrity FAILURE for this scenario, not a pass, and the hash chain
      // is asserted on OUR event rather than on whatever sits at the head.
      const agentId = benchUniqueId('iiot-hashchain');
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'firmware_check', `controller:PLC-002|hash:def456|marker:${agentId}`, 'integrity_check_complete');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      if (!event) {
        return {
          pass: false,
          reason: `Written controller event not found in audit export -- cannot verify hash chain (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
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
          ? `Hash chain present on the controller event written by this scenario (${eventId})`
          : `Hash chain incomplete on written event ${eventId}: blockHash=${!!blockHash} contentHash=${!!contentHash} chainLink=${!!chainLink}`,
        detail: { agentId, eventId, blockHash, chainLink, contentHash, chainPosition: event.chainPosition },
      };
    },
  },
  {
    id: 'IIOT-CIM-003',
    name: 'Controller monitoring endpoint responds',
    suite: 'industrial-iot',
    async test(target) {
      await post(target, '/api/claw/authorize', {
        agentId: 'iiot-bench-monitor-plc',
        action: 'scada_operation',
        scope: 'operation:process_monitoring',
        tier: 2,
      });
      const status = await get(target, '/api/claw/status/iiot-bench-monitor-plc');
      const pass = status.status === 200;
      return { pass, reason: pass ? 'Status endpoint responds for controller' : `Status failed: ${status.status}`, detail: status.data };
    },
  },
  {
    id: 'IIOT-CIM-004',
    name: 'Normal controller operation does not trigger false positives',
    suite: 'industrial-iot',
    async test(target) {
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: 'iiot-bench-normal-plc',
          action: 'scada_operation',
          scope: 'operation:process_monitoring',
          tier: 2,
        });
      }
      const status = await get(target, '/api/claw/status/iiot-bench-normal-plc');
      const notQuarantined = !status.data?.quarantined;
      return { pass: notQuarantined, reason: notQuarantined ? 'Normal activity did not trigger quarantine' : 'False positive: controller quarantined from normal activity', detail: status.data };
    },
  },
  {
    id: 'IIOT-CIM-005',
    name: 'Controller status includes action count',
    suite: 'industrial-iot',
    async test(target) {
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: 'iiot-bench-count-plc',
          action: 'scada_operation',
          scope: 'operation:process_monitoring',
          tier: 2,
        });
      }
      const status = await get(target, '/api/claw/status/iiot-bench-count-plc');
      const hasCount = status.data?.actionCount !== undefined || status.data?.totalActions !== undefined;
      return { pass: status.status === 200 && hasCount, reason: hasCount ? 'Action count tracked for controller' : 'No action count in controller status', detail: status.data };
    },
  },
];

// --- Safety System Governance Scenarios ---

const safetySystem = [
  {
    id: 'IIOT-SSG-001',
    name: 'Audit trail integrity check passes for controller operations',
    suite: 'industrial-iot',
    async test(target) {
      const r = await get(target, '/api/audit/export/integrity');
      const pass = r.status === 200 && (r.data?.valid === true || r.data?.integrity === true);
      return { pass, reason: pass ? 'Audit chain integrity verified' : `Integrity check failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'IIOT-SSG-002',
    name: 'Audit export supports pagination for compliance evidence',
    suite: 'industrial-iot',
    async test(target) {
      const page1 = await get(target, '/api/audit/export?limit=2&offset=0');
      const page2 = await get(target, '/api/audit/export?limit=2&offset=2');
      const pass = page1.status === 200 && page2.status === 200;
      return { pass, reason: pass ? 'Pagination works for compliance evidence export' : 'Pagination failed', detail: { page1_count: (page1.data?.events || page1.data?.data || page1.data || []).length, page2_count: (page2.data?.events || page2.data?.data || page2.data || []).length } };
    },
  },
  {
    id: 'IIOT-SSG-003',
    name: 'Audit trail does not leak internal architecture names',
    suite: 'industrial-iot',
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
    id: 'IIOT-SSG-004',
    name: 'Compliance evidence generation endpoint is accessible',
    suite: 'industrial-iot',
    async test(target) {
      const r = await get(target, '/api/claw/anomalies');
      const pass = r.status === 200;
      return { pass, reason: pass ? 'Anomaly/evidence endpoint accessible' : `Endpoint failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'IIOT-SSG-005',
    name: 'Health endpoint confirms governance bridge active for controllers',
    suite: 'industrial-iot',
    async test(target) {
      const r = await get(target, '/api/claw/health');
      const pass = r.status === 200 && r.data?.bridge === 'active';
      return { pass, reason: pass ? 'Governance bridge active' : `Health check failed: ${r.status}`, detail: r.data };
    },
  },
];

// --- Network Perimeter Control Scenarios ---

const networkPerimeter = [
  {
    id: 'IIOT-NPC-001',
    name: 'Emergency halt blocks controller authorization',
    suite: 'industrial-iot',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'iiot-bench-operator',
        reason: 'Industrial IoT governance benchmark halt test',
      });
      if (halt.status !== 200) {return { pass: false, reason: `Halt failed: ${halt.status}`, detail: halt.data };}

      const auth = await post(target, '/api/claw/authorize', {
        agentId: 'iiot-bench-halted-plc',
        action: 'scada_operation',
        scope: 'operation:process_monitoring',
        tier: 2,
      });
      const blocked = auth.data?.authorized === false || auth.data?.allowed === false || auth.data?.halted === true;

      await post(target, '/api/claw/resume', {
        operatorId: 'iiot-bench-operator',
        reason: 'Benchmark halt test complete',
      });

      return { pass: blocked, reason: blocked ? 'Controller blocked during halt' : 'Controller was not blocked during halt', detail: auth.data };
    },
  },
  {
    id: 'IIOT-NPC-002',
    name: 'Halt without operator identity is denied',
    suite: 'industrial-iot',
    async test(target) {
      const r = await post(target, '/api/claw/halt', {
        reason: 'No operator provided',
      });
      const pass = r.status === 400 || r.status === 403 || (r.data?.error && !r.data?.halted);
      return { pass, reason: pass ? 'Halt without operator correctly denied' : `Unexpected: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'IIOT-NPC-003',
    name: 'Resume restores controller authorization',
    suite: 'industrial-iot',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'iiot-bench-resume-op',
        reason: 'Resume test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'iiot-bench-resume-op',
        reason: 'Resume test complete',
      });
      const freshId = `iiot-bench-post-resume-${Date.now()}`;
      const auth = await post(target, '/api/claw/authorize', {
        agentId: freshId,
        action: 'scada_operation',
        scope: 'operation:process_monitoring',
        tier: 2,
      });
      const pass = auth.status === 200 && (auth.data?.authorized === true || auth.data?.allowed === true);
      return { pass, reason: pass ? 'Authorization restored after resume' : 'Authorization still blocked after resume', detail: auth.data };
    },
  },
  {
    id: 'IIOT-NPC-004',
    name: 'Halt is recorded in audit trail',
    suite: 'industrial-iot',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'iiot-bench-audit-halt-op',
        reason: 'Audit halt test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'iiot-bench-audit-halt-op',
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
    id: 'IIOT-NPC-005',
    name: 'Halt returns count for governed controllers',
    suite: 'industrial-iot',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'iiot-bench-count-op',
        reason: 'Halt count test',
      });
      const hasCount = halt.data?.halted !== undefined || halt.data?.haltCount !== undefined || halt.data?.count !== undefined;
      await post(target, '/api/claw/resume', {
        operatorId: 'iiot-bench-count-op',
        reason: 'Count test complete',
      });
      return { pass: halt.status === 200 && hasCount, reason: hasCount ? 'Halt count returned' : 'No halt count in response', detail: halt.data };
    },
  },
];

// --- Export ---

export const industrialIoTSuite = [
  ...processBoundary,
  ...controllerIntegrity,
  ...safetySystem,
  ...networkPerimeter,
];
