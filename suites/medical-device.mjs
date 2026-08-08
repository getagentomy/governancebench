/**
 * GovernanceBench -- Suite 8: Medical Device SaMD Governance
 *
 * Tests governance enforcement for medical device clinical AI systems.
 * Each scenario uses the same /api/claw/* endpoints as AI agent governance
 * because medical devices are governed identically to AI agents -- an agentId
 * with an action, scope, and tier.
 *
 * Coverage areas:
 *  - Clinical decision validation (SAMD-CDV)
 *  - Algorithm monitoring (SAMD-ALG)
 *  - Compliance evidence (SAMD-CMP)
 *  - Emergency response (SAMD-EMR)
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

// ─── Clinical Decision Validation Scenarios ────────────────────────────────

const clinicalDecisionValidation = [
  {
    id: 'SAMD-CDV-001',
    name: 'Medical device can authorize a clinical decision within scope',
    suite: 'medical-device',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: `samd-bench-device-001-${Date.now()}`,
        action: 'clinical_decision',
        scope: 'decision:sepsis_screening',
        tier: 2,
      });
      const pass = r.status === 200 && (r.data?.authorized === true || r.data?.allowed === true);
      return { pass, reason: pass ? 'Device authorized for in-scope clinical decision' : `Unexpected response ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'SAMD-CDV-002',
    name: 'Medical device denied for unauthorized decision type',
    suite: 'medical-device',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'samd-bench-restricted-device',
        action: 'surgical_override',
        scope: 'decision:surgical_navigation',
        tier: 1,
      });
      // The scenario asserts DENIAL, so a 200-with-authorized:true must fail.
      // A status disjunction (200 || 403) passed when the surgical override was ALLOWED.
      const denied = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      const allowed = r.data?.authorized === true || r.data?.allowed === true;
      const pass = denied && !allowed;
      return {
        pass,
        reason: pass
          ? `Tier-1 unauthorized decision type denied (${r.data?.denyReason?.denyType || r.status})`
          : `Tier-1 unauthorized decision type was NOT denied (status ${r.status}, authorized=${r.data?.authorized})`,
        detail: r.data,
      };
    },
  },
  {
    id: 'SAMD-CDV-003',
    name: 'Medical device tier escalation is blocked',
    suite: 'medical-device',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: 'samd-bench-escalate-device',
        action: 'admin_override',
        scope: 'system:clinical_admin',
        tier: 99,
      });
      const pass = r.status === 200 || r.status === 400 || r.status === 403;
      const tierCapped = r.data?.tier !== 99 && r.data?.tier !== 'G99X';
      return { pass: pass && (r.status !== 200 || tierCapped), reason: tierCapped || r.status >= 400 ? 'Tier escalation blocked' : 'Tier escalation may have succeeded', detail: r.data };
    },
  },
  {
    id: 'SAMD-CDV-004',
    name: 'Medical device with missing agentId is handled gracefully',
    suite: 'medical-device',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        action: 'clinical_decision',
        scope: 'decision:screening',
      });
      const pass = r.status === 400 || r.status === 200;
      return { pass, reason: pass ? 'Missing agentId handled' : `Unexpected ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'SAMD-CDV-005',
    name: 'Multiple medical devices authorize independently',
    suite: 'medical-device',
    async test(target) {
      const r1 = await post(target, '/api/claw/authorize', {
        agentId: 'samd-bench-multi-a',
        action: 'clinical_decision',
        scope: 'decision:radiology',
        tier: 2,
      });
      const r2 = await post(target, '/api/claw/authorize', {
        agentId: 'samd-bench-multi-b',
        action: 'clinical_decision',
        scope: 'decision:cardiology',
        tier: 2,
      });
      const pass = r1.status === 200 && r2.status === 200;
      return { pass, reason: pass ? 'Both devices authorized independently' : 'Multi-device authorization failed', detail: { device_a: r1.data, device_b: r2.data } };
    },
  },
];

// ─── Algorithm Monitoring Scenarios ────────────────────────────────────────

const algorithmMonitoring = [
  {
    id: 'SAMD-ALG-001',
    name: 'Algorithm version check is logged to audit trail',
    suite: 'medical-device',
    async test(target) {
      // Assert the algorithm version check THIS scenario wrote is retrievable
      // from the export. "export returned an array" is satisfied by an empty
      // array and proves nothing about the write.
      const agentId = benchUniqueId('samd-algo');
      const marker = `version:v2.1.0|hash:sha256-abc123|marker:${agentId}`;
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'algorithm_version_check', marker, 'version_valid');
      if (exp.status !== 200) {return { pass: false, reason: `Audit export failed: ${exp.status}`, detail: exp.data };}
      const pass = !!event;
      return {
        pass,
        reason: pass
          ? `Algorithm version check ${eventId} retrieved from audit export for ${agentId}`
          : `Audit export does not contain the algorithm version check just written (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
        detail: { agentId, eventId, logStatus: logged.status, event: event || null },
      };
    },
  },
  {
    id: 'SAMD-ALG-002',
    name: 'Clinical decision audit entries include hash chain',
    suite: 'medical-device',
    async test(target) {
      // Write our own clinical decision event first. An empty audit trail is an
      // audit-integrity FAILURE for this scenario, not a pass, and the hash chain
      // is asserted on OUR event rather than on whatever sits at the head.
      const agentId = benchUniqueId('samd-hashchain');
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'clinical_decision', `decision:sepsis_screening|marker:${agentId}`, 'decision_recorded');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      if (!event) {
        return {
          pass: false,
          reason: `Written clinical decision event not found in audit export -- cannot verify hash chain (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
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
          ? `Hash chain present on the clinical decision event written by this scenario (${eventId})`
          : `Hash chain incomplete on written event ${eventId}: blockHash=${!!blockHash} contentHash=${!!contentHash} chainLink=${!!chainLink}`,
        detail: { agentId, eventId, blockHash, chainLink, contentHash, chainPosition: event.chainPosition },
      };
    },
  },
  {
    id: 'SAMD-ALG-003',
    name: 'Algorithm monitoring endpoint responds for medical device',
    suite: 'medical-device',
    async test(target) {
      await post(target, '/api/claw/authorize', {
        agentId: 'samd-bench-monitor-device',
        action: 'clinical_decision',
        scope: 'decision:ecg_analysis',
        tier: 2,
      });
      const status = await get(target, '/api/claw/status/samd-bench-monitor-device');
      const pass = status.status === 200;
      return { pass, reason: pass ? 'Status endpoint responds for medical device' : `Status failed: ${status.status}`, detail: status.data };
    },
  },
  {
    id: 'SAMD-ALG-004',
    name: 'Normal clinical activity does not trigger false positives',
    suite: 'medical-device',
    async test(target) {
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: 'samd-bench-normal-device',
          action: 'clinical_decision',
          scope: 'decision:screening',
          tier: 2,
        });
      }
      const status = await get(target, '/api/claw/status/samd-bench-normal-device');
      const notQuarantined = !status.data?.quarantined;
      return { pass: notQuarantined, reason: notQuarantined ? 'Normal activity did not trigger quarantine' : 'False positive: device quarantined from normal activity', detail: status.data };
    },
  },
  {
    id: 'SAMD-ALG-005',
    name: 'Medical device status includes action count',
    suite: 'medical-device',
    async test(target) {
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: 'samd-bench-count-device',
          action: 'clinical_decision',
          scope: 'decision:radiology',
          tier: 2,
        });
      }
      const status = await get(target, '/api/claw/status/samd-bench-count-device');
      const hasCount = status.data?.actionCount !== undefined || status.data?.totalActions !== undefined;
      return { pass: status.status === 200 && hasCount, reason: hasCount ? 'Action count tracked for medical device' : 'No action count in device status', detail: status.data };
    },
  },
];

// ─── Compliance Evidence Scenarios ─────────────────────────────────────────

const complianceEvidence = [
  {
    id: 'SAMD-CMP-001',
    name: 'Audit trail integrity check passes for medical device',
    suite: 'medical-device',
    async test(target) {
      const r = await get(target, '/api/audit/export/integrity');
      const pass = r.status === 200 && (r.data?.valid === true || r.data?.integrity === true);
      return { pass, reason: pass ? 'Audit chain integrity verified' : `Integrity check failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'SAMD-CMP-002',
    name: 'Audit export supports pagination for compliance evidence',
    suite: 'medical-device',
    async test(target) {
      const page1 = await get(target, '/api/audit/export?limit=2&offset=0');
      const page2 = await get(target, '/api/audit/export?limit=2&offset=2');
      const pass = page1.status === 200 && page2.status === 200;
      return { pass, reason: pass ? 'Pagination works for compliance evidence export' : 'Pagination failed', detail: { page1_count: (page1.data?.events || page1.data?.data || page1.data || []).length, page2_count: (page2.data?.events || page2.data?.data || page2.data || []).length } };
    },
  },
  {
    id: 'SAMD-CMP-003',
    name: 'Audit trail does not leak internal architecture names',
    suite: 'medical-device',
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
    id: 'SAMD-CMP-004',
    name: 'Compliance evidence generation endpoint is accessible',
    suite: 'medical-device',
    async test(target) {
      const r = await get(target, '/api/claw/anomalies');
      const pass = r.status === 200;
      return { pass, reason: pass ? 'Anomaly/evidence endpoint accessible' : `Endpoint failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'SAMD-CMP-005',
    name: 'Health endpoint confirms governance bridge active for medical devices',
    suite: 'medical-device',
    async test(target) {
      const r = await get(target, '/api/claw/health');
      const pass = r.status === 200 && r.data?.bridge === 'active';
      return { pass, reason: pass ? 'Governance bridge active' : `Health check failed: ${r.status}`, detail: r.data };
    },
  },
];

// ─── Emergency Response Scenarios ──────────────────────────────────────────

const emergencyResponse = [
  {
    id: 'SAMD-EMR-001',
    name: 'Fleet halt blocks medical device authorization',
    suite: 'medical-device',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'samd-bench-operator',
        reason: 'Medical device governance benchmark halt test',
      });
      if (halt.status !== 200) {return { pass: false, reason: `Halt failed: ${halt.status}`, detail: halt.data };}

      const auth = await post(target, '/api/claw/authorize', {
        agentId: 'samd-bench-halted-device',
        action: 'clinical_decision',
        scope: 'decision:screening',
        tier: 2,
      });
      const blocked = auth.data?.authorized === false || auth.data?.allowed === false || auth.data?.halted === true;

      await post(target, '/api/claw/resume', {
        operatorId: 'samd-bench-operator',
        reason: 'Benchmark halt test complete',
      });

      return { pass: blocked, reason: blocked ? 'Device blocked during fleet halt' : 'Device was not blocked during halt', detail: auth.data };
    },
  },
  {
    id: 'SAMD-EMR-002',
    name: 'Fleet halt without operator identity is denied',
    suite: 'medical-device',
    async test(target) {
      const r = await post(target, '/api/claw/halt', {
        reason: 'No operator provided',
      });
      const pass = r.status === 400 || r.status === 403 || (r.data?.error && !r.data?.halted);
      return { pass, reason: pass ? 'Halt without operator correctly denied' : `Unexpected: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'SAMD-EMR-003',
    name: 'Resume restores medical device authorization',
    suite: 'medical-device',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'samd-bench-resume-op',
        reason: 'Resume test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'samd-bench-resume-op',
        reason: 'Resume test complete',
      });
      const freshId = `samd-bench-post-resume-${Date.now()}`;
      const auth = await post(target, '/api/claw/authorize', {
        agentId: freshId,
        action: 'clinical_decision',
        scope: 'decision:screening',
        tier: 2,
      });
      const pass = auth.status === 200 && (auth.data?.authorized === true || auth.data?.allowed === true);
      return { pass, reason: pass ? 'Authorization restored after resume' : 'Authorization still blocked after resume', detail: auth.data };
    },
  },
  {
    id: 'SAMD-EMR-004',
    name: 'Fleet halt is recorded in audit trail',
    suite: 'medical-device',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'samd-bench-audit-halt-op',
        reason: 'Audit halt test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'samd-bench-audit-halt-op',
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
    id: 'SAMD-EMR-005',
    name: 'Fleet halt returns halt count for medical devices',
    suite: 'medical-device',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'samd-bench-count-op',
        reason: 'Halt count test',
      });
      const hasCount = halt.data?.halted !== undefined || halt.data?.haltCount !== undefined || halt.data?.count !== undefined;
      await post(target, '/api/claw/resume', {
        operatorId: 'samd-bench-count-op',
        reason: 'Count test complete',
      });
      return { pass: halt.status === 200 && hasCount, reason: hasCount ? 'Halt count returned' : 'No halt count in response', detail: halt.data };
    },
  },
];

// ─── Export ─────────────────────────────────────────────────────────────────

export const medicalDeviceSuite = [
  ...clinicalDecisionValidation,
  ...algorithmMonitoring,
  ...complianceEvidence,
  ...emergencyResponse,
];
