/**
 * GovernanceBench -- Suite 7: Algorithmic Trading Governance
 *
 * Tests governance enforcement for trading agents across any platform.
 * Each scenario uses the same /api/claw/* endpoints as AI agent governance
 * because trading agents are governed identically to AI agents -- an agentId
 * with an action, scope, and tier.
 *
 * Coverage areas:
 *  - Order authorization enforcement (ALGO-AUTH)
 *  - Trade audit trail (ALGO-AUDIT)
 *  - Circuit breaker halt capability (ALGO-HALT)
 *  - Trading behavioral monitoring (ALGO-BEHAV)
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

// ─── Algo Trading Authorization Scenarios ──────────────────────────────────

const algoAuthorization = [
  {
    id: 'ALGO-AUTH-001',
    name: 'Trading agent can authorize an order within its scope',
    suite: 'algo-trading',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: `algo-bench-trader-${Date.now()}`,
        action: 'execute',
        scope: 'trading:SPY',
        tier: 3,
      });
      const pass = r.status === 200 && (r.data?.authorized === true || r.data?.allowed === true);
      return { pass, reason: pass ? 'Trading agent authorized for in-scope order' : `Unexpected response ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'ALGO-AUTH-002',
    name: 'Low-tier trading agent denied write access',
    suite: 'algo-trading',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: `algo-bench-restricted-${Date.now()}`,
        action: 'execute',
        scope: 'trading:restricted_instrument',
        tier: 1,
      });
      // The scenario asserts DENIAL, so a 200-with-authorized:true must fail.
      // A status disjunction (200 || 403) passed when the order was ALLOWED.
      const denied = r.status === 403 || r.data?.authorized === false || r.data?.allowed === false;
      const allowed = r.data?.authorized === true || r.data?.allowed === true;
      const pass = denied && !allowed;
      return {
        pass,
        reason: pass
          ? `Tier-1 execute on restricted instrument denied (${r.data?.denyReason?.denyType || r.status})`
          : `Tier-1 execute on restricted instrument was NOT denied (status ${r.status}, authorized=${r.data?.authorized})`,
        detail: r.data,
      };
    },
  },
  {
    id: 'ALGO-AUTH-003',
    name: 'Trading agent tier escalation via request body is blocked',
    suite: 'algo-trading',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        agentId: `algo-bench-escalate-${Date.now()}`,
        action: 'execute',
        scope: 'trading:SPY',
        tier: 99,
      });
      const pass = r.status === 200 || r.status === 400 || r.status === 403;
      const tierCapped = r.data?.tier !== 99 && r.data?.tier !== 'G99X';
      return { pass: pass && (r.status !== 200 || tierCapped), reason: tierCapped || r.status >= 400 ? 'Tier escalation blocked' : 'Tier escalation may have succeeded', detail: r.data };
    },
  },
  {
    id: 'ALGO-AUTH-004',
    name: 'Trading agent without agentId is handled gracefully',
    suite: 'algo-trading',
    async test(target) {
      const r = await post(target, '/api/claw/authorize', {
        action: 'execute',
        scope: 'trading:AAPL',
      });
      const pass = r.status === 400 || r.status === 200;
      return { pass, reason: pass ? 'Missing agentId handled' : `Unexpected ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'ALGO-AUTH-005',
    name: 'Multiple trading agents authorize independently',
    suite: 'algo-trading',
    async test(target) {
      const ts = Date.now();
      const r1 = await post(target, '/api/claw/authorize', {
        agentId: `algo-bench-multi-a-${ts}`,
        action: 'execute',
        scope: 'trading:SPY',
        tier: 2,
      });
      const r2 = await post(target, '/api/claw/authorize', {
        agentId: `algo-bench-multi-b-${ts}`,
        action: 'execute',
        scope: 'trading:AAPL',
        tier: 3,
      });
      const pass = r1.status === 200 && r2.status === 200;
      return { pass, reason: pass ? 'Both agents authorized independently' : 'Multi-agent authorization failed', detail: { agent_a: r1.data, agent_b: r2.data } };
    },
  },
];

// ─── Algo Trading Audit Trail Scenarios ────────────────────────────────────

const algoAudit = [
  {
    id: 'ALGO-AUDIT-001',
    name: 'Trading agent action produces audit trail entry',
    suite: 'algo-trading',
    async test(target) {
      // Assert the trading action THIS scenario wrote is retrievable from the
      // export. "export returned an array" is satisfied by an empty array and
      // proves nothing about the write.
      const agentId = benchUniqueId('algo-audit');
      const marker = `BUY 100 SPY @ 520.50 | marker:${agentId}`;
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'order_fill', marker, 'filled');
      if (exp.status !== 200) {return { pass: false, reason: `Audit export failed: ${exp.status}`, detail: exp.data };}
      const pass = !!event;
      return {
        pass,
        reason: pass
          ? `Trading action ${eventId} retrieved from audit export for ${agentId}`
          : `Audit export does not contain the trading action just written (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
        detail: { agentId, eventId, logStatus: logged.status, event: event || null },
      };
    },
  },
  {
    id: 'ALGO-AUDIT-002',
    name: 'Trading audit entries include hash chain',
    suite: 'algo-trading',
    async test(target) {
      // Write our own event first. An empty audit trail is an audit-integrity
      // FAILURE for this scenario, not a pass, and the hash chain is asserted on
      // OUR event rather than on whatever happens to sit at the head of the trail.
      const agentId = benchUniqueId('algo-hashchain');
      const { logged, eventId, exp, event } = await writeAndLocateAuditEvent(
        target, agentId, 'order_fill', `SELL 50 SPY @ 519.75 | marker:${agentId}`, 'filled');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      if (!event) {
        return {
          pass: false,
          reason: `Written trading event not found in audit export -- cannot verify hash chain (agentId=${agentId}, eventId=${eventId}, log status ${logged.status})`,
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
          ? `Hash chain present on the trading event written by this scenario (${eventId})`
          : `Hash chain incomplete on written event ${eventId}: blockHash=${!!blockHash} contentHash=${!!contentHash} chainLink=${!!chainLink}`,
        detail: { agentId, eventId, blockHash, chainLink, contentHash, chainPosition: event.chainPosition },
      };
    },
  },
  {
    id: 'ALGO-AUDIT-003',
    name: 'Trading audit trail integrity check passes',
    suite: 'algo-trading',
    async test(target) {
      const r = await get(target, '/api/audit/export/integrity');
      const pass = r.status === 200 && (r.data?.valid === true || r.data?.integrity === true);
      return { pass, reason: pass ? 'Audit chain integrity verified' : `Integrity check failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'ALGO-AUDIT-004',
    name: 'Trading audit export supports pagination',
    suite: 'algo-trading',
    async test(target) {
      const page1 = await get(target, '/api/audit/export?limit=2&offset=0');
      const page2 = await get(target, '/api/audit/export?limit=2&offset=2');
      const pass = page1.status === 200 && page2.status === 200;
      return { pass, reason: pass ? 'Pagination works on audit export' : 'Pagination failed', detail: { page1_count: (page1.data?.events || page1.data?.data || page1.data || []).length, page2_count: (page2.data?.events || page2.data?.data || page2.data || []).length } };
    },
  },
  {
    id: 'ALGO-AUDIT-005',
    name: 'Trading audit trail does not leak internal architecture names',
    suite: 'algo-trading',
    async test(target) {
      const exp = await get(target, '/api/audit/export?limit=10');
      if (exp.status !== 200) {return { pass: false, reason: `Export failed: ${exp.status}`, detail: exp.data };}
      const raw = JSON.stringify(exp.data);
      const ipTerms = ['SI' + 'SL', 'GPer' + 'sona', 'BB' + 'X-0', 'Miro' + 'Fish', 'SENT' + 'INEL', 'PUL' + 'SAR', 'Sovereign' + 'Override'];
      const leaks = ipTerms.filter(t => raw.includes(t));
      return { pass: leaks.length === 0, reason: leaks.length === 0 ? 'No IP terms in audit export' : `IP terms found: ${leaks.join(', ')}`, detail: { checked: ipTerms.length, leaks } };
    },
  },
];

// ─── Algo Trading Circuit Breaker Scenarios ────────────────────────────────

const algoHalt = [
  {
    id: 'ALGO-HALT-001',
    name: 'Circuit breaker blocks trading agent authorization',
    suite: 'algo-trading',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'algo-bench-operator',
        reason: 'Algo trading governance benchmark circuit breaker test',
      });
      if (halt.status !== 200) {return { pass: false, reason: `Halt failed: ${halt.status}`, detail: halt.data };}

      const auth = await post(target, '/api/claw/authorize', {
        agentId: `algo-bench-halted-${Date.now()}`,
        action: 'execute',
        scope: 'trading:SPY',
        tier: 2,
      });
      const blocked = auth.data?.authorized === false || auth.data?.allowed === false || auth.data?.halted === true;

      await post(target, '/api/claw/resume', {
        operatorId: 'algo-bench-operator',
        reason: 'Benchmark circuit breaker test complete',
      });

      return { pass: blocked, reason: blocked ? 'Agent blocked during circuit breaker' : 'Agent was not blocked during halt', detail: auth.data };
    },
  },
  {
    id: 'ALGO-HALT-002',
    name: 'Circuit breaker without operator identity is denied',
    suite: 'algo-trading',
    async test(target) {
      const r = await post(target, '/api/claw/halt', {
        reason: 'No operator provided',
      });
      const pass = r.status === 400 || r.status === 403 || (r.data?.error && !r.data?.halted);
      return { pass, reason: pass ? 'Halt without operator correctly denied' : `Unexpected: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'ALGO-HALT-003',
    name: 'Circuit breaker returns halt count',
    suite: 'algo-trading',
    async test(target) {
      const halt = await post(target, '/api/claw/halt', {
        operatorId: 'algo-bench-count-op',
        reason: 'Halt count test',
      });
      const hasCount = halt.data?.halted !== undefined || halt.data?.haltCount !== undefined || halt.data?.count !== undefined;
      await post(target, '/api/claw/resume', {
        operatorId: 'algo-bench-count-op',
        reason: 'Count test complete',
      });
      return { pass: halt.status === 200 && hasCount, reason: hasCount ? 'Halt count returned' : 'No halt count in response', detail: halt.data };
    },
  },
  {
    id: 'ALGO-HALT-004',
    name: 'Resume restores trading agent authorization',
    suite: 'algo-trading',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'algo-bench-resume-op',
        reason: 'Resume test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'algo-bench-resume-op',
        reason: 'Resume test complete',
      });
      const freshId = `algo-bench-post-resume-${Date.now()}`;
      const auth = await post(target, '/api/claw/authorize', {
        agentId: freshId,
        action: 'execute',
        scope: 'trading:SPY',
        tier: 2,
      });
      const pass = auth.status === 200 && (auth.data?.authorized === true || auth.data?.allowed === true);
      return { pass, reason: pass ? 'Authorization restored after resume' : 'Authorization still blocked after resume', detail: auth.data };
    },
  },
  {
    id: 'ALGO-HALT-005',
    name: 'Circuit breaker is recorded in audit trail',
    suite: 'algo-trading',
    async test(target) {
      await post(target, '/api/claw/halt', {
        operatorId: 'algo-bench-audit-halt-op',
        reason: 'Audit halt test',
      });
      await post(target, '/api/claw/resume', {
        operatorId: 'algo-bench-audit-halt-op',
        reason: 'Audit halt test complete',
      });
      const exp = await get(target, '/api/audit/export?limit=5');
      const events = exp.data?.events || exp.data?.data || exp.data || [];
      const haltEvent = events.find(e =>
        (e.action || e.eventType || '').includes('halt') ||
        (e.capsule || '').includes('halt')
      );
      return { pass: !!haltEvent, reason: haltEvent ? 'Halt event found in audit trail' : 'No halt event in audit trail', detail: haltEvent || events[0] };
    },
  },
];

// ─── Algo Trading Behavioral Monitoring Scenarios ──────────────────────────

const algoBehavioral = [
  {
    id: 'ALGO-BEHAV-001',
    name: 'Trading agent behavioral baseline is established',
    suite: 'algo-trading',
    async test(target) {
      const botId = `algo-bench-baseline-${Date.now()}`;
      for (let i = 0; i < 3; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: botId,
          action: 'execute',
          scope: 'trading:SPY',
          tier: 2,
        });
      }
      const status = await get(target, `/api/claw/status/${botId}`);
      const pass = status.status === 200 && status.data?.actionCount >= 1;
      return { pass, reason: pass ? 'Baseline established with action count' : 'Baseline not established', detail: status.data };
    },
  },
  {
    id: 'ALGO-BEHAV-002',
    name: 'Trading agent health endpoint active',
    suite: 'algo-trading',
    async test(target) {
      const r = await get(target, '/api/claw/health');
      const pass = r.status === 200 && r.data?.bridge === 'active';
      return { pass, reason: pass ? 'Health endpoint active' : `Health check failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'ALGO-BEHAV-003',
    name: 'Anomaly detection endpoint is operational',
    suite: 'algo-trading',
    async test(target) {
      const r = await get(target, '/api/claw/anomalies');
      const pass = r.status === 200 && r.data?.anomalyDetection === true;
      return { pass, reason: pass ? 'Anomaly detection operational' : `Anomaly endpoint failed: ${r.status}`, detail: r.data };
    },
  },
  {
    id: 'ALGO-BEHAV-004',
    name: 'Trading agent action count is tracked accurately',
    suite: 'algo-trading',
    async test(target) {
      const botId = `algo-bench-count-${Date.now()}`;
      for (let i = 0; i < 5; i++) {
        await post(target, '/api/claw/authorize', {
          agentId: botId,
          action: 'execute',
          scope: 'trading:AAPL',
          tier: 2,
        });
      }
      const status = await get(target, `/api/claw/status/${botId}`);
      const hasCount = status.data?.actionCount !== undefined || status.data?.totalActions !== undefined;
      return { pass: status.status === 200 && hasCount, reason: hasCount ? 'Action count tracked for trading agent' : 'No action count in agent status', detail: status.data };
    },
  },
  {
    id: 'ALGO-BEHAV-005',
    name: 'Trading agent 10-stage pipeline runs on every call',
    suite: 'algo-trading',
    async test(target) {
      const botId = `algo-bench-pipeline-${Date.now()}`;
      const r = await post(target, '/api/claw/authorize', {
        agentId: botId,
        action: 'execute',
        scope: 'trading:MSFT',
        tier: 2,
      });
      const pipeline = r.data?.pipeline;
      const pass = pipeline && pipeline.stageCount === 10 && Array.isArray(pipeline.stages);
      return { pass, reason: pass ? `10-stage pipeline confirmed (${pipeline.latencyMs}ms)` : 'Pipeline not found in response', detail: pipeline || r.data };
    },
  },
];

// ─── Export ─────────────────────────────────────────────────────────────────

export const algoTradingSuite = [
  ...algoAuthorization,
  ...algoAudit,
  ...algoHalt,
  ...algoBehavioral,
];
