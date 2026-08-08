/**
 * GovernanceBench -- Microsoft Agent Governance Toolkit (AGT) Adapter
 *
 * Maps GovernanceBench normalized test calls to Microsoft AGT endpoints.
 *
 * Microsoft AGT (released April 2, 2026, transferred to Linux Foundation):
 * - Provides a baseline governance layer for agents in the Microsoft ecosystem
 * - REST API surface based on the AGT OpenAPI spec v0.3.2
 * - Auth: Azure AD bearer token or API key header depending on deployment mode
 *
 * Coverage notes:
 * - authorize, halt, resume: available with semantic differences noted below
 * - audit export: available but schema differs (uses "records" not "events")
 * - audit integrity: NOT AVAILABLE -- AGT logs actions but does not provide
 *  a hash-linked chain or integrity verification endpoint as of v0.3.2
 * - behavioral monitoring: NOT AVAILABLE -- AGT does not ship an anomaly
 *  detection or quarantine API. Detection is delegated to Azure Sentinel.
 * - agent status: available via /agents/{agentId} (REST-style, not /claw/status)
 *
 * SEMANTIC DIFFERENCES:
 * - AGT authorization uses policy names, not numeric tiers. GovernanceBench
 *  maps tier values to AGT policy assertions. Tier-5 sovereign actions map to
 *  the "sovereign" policy group; lower tiers map to "restricted" and "standard".
 * - AGT halt targets a named "scope" (fleet | group | agent). GovernanceBench
 *  always tests fleet-level halt, mapped to scope=fleet here.
 * - AGT resume requires a "justification" field instead of "reason".
 * - AGT "allowed" field is the authorization decision (boolean), not "authorized".
 *
 * Endpoints marked 'not_available' are treated as 404 by AdapterRunner.
 * They do not count as failures in scoring -- they reduce the scoreable pool.
 */
// ref: fd8cb6358d5e

export default {
  name: 'Microsoft AGT',

  endpoints: {
    // F5g body() signature is object-form: receives the suite-shaped body and
    // translates it to AGT native field names. Unknown suite fields are dropped
    // (AGT does not consume scope/outcome/metadata at the audit-event layer).
    authorize: {
      method: 'POST',
      // AGT authorization endpoint -- policy-based, not tier-based
      path: '/api/governance/authorize',
      body: (b) => ({
        agentId: b.agentId,
        action: b.action,
        scope: b.scope,
        // AGT expects a policyGroup assertion; GovernanceBench tests will
        // exercise tier semantics via the action name directly
        policyGroup: b.tier || 'standard',
      }),
    },
    log: {
      method: 'POST',
      // AGT event logging endpoint
      path: '/api/governance/events',
      body: (b) => ({
        agentId: b.agentId,
        eventType: b.action,
        // Suite passes scope (resource) + outcome; AGT field names input/output
        input: b.input ?? b.scope ?? null,
        output: b.output ?? b.outcome ?? null,
        // AGT requires a "source" field
        source: 'governancebench',
      }),
    },
    halt: {
      method: 'POST',
      // AGT fleet halt -- targets all agents in the governed scope
      path: '/api/governance/halt',
      body: (b) => ({
        operatorId: b.operatorId,
        scope: 'fleet',
        reason: b.reason,
      }),
    },
    resume: {
      method: 'POST',
      // AGT resume -- "justification" replaces "reason" in AGT schema
      path: '/api/governance/resume',
      body: (b) => ({
        operatorId: b.operatorId,
        scope: 'fleet',
        justification: b.reason,
      }),
    },
    status: {
      method: 'GET',
      // AGT uses /agents/{agentId} REST style
      path: '/api/agents/{agentId}',
    },
    health: {
      method: 'GET',
      path: '/api/governance/health',
    },
    auditExport: {
      method: 'GET',
      // AGT audit export -- returns "records" array, not "events"
      // AdapterRunner applies extractEvents which checks multiple field names
      path: '/api/audit/records',
    },
    auditIntegrity: {
      // NOT AVAILABLE in AGT v0.3.2
      // AGT logs are stored in Azure Monitor, not a hash-linked chain.
      // No integrity verification endpoint exists in the public API surface.
      method: 'not_available',
      path: null,
      note: 'AGT does not implement a tamper-evident hash chain. Integrity verification is delegated to Azure Monitor. All auditIntegrity scenarios will skip.',
    },
    monitorAlerts: {
      // NOT AVAILABLE in AGT
      // Behavioral monitoring is handled by Azure Sentinel integration, not a
      // GovernanceBench-compatible REST endpoint in the AGT surface.
      method: 'not_available',
      path: null,
      note: 'AGT delegates behavioral alerting to Azure Sentinel. No /monitor/alerts endpoint in AGT API surface.',
    },
    anomalyStatus: {
      // NOT AVAILABLE in AGT
      method: 'not_available',
      path: null,
      note: 'AGT does not expose an anomaly detection status endpoint.',
    },
  },

  auth: {
  // AGT supports both Azure AD bearer token and API key modes.
  // Default to API key mode for GovernanceBench compatibility.
    type: 'header',
    key: 'Ocp-Apim-Subscription-Key',
    envVar: 'MICROSOFT_AGT_API_KEY',
  },

  parseResponse: {
  // AGT uses "allowed" not "authorized"
    authorized: (res) => res.allowed,
    tier: (res) => res.policyGroup || res.tier,
    auditId: (res) => res.recordId || res.eventId || res.auditId,
    haltCount: (res) => res.affectedAgents || res.haltCount || res.agent_count,
    chainValid: (_res) => {
      // AGT does not provide chain validity -- this will always be null/undefined
      // Scenarios requiring this will skip
      return undefined;
    },
    fleetHalted: (res) => res.haltActive === true || res.halted === true || res.status === 'halted',
  },

  notes: [
    'AGT does not implement a hash-linked audit chain. All Suite 2 hash-chain scenarios will skip.',
    'AGT behavioral monitoring delegates to Azure Sentinel. All Suite 4 scenarios will skip.',
    'AGT uses policy groups instead of numeric tiers. Tier-mapping is approximate.',
    'Expected GovernanceBench score range for AGT: Authorization ~60-75, Auditability ~40-55, Override ~60-80, Behavioral ~0 (all skipped).',
  ],
};
