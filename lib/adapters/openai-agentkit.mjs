/**
 * GovernanceBench -- OpenAI AgentKit Guardrails Adapter
 *
 * Maps GovernanceBench normalized test calls to OpenAI AgentKit endpoints.
 *
 * OpenAI AgentKit (Responses API + Guardrails, 2025-2026):
 * - Provides input/output content filtering via guardrail policies
 * - REST API surface via the Responses API with assistant-level guardrails
 * - Auth: Bearer token (OpenAI API key)
 *
 * ARCHITECTURAL NOTE:
 * OpenAI AgentKit is a build-time and inference-time tool framework, not a
 * governance platform in the GovernanceBench sense. It does not expose:
 * - An authorization tier API
 * - An audit trail export endpoint
 * - A hash-linked chain integrity endpoint
 * - A fleet halt / resume mechanism
 * - A behavioral anomaly detection API
 *
 * The only governance-adjacent surface is the guardrail evaluation endpoint,
 * which checks whether content passes configured policies. This maps partially
 * to GovernanceBench's authorization dimension (content-level policy check),
 * but does not enforce agent identity tiers, scope restrictions, or kill switch.
 *
 * EXPECTED SCORE PROFILE:
 * - Authorization: ~20-35 (content policy check only; tier mechanics not present)
 * - Auditability: 0 (all scenarios skip; no audit export endpoint)
 * - Override: 0 (all scenarios skip; no halt/resume endpoint)
 * - Behavioral: 0 (all scenarios skip; no anomaly/monitor endpoint)
 * - Overall: ~5-10
 *
 * This adapter is useful for benchmarking the gap between content guardrails
 * and full governance. The low score is not a flaw in the adapter -- it reflects
 * what AgentKit actually provides vs. what enterprise agent governance requires.
 */
// build-ref: a200e223ccab

export default {
  name: 'OpenAI AgentKit',

  endpoints: {
    authorize: {
      // AgentKit's closest equivalent: guardrail evaluation
      // Checks whether a proposed action passes content policy
      // Does not enforce tier-based permissions
      method: 'POST',
      path: '/v1/responses',
      body: (agentId, action, scope) => ({
        model: 'gpt-4o',
        input: `Governance check: agent=${agentId} action=${action} scope=${scope}`,
        // Guardrail evaluation is triggered by assistant-level policy config,
        // not by this body. The endpoint will process the input through
        // whatever guardrails are configured on the assistant.
        metadata: {
          agent_id: agentId,
          governance_action: action,
          governance_scope: scope,
        },
      }),
    },
    log: {
      // NOT AVAILABLE
      // AgentKit does not expose a governance event logging endpoint.
      // Activity is logged internally to OpenAI platform logs (not exportable via API).
      method: 'not_available',
      path: null,
      note: 'AgentKit does not provide a governance event log endpoint. Platform activity is stored internally and not exportable in a GovernanceBench-compatible format.',
    },
    halt: {
      // NOT AVAILABLE
      // AgentKit has no fleet halt or kill switch mechanism.
      // There is no way to halt all governed agents via a single API call.
      method: 'not_available',
      path: null,
      note: 'AgentKit has no halt endpoint. Fleet-level emergency stop is not part of the AgentKit API surface.',
    },
    resume: {
      // NOT AVAILABLE
      method: 'not_available',
      path: null,
      note: 'AgentKit has no resume endpoint. No halt state exists to resume from.',
    },
    status: {
      // Partial: assistants can be retrieved, but status is not a governance concept in AgentKit
      method: 'GET',
      path: '/v1/assistants/{agentId}',
    },
    health: {
      // OpenAI does not expose a public health/readiness endpoint for the API
      method: 'not_available',
      path: null,
      note: 'OpenAI does not expose a governance health endpoint. Platform status is available at status.openai.com but not via the API.',
    },
    auditExport: {
      // NOT AVAILABLE
      // OpenAI platform logs are not exportable via the public API.
      method: 'not_available',
      path: null,
      note: 'AgentKit does not expose an audit export endpoint. Platform logs are internal to OpenAI.',
    },
    auditIntegrity: {
      // NOT AVAILABLE
      method: 'not_available',
      path: null,
      note: 'AgentKit does not implement a hash-linked audit chain or integrity endpoint.',
    },
    monitorAlerts: {
      // NOT AVAILABLE
      method: 'not_available',
      path: null,
      note: 'AgentKit does not expose a behavioral monitoring or alerts endpoint.',
    },
    anomalyStatus: {
      // NOT AVAILABLE
      method: 'not_available',
      path: null,
      note: 'AgentKit does not implement agent-level anomaly detection.',
    },
  },

  auth: {
    type: 'header',
    key: 'Authorization',
    envVar: 'OPENAI_API_KEY',
    prefix: 'Bearer ',
  },

  parseResponse: {
  // AgentKit guardrail results are in the response content, not a governance field
  // "authorized" maps to: did the content pass the guardrail without being flagged?
    authorized: (res) => {
      // If status is not refusal, treat as permitted
      if (res.status === 'completed') {return true;}
      if (res.status === 'incomplete' || res.output_text?.includes('refusal')) {return false;}
      return undefined;
    },
    tier: (_res) => undefined, // No tier concept in AgentKit
    auditId: (res) => res.id, // Response ID is the closest analog
    haltCount: (_res) => undefined, // No halt concept
    chainValid: (_res) => undefined, // No chain concept
    fleetHalted: (_res) => false, // Halt is not available
  },

  notes: [
    'AgentKit is a guardrails framework, not a governance platform. Most GovernanceBench dimensions do not apply.',
    'Only the authorization suite runs against a real endpoint. All other suites skip.',
    'Authorization tests map GovernanceBench tier-action checks to guardrail content policy. Tier semantics are not enforced.',
    'The low overall score reflects the governance gap, not a defect in the adapter.',
    'For a meaningful comparison: Agentomy score - AgentKit score = governance gap that needs to be filled.',
  ],
};
