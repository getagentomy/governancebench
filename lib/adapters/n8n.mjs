/**
 * GovernanceBench -- n8n Adapter
 *
 * Maps GovernanceBench normalized test calls to n8n REST API endpoints.
 *
 * n8n (released 2019; self-host + n8n.cloud; fair-code Sustainable Use License
 * for the core engine since 2022, community nodes remain Apache-2.0):
 * - Provides workflow orchestration with a node-graph execution model
 * - REST API surface at /api/v1/* (workflows, executions, credentials, users)
 * - Webhook surface at /webhook/{path} for trigger nodes
 * - Auth: X-N8N-API-KEY header (Personal Access Token)
 *
 * ARCHITECTURAL NOTE:
 * n8n is a workflow runtime, not a governance platform in the GovernanceBench
 * sense. It does not expose:
 * - An authorization tier API (workflows are owned by users, not tiered)
 * - An audit trail export endpoint (executions are logged but not exported
 *   via REST in a governance-event shape)
 * - A hash-linked chain integrity endpoint (executions are stored in SQLite/
 *   Postgres but no integrity verification surface)
 * - A fleet halt / resume mechanism (workflows are individually activated /
 *   deactivated)
 * - A behavioral anomaly detection API (workflow failures are visible per
 *   execution but no anomaly-detection surface)
 *
 * The closest n8n-native primitive for each GovernanceBench dimension is
 * documented below as 'partial' or 'not_available'. n8n's stock posture
 * therefore scores low on agent-shape GovernanceBench. Agentomy-governed n8n
 * (via the @agentomy/n8n-nodes package, Track B5) lifts this materially: the
 * Authorize / Audit Action / IPI Guard / Policy Check / Halt Trigger nodes
 * route through Agentomy's governance server before n8n executes downstream.
 *
 * COVERAGE TABLE (Slice 4 mapping):
 * - authorize: NOT AVAILABLE (n8n has no tier-based authorization API)
 * - audit log:   PARTIAL  (execution history exists at /api/v1/executions/{id};
 *                schema differs from GovernanceBench audit-event shape)
 * - halt / resume: PARTIAL (per-workflow PATCH /api/v1/workflows/{id} active=false;
 *                no fleet-scope halt)
 * - audit integrity: NOT AVAILABLE
 * - behavioral monitoring: NOT AVAILABLE
 *
 * Endpoints marked 'not_available' are treated as 404 by AdapterRunner.
 * They do not count as failures in scoring -- they reduce the scoreable pool.
 *
 * Expected GovernanceBench score range for stock n8n: Authorization ~0-10,
 * Auditability ~15-30, Override ~20-35, Behavioral ~0, OWASP ~10-20.
 * Overall: ~10-20/100. Agentomy-governed n8n (Track C will measure live):
 * substantially higher per the Track B node set.
 */

export default {
  name: 'n8n',

  endpoints: {
    authorize: {
      // NOT AVAILABLE in stock n8n: no tier-authorization API.
      // Workflows are owned by users (RBAC at user level, not action level).
      method: 'not_available',
      path: null,
      note: 'n8n has no tier-based authorization endpoint. Workflows execute based on activation state + user RBAC, not per-action tier checks.',
    },
    log: {
      // PARTIAL: n8n logs executions but the shape differs from GovernanceBench
      // event-level audit-write. The closest analog is creating an execution
      // record, which happens automatically on workflow trigger.
      method: 'not_available',
      path: null,
      note: 'n8n records executions automatically on workflow trigger; no explicit "log event" REST endpoint exists. Audit-event-level write is not directly addressable.',
    },
    halt: {
      // PARTIAL: per-workflow deactivation. No fleet-scope halt primitive.
      // F5g body() object-form: n8n PATCH workflow does not accept operator/
      // reason fields (captured in deactivation audit log automatically); body
      // is empty regardless of what the suite passes.
      method: 'POST',
      path: '/api/v1/workflows/{workflowId}/deactivate',
      body: (_b) => ({}),
      note: 'Halt is per-workflow only. No fleet-scope halt exists. operatorId and reason are not persisted at the platform level.',
    },
    resume: {
      method: 'POST',
      path: '/api/v1/workflows/{workflowId}/activate',
      body: (_b) => ({}),
      note: 'Resume is per-workflow activation. No justification field exists.',
    },
    status: {
      method: 'GET',
      path: '/api/v1/workflows/{workflowId}',
    },
    health: {
      method: 'GET',
      path: '/healthz',
    },
    auditExport: {
      // n8n /api/v1/executions returns workflow executions, not governance-event-shape audit
      method: 'GET',
      path: '/api/v1/executions',
    },
    auditIntegrity: {
      // NOT AVAILABLE: n8n executions stored in DB but no hash-linked chain or integrity endpoint
      method: 'not_available',
      path: null,
      note: 'n8n executions are stored in SQLite/Postgres without hash-chain integrity. No verification endpoint.',
    },
    monitorAlerts: {
      // NOT AVAILABLE: no behavioral-anomaly REST surface
      method: 'not_available',
      path: null,
      note: 'n8n does not expose a behavioral anomaly detection endpoint. Workflow failures are visible per-execution but not aggregated as anomalies.',
    },
    anomalyStatus: {
      method: 'not_available',
      path: null,
      note: 'n8n does not expose an anomaly status endpoint.',
    },
  },

  auth: {
    type: 'header',
    key: 'X-N8N-API-KEY',
    envVar: 'N8N_API_KEY',
  },

  parseResponse: {
    // n8n does not return "authorized" in any response (no auth endpoint)
    authorized: (_res) => undefined,
    tier: (_res) => undefined,
    auditId: (res) => res.id || res.executionId,
    haltCount: (_res) => 1, // per-workflow halt halts exactly 1 workflow
    chainValid: (_res) => undefined,
    fleetHalted: (res) => res.active === false,
  },

  notes: [
    'n8n is a workflow runtime, not a governance platform in the GovernanceBench sense.',
    'Stock n8n exposes per-workflow activation but no fleet-scope halt; no tier-authorization endpoint; no hash-linked audit chain; no behavioral anomaly API.',
    'Expected GovernanceBench score range for stock n8n: ~10-20/100. Agentomy-governed n8n (via @agentomy/n8n-nodes) materially uplifts via Authorize / Audit Action / IPI Guard / Policy Check nodes routing through Agentomy governance server before downstream node execution.',
    'For workflow-class threats (trigger-spoofing / cascade-poisoning / audit-bypass / cross-workflow-leak / supply-chain / replay-tampering), see WorkflowBench (cli/workflowbench/) which scores the workflow-shape surface that GovernanceBench does not cover.',
  ],
};
