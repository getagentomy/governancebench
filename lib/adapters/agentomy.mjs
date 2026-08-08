/**
 * GovernanceBench -- Agentomy Adapter
 *
 * Maps GovernanceBench normalized test calls to Agentomy's /api/claw/* endpoints.
 * This is the default adapter. Used automatically when --adapter is not specified.
 */
// build-ref: ae4b64d7ea94

export default {
  name: 'Agentomy',

  endpoints: {
    // F5g body() signature is object-form: takes the suite-shaped body verbatim
    // and pass-through (Agentomy is the canonical / native target). Non-Agentomy
    // adapters translate the same object to native shape.
    authorize: {
      method: 'POST',
      path: '/api/claw/authorize',
      body: (b) => b,
    },
    log: {
      method: 'POST',
      path: '/api/claw/log',
      body: (b) => b,
    },
    halt: {
      method: 'POST',
      path: '/api/claw/halt',
      body: (b) => b,
    },
    resume: {
      method: 'POST',
      path: '/api/claw/resume',
      body: (b) => b,
    },
    status: {
      method: 'GET',
      path: '/api/claw/status/{agentId}',
    },
    health: {
      method: 'GET',
      path: '/api/claw/health',
    },
    auditExport: {
      method: 'GET',
      path: '/api/audit/export',
      // Query filters this platform claims to serve. Declared filters are held
      // to the same standard as declared endpoints: a rejected filter is a
      // failure, not an exemption (lib/endpoint-contract.mjs).
      params: ['limit', 'offset', 'startTime', 'endTime', 'agentId', 'eventType', 'search'],
    },
    auditExportPdf: {
      method: 'GET',
      path: '/api/audit/pdf',
    },
    auditIntegrity: {
      method: 'GET',
      path: '/api/audit/export/integrity',
    },
    monitorAlerts: {
      method: 'GET',
      path: '/api/monitor/alerts',
    },
    anomalyStatus: {
      method: 'GET',
      path: '/api/anomaly/status',
    },
    // Capabilities the suites probe by literal path. Declaring them here is what
    // makes their absence a scored failure on this platform while leaving them
    // skippable on adapters that do not claim them.
    anomalies: {
      method: 'GET',
      path: '/api/claw/anomalies',
    },
    agentMonitor: {
      method: 'GET',
      path: '/api/monitor/agent/{agentId}',
    },
    quarantine: {
      method: 'POST',
      path: '/api/claw/quarantine',
    },
    release: {
      method: 'POST',
      path: '/api/claw/release',
    },
    keyManagement: {
      method: 'POST',
      path: '/api/auth/keys',
    },
  },

  auth: {
    type: 'header',
    key: 'X-API-Key',
    envVar: 'AGENTOMY_API_KEY',
  },

  parseResponse: {
    authorized: (res) => res.authorized,
    tier: (res) => res.tier,
    auditId: (res) => res.auditId,
    haltCount: (res) => res.haltCount || res.agent_count,
    chainValid: (res) => res.integrity === 1.0 || res.chain_valid === true,
    fleetHalted: (res) => res.fleetHaltActive === true || res.halted === true,
  },
};
