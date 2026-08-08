/**
 * GovernanceBench -- Adapter Runner
 *
 * Wraps all HTTP calls through an adapter's endpoint mapping.
 * Normalizes responses through the adapter's parseResponse functions.
 * Handles auth header injection from adapter config.
 *
 * AdapterRunner is the translation layer between GovernanceBench's
 * normalized test API and a target platform's actual endpoint schema.
 *
 * Usage in suites (future use -- current suites call endpoints directly):
 *  const runner = new AdapterRunner('http://target:3000', adapter);
 *  const result = await runner.authorize('agent-1', 'read', 'documents');
 *  // result: { authorized: true, tier: '2', auditId: 'evt-123', raw: {...} }
 */

/**
 * Load an adapter by name or config path.
 *
 * @param {string} adapterName - 'agentomy' | 'generic' | 'microsoft-agt' | 'openai-agentkit' | 'n8n'
 * @param {string|null} configPath - Required when adapterName === 'generic'
 * @returns {Promise<object>} Resolved adapter config object
 */
export async function loadAdapter(adapterName, configPath = null) {
  const name = adapterName.toLowerCase().trim();
  // build-ref: bd5fc881cd33

  if (name === 'agentomy') {
    const mod = await import('./adapters/agentomy.mjs');
    return mod.default;
  }

  if (name === 'generic') {
    if (!configPath) {
      throw new Error('Generic adapter requires --config <path> pointing to a JSON adapter config file.');
    }
    const mod = await import('./adapters/generic.mjs');
    return mod.loadGenericAdapter(configPath);
  }

  if (name === 'microsoft-agt' || name === 'microsoft_agt' || name === 'agt') {
    const mod = await import('./adapters/microsoft-agt.mjs');
    return mod.default;
  }

  if (name === 'openai-agentkit' || name === 'openai_agentkit' || name === 'agentkit') {
    const mod = await import('./adapters/openai-agentkit.mjs');
    return mod.default;
  }

  if (name === 'n8n' || name === 'n8n-workflow' || name === 'workflow-n8n') {
    const mod = await import('./adapters/n8n.mjs');
    return mod.default;
  }

  throw new Error(
    `Unknown adapter: "${adapterName}". Available adapters: agentomy, generic, microsoft-agt, openai-agentkit, n8n`
  );
}

/**
 * Build request headers for a given adapter config.
 *
 * @param {object} auth - Adapter auth config ({ type, key, envVar, prefix })
 * @returns {object} Headers object
 */
function buildAuthHeaders(auth) {
  if (!auth) {return {};}

  const headers = {};

  if (auth.type === 'header' && auth.key && auth.envVar) {
    const apiKey = process.env[auth.envVar];
    if (apiKey) {
      const prefix = auth.prefix || '';
      headers[auth.key] = `${prefix}${apiKey}`;
    }
  }

  if (auth.type === 'bearer' && auth.envVar) {
    const token = process.env[auth.envVar];
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  return headers;
}

/**
 * Resolve a path template, substituting {agentId} and other tokens.
 *
 * @param {string} pathTemplate - e.g. '/api/claw/status/{agentId}'
 * @param {object} params - e.g. { agentId: 'agent-123' }
 * @returns {string} Resolved path
 */
function resolvePath(pathTemplate, params = {}) {
  let path = pathTemplate;
  for (const [key, value] of Object.entries(params)) {
    path = path.replace(`{${key}}`, encodeURIComponent(String(value)));
  }
  return path;
}

/**
 * Execute an HTTP request through an adapter endpoint definition.
 *
 * @param {string} target - Base URL (no trailing slash)
 * @param {object} endpointDef - Endpoint definition from adapter.endpoints
 * @param {object} auth - Adapter auth config
 * @param {object} options - { body, pathParams, queryString, timeout }
 * @returns {Promise<{ status: number, data: object, raw: string }>}
 */
async function adapterFetch(target, endpointDef, auth, options = {}) {
  const { body = null, pathParams = {}, queryString = '', timeout = 10000 } = options;

  // 'not_available' endpoints simulate a 404 without making a network call
  if (endpointDef.method === 'not_available' || !endpointDef.path) {
    return { status: 404, data: { skipped: true, note: endpointDef.note || 'Endpoint not available in this adapter' }, raw: '' };
  }

  const resolvedPath = resolvePath(endpointDef.path, pathParams);
  const url = `${target}${resolvedPath}${queryString ? '?' + queryString : ''}`;

  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...buildAuthHeaders(auth),
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const fetchOptions = {
      method: endpointDef.method,
      headers,
      signal: controller.signal,
    };

    if (body !== null && endpointDef.method !== 'GET' && endpointDef.method !== 'HEAD') {
      fetchOptions.body = JSON.stringify(body);
    }

    const res = await fetch(url, fetchOptions);
    clearTimeout(timer);

    let data;
    const rawText = await res.text();
    try {
      data = JSON.parse(rawText);
    } catch {
      data = {};
    }

    return { status: res.status, data, raw: rawText };
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {throw new Error(`Request timed out after ${timeout}ms`);}
    throw err;
  }
}

/**
 * AdapterRunner
 *
 * Wraps GovernanceBench's normalized operation set through a loaded adapter.
 * Returns standardized result objects that test scenarios can consume.
 */
export class AdapterRunner {
  /**
  * @param {string} target - Base URL of the governance platform (no trailing slash)
  * @param {object} adapter - Loaded adapter config object
  * @param {object} options - { timeout: number }
  */
  constructor(target, adapter, options = {}) {
    this.target = target.replace(/\/$/, '');
    this.adapter = adapter;
    this.timeout = options.timeout || 10000;
  }

  /**
  * Check whether an agent action is authorized.
  *
  * @param {string} agentId
  * @param {string} action
  * @param {string} scope
  * @param {object} extra - Additional fields merged into request body
  * @returns {Promise<{ authorized: boolean|undefined, tier: string|undefined, auditId: string|undefined, status: number, raw: object }>}
  */
  async authorize(agentId, action, scope, extra = {}) {
    const ep = this.adapter.endpoints.authorize;
    const bodyFn = ep.body || ((id, act, sc) => ({ agentId: id, action: act, scope: sc }));
    const body = { ...bodyFn(agentId, action, scope), ...extra };

    const res = await adapterFetch(this.target, ep, this.adapter.auth, { body, timeout: this.timeout });

    const parse = this.adapter.parseResponse || {};
    return {
      authorized: parse.authorized ? parse.authorized(res.data) : res.data?.authorized,
      tier: parse.tier ? parse.tier(res.data) : res.data?.tier,
      auditId: parse.auditId ? parse.auditId(res.data) : res.data?.auditId,
      status: res.status,
      raw: res.data,
    };
  }

  /**
  * Log a governance event.
  *
  * @param {string} agentId
  * @param {string} action
  * @param {*} input
  * @param {*} output
  * @param {object} extra
  * @returns {Promise<{ auditId: string|undefined, status: number, raw: object }>}
  */
  async log(agentId, action, input = null, output = null, extra = {}) {
    const ep = this.adapter.endpoints.log;
    const bodyFn = ep.body || ((id, act, i, o) => ({ agentId: id, action: act, input: i, output: o }));
    const body = { ...bodyFn(agentId, action, input, output), ...extra };

    const res = await adapterFetch(this.target, ep, this.adapter.auth, { body, timeout: this.timeout });

    const parse = this.adapter.parseResponse || {};
    return {
      auditId: parse.auditId ? parse.auditId(res.data) : (res.data?.auditId || res.data?.id),
      status: res.status,
      raw: res.data,
    };
  }

  /**
  * Execute a fleet halt.
  *
  * @param {string} operatorId
  * @param {string} reason
  * @returns {Promise<{ fleetHalted: boolean|undefined, haltCount: number|undefined, status: number, raw: object }>}
  */
  async halt(operatorId, reason) {
    const ep = this.adapter.endpoints.halt;
    const bodyFn = ep.body || ((id, r) => ({ operatorId: id, reason: r }));
    const body = bodyFn(operatorId, reason);

    const res = await adapterFetch(this.target, ep, this.adapter.auth, { body, timeout: this.timeout });

    const parse = this.adapter.parseResponse || {};
    return {
      fleetHalted: parse.fleetHalted ? parse.fleetHalted(res.data) : res.data?.fleetHaltActive,
      haltCount: parse.haltCount ? parse.haltCount(res.data) : res.data?.haltCount,
      status: res.status,
      raw: res.data,
    };
  }

  /**
  * Resume from a fleet halt.
  *
  * @param {string} operatorId
  * @param {string} reason
  * @returns {Promise<{ status: number, raw: object }>}
  */
  async resume(operatorId, reason) {
    const ep = this.adapter.endpoints.resume;
    const bodyFn = ep.body || ((id, r) => ({ operatorId: id, reason: r }));
    const body = bodyFn(operatorId, reason);

    const res = await adapterFetch(this.target, ep, this.adapter.auth, { body, timeout: this.timeout });
    return { status: res.status, raw: res.data };
  }

  /**
  * Retrieve status for a specific agent.
  *
  * @param {string} agentId
  * @returns {Promise<{ status: number, raw: object }>}
  */
  async getStatus(agentId) {
    const ep = this.adapter.endpoints.status;
    const res = await adapterFetch(this.target, ep, this.adapter.auth, {
      pathParams: { agentId },
      timeout: this.timeout,
    });
    return { status: res.status, raw: res.data };
  }

  /**
  * Retrieve system health / governance readiness.
  *
  * @returns {Promise<{ status: number, raw: object }>}
  */
  async getHealth() {
    const ep = this.adapter.endpoints.health;
    const res = await adapterFetch(this.target, ep, this.adapter.auth, { timeout: this.timeout });
    return { status: res.status, raw: res.data };
  }

  /**
  * Export audit events.
  *
  * @param {object} params - Query params: { limit, offset, startTime, endTime, agentId, eventType }
  * @returns {Promise<{ status: number, raw: object, events: Array }>}
  */
  async getAuditExport(params = {}) {
    const ep = this.adapter.endpoints.auditExport;

    const queryParts = [];
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
      }
    }
    const queryString = queryParts.join('&');

    const res = await adapterFetch(this.target, ep, this.adapter.auth, { queryString, timeout: this.timeout });

    // Extract events from various response shapes
    const data = res.data;
    let events = [];
    if (Array.isArray(data)) {events = data;}
    else if (Array.isArray(data?.events)) {events = data.events;}
    else if (Array.isArray(data?.data)) {events = data.data;}
    else if (Array.isArray(data?.entries)) {events = data.entries;}
    else if (Array.isArray(data?.blocks)) {events = data.blocks;}
    else if (Array.isArray(data?.records)) {events = data.records;}

    return { status: res.status, raw: data, events };
  }

  /**
  * Check audit chain integrity.
  *
  * @returns {Promise<{ status: number, chainValid: boolean|undefined, raw: object }>}
  */
  async getAuditIntegrity() {
    const ep = this.adapter.endpoints.auditIntegrity;
    const res = await adapterFetch(this.target, ep, this.adapter.auth, { timeout: this.timeout });

    const parse = this.adapter.parseResponse || {};
    return {
      status: res.status,
      chainValid: parse.chainValid ? parse.chainValid(res.data) : undefined,
      raw: res.data,
    };
  }

  /**
  * Retrieve active behavioral monitoring alerts.
  *
  * @returns {Promise<{ status: number, raw: object }>}
  */
  async getMonitorAlerts() {
    const ep = this.adapter.endpoints.monitorAlerts;
    const res = await adapterFetch(this.target, ep, this.adapter.auth, { timeout: this.timeout });
    return { status: res.status, raw: res.data };
  }

  /**
  * Retrieve anomaly detection system status.
  *
  * @returns {Promise<{ status: number, raw: object }>}
  */
  async getAnomalyStatus() {
    const ep = this.adapter.endpoints.anomalyStatus;
    const res = await adapterFetch(this.target, ep, this.adapter.auth, { timeout: this.timeout });
    return { status: res.status, raw: res.data };
  }
}
