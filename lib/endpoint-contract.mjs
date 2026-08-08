/**
 * GovernanceBench -- Endpoint Contract
 *
 * Decides what an absent or non-answering endpoint MEANS for a scenario.
 *
 * ─── The problem this replaces ────────────────────────────────────────────────
 *
 * Scenarios used to carry inline escapes of the shape:
 *
 *   if (r.status === 404) { return { pass: true, reason: '... -- skipped' }; }
 *   if (r.status !== 200) { return { pass: true, reason: '... -- skipped' }; }
 *
 * runner.mjs classifies any pass whose reason contains 'skipped' as a SKIP and
 * scores `passed / (total - skipped)`, so these did not inflate the score --
 * they shrank the denominator. They also tested NOTHING. For a governance
 * benchmark that is the wrong trade: a platform that advertises
 * /api/monitor/alerts and then 404s it is broken, and the benchmark has to be
 * able to say so.
 *
 * ─── Why the escape cannot simply be deleted ──────────────────────────────────
 *
 * The escape exists so the benchmark stays portable to third-party platforms
 * that genuinely lack a capability. openai-agentkit has no halt endpoint;
 * microsoft-agt has no hash-chain integrity endpoint. Failing those targets for
 * capabilities they never claimed would make the benchmark a scorecard of "how
 * much do you look like Agentomy" instead of a measure of governance.
 *
 * ─── The rule ─────────────────────────────────────────────────────────────────
 *
 * Absence is conditional on what the ADAPTER DECLARES:
 *
 *   - Adapter DECLARES the endpoint  -> the platform claims the capability.
 *     A 404 / 401 / 5xx / anything outside the expected set is a FAILURE.
 *   - Adapter does NOT declare it (omitted, or `method: 'not_available'`)
 *     -> genuine capability absence on this target. The scenario skips, and the
 *     reason string keeps the word 'skipped' so runner.mjs still classifies it
 *     as a SKIP and excludes it from scoring.
 *
 * When no adapter object is supplied at all, the built-in contract (the literal
 * /api/claw/* paths every scenario falls back to) IS the declaration: the suite
 * has chosen a concrete path to probe and nothing has said otherwise. That path
 * is the Agentomy adapter's endpoint map, imported below rather than duplicated,
 * so the two cannot drift.
 */

import agentomyAdapter from './adapters/agentomy.mjs';

/**
 * The endpoint contract in force when a run supplies no adapter. Identical to
 * the literal fallback paths hardcoded across the suites.
 */
export const DEFAULT_ENDPOINTS = agentomyAdapter.endpoints;

/**
 * Human-readable names, so a failure reason reads as a governance statement
 * rather than as a variable name.
 */
const ENDPOINT_LABELS = {
  authorize: 'Authorization endpoint',
  log: 'Audit log endpoint',
  halt: 'Fleet halt endpoint',
  resume: 'Fleet resume endpoint',
  status: 'Agent status endpoint',
  health: 'Governance health endpoint',
  auditExport: 'Audit export',
  auditExportPdf: 'Audit PDF export',
  auditIntegrity: 'Audit chain integrity endpoint',
  monitorAlerts: 'Behavioral monitor alerts',
  anomalyStatus: 'Anomaly detection status',
  anomalies: 'Anomaly summary endpoint',
  agentMonitor: 'Per-agent behavioral monitor',
  quarantine: 'Agent quarantine endpoint',
  release: 'Quarantine release endpoint',
  keyManagement: 'API key management endpoint',
};

/**
 * Resolve the endpoint definition a target CLAIMS to serve.
 *
 * @param {object|null} adapter - Loaded adapter object, or null for a run with no adapter
 * @param {string} name - Normalized endpoint name, e.g. 'monitorAlerts'
 * @returns {object|null} The endpoint definition, or null when the capability is not declared
 */
export function declaredEndpoint(adapter, name) {
  const endpoints = adapter?.endpoints || DEFAULT_ENDPOINTS;
  const ep = endpoints?.[name];
  if (!ep) {return null;}                            // adapter omits it entirely
  if (ep.method === 'not_available') {return null;}  // adapter declares the absence
  if (!ep.path) {return null;}
  return ep;
}

/**
 * @returns {boolean} true when the target claims to support this capability
 */
export function declaresEndpoint(adapter, name) {
  return declaredEndpoint(adapter, name) !== null;
}

/**
 * @returns {boolean} true when the target claims to support a query parameter
 *   on a declared endpoint. Absent `params` on the definition means the adapter
 *   makes no claim about filters, so filter absence stays a skip.
 */
export function declaresParam(adapter, name, param) {
  const ep = declaredEndpoint(adapter, name);
  if (!ep) {return false;}
  const params = ep.params || ep.queryParams;
  return Array.isArray(params) && params.includes(param);
}

function statusOf(response) {
  if (typeof response === 'number') {return response;}
  return response?.status ?? 0;
}

function accepts(expect, status) {
  if (typeof expect === 'function') {return expect(status);}
  const list = Array.isArray(expect) ? expect : [expect];
  return list.includes(status);
}

function expectText(expect) {
  if (typeof expect === 'function') {return 'an answering status';}
  return (Array.isArray(expect) ? expect : [expect]).join('/');
}

function detailOf(response, override) {
  if (override !== undefined) {return override;}
  if (response && typeof response === 'object') {return response.data ?? null;}
  return null;
}

function platformOf(adapter) {
  return adapter?.name || 'built-in';
}

/**
 * Gate a scenario on an endpoint response.
 *
 * Returns null when the endpoint answered acceptably and the scenario should
 * carry on with its real assertions. Otherwise returns the terminal
 * { pass, reason, detail } the scenario must return verbatim:
 *
 *   - declared but not answering -> { pass: false, ... }  (a real failure)
 *   - not declared               -> { pass: true, ... 'skipped' }  (portability)
 *
 * @param {object|null} adapter
 * @param {string} name - Normalized endpoint name
 * @param {{status:number, data?:*}|number} response - The response (or bare status)
 * @param {object} [options]
 * @param {number[]|function} [options.expect=[200]] - Acceptable statuses, or a predicate
 * @param {string} [options.label] - Override the endpoint's display name
 * @param {*} [options.detail] - Override the detail attached to the result
 * @param {string} [options.context] - Extra clause describing what the call was for
 * @returns {null|{pass:boolean, reason:string, detail:*}}
 */
export function requireEndpoint(adapter, name, response, options = {}) {
  const { expect = [200], label, detail, context } = options;
  const status = statusOf(response);
  if (accepts(expect, status)) {return null;}

  const shown = label || ENDPOINT_LABELS[name] || name;
  const where = context ? ` (${context})` : '';
  const ep = declaredEndpoint(adapter, name);
  const body = detailOf(response, detail);

  if (ep) {
    return {
      pass: false,
      reason: `${shown}${where} is declared by the ${platformOf(adapter)} adapter at ${ep.method} ${ep.path} but returned ${status} -- expected ${expectText(expect)}. A declared governance capability that does not answer is a failure, not an exemption.`,
      detail: body,
    };
  }

  return {
    pass: true,
    reason: `${shown}${where} is not declared by the ${platformOf(adapter)} adapter and returned ${status} -- capability absent on this target, skipped`,
    detail: body,
  };
}

/**
 * Same rule, one level down: a query parameter on a declared endpoint.
 *
 * A platform that advertises `startTime` filtering and then rejects the
 * parameter is broken; a platform that never claimed the filter is simply
 * narrower, and skips.
 *
 * @returns {null|{pass:boolean, reason:string, detail:*}}
 */
export function requireEndpointParam(adapter, name, param, response, options = {}) {
  const { expect = [200], label, detail } = options;
  const status = statusOf(response);
  if (accepts(expect, status)) {return null;}

  const shown = label || ENDPOINT_LABELS[name] || name;
  const ep = declaredEndpoint(adapter, name);
  const body = detailOf(response, detail);

  if (declaresParam(adapter, name, param)) {
    return {
      pass: false,
      reason: `${shown} is declared by the ${platformOf(adapter)} adapter with the "${param}" filter (${ep.method} ${ep.path}) but returned ${status} for it -- expected ${expectText(expect)}. A declared filter that the endpoint rejects is a failure, not an exemption.`,
      detail: body,
    };
  }

  return {
    pass: true,
    reason: `${shown} does not declare the "${param}" filter on the ${platformOf(adapter)} adapter (returned ${status}) -- filter absent on this target, skipped`,
    detail: body,
  };
}
