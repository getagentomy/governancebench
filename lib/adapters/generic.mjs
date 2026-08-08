/**
 * GovernanceBench -- Generic Adapter
 *
 * Loads endpoint mapping from a user-supplied JSON config file.
 * Allows GovernanceBench to score any governance platform without
 * writing a dedicated adapter.
 *
 * Usage:
 *  governancebench run --target http://host --adapter generic --config ./my-adapter.json
 *
 * Config file format (JSON):
 * {
 *  "name": "My Platform",
 *  "endpoints": {
 *  "authorize": { "method": "POST", "path": "/authorize" },
 *  "log":  { "method": "POST", "path": "/events" },
 *  "halt":  { "method": "POST", "path": "/halt" },
 *  "resume":  { "method": "POST", "path": "/resume" },
 *  "status":  { "method": "GET",  "path": "/agents/{agentId}" },
 *  "health":  { "method": "GET",  "path": "/health" },
 *  "auditExport":  { "method": "GET", "path": "/audit" },
 *  "auditIntegrity": { "method": "GET", "path": "/audit/integrity" },
 *  "monitorAlerts":  { "method": "GET", "path": "/alerts" },
 *  "anomalyStatus":  { "method": "GET", "path": "/anomaly" }
 *  },
 *  "auth": {
 *  "type": "header",
 *  "key": "Authorization",
 *  "envVar": "MY_PLATFORM_API_KEY",
 *  "prefix": "Bearer "
 *  },
 *  "fieldMap": {
 *  "agentId": "agent_id",
 *  "operatorId": "operator_id",
 *  "authorized": "allowed",
 *  "haltCount": "affected_count"
 *  }
 * }
 *
 * Omitted endpoints default to the Agentomy path. Endpoints listed as
 * "not_available" are skipped (treated as 404) during test runs.
 */

import { readFileSync } from 'fs';
// build-ref: 81f61e0a7f9c

/**
 * Load and validate a generic adapter config from a JSON file.
 * Returns a fully resolved adapter object compatible with AdapterRunner.
 *
 * @param {string} configPath - Absolute or relative path to the JSON config
 * @returns {object} Resolved adapter config
 */
export function loadGenericAdapter(configPath) {
  let raw;
  try {
    raw = readFileSync(configPath, 'utf-8');
  } catch (err) {
    throw new Error(`Generic adapter: cannot read config at "${configPath}": ${err.message}`);
  }

  let config;
  try {
    config = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Generic adapter: invalid JSON in "${configPath}": ${err.message}`);
  }

  if (!config.endpoints || typeof config.endpoints !== 'object') {
    throw new Error('Generic adapter: config must include an "endpoints" object');
  }

  // Build the fieldMap resolver used by AdapterRunner
  const fieldMap = config.fieldMap || {};

  function resolveField(res, standardKey) {
    const mappedKey = fieldMap[standardKey] || standardKey;
    return res[mappedKey] !== undefined ? res[mappedKey] : res[standardKey];
  }

  return {
    name: config.name || 'Generic',
    endpoints: config.endpoints,
    auth: config.auth || null,
    parseResponse: {
      authorized: (res) => resolveField(res, 'authorized') || resolveField(res, 'allowed'),
      tier: (res) => resolveField(res, 'tier'),
      auditId: (res) => resolveField(res, 'auditId') || resolveField(res, 'audit_id'),
      haltCount: (res) => resolveField(res, 'haltCount') || resolveField(res, 'agent_count') || resolveField(res, 'affected_count'),
      chainValid: (res) => {
        const v = resolveField(res, 'chainValid') || resolveField(res, 'chain_valid');
        if (v !== undefined) {return v === true || v === 1 || v === 1.0;}
        return res.integrity === 1.0 || res.valid === true;
      },
      fleetHalted: (res) => {
        const v = resolveField(res, 'fleetHalted') || resolveField(res, 'halted');
        return v === true;
      },
    },
    _isGeneric: true,
  };
}

export default {
  name: 'Generic',
  _requiresConfig: true,
  loadFromConfig: loadGenericAdapter,
};
