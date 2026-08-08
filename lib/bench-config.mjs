/**
 * GovernanceBench -- Shared Configuration
 *
 * Module-level state shared across runner and suites.
 * Stores the API key set via --api-key so all HTTP helpers
 * can inject the X-API-Key header automatically.
 */

let _apiKey = null;
const _evalToken = process.env.EVAL_TOKEN || null;

/**
 * Set the API key for all GovernanceBench HTTP requests.
 * @param {string|null} key
 */
export function setApiKey(key) {
  _apiKey = key || null;
}

/**
 * Get the current API key (or null if not set).
 * @returns {string|null}
 */
export function getApiKey() {
  return _apiKey;
}

/**
 * Build auth headers object. Returns empty object if no key is set.
 * @returns {object}
 */
export function getAuthHeaders() {
  const headers = {};
  if (_apiKey) headers['X-API-Key'] = _apiKey;
  if (_evalToken) headers['X-Eval-Token'] = _evalToken;
  return headers;
}
