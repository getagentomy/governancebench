/**
 * GovernanceBench -- Auto-Detection
 *
 * Probes a target URL to detect which governance platform is running,
 * and returns the correct adapter name.
 */

const PROBES = [
  { path: '/api/claw/status', adapter: 'agentomy' },
  { path: '/api/governance/health', adapter: 'microsoft-agt' },
  { path: '/api/agents', adapter: 'microsoft-agt' },
  // n8n public API v1 surface: /api/v1/workflows requires auth but returns 401/200 not 404
  // (404 would mean n8n is not running). The /healthz endpoint on n8n returns "ok" without auth.
  { path: '/api/v1/workflows', adapter: 'n8n' },
  { path: '/healthz', adapter: 'generic' },  // n8n + many runtimes use this; generic falls through if no /api/v1/workflows
  { path: '/health', adapter: 'generic' },
];

/**
 * Probe a target URL to auto-detect the governance platform adapter.
 *
 * Tries each probe endpoint with a 2-second timeout.
 * Returns the first adapter that gets a non-404 response, or null.
 *
 * @param {string} targetUrl - Base URL to probe (e.g. http://localhost:3000)
 * @returns {Promise<string|null>} Adapter name or null if no governance detected
 */
export async function detectAdapter(targetUrl) {
  const base = targetUrl.replace(/\/$/, '');

  for (const probe of PROBES) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2000);

      const response = await fetch(`${base}${probe.path}`, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      });

      clearTimeout(timer);

      if (response.status !== 404) {
        return probe.adapter;
      }
    } catch {
      // Timeout, connection refused, or other network error -- skip this probe
      continue;
    }
  }

  return null;
}
