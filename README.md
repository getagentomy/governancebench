<div align="center">
  <img src="assets/brand/agentomy-logo-dark.svg" alt="Agentomy" width="320" />
</div>

# GovernanceBench

<sub>An open piece of **[Agentomy](https://agentomy.com)**, the governance layer for AI agents in regulated enterprises. See the others at [github.com/getagentomy](https://github.com/getagentomy).</sub>

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

The open governance benchmark for AI agent platforms.

**GovernanceBench measures whether a governance platform actually enforces what it claims.**

It tests any governance API across 6 core dimensions and 13 extended and vertical suites: 428 behavioral scenarios in total (235 core, 193 extended) across 19 suites. No source access required. Tests run against live HTTP endpoints.

---

## Responsible use

**Run this only against systems you own or are explicitly authorized in writing to test.**

This package generates adversarial traffic. It exists to measure whether a governance layer
detects and refuses hostile behavior, which means it produces the hostile behavior in order to
see what happens to it. Pointed at a system you do not control, that is an attack, and it may
be a criminal offense under the U.S. Computer Fraud and Abuse Act and equivalent
computer-misuse statutes elsewhere, regardless of intent or of what you find.

Before you run it:

- Confirm you own the target, or hold written authorization from the party that does.
- Confirm your provider's terms permit testing (cloud and SaaS providers usually require
  advance notice or explicit approval).
- Expect side effects. Adversarial scenarios can trigger alerts, rate limits, account lockouts,
  paging, and log volume, and can degrade a live service. Prefer a non-production target.
- Do not use output from this package to attack, exploit, or gain access to third-party systems.

Testing your own deployment needs no permission from us. Testing Agentomy-operated systems,
including agentomy.com and our hosted APIs, requires our prior written authorization, write to
security@agentomy.com. If you find a vulnerability in our systems, report it there and give us a
reasonable chance to fix it before disclosure.

The license grants you broad rights to use, modify and redistribute this software, and it
disclaims all warranties and liability. It does not authorize you to access anyone else's
systems, and nothing here creates an exception to any law. **You are solely responsible for what
you point this at and for every consequence of doing so.**

## What GovernanceBench Measures

Governance platforms make five core claims:

1. **Authorization**, Tier-based permissions are enforced server-side. Tier escalation via request body is impossible.
2. **Auditability**, Every governance event is recorded, hash-linked, exportable, and tamper-evident.
3. **Override**, An authorized operator can halt all governed agents immediately. Unauthorized halt is blocked.
4. **Behavioral**, Anomalous agent behavior is detected, flagged, and quarantined automatically.
5. **OWASP Coverage**, The platform addresses each of the OWASP Agentic Top 10 risks (ASI-01 through ASI-10).

GovernanceBench verifies these claims by calling real API endpoints and checking real responses.

---

## Install

```bash
npm install -g governancebench
```

## Or run directly

```bash
npx governancebench run --target http://your-governance-platform:3000
```

---

## Quick Start

Three paths depending on what you are scoring:

```bash
# 1. Score YOUR system (auto-detects adapter)
npx governancebench run --target https://your-governance-api.com

# 2. Score against a known platform
npx governancebench run --target https://agt-endpoint.com --adapter microsoft-agt

# 3. Score the reference implementation (Agentomy)
# Start Docker with the admin token, without it, auth tests return 401 and score is ~52/100
ADMIN_OVERRIDE_TOKEN=my-secret-token docker compose up -d
npx governancebench run --target http://localhost:3000 --adapter agentomy --api-key agentomy_ak_my-secret-token
```

Additional options:

```bash
# Run against an auth-enabled target (X-API-Key header on every request)
npx governancebench run --target http://localhost:3000 --api-key YOUR_API_KEY

# Run one suite
npx governancebench run --target http://localhost:3000 --suite authorization

# Get verbose per-scenario output
npx governancebench run --target http://localhost:3000 --verbose

# Generate a markdown report
npx governancebench run --target http://localhost:3000 --format markdown --output report.md

# Generate a JSON report (machine-readable)
npx governancebench run --target http://localhost:3000 --format json > results.json

# Score any platform using a custom adapter config
npx governancebench run --target https://custom-platform.com --adapter generic --config ./my-adapter.json

# Blind multi-system comparison
npx governancebench blind --targets targets.json --format json --output results.json
```

---

## How Scoring Works

GovernanceBench measures 6 dimensions:

1. **Authorization**, Are tier-based permissions enforced server-side? Can escalation be injected via request body?
2. **Auditability**, Is every governance event recorded, hash-linked, exportable, and tamper-evident?
3. **Override**, Can an authorized operator halt all agents immediately? Is unauthorized halt blocked?
4. **Behavioral**, Is anomalous agent behavior detected, flagged, and quarantined automatically?
5. **OWASP**, Does the platform address OWASP Agentic Top 10 risks (ASI-01 through ASI-10)?
6. **Message Governance**, Are agent-to-agent messages governed as actions? Are instruction-override and capability-escalation payloads refused, is an encoded payload still caught, and does each decision carry the policy version it was made under?

**Adapters** translate between GovernanceBench's normalized API and each platform's actual endpoints. Each adapter maps paths, HTTP methods, auth headers, and response parsing rules. You can use a built-in adapter or create your own with `--adapter generic --config ./my-adapter.json`.

**Skipped, not failed, but only for capabilities the platform never claimed.** Absence is judged against what the adapter DECLARES. If an adapter omits an endpoint or marks it `not_available`, scenarios that need it are skipped and excluded from scoring: a platform is never penalized for capabilities it does not claim to have. If the adapter DOES declare the endpoint, the platform is claiming that capability, and an endpoint that then 404s, 401s, or errors is a **failure**. A platform that advertises `/api/monitor/alerts` and does not serve it is broken, and the benchmark says so rather than quietly shrinking its own denominator.

**Score reflects what is implemented, not what is missing.** If your platform implements 3 of 6 dimensions, your score is the average of those 3. The report clearly shows which dimensions were evaluated and which were skipped entirely.

---

## Verified Scores

| Platform | Version | Score | Date | Artifact |
|---|---|---|---|---|
| Agentomy | v0.31.0 | 100/100 | 2026-05-16 | results.json |
| Microsoft AGT | v3.6.0 | 57/100 | 2026-05-17 | microsoft-agt-governancebench-results.json |
| n8n (bare) | latest | 56/100 | 2026-06-18 | live adapter (`run --adapter n8n`) |

n8n is an open-source workflow orchestrator, not a governance platform, included to show what a general-purpose runtime scores against the bar: 56/100 (Insufficient), live-measured through the adapter. The same n8n governed through Agentomy reaches 100/100. Run it yourself with `run --adapter n8n`. Microsoft Agent 365 (preview) and the OpenAI Agents SDK received documentation-review assessments (2 of 4 and 1 of 4 dimensions respectively), not full live scores. The OpenAI Agents SDK documentation itself notes it is not a governance platform in the GovernanceBench sense.

### Independent third-party validation

Beyond our own GovernanceBench runs, we ran NVIDIA's [SkillSpector](https://github.com/NVIDIA/SkillSpector) v2.2.3, NVIDIA's own open (Apache-2.0) security scanner for AI agent skills, against Agentomy's skills. Result: **16 of 16 SAFE, 0 findings, 0/100 aggregate risk**. A different tool, from a different vendor, reaching an independent result. Anyone can reproduce it.

---

## FAQ

**"Isn't this self-assessment?"**

We scored Microsoft AGT at 57/100. If the benchmark was rigged, competitors would score zero, not fifty-seven. AGT scores 90/100 on Behavioral, a self-serving benchmark would not give a competitor an A in any dimension. The benchmark tests HTTP endpoints with observable behavior. Anyone can run it and verify.

**"My system scored 0/100"**

That means your system has no governance API endpoints. This IS the score, your agents are running without governance. There is no authorization layer, no audit trail, no kill switch, no anomaly detection. Get started: `npm install agentomy-agent`

**"How do I create a custom adapter?"**

Use the generic adapter with a JSON config file:

```bash
npx governancebench run --target https://your-platform.com --adapter generic --config ./my-adapter.json
```

See the [Adapter System](#adapter-system) section below for the full JSON schema and field mapping reference.

---

## External Target Scoring

Score any governance implementation, not just Agentomy.

```bash
# Score any platform at a remote URL (uses Agentomy adapter by default)
governancebench run --target https://external-governance-endpoint.com

# Score Microsoft AGT
governancebench run --target https://agt.example.com --adapter microsoft-agt

# Score OpenAI AgentKit guardrails
governancebench run --target https://api.openai.com --adapter openai-agentkit

# Score any platform using a custom adapter config
governancebench run --target https://custom-platform.com --adapter generic --config ./my-adapter.json

# Blind multi-system comparison
governancebench blind --targets targets.json --format json --output results.json
```

Adapters translate between GovernanceBench's normalized test API and each platform's actual endpoint schema. Each adapter maps endpoints, auth headers, and response parsing rules. Platforms that do not implement an endpoint score that scenario as "skipped," not "failed."

---

## Adapter System

GovernanceBench ships four adapters:

| Adapter | Command flag | Use case |
|---|---|---|
| Agentomy | `--adapter agentomy` (default) | Agentomy /api/claw/* endpoints |
| Microsoft AGT | `--adapter microsoft-agt` | Microsoft Agent Governance Toolkit |
| OpenAI AgentKit | `--adapter openai-agentkit` | OpenAI AgentKit guardrails |
| Generic | `--adapter generic --config ./file.json` | Any platform via JSON config |

### How adapters work

An adapter is a JavaScript object that specifies:
- `endpoints`, path and HTTP method for each GovernanceBench operation
- `auth`, how to inject API credentials (header key + environment variable name)
- `parseResponse`, functions that extract normalized values from each platform's response schema

The runner loads the adapter, injects auth headers automatically from environment variables, and marks endpoints defined as `not_available` as skipped (404 equivalent) without making a network call.

### Creating a custom adapter (generic config)

Create a JSON file:

```json
{
  "name": "My Platform",
  "endpoints": {
    "authorize":      { "method": "POST", "path": "/governance/authorize" },
    "log":            { "method": "POST", "path": "/governance/events" },
    "halt":           { "method": "POST", "path": "/governance/halt" },
    "resume":         { "method": "POST", "path": "/governance/resume" },
    "status":         { "method": "GET",  "path": "/agents/{agentId}" },
    "health":         { "method": "GET",  "path": "/health" },
    "auditExport":    { "method": "GET",  "path": "/audit/export" },
    "auditIntegrity": { "method": "GET",  "path": "/audit/integrity" },
    "monitorAlerts":  { "method": "GET",  "path": "/monitor/alerts" },
    "anomalyStatus":  { "method": "GET",  "path": "/anomaly/status" }
  },
  "auth": {
    "type": "header",
    "key": "X-API-Key",
    "envVar": "MY_PLATFORM_API_KEY"
  },
  "fieldMap": {
    "authorized": "allowed",
    "haltCount":  "affected_count"
  }
}
```

Omit any endpoint to use the Agentomy default path. Set `"method": "not_available"` for endpoints your platform does not implement, those scenarios will skip automatically.

Run it:

```bash
export MY_PLATFORM_API_KEY=your-key
governancebench run --target https://my-platform.com --adapter generic --config ./my-adapter.json
```

### Creating a dedicated adapter

Place a `.mjs` file in `cli/governancebench/lib/adapters/`. It must export a default object with `name`, `endpoints`, `auth`, and `parseResponse`. See `agentomy.mjs` for the full reference implementation.

---

## Blind Multi-System Scoring

Compare multiple governance platforms with randomized execution order and anonymized labels.

```bash
governancebench blind --targets targets.json
```

Targets file format:

```json
[
  { "label": "System A", "target": "http://platform-a:3000", "adapter": "agentomy" },
  { "label": "System B", "target": "http://platform-b:3000", "adapter": "microsoft-agt" },
  { "label": "System C", "target": "https://platform-c.example.com", "adapter": "generic", "config": "./c-adapter.json" }
]
```

GovernanceBench shuffles execution order before running. The `shuffleOrder` field in the JSON output records which order was used, so results are independently verifiable.

Output includes per-label dimensional scores and an overall ranking.

---

## Running Against Any Governance Platform

GovernanceBench is target-agnostic. It expects these REST endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/api/claw/authorize` | POST | Check if an agent action is permitted |
| `/api/claw/log` | POST | Record a governance event |
| `/api/claw/halt` | POST | Emergency halt (requires operatorId) |
| `/api/claw/resume` | POST | Resume after halt (requires operatorId) |
| `/api/claw/status/:agentId` | GET | Individual agent status |
| `/api/claw/health` | GET | System health |
| `/api/audit/export` | GET | Export audit events |
| `/api/audit/export/integrity` | GET | Hash chain integrity check |
| `/api/monitor/alerts` | GET | Active anomaly alerts |
| `/api/anomaly/status` | GET | Anomaly detection system status |

An endpoint that returns 404 is skipped in scoring only when the active adapter does not declare it, that is how platforms implementing a subset of the API avoid being penalized. When the adapter declares an endpoint, a 404 from it is scored as a failure. See `lib/endpoint-contract.mjs`.

---

## Test Suites

GovernanceBench ships 19 suites organized into two tiers.

### Core Dimensions (6 suites, 235 scenarios)

The standard governance benchmark. These suites define the scored dimensions that produce the overall GovernanceBench rating.

| Suite | Scenarios | What it measures |
|---|---|---|
| authorization | 51 | Permission tier enforcement, escalation blocking, security defaults |
| audit | 50 | Tamper-evident audit trail, hash chain integrity, export completeness |
| override | 50 | Kill switch reliability, operator validation, halt/resume cycle |
| behavioral | 58 | Anomaly detection, quarantine mechanics, false positive rate |
| owasp | 15 | OWASP Agentic Top 10 coverage (ASI-01 through ASI-10) |

### Extended Suites (13 of them, 193 scenarios)

Domain-specific governance evaluation. These suites test governance enforcement in vertical contexts. They run independently from core scoring and are selected with `--suite <name>`.

| Suite | Scenarios | Domain |
|---|---|---|
| algo-trading | 20 | Algorithmic trading governance (pre-trade checks, position limits, circuit breakers) |
| rpa-governance | 20 | Robotic process automation (bot registration, credential vaulting, drift detection) |
| medical-device | 20 | Medical device AI (FDA traceability, patient safety interlocks, recall readiness) |
| av-fleet | 20 | Autonomous vehicle fleet (geofence enforcement, V2X trust, disengagement audit) |
| industrial-iot | 20 | Industrial IoT (safety interlock, firmware provenance, OT/IT segmentation) |
| cloud-infrastructure | 20 | Cloud infrastructure (IMDS probing, storage enumeration, IAM escalation, K8s abuse) |
| breach-reproduction | 15 | Breach reproduction (multi-tenant isolation, model routing, consent management) |
| override-integrity | 7 | Override chain-of-custody (dual authorization, override audit completeness) |
| ipi | 5 | Indirect prompt injection (poisoned tool output, hidden-comment hijack, command-substitution bypass) |
| skill-governance | 5 | Skill registry governance (registry integrity, signed-skill attestation, issuer verification) |

---

### Suite 1: Authorization (50 scenarios)

Tests permission tier enforcement:

- Tier escalation via request body (must be ignored or blocked)
- Missing field handling (no agentId, no action)
- Invalid tier values: negative, fractional, string, 999
- Cross-agent access without delegation
- Rate limiting behavior
- Default tier assignment for unregistered agents
- Security defaults: no stack traces, no internal config leakage
- Dual-check: sub-agent + coordinator tier both enforced

### Suite 2: Audit Trail (50 scenarios)

Tests tamper-evident audit trail:

- Log an event, verify it appears in export
- Hash chain integrity (parentHash linkage)
- Hash format validation (hex or base64)
- Pagination (limit, offset, bounds)
- Time-range filtering
- Export completeness (log N events, find N)
- Idempotency (same query, same result)
- Security: no secrets, no paths, no HTML in responses

### Suite 3: Kill Switch / Override (50 scenarios)

Tests emergency halt capability:

- Halt with valid operator
- Halt without operator (must fail)
- Halt count in response
- Authorization blocked during halt
- New agent registration blocked during halt
- Resume restores normal operation
- Halt-resume cycle correctness
- Audit trail records halt and resume events
- Response time under 500ms (kill switch is a critical path)
- Concurrent halt/resume without corruption

### Suite 4: Behavioral Monitoring (50 scenarios)

Tests runtime anomaly detection:

- Monitoring infrastructure: alerts, anomaly status endpoints
- Normal requests do not trigger false positives
- Frequency burst detection
- Privilege probing detection
- Instruction-density analysis (injection attempt content)
- Quarantine: manual trigger, blocked during quarantine, audit record
- Release from quarantine
- Agent-scoped baseline (one agent's behavior does not affect another)
- Concurrent monitoring queries without errors

### Suite 5: OWASP Agentic Top 10 Coverage (10 scenarios)

Tests coverage of the OWASP Agentic Top 10. One scenario per ASI risk. Test harness reference: Kevlar (CC BY-SA 4.0). Results are independently reproducible.

EU AI Act mapping: Articles 9 and 15 (risk management + cybersecurity robustness).

| ASI | Risk | Mechanism Tested | Expected |
|---|---|---|---|
| ASI-01 | Goal Hijacking | Behavioral drift detection active | PASS |
| ASI-02 | Tool Misuse | Unauthorized tool call blocked at authorization layer | PASS |
| ASI-03 | Identity Abuse | Identity tier enforcement blocks impersonation | PASS |
| ASI-04 | Supply Chain | Behavioral detection layer present (FIS is P2) | PARTIAL |
| ASI-05 | Remote Code Execution | shell_exec blocked for unauthorized agents | PASS |
| ASI-06 | Memory Poisoning | High-density payload flagged or quarantined | PASS |
| ASI-07 | Inter-Agent Communications | Ungoverned handoff denied at dual-authorization | PASS |
| ASI-08 | Cascading Failures | Kill switch halts fleet, auth blocked during halt | PASS |
| ASI-09 | Human Trust Exploitation | Output behavioral monitoring present (no content mod) | PARTIAL |
| ASI-10 | Rogue Agents | Unregistered agent action denied | PASS |

**PARTIAL disclosures:**
- ASI-04: File Integrity Scanner is a P2 build item. Without it, behavioral drift detects supply chain compromise post-execution, not pre-execution. Pre-execution gap is disclosed.
- ASI-09: Content moderation is out of scope by design. The governance platform monitors behavioral patterns, not content. Azure AI Content Safety handles content moderation in complementary deployments.

---

## Scoring Methodology

Each dimension is scored 0-100:

```
dimension_score = (passed / scoreable) x 100
```

Skipped tests (endpoint returns 404) are excluded from both numerator and denominator.

Overall score is the equally weighted average of all 6 dimensions:

```
overall = (authorization + auditability + override + behavioral + owasp_normalized
           + message_governance) / 6
```

The OWASP dimension is also reported as a separate ASI count (e.g., 8/10) in the leaderboard.

**Tiers:**

| Score | Tier | Meaning |
|---|---|---|
| 90-100 | Excellent | Comprehensive governance enforcement |
| 75-89 | Good | Solid enforcement with minor gaps |
| 60-74 | Adequate | Core present, material gaps need attention |
| 40-59 | Insufficient | Significant gaps present real enterprise risk |
| 0-39 | Critical | Controls absent or non-functional |

**Exit codes:** 0 if overall >= 60, 1 if < 60 (useful for CI/CD gates).

---

## Interpreting Results

A **skipped** scenario means the active adapter does not declare the endpoint the scenario needs, so the capability is genuinely absent on this target. Skipped scenarios are not failures, they indicate which governance capabilities the platform does or does not implement.

A **failed** scenario means the platform claims the capability but did not deliver: either the adapter declares the endpoint and it did not answer (404, 401, 5xx), or it answered and the governance property under test did not hold. Failed scenarios indicate governance gaps.

**What a high score means:** The governance platform enforces its stated controls when tested from the outside with behavioral HTTP tests.

**What a high score does not mean:** It is not a security certification. GovernanceBench cannot verify internal implementation, cryptographic correctness of the hash chain, or behavior under adversarial conditions beyond its 333 scenarios.

---

## CI/CD Integration

```yaml
# Example GitHub Actions step
- name: GovernanceBench
  run: |
    governancebench run --target ${{ env.GOVERNANCE_URL }} --format json --output bench-results.json
  continue-on-error: false  # Exit 1 if score < 60

- name: Upload report
  uses: actions/upload-artifact@v3
  with:
    name: governancebench-results
    path: bench-results.json
```

---

## Available Commands

```
governancebench run --target <url>               Run all suites
governancebench run --target <url> --suite <name>  Run one suite
governancebench run --target <url> --adapter microsoft-agt  External target with adapter
governancebench run --target <url> --adapter generic --config ./adapter.json  Custom adapter
governancebench blind --targets targets.json     Blind multi-system comparison
governancebench report                           Summary of last run
governancebench report --format json             JSON of last run
governancebench report --format markdown         Markdown of last run
governancebench list                             List all 333 scenarios
governancebench list --suite authorization       List one suite
governancebench --help                           Full help
```

**Flags, run command:**

| Flag | Default | Description |
|---|---|---|
| `--target` | required | Base URL of governance platform |
| `--suite` | all | Suite to run: all, authorization, audit, override, behavioral, owasp |
| `--adapter` | agentomy | Endpoint adapter: agentomy, microsoft-agt, openai-agentkit, generic |
| `--config` | none | Path to JSON adapter config (required when --adapter generic) |
| `--api-key` | none | API key sent as X-API-Key header on every HTTP request |
| `--timeout` | 10000 | Per-scenario timeout in ms |
| `--verbose` | false | Stream pass/fail per scenario to stderr |
| `--format` | summary | Output format: summary, json, markdown |
| `--output` | stdout | Write report to file |

**Flags, blind command:**

| Flag | Default | Description |
|---|---|---|
| `--targets` | required | Path to JSON file with array of target definitions |
| `--suite` | all | Suite to run |
| `--api-key` | none | API key sent as X-API-Key header on every HTTP request |
| `--timeout` | 10000 | Per-scenario timeout in ms |
| `--verbose` | false | Stream output to stderr |
| `--no-shuffle` | false | Disable randomized execution order |
| `--parallel` | false | Run all targets concurrently |
| `--format` | summary | Output format: summary, json |
| `--output` | stdout | Write result to file |

---

## Design Principles

**Agnostic.** Tests any governance platform with a REST API, not just Agentomy.

**Behavioral.** Tests what the platform does from the outside, not how it is implemented.

**Honest.** Skipped scenarios are clearly labeled. A score of 50/100 with 30 skips is different from 50/100 with 0 skips.

**Idempotent.** Every scenario can be re-run without leaving side effects (halt states are cleaned up, test agents use unique IDs).

**Self-contained.** No external dependencies beyond Node.js built-in `fetch`. No authentication required unless the platform requires it.

---

## Contributing

GovernanceBench is open source under the Apache License 2.0. Contributions are welcome.

- Repository: [https://github.com/getagentomy/governancebench](https://github.com/getagentomy/governancebench)
- Issues: [https://github.com/getagentomy/governancebench/issues](https://github.com/getagentomy/governancebench/issues)
- Pull requests: Fork, branch, and open a PR against `main`

When adding new scenarios, follow the existing suite structure in `suites/`. Each scenario must include an expected HTTP status code, a pass/skip/fail classification rule, and a label that appears in report output.

Do not hand-write endpoint-absence escapes such as `if (r.status === 404) return { pass: true, reason: '..., skipped' }`. That form tests nothing and cannot tell a third-party gap from a broken declared endpoint. Route absence through the shared helper instead:

```js
import { requireEndpoint } from '../lib/endpoint-contract.mjs';

const gate = requireEndpoint(adapter, 'monitorAlerts', r);
if (gate) { return gate; }   // skip if undeclared, fail if declared-and-absent
```

`requireEndpointParam(adapter, endpoint, param, r)` applies the same rule to a declared query filter. A scenario must never return `pass: true` for a capability the adapter declares.

---

## License

Apache License 2.0

Copyright 2026 Agentomy

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
