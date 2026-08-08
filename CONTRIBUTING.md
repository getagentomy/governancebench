# Contributing to GovernanceBench

GovernanceBench is the open methodology for measuring AI agent governance platforms across five dimensions: Authorization, Auditability, Override, Behavioral, and OWASP Coverage. It is published under the Apache License 2.0 (see [LICENSE](LICENSE)) to function as a category benchmark that any governance platform can be scored against.

This document describes how to add your system to the published [LEADERBOARD](../../governancebench-results/LEADERBOARD.md), the evidence-class discipline that determines whether a submission qualifies for live-adapter scoring or stays at documentation-review, and the blind-scoring methodology for future rounds.

---

## Submission paths

There are two evidence classes a submission can qualify for. The class determines what gets published and how.

### Class 1: Live-adapter measurement (preferred)

The submitting platform provides a reproducible access path (open-source binary, free trial, public API, self-serve hosted endpoint) that the scorer can reach without sales engagement. The scorer writes a thin adapter (see `cli/governancebench/lib/adapters/microsoft-agt.mjs` for the reference template, approximately 145 lines) that maps GovernanceBench calls to the target platform's surface, runs the full benchmark, and submits the resulting `governancebench-results.json` artifact alongside the adapter.

Live-adapter submissions appear in the LEADERBOARD with a per-dimension score, the measured date, and the reproducibility command. They appear in [BLIND-SCORING-RECORD](../../governancebench-results/BLIND-SCORING-RECORD.md) as the round they were measured in, with the reproducibility artifact path on disk.

To submit a live-adapter measurement:

1. Fork or clone this repository
2. Add an adapter under `cli/governancebench/lib/adapters/<your-platform>.mjs` modeled on `microsoft-agt.mjs`
3. Run the full benchmark: `npx governancebench run --adapter <your-platform> --target <your-endpoint>`
4. Place the resulting artifact under `tests/artifacts/<your-platform>-governancebench-results.json`
5. Open a pull request adding (a) the adapter file, (b) the artifact, (c) a row in LEADERBOARD.md citing the artifact path and measured date, (d) the corresponding entry in BLIND-SCORING-RECORD.md under the appropriate round

### Class 2: Documentation review

When live-adapter access is not available (the platform is sales-gated, requires enterprise licensing the scorer does not hold, or has no public API surface), a documentation-review entry may be added. Documentation-review entries are scored per-dimension as PASS, PARTIAL, or FAIL based on the platform's published source code, public documentation, and product pages, with the source URL date-stamped.

Documentation-review entries appear in BLIND-SCORING-RECORD under the doc-review round with the source URLs and review date. They do not appear in the LEADERBOARD with a numeric score because the evidence class does not match live-adapter measurement and mixing classes in the leaderboard would create reader confusion about per-row evidence ceiling.

Documentation-review submissions are queued for live-adapter elevation when the platform provides a reproducible access path. Submitters of documentation-review entries that later become accessible are invited to follow up with the live-adapter submission.

To submit a documentation-review entry:

1. Open an issue titled "Doc-review submission: <platform name>"
2. Include the source URLs you reviewed (with review date)
3. Include your per-dimension PASS/PARTIAL/FAIL judgments with the source-line that supports each
4. Note the access-class (open-source / free-trial / sales-gated / enterprise-license-required)

---

## Evidence-class ceiling discipline

The fundamental discipline of GovernanceBench is that **claims must derive from evidence**, and the evidence class is published per-row. This is the Stripe-pattern "verify us" infrastructure: every score on the leaderboard must be reproducible by the reader via the published command or artifact.

The evidence-class ceiling rules:

1. **Live-adapter measurement** is the highest evidence class. It requires (a) a reproducible access path the scorer can reach, (b) a working adapter that maps GovernanceBench to the target surface, (c) a stored artifact `tests/artifacts/<platform>-governancebench-results.json` with the run output, (d) a date-stamped measurement.

2. **Documentation review** is a lower evidence class. It does not produce numeric LEADERBOARD scores. It produces qualitative per-dimension judgments in BLIND-SCORING-RECORD with source-line citations.

3. **No system may be promoted from documentation-review to live-adapter without an actual live-adapter run.** Inferring scores from documentation is not a substitute for measurement.

4. **Live-adapter measurements are point-in-time.** Per [METHODOLOGY.md](../../governancebench-results/METHODOLOGY.md) "Point-in-Time Scoring Disclosure": scores stamp to a specific version + measurement date. Vendors may improve their scores by addressing the failing dimensions; the leaderboard reflects state-at-measurement, not current state.

5. **Sales-gated platforms cannot reach live-adapter elevation through this submission process alone.** If your platform is sales-gated and you want it elevated, you must provide reproducible access (a free tier, a public API, a sandbox URL) that the scorer can reach without contacting your sales team. Otherwise the documentation-review ceiling applies.

---

## Blind-scoring methodology (future rounds)

[BLIND-SCORING-RECORD.md](../../governancebench-results/BLIND-SCORING-RECORD.md) documents that Round 1 (April 2026) was scored from public source code and documentation review with the scorer having prior knowledge of which system corresponded to which label (because scoring and label assignment occurred in the same session).

Future blind rounds will use the GovernanceBench external target test harness with the blind-scorer module:

1. An operator (not the scorer) assigns labels to anonymized target configurations
2. A fresh scoring session scores all targets without knowing the label-to-system mapping
3. The operator reveals the mapping after scores are committed
4. Scores are published with verified blind methodology in BLIND-SCORING-RECORD

If you are submitting a live-adapter measurement and want to participate in blind methodology: open an issue requesting blind-round participation. We coordinate the operator role, label assignment, and scoring session offline before the run.

---

## Scoring dimensions (reference)

Per [METHODOLOGY.md](../../governancebench-results/METHODOLOGY.md):

- **Authorization** (51 scenarios): tier enforcement, capability scoping, permission boundary verification
- **Auditability** (50 scenarios): tamper-evident audit trail, hash-chain integrity, retroactive query
- **Override** (50 scenarios): kill-switch latency, fleet-wide halt, operator override authorization
- **Behavioral** (58 scenarios): drift detection, anomaly identification, behavioral baseline comparison
- **OWASP Coverage** (13 + 48 Kevlar): OWASP ASI vulnerability coverage with external red-team Kevlar (CC BY-SA 4.0) verification

Each dimension produces a PASS/FAIL/PARTIAL per scenario. The dimension score is the percentage of scenarios passed. The overall score is the geometric mean of dimension scores rounded to whole numbers.

---

## Reviewing existing submissions

The [LEADERBOARD.md](../../governancebench-results/LEADERBOARD.md) shows the current published scores with the reproducibility command for each. To reproduce any published score:

```bash
# Find the adapter and artifact for the system you want to verify
ls cli/governancebench/lib/adapters/
ls tests/artifacts/*governancebench-results.json

# Re-run against your local instance
cd cli/governancebench && npx governancebench run --adapter <adapter-name> --target <endpoint>

# Compare your output against the stored artifact
diff <your-output> <tests/artifacts/...governancebench-results.json>
```

If your reproduction produces a different score than what is published, open an issue with both outputs attached. Score divergence between reproductions is itself useful data about platform stability over time.

---

## Workflow-orchestration class submissions (WorkflowBench)

GovernanceBench scores agent-shape governance. Workflow runtimes (n8n, Zapier, Make, Pipedream, Tray, Workato, Power Automate, Apache Airflow, Temporal) execute DAGs of nodes against inbound triggers + intermediate state + tool-call cascades. The attack surface is different from single-agent governance and is scored by [WorkflowBench](../workflowbench/) -- the sibling benchmark under the same Apache 2.0 license and the same evidence-class discipline.

Six workflow-class threats: trigger-spoofing, cascade-poisoning, audit-bypass via node-reorder, cross-workflow leak, third-party-node supply-chain, workflow-replay tampering. See [docs/WORKFLOW-GOVERNANCE-CATEGORY.md](../../docs/WORKFLOW-GOVERNANCE-CATEGORY.md) for the category-defining cross-walk including the threat -> Agentomy primitive mapping and the GovernanceBench <-> WorkflowBench scenario relationship.

To submit a workflow runtime to the WorkflowBench cohort:

1. Fork or clone this repository
2. Add an adapter under `cli/workflowbench/lib/adapters/<your-runtime>.mjs` modeled on `cli/workflowbench/lib/adapters/n8n.mjs` (which maps to n8n public API v1)
3. Spin up the target runtime locally and run the benchmark: `node cli/workflowbench/bin/workflowbench.mjs run --adapter <your-runtime> --target <your-endpoint> --suite trigger-spoofing`
4. Place the resulting artifact under `tests/artifacts/n8n-measurement/<your-runtime>-workflowbench-results.json`
5. Open a pull request adding (a) the adapter file, (b) the artifact, (c) a row in the cohort matrix on `website/workflowbench.html` Tier 1, (d) a row in the GovernanceBench cohort if the same runtime is also being agent-shape scored

Documentation-review tier for closed-source workflow runtimes that lack a runnable governance API uses the same form as GovernanceBench Class 2 above: open an issue, cite source URLs, per-dimension PASS/PARTIAL/FAIL judgments.

---

## Code of Conduct

GovernanceBench contributions follow the Agentomy [Code of Conduct](../../CODE_OF_CONDUCT.md) (Contributor Covenant 3.0).

## License

Contributions to GovernanceBench are licensed under the Apache License 2.0, matching the rest of the GovernanceBench source tree. Submitted scoring artifacts may be redistributed as part of the published leaderboard under the same license.
