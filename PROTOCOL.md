# Experimental protocol (pre-registration) — Article 2 / dissertation chapters 3–4

**Commit and tag this file (`git tag prereg-v1`) BEFORE collecting any cloud data.** Anything decided after seeing data goes into the deviation log (§12). Numbers below that say *pre-declared* must not be tuned afterwards.

## 1. Questions and decision rules
Thesis hypothesis (individual plan): integrated architectural patterns + DevSecOps practice improve resilience, reduce vulnerability exposure and maintain performance for secure inter-service communication in fintech environments.

| ID | Question | Evidence | Decision rule (pre-declared) |
|---|---|---|---|
| H1 | Does strict mTLS + identity-based AuthZ (C) keep latency acceptable? | E1 | Per cell, ratio of median p95 (C/A1 and C/A0): **negligible** if the 90 % bootstrap CI ⊂ [1/1.10, 1.10]; **acceptable** if the 95 % CI upper bound < 1.25; **exceeds** if the 95 % CI lower bound > 1.25; otherwise **inconclusive**. H1 is supported only if C is *negligible or acceptable* at every rate ≤ 0.8×knee on the 3-hop chain. |
| H2a | Does C remove unauthorised east-west paths? | E2 | Observed allow == intended allow for every directed pair (156 pairs × 2 credential modes). One unauthorised pair that succeeds falsifies "100 % blocked". |
| H2b | Does the DevSecOps gate catch misconfiguration before deployment? | E4 | Detection ≥ 90 % on the **held-out** mutation set with 0 false positives on clean manifests. |
| H3 | Does C preserve availability under faults? | E3 | C non-inferior to A1: median recovery time ≤ A1 + 5 s **and** failed requests ≤ 1.5 × A1, per fault type (descriptive, n = 5 per cell). |

## 2. Scenarios (one namespace each, identical topology/resources)
| ID | Mesh | Transport | AuthN/Z |
|---|---|---|---|
| A0 | none (no injection) | plain HTTP | none — **true baseline** |
| A1 | Istio sidecars, PERMISSIVE (auto-mTLS still on) | opportunistic mTLS | none — isolates the "mesh tax" |
| B  | none | plain HTTP | every service validates the RS256 JWT and propagates it (app-layer JWT-only) |
| C  | sidecars | STRICT mTLS (edge port permissive) | per-service ServiceAccount identity, ALLOW-list AuthorizationPolicy, REGISTRY_ONLY egress |
| D  | as C | as C | C + mesh-level JWT validation at the edge (RequestAuthentication) |
Article 1 differences fixed here: baseline had sidecars (2/2 pods); "JWT-only" ran in the gateway sidecar, not in the app; all workloads shared the `default` ServiceAccount.

## 3. Workload
12 services from one Go binary (`svc/`) — `topology/topology.yaml` is the single source of truth for services, chains **and** the intended policy. Chains c0–c4 have 0–4 service-to-service hops. 2 replicas each, spread across nodes, requests 50m/32Mi (+sidecar 50m/64Mi), limits 1 CPU. Payload 2 KiB, 1000 SHA-256 iterations/hop (fixed; recorded in manifests). tenge-tracker (decomposed) is the realism case study for E2–E4 (§9).

## 4. E1 design
* **Load model:** open (k6 `constant-arrival-rate`), 30 s warm-up (discarded) + 90 s measurement, 15 s cool-down. Fixed-VU closed-loop tests are *not* used (Article 1: latency ∝ VUs/throughput ⇒ queueing, not cost).
* **Generator:** separate VM in the same region; CPU sampled; run invalid if mean > 80 %.
* **Capacity calibration:** `k6/ramp.js` on A0, c3 → `analysis/knee.py` (rule in script). Rates = {0.2, 0.4, 0.6, 0.8, 0.9} × knee.
* **E1a rate sweep:** A0, A1, B, C × 5 rates × chain c3 × 10 reps = 200 runs.
* **E1b depth sweep:** A0, A1, B, C × chains c0–c4 × 0.5×knee × 6 reps = 120 runs → ms added per hop.
* **E1c:** D vs C, c3, 0.5×knee, 10 reps = 20 runs.
* **Order:** complete randomised blocks (every cell once per repetition, shuffled; seed in `meta.json`). All five namespaces stay deployed; idle ones are idle (shared-node threat noted).
* **Total:** 340 runs × 138 s ≈ 13 h of cluster time.

## 5. Validity rules (pre-declared, applied identically to all scenarios)
A run is *invalid* (reported in `invalid_runs.csv`, excluded from latency inference only) if failed-request fraction > 1 %, generator-dropped iterations > 1 %, or generator CPU > 80 %. **Never filter by latency value.** Failure rate itself is a reported outcome. Sensitivity: every verdict is recomputed with failed-fraction caps 0.1 %, 5 % and no filter; a verdict that changes is reported as unstable.

## 6. Statistics
Unit = run (its p95). Effect = ratio of medians with percentile bootstrap (10 000 resamples, seeded). Equivalence from the 90 % CI (≡ TOST, α = 0.05); superiority from the 95 % CI; Mann–Whitney p with Holm adjustment as supplementary. Per-hop cost = OLS slope of p95 on hops (bootstrap over runs, stratified by hop), contrast vs A0. Report p50/p99, success rate, sidecar CPU/RAM (`kubectl top`, mid-measurement) — resource cost is a first-class outcome. **No claim of the form "overhead < x %" without an interval that supports it.**

## 7. E2 security efficacy (scripts/attack_matrix.py)
Sources: 12 services + `attacker-mesh` (meshed, unknown identity) + `attacker-nomesh` (plaintext). 156 directed pairs × {no token, valid token}; intended = `topology.yaml` (28 service pairs + 2 attacker→edge). Plus: 9 token variants (valid, expired, wrong aud/iss/key, nbf-future, tampered, alg=none, HS256 key-confusion) at the edge and an internal service; egress to the Internet from `ai`. Report block rate of unauthorised pairs, false-block rate of intended pairs (Wilson 95 % CI), invalid-token acceptance, egress reachability. For B the token-holding attacker case is the key result (a bearer token carries no caller identity).

## 8. E3 resilience (scripts/run_resilience.py)
Faults: pod-kill, rollout (sidecar warm-up; `--hold-proxy` manifests vs default), node-drain, istiod-down (+ pod churn), cert-observe (30 min, short certificate TTL). 60 s baseline, fault, ≥120 s after. Load 0.5×knee, c3. Scenarios A0, A1, C. n = 5 per cell. Metrics: baseline success, minimum success, failed requests, time-to-recover (analysis/resilience.py). **Cert-rotation knob (`SECRET_TTL` via proxyMetadata) is unverified for your Istio version** — the experiment must *observe* rotations (logged `cert_seen` events); if none occur, fix the knob before reporting anything.

## 9. E4 DevSecOps gate + case study
* Gate = kubeconform → conftest (R1–R12) → topology-intent check → (CI) gitleaks, Trivy, SBOM, cosign.
* **Development set:** M01–M19 in `seeded/mutate.py`. The rules were written with these in view, so 19/19 is a regression test, **not evidence of detection power**.
* **Evaluation set (must be created after freezing the rules):** ≥ 20 faults authored by a second person or taken from CIS Kubernetes Benchmark / Istio security best-practice lists, plus the real historical incident in the tenge-tracker git history (credential in source; revoke it and keep the commit hash as ground truth). Report detection (Wilson CI), false positives on clean manifests, gate wall-time.
* **tenge-tracker:** decompose per the design in the article draft (identity, ledger, receipt, health, gamification, ai-assistant + gateway; asymmetric JWT). Run E2–E4 on it; run a reduced E1 (0.5×knee, c-equivalent flows) with real payloads and an in-cluster PostgreSQL.

## 10. Environment record
`scripts/collect_env.sh` per session (Kubernetes, Istio, k6 versions; node SKUs; policies in force); `scripts/verify_mesh.sh` before E1 (pods 1/1 vs 2/2; mTLS handshake counters; STRICT behaviour). Pin the Istio version.

## 11. Known limitations (state in the paper)
One mesh implementation (Istio sidecar mode, not ambient/Linkerd); one provider/region; synthetic call graph (+ one real app); idle scenarios share nodes; 2-vCPU nodes; no WAN/multi-region; student-credit SKUs; load is synthetic, not production traffic.

## 12. Deviation log
| Date | Deviation | Reason | Effect on conclusions |
|---|---|---|---|

## Pilot-informed changes (laptop pilot, 2026-10-10, before preregistration)
1. Knee rule: p95 limit is max(2x, +10 ms) of the reference; the partial final bin is discarded; a ramp that never leaves the healthy region is reported as a lower bound only.
2. A knee is measured for EVERY scenario. Test rates are fractions of the LOWEST knee among the compared scenarios, so no scenario is saturated; E1c (D vs C) uses 0.5 x min(knee_C, knee_D).
3. Capacity ratio (knee / knee of A0) and sidecar CPU per 1,000 req/s are primary outcomes.
4. Runs per cell are derived from the pilot: n = ceil(2960 x sigma^2) for ~80% power to show "negligible" (checked by simulation), where sigma = SD of log p95 across runs.
5. The load-generator CPU validity limit (80%) applies only when the generator runs on a separate host; on a shared host set MAX_GEN_CPU=100 and say so.
6. The `kubectl top` snapshot is taken 1 s after the measurement window, not inside it (it ran 0.7 x duration into the window in the first pilots). Diagnostic: 6 A1 runs without it had sd(log p95) = 0.10, versus 0.25-0.51 with it (suggestive only: different time of day, n = 5 vs 6). Sidecar CPU is therefore the last metrics-server sample (15 s resolution) and is reported as approximate.

## 7. Local-study amendment (prereg-v1, 2026-11-11)
1. Environment: one Windows laptop, WSL2 (about 10 GB), 3-node k3d cluster, k6 on the same host, MAX_GEN_CPU=100. Absolute latencies do not transfer to a cloud; claims are relative comparisons between scenarios on this host.
2. Host-interruption rule: a run that overlaps a WSL/session restart, sleep, or any manual intervention is invalid and is rerun. Every such event is logged.
3. Sizing pilot `noise1` (A1 and C, c3, 0.3 x knee, 10 runs each) is not confirmatory data. After the pre-declared failed>1% rule, SD of log p95 was 0.143 (A1) and 0.029 (C). Margin: +/-10% on p95; 16 runs per cell.
4. Stage 1: scenarios a0,a1,b,c; chain c3; rates 0.3,0.6,0.8 x 572 req/s; 10 s warm-up, 60 s window; --no-kube. Sidecar CPU is measured separately.
5. Stage 2: if the 95% CI of the C/A1 p95 ratio at any rate is wider than +/-10%, extend A1 and C at that rate to 60 runs per cell.
6. Spread is recomputed from Stage 1 data; any change to this design after Stage 1 goes in the deviation log.

## 8. Amendment prereg-v2 (2026-11-13): drift and restart rule
1. Observation: after about 2.5 days of cluster uptime, A1 p95 at 0.6 x knee rose from 6.0 ms (early block) to 25.7 ms; A0 rose from 1.8 to 2.7 ms. Restarting the mesh-a1 workloads returned A1 to 6.6 ms (5 runs, results/drift_check_a1_restart). Cause not identified.
2. Stage-1 reps 17-60 (A1, C) ran in the degraded state and are reported as exploratory only. Stage-1 reps 1-16 (all scenarios) are replicate 1.
3. Session 3 (replicate 2): scenarios a0,a1,b,c; chain c3; rates 0.3,0.6,0.8 x 572; 16 runs per cell; workloads in mesh-a0/a1/b/c are restarted and given 30 s before each repetition block of 12 runs.
4. Analysis: each replicate is analysed on its own; pooled results are reported only if both replicates agree. The drift of p95 over repetition number within session 3 is reported.

## 9. Amendment prereg-v3 (2026-11-14): E3 design on this host
1. Scenarios a0,a1,c; faults pod-kill, rollout, node-drain (a0,a1,c) and istiod-down, plain and with --with-restart (a1,c only); n=5 per cell; chain c3; target ledger.
2. Load 286 req/s = 0.5 x the A1/C knee (572), not 0.5 x the A0 knee (about 1095 req/s), which would overload the meshed scenarios on this host.
3. Before every run: istiod scaled to 1, all nodes uncordoned, the scenario's workloads restarted and given 30 s (drift rule, section 8).
4. Order: repetition-major (rep 1 of every cell, then rep 2 ...), so stopping early leaves a balanced design.
5. Cert-observe (30 min) is not run here; certificate rotation is reported as not observed.
