# secure-mesh-cloud-study

Test harness for **Article 2 / dissertation chapters 3–4**: a corrected, cloud-ready replication of Article 1 (service-mesh overhead) extended with security-efficacy, resilience and DevSecOps experiments. Read **PROTOCOL.md** first.

## What is verified (on a laptop-class sandbox) and what is not
| Component | Status |
|---|---|
| Go service + JWT verifier (`svc/`) | unit tests pass; cross-checked with Python-minted tokens (`tests/test_jwt_crosscheck.py`) |
| Manifests for 5 scenarios + attackers | generated from `topology.yaml`; **229/229 resources pass kubeconform** (Kubernetes + Istio CRD schemas) |
| Policy gate (R1–R12 + intent check) | `opa test` 9/9; clean C/D pass; seeded benchmark 19/19 (development set — see PROTOCOL §9) |
| k6 scripts, matrix runner, knee finder | run against a local 12-process stack (A/A test: no false differences) |
| Statistics (`analysis/analyze.py`) | known-effect synthetic test: true ratios and per-hop slopes fall inside the CIs; contaminated runs flagged |
| E3 analyser | real k6 load + killed process: outage and recovery measured |
| **Anything involving Istio, AKS or k3d** | **NOT run** — no cluster was available. Treat the manifests, `attack_matrix.py` against a live cluster, `run_resilience.py`, and the cluster scripts as untested until your first dry run. The `--model` mode of `attack_matrix.py` only tests the scoring code. |
| `.github/workflows/devsecops.yml` | YAML valid, action versions checked to exist; never executed |

## Quick start
```bash
pip install -r requirements.txt            # needs go, k6, opa, conftest, kubeconform on PATH for `make test`
make test                                  # everything verifiable without a cluster
make local-smoke                           # k6 + fault injection on a local process stack
```
### Local cluster dry run (free) → then cloud
```bash
scripts/cluster_local.sh                   # k3d (3 nodes) + Istio + all scenarios
scripts/verify_mesh.sh                     # are A0/B really 1/1 and A1/C/D really 2/2? mTLS handshakes visible?
python3 scripts/attack_matrix.py --out results/e2
k6 run --out csv=results/knee/a0.csv -e GATEWAY_URL=http://127.0.0.1:8100 -e CHAIN=c3 k6/ramp.js
python3 analysis/knee.py results/knee/a0.csv
python3 scripts/run_matrix.py --local-lb --knee <KNEE> --reps 2 --duration 30   # pilot only: k6 shares the laptop
```
Azure: `scripts/cluster_azure.sh preflight` → `up` → `scripts/install_istio.sh` → `IMAGE=ghcr.io/<you>/mesh-svc:<sha> scripts/deploy.sh`; run matrices **from the load-generator VM**; `down` when finished. Push the repo first so CI builds the multi-arch image.

## Results → paper
`python3 analysis/analyze.py --in results/e1a results/e1b --out results/analysis` → `tables.tex`, figures, `sensitivity.csv`, `invalid_runs.csv`. Never type numbers into the paper by hand.

## Layout
`topology/` single source of truth · `svc/` service · `tools/` key, manifest and policy-intent generators · `k8s/generated/` output · `k6/` load · `scripts/` cluster + experiment drivers · `policy/` Rego · `seeded/` E4 benchmark · `analysis/` statistics · `tests/` self-tests · `article/` LaTeX skeleton.

## Verification log (what was actually run, and what it showed)
Run in a sandbox with Go 1.22, k6 2.3, OPA 1.21, conftest 0.71, kubeconform 0.8 — **no Kubernetes, Istio, AKS or k3d**.

| Check | Result |
|---|---|
| `make test` | exit 0: Go vet/tests; Python-vs-Go JWT cross-check (9 tokens + no-token); `opa test` 9/9; clean C and D pass all gates; seeded benchmark 19/19 (rego alone 15/19, 0/2 false positives); attack-matrix scoring self-test; known-effect statistics test; certificate-validity decoding test |
| kubeconform | 229/229 resources valid (Kubernetes + Istio CRD schemas) |
| A/A smoke (3 identical configs, 18 runs, local stack) | ratios 0.92–1.04, every CI contains 1, Holm p = 1.0, 0 invalid runs, no verdict "exceeds". With n = 6 and ~2 ms latencies the 95 % CIs are about ±15–20 %, so **"negligible (±10 %)" cannot be shown at that n** — size the cloud repetitions from a pilot's variance |
| E3 analyser, real k6 load, `ledger` killed 6 s | baseline 100 %, minimum 0 %, 1 201 failed requests (≈ 200 rps × 6 s), recovery detected at 7 s |
| CI workflow | YAML parses; the 12 action versions pinned in it exist upstream; **never executed** |

Bug found and fixed while verifying: `scripts/local_stack.py` orphaned its child processes on SIGTERM, so a later stack silently talked to stale services and the fault demo falsely passed its health check but saw no outage. It now shuts down cleanly and refuses to start over a stale stack.

### Still unverified — treat as hypotheses until your first cluster dry run
* Everything that needs Istio: `verify_mesh.sh`, the live behaviour of `attack_matrix.py` (its `expected` semantics — 401 vs 403 vs connection reset — are my model of Istio), `run_resilience.py` (faults), `cluster_*.sh`, `deploy.sh`.
* The `SECRET_TTL` certificate-lifetime knob and the JSON layout of `istioctl proxy-config secret` (decoding is unit-tested on a synthetic entry only).
* `article/main.tex` (IEEEtran not installed in the sandbox).
* E4 numbers are a **development-set regression test**; create the held-out set after freezing the rules (PROTOCOL §9).
