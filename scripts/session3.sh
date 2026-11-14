#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
export MAX_GEN_CPU=100
for rep in $(seq 1 16); do
  echo "== block rep=$rep: restarting workloads $(date +%T)"
  for s in a0 a1 b c; do kubectl rollout restart deploy -n mesh-$s >/dev/null; done
  for s in a0 a1 b c; do for d in $(kubectl get deploy -n mesh-$s -o name); do kubectl rollout status $d -n mesh-$s --timeout=300s >/dev/null; done; done
  sleep 30
  python3 scripts/run_matrix.py --local-lb --knee 572 --scenarios a0,a1,b,c --chains c3 --rates 0.3,0.6,0.8 --reps $rep --warmup 10 --duration 60 --cooldown 10 --max-vus 500 --no-kube --out results/stage3 | tail -1
done
echo "ALL DONE $(date +%T)"
