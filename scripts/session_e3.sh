#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
RATE=286; OUT=results/e3
for rep in 1 2 3 4 5; do
 for fault in pod-kill rollout node-drain istiod-down istiod-down-churn; do
  for s in a0 a1 c; do
   case $fault in istiod-down*) [ $s = a0 ] && continue;; esac
   f=$fault; flag=""; tag="rep$rep"
   if [ $fault = istiod-down-churn ]; then f=istiod-down; flag="--with-restart"; tag="churn-rep$rep"; fi
   if grep -qs load_end $OUT/$s-$f-$tag-*/events.jsonl 2>/dev/null; then continue; fi
   kubectl scale deploy/istiod -n istio-system --replicas=1 >/dev/null
   kubectl rollout status deploy/istiod -n istio-system --timeout=300s >/dev/null
   for n in $(kubectl get nodes -o name); do kubectl uncordon $n >/dev/null; done
   kubectl rollout restart deploy -n mesh-$s >/dev/null
   for d in $(kubectl get deploy -n mesh-$s -o name); do kubectl rollout status $d -n mesh-$s --timeout=300s >/dev/null; done
   sleep 30
   echo "== $(date +%T) $s $f $tag"
   python3 scripts/run_resilience.py --scenario $s --fault $f --rate $RATE --seed $rep --tag $tag $flag --out $OUT | tail -1
   sleep 20
  done
 done
done
echo "ALL DONE $(date +%T)"
