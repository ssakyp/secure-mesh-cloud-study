#!/usr/bin/env bash
# Generate + apply every scenario and wait until all pods are ready.
# usage: IMAGE=ghcr.io/<you>/mesh-svc:<tag> scripts/deploy.sh [extra gen_manifests.py flags, e.g. --hold-proxy]
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-mesh-svc:dev}"
[ -f keys/jwt_public.pem ] || python3 tools/gen_keys.py
python3 tools/gen_manifests.py --image "$IMAGE" "$@"
kubectl apply -f k8s/generated/attackers.yaml
for s in a0 a1 b c d; do kubectl apply -f "k8s/generated/$s.yaml"; done
for s in a0 a1 b c d; do
  for d in $(kubectl get deploy -n "mesh-$s" -o name); do kubectl rollout status "$d" -n "mesh-$s" --timeout=300s; done
done
kubectl wait --for=condition=Ready pod/attacker -n attacker-mesh --timeout=120s
kubectl wait --for=condition=Ready pod/attacker -n attacker-nomesh --timeout=120s
echo "deployed. LoadBalancer addresses:"; kubectl get svc -A | grep -E "NAMESPACE|gateway-lb"
