#!/usr/bin/env bash
# Install Istio (control plane only: no ingress gateway is needed, the `gateway` service is the edge).
set -euo pipefail
ISTIO_VERSION="${ISTIO_VERSION:-}"   # empty = whatever istioctl you have; RECORD it (results/env) and pin it for the paper
command -v istioctl >/dev/null || { echo "istioctl not found: https://istio.io/latest/docs/setup/getting-started/#download"; exit 1; }
istioctl version --remote=false
istioctl install -y --set profile=minimal ${ISTIO_VERSION:+--set tag=$ISTIO_VERSION}
kubectl -n istio-system rollout status deploy/istiod --timeout=180s
kubectl top nodes >/dev/null 2>&1 || echo "WARNING: metrics-server not answering; 'kubectl top' snapshots will be empty"
