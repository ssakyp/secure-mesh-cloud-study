#!/usr/bin/env bash
# Environment fingerprint stored with the results (versions, node sizes, policies in force).
set -uo pipefail
out="${1:-results/env}"; mkdir -p "$out"
{ date -u; uname -a; k6 version; kubectl version; istioctl version; } > "$out/versions.txt" 2>&1
kubectl get nodes -o wide > "$out/nodes.txt" 2>&1
kubectl top nodes > "$out/top_nodes.txt" 2>&1
kubectl get pods -A -o wide > "$out/pods.txt" 2>&1
kubectl get peerauthentication,authorizationpolicy,requestauthentication,sidecar -A -o yaml > "$out/istio_policies.yaml" 2>&1
git rev-parse HEAD > "$out/git_commit.txt" 2>&1
echo "environment written to $out"
