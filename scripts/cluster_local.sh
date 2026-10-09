#!/usr/bin/env bash
# Local multi-node dry run (k3d). Free; use it to debug everything before spending cloud credit.
# Needs: docker, k3d, kubectl, istioctl.   Ports 8100-8104 are published for the five scenarios.
set -euo pipefail
cd "$(dirname "$0")/.."
k3d cluster create mesh --servers 1 --agents 2 --k3s-arg "--disable=traefik@server:0" -p "8100-8104:8100-8104@loadbalancer" --wait
docker build -t mesh-svc:dev svc/
k3d image import mesh-svc:dev -c mesh
scripts/install_istio.sh
IMAGE=mesh-svc:dev scripts/deploy.sh
echo "now: python3 scripts/run_matrix.py --local-lb --knee <rps> ...   (k6 on the same laptop => results are a pilot only)"
