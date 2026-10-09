#!/usr/bin/env bash
# Pre-flight checks that the scenarios really are what the paper says they are.
# Article 1 baseline pods were 2/2 (sidecar injected) - this script makes such confounds visible BEFORE any experiment.
set -uo pipefail
for s in a0 a1 b c d; do
  ns="mesh-$s"
  echo "== $ns =="
  kubectl get pods -n "$ns" -l app=gateway --no-headers | awk '{print "  gateway pod READY="$2}'
  kubectl get peerauthentication -n "$ns" --no-headers 2>/dev/null | sed 's/^/  PeerAuthentication: /'
  case $s in a1|c|d)
    gw=$(kubectl get pod -n "$ns" -l app=gateway -o jsonpath='{.items[0].metadata.name}')
    kubectl exec -n "$ns" "$gw" -c app -- curl -s -o /dev/null -m 5 http://ledger:8080/ping || true
    echo -n "  mTLS handshakes seen by the sidecar (outbound): "
    kubectl exec -n "$ns" "$gw" -c istio-proxy -- pilot-agent request GET stats 2>/dev/null | grep -c 'ssl.handshake' || true ;;
  esac
done
echo
echo "Expected: a0,b -> READY=1/1 and no handshakes; a1,c,d -> READY=2/2 and handshake counters present."
echo "NOTE a1 (PERMISSIVE) normally STILL uses mTLS between sidecars (Istio auto-mTLS): that is why a0 exists."
