#!/usr/bin/env python3
"""Generate Kubernetes/Istio manifests for every scenario from topology.yaml.

Scenarios
  a0  no mesh (namespace not injected), no authN/authZ            -> true baseline
  a1  mesh (sidecars, Istio auto-mTLS under PERMISSIVE), no policy -> isolates "mesh tax"
  b   no mesh; every service validates the RS256 JWT itself        -> application-layer JWT-only
  c   mesh, STRICT mTLS, per-service identity AuthorizationPolicy, REGISTRY_ONLY egress
  d   scenario c + mesh-level JWT validation (RequestAuthentication) at the edge
"""
import argparse, json, pathlib, sys
import yaml
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import topo

ROOT = topo.ROOT
SCEN = {
    "a0": dict(mesh=False, app_jwt=False, strict=False, authz=False, mesh_jwt=False),
    "a1": dict(mesh=True, app_jwt=False, strict=False, authz=False, mesh_jwt=False),
    "b": dict(mesh=False, app_jwt=True, strict=False, authz=False, mesh_jwt=False),
    "c": dict(mesh=True, app_jwt=False, strict=True, authz=True, mesh_jwt=False),
    "d": dict(mesh=True, app_jwt=False, strict=True, authz=True, mesh_jwt=True),
}
LB_BASE_PORT = 8100
ISS, AUD = "mesh-study", "mesh-api"


def ns_of(s):
    return f"mesh-{s}"


def routes_for(t, svc):
    r = {}
    for cname, chain in t["chains"].items():
        if svc in chain:
            i = chain.index(svc)
            r[f"/{cname}"] = {"to": chain[i + 1], "path": f"/{cname}"} if i + 1 < len(chain) else {"to": ""}
    return r


def container_security():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "runAsNonRoot": True,
            "runAsUser": 10001, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}


def deployment(t, s, svc, a):
    sc, ns = SCEN[s], ns_of(s)
    env = [("SERVICE_NAME", svc), ("PORT", "8080"), ("ROUTES", json.dumps(routes_for(t, svc), separators=(",", ":"))),
           ("PAYLOAD_BYTES", str(a.payload)), ("CPU_WORK_ITERS", str(a.cpu_iters))]
    vols, mounts = [], []
    if sc["app_jwt"]:
        env += [("JWT_MODE", "app"), ("JWT_PUBKEY_FILE", "/keys/jwt_public.pem"), ("JWT_ISS", ISS), ("JWT_AUD", AUD)]
        vols = [{"name": "jwt-pub", "configMap": {"name": "jwt-pub"}}]
        mounts = [{"name": "jwt-pub", "mountPath": "/keys", "readOnly": True}]
    ann = {}
    if sc["mesh"]:
        ann.update({"sidecar.istio.io/proxyCPU": "50m", "sidecar.istio.io/proxyMemory": "64Mi",
                    "sidecar.istio.io/proxyCPULimit": "1000m", "sidecar.istio.io/proxyMemoryLimit": "256Mi"})
        pc = {}
        if a.hold_proxy:
            pc["holdApplicationUntilProxyStarts"] = True
        if a.cert_ttl:
            pc["proxyMetadata"] = {"SECRET_TTL": a.cert_ttl}   # VERIFY on your Istio version (see PROTOCOL E3)
        if pc:
            ann["proxy.istio.io/config"] = json.dumps(pc)
    labels = {"app": svc, "scenario": s}
    pod = {"metadata": {"labels": labels, **({"annotations": ann} if ann else {})},
           "spec": {"serviceAccountName": f"sa-{svc}", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                    "topologySpreadConstraints": [{"maxSkew": 1, "topologyKey": "kubernetes.io/hostname",
                                                   "whenUnsatisfiable": "ScheduleAnyway", "labelSelector": {"matchLabels": {"app": svc}}}],
                    "containers": [{"name": "app", "image": a.image, "imagePullPolicy": "IfNotPresent",
                                    "ports": [{"containerPort": 8080, "name": "http"}],
                                    "env": [{"name": k, "value": v} for k, v in env],
                                    "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080}, "periodSeconds": 2},
                                    "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}, "periodSeconds": 10, "initialDelaySeconds": 5},
                                    "resources": {"requests": {"cpu": "50m", "memory": "32Mi"}, "limits": {"cpu": "1000m", "memory": "128Mi"}},
                                    "securityContext": container_security(),
                                    **({"volumeMounts": mounts} if mounts else {})}],
                    **({"volumes": vols} if vols else {})}}
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": svc, "namespace": ns, "labels": labels},
            "spec": {"replicas": a.replicas, "selector": {"matchLabels": {"app": svc}}, "template": pod}}


def authz_policies(t, s, svc_names):
    """One ALLOW policy per destination: allow-listed caller identities only."""
    sc, ns = SCEN[s], ns_of(s)
    out = []
    for dst in svc_names:
        meta = {"name": f"allow-to-{dst}", "namespace": ns}
        spec = {"selector": {"matchLabels": {"app": dst}}, "action": "ALLOW"}
        if dst in t.get("public", []):
            meta["annotations"] = {"policy.study/edge": "true"}
            rule = {"from": [{"source": {"requestPrincipals": ["*"]}}]} if sc["mesh_jwt"] else {}
            spec["rules"] = [rule]
        else:
            callers = topo.callers_of(t, dst)
            spec["rules"] = [{"from": [{"source": {"principals": [f"cluster.local/ns/{ns}/sa/sa-{c}" for c in callers]}}]}] if callers else []
        out.append({"apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy", "metadata": meta, "spec": spec})
    return out


def scenario_docs(t, s, a):
    sc, ns = SCEN[s], ns_of(s)
    svcs = t["services"]
    nsmeta = {"name": ns, "labels": {"study/scenario": s}, "annotations": {}}
    if sc["mesh"]:
        nsmeta["labels"]["istio-injection"] = "enabled"
        nsmeta["annotations"]["policy.study/expect-mesh"] = "true"
    docs = [{"apiVersion": "v1", "kind": "Namespace", "metadata": nsmeta}]
    if sc["app_jwt"]:
        pub = (ROOT / "keys" / "jwt_public.pem").read_text()
        docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "jwt-pub", "namespace": ns}, "data": {"jwt_public.pem": pub}})
    for svc in svcs:
        docs.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": f"sa-{svc}", "namespace": ns}, "automountServiceAccountToken": False})
        docs.append(deployment(t, s, svc, a))
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": svc, "namespace": ns, "labels": {"app": svc}},
                     "spec": {"selector": {"app": svc}, "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    idx = list(SCEN).index(s)
    docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "gateway-lb", "namespace": ns},
                 "spec": {"type": "LoadBalancer", "selector": {"app": "gateway"},
                          "ports": [{"name": "http", "port": LB_BASE_PORT + idx, "targetPort": 8080}]}})
    if sc["strict"]:
        docs.append({"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": ns},
                     "spec": {"mtls": {"mode": "STRICT"}}})
        # the edge service must accept external (non-mesh) clients on its public port
        docs.append({"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication", "metadata": {"name": "gateway-edge", "namespace": ns, "annotations": {"policy.study/edge": "true"}},
                     "spec": {"selector": {"matchLabels": {"app": "gateway"}}, "mtls": {"mode": "STRICT"},
                              "portLevelMtls": {"8080": {"mode": "PERMISSIVE"}}}})
        docs.append({"apiVersion": "networking.istio.io/v1", "kind": "Sidecar", "metadata": {"name": "default", "namespace": ns},
                     "spec": {"egress": [{"hosts": ["*/*"]}], "outboundTrafficPolicy": {"mode": "REGISTRY_ONLY"}}})
    elif sc["mesh"]:
        docs.append({"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication", "metadata": {"name": "default", "namespace": ns},
                     "spec": {"mtls": {"mode": "PERMISSIVE"}}})
    if sc["authz"]:
        docs += authz_policies(t, s, svcs)
    if sc["mesh_jwt"]:
        jwks = (ROOT / "keys" / "jwks.json").read_text().strip()
        docs.append({"apiVersion": "security.istio.io/v1", "kind": "RequestAuthentication", "metadata": {"name": "jwt-edge", "namespace": ns},
                     "spec": {"selector": {"matchLabels": {"app": "gateway"}},
                              "jwtRules": [{"issuer": ISS, "audiences": [AUD], "jwks": jwks}]}})
    return docs


def attacker_docs(a):
    """Two probe pods that simulate a foreign workload: one outside the mesh (plaintext), one inside the mesh with an unknown identity."""
    out = []
    for name, mesh in (("attacker-nomesh", False), ("attacker-mesh", True)):
        meta = {"name": name, "labels": {"study/role": "attacker"}}
        if mesh:
            meta["labels"]["istio-injection"] = "enabled"
        out.append({"apiVersion": "v1", "kind": "Namespace", "metadata": meta})
        out.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sa-attacker", "namespace": name}, "automountServiceAccountToken": False})
        out.append({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "attacker", "namespace": name, "labels": {"app": "attacker"}},
                    "spec": {"serviceAccountName": "sa-attacker", "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "app", "image": a.image, "imagePullPolicy": "IfNotPresent", "command": ["sleep", "infinity"],
                                             "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "200m", "memory": "64Mi"}},
                                             "securityContext": container_security()}]}})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="mesh-svc:dev")
    ap.add_argument("--replicas", type=int, default=2)
    ap.add_argument("--payload", type=int, default=2048)
    ap.add_argument("--cpu-iters", type=int, default=1000)
    ap.add_argument("--hold-proxy", action="store_true", help="holdApplicationUntilProxyStarts=true (E3 warm-up study)")
    ap.add_argument("--cert-ttl", default="", help="e.g. 30m -> SECRET_TTL for cert-rotation study (verify knob on your Istio version)")
    ap.add_argument("--out", default=str(ROOT / "k8s" / "generated"))
    a = ap.parse_args()
    t = topo.load()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for s in SCEN:
        if SCEN[s]["app_jwt"] or SCEN[s]["mesh_jwt"]:
            if not (ROOT / "keys" / "jwt_public.pem").exists():
                sys.exit("run tools/gen_keys.py first")
        docs = scenario_docs(t, s, a)
        (out / f"{s}.yaml").write_text(yaml.safe_dump_all(docs, sort_keys=False))
    (out / "attackers.yaml").write_text(yaml.safe_dump_all(attacker_docs(a), sort_keys=False))
    print(f"wrote {len(SCEN)} scenarios + attackers to {out}")


if __name__ == "__main__":
    main()
