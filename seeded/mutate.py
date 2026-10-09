#!/usr/bin/env python3
"""Seeded-misconfiguration benchmark for the DevSecOps gate (experiment E4).
Applies realistic single-fault mutations to the known-good scenario C manifest and
records which check detects each one. Also runs the clean manifests as false-positive controls."""
import argparse, copy, csv, json, pathlib, subprocess, sys, time
import yaml
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import policy_intent_check as pic, topo

NS = "mesh-c"


def find(docs, kind, name):
    for d in docs:
        if d.get("kind") == kind and d["metadata"]["name"] == name:
            return d
    raise KeyError((kind, name))


def drop(docs, kind, name):
    return [d for d in docs if not (d.get("kind") == kind and d["metadata"]["name"] == name)]


def cont(docs, dep):
    return find(docs, "Deployment", dep)["spec"]["template"]["spec"]["containers"][0]


def podspec(docs, dep):
    return find(docs, "Deployment", dep)["spec"]["template"]["spec"]


def m01(d): podspec(d, "health")["serviceAccountName"] = "default"; return d
def m02(d): podspec(d, "ai")["serviceAccountName"] = "sa-ledger"; return d
def m03(d): find(d, "PeerAuthentication", "default")["spec"]["mtls"]["mode"] = "PERMISSIVE"; return d
def m04(d): return drop(d, "PeerAuthentication", "default")
def m05(d): return drop(d, "AuthorizationPolicy", "allow-to-health")
def m06(d): find(d, "AuthorizationPolicy", "allow-to-health")["spec"]["rules"] = [{}]; return d
def m07(d): find(d, "AuthorizationPolicy", "allow-to-health")["spec"]["rules"][0]["from"][0]["source"]["principals"].append(f"cluster.local/ns/{NS}/sa/sa-ai"); return d
def m08(d): find(d, "AuthorizationPolicy", "allow-to-ledger")["spec"]["rules"][0]["from"][0]["source"]["principals"] = ["*"]; return d
def m09(d): find(d, "AuthorizationPolicy", "allow-to-ledger")["spec"]["rules"][0]["from"][0]["source"]["principals"].pop(); return d
def m10(d): cont(d, "ledger")["image"] = "ghcr.io/example/mesh-svc:latest"; return d
def m11(d): cont(d, "receipt")["securityContext"]["privileged"] = True; return d
def m12(d): c = cont(d, "ai"); c["securityContext"].update(runAsUser=0, runAsNonRoot=False); podspec(d, "ai")["securityContext"]["runAsNonRoot"] = False; return d
def m13(d): cont(d, "report")["resources"].pop("limits"); return d
def m14(d): d.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "oops", "namespace": NS}, "data": {"key.pem": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"}}); return d
def m15(d): cont(d, "ai").setdefault("env", []).append({"name": "GROQ_API_KEY", "value": "gsk_live_example"}); return d
def m16(d): return drop(d, "Sidecar", "default")
def m17(d): find(d, "Namespace", NS)["metadata"]["labels"].pop("istio-injection"); return d
def m18(d): podspec(d, "category")["serviceAccountName"] = "sa-account"; return d
def m19(d): d.append({"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication", "metadata": {"name": "health-relax", "namespace": NS},
                      "spec": {"selector": {"matchLabels": {"app": "health"}}, "mtls": {"mode": "PERMISSIVE"}}}); return d


MUT = [
    ("M01", "identity", "health workload falls back to the default ServiceAccount", m01),
    ("M02", "identity", "ai workload runs with ledger's ServiceAccount (identity borrowing)", m02),
    ("M03", "transport", "namespace-wide mTLS relaxed to PERMISSIVE", m03),
    ("M04", "transport", "namespace-wide PeerAuthentication deleted", m04),
    ("M05", "authz", "AuthorizationPolicy of health deleted", m05),
    ("M06", "authz", "health policy replaced by allow-all rule", m06),
    ("M07", "authz", "ai added to health's allowed callers (blast-radius violation)", m07),
    ("M08", "authz", "wildcard principal on ledger", m08),
    ("M09", "authz", "intended caller (receipt) removed from ledger policy (availability)", m09),
    ("M10", "container", "ledger image pinned to :latest", m10),
    ("M11", "container", "receipt runs privileged", m11),
    ("M12", "container", "ai runs as root", m12),
    ("M13", "container", "report has no resource limits", m13),
    ("M14", "secret", "private key committed in a ConfigMap", m14),
    ("M15", "secret", "literal API key in ai env", m15),
    ("M16", "egress", "REGISTRY_ONLY egress restriction removed", m16),
    ("M17", "transport", "sidecar injection disabled for the namespace", m17),
    ("M18", "identity", "two services share one ServiceAccount", m18),
    ("M19", "transport", "workload-level mTLS downgrade on health", m19),
]


def run_checks(path, docs, t, conftest):
    t0 = time.perf_counter()
    r = subprocess.run([conftest, "test", "--combine", "-p", str(ROOT / "policy"), "-o", "json", "--no-color", str(path)], capture_output=True, text=True)
    t_rego = (time.perf_counter() - t0) * 1000
    rules = set()
    try:
        for res in json.loads(r.stdout):
            rules |= {f["msg"].split()[0] for f in res.get("failures", [])}
    except Exception:
        pass
    t0 = time.perf_counter()
    intent = pic.check(docs, t)
    t_int = (time.perf_counter() - t0) * 1000
    return sorted(rules), sorted({v.split()[0] for v in intent}), t_rego, t_int


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(ROOT / "k8s/generated/c.yaml"))
    ap.add_argument("--out", default=str(ROOT / "seeded/out"))
    ap.add_argument("--conftest", default="conftest")
    a = ap.parse_args()
    t = topo.load()
    base = [d for d in yaml.safe_load_all(open(a.base)) if d]
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for ctrl in ("c", "d"):  # false-positive controls
        p = ROOT / f"k8s/generated/{ctrl}.yaml"
        docs = [d for d in yaml.safe_load_all(open(p)) if d]
        rules, intent, tr, ti = run_checks(p, docs, t, a.conftest)
        rows.append(dict(id=f"CLEAN-{ctrl}", category="control", description=f"unmodified scenario {ctrl}", rego=";".join(rules), intent=";".join(intent),
                         detected=bool(rules or intent), ms_rego=round(tr, 1), ms_intent=round(ti, 1)))
    for mid, cat, desc, fn in MUT:
        docs = fn(copy.deepcopy(base))
        p = out / f"{mid}.yaml"
        p.write_text(yaml.safe_dump_all(docs, sort_keys=False))
        rules, intent, tr, ti = run_checks(p, docs, t, a.conftest)
        rows.append(dict(id=mid, category=cat, description=desc, rego=";".join(rules), intent=";".join(intent),
                         detected=bool(rules or intent), ms_rego=round(tr, 1), ms_intent=round(ti, 1)))
    with open(out / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    mut = [r for r in rows if r["category"] != "control"]
    ctl = [r for r in rows if r["category"] == "control"]
    det = sum(r["detected"] for r in mut)
    rego_only = sum(bool(r["rego"]) for r in mut)
    print(f"{'id':8s}{'category':10s}{'detected':9s}{'rego rules':22s}{'intent':26s}description")
    for r in rows:
        print(f"{r['id']:8s}{r['category']:10s}{str(r['detected']):9s}{r['rego']:22s}{r['intent']:26s}{r['description']}")
    print(f"\nseeded misconfigurations detected: {det}/{len(mut)} (rego policies alone: {rego_only}/{len(mut)}); "
          f"false positives on clean manifests: {sum(r['detected'] for r in ctl)}/{len(ctl)}")
    sys.exit(0 if det == len(mut) and not any(r["detected"] for r in ctl) else 1)


if __name__ == "__main__":
    main()
