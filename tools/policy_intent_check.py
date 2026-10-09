#!/usr/bin/env python3
"""Compare the AuthorizationPolicies / identities in a manifest file against the
intended policy in topology.yaml. Catches *semantic* misconfigurations that generic
hygiene rules cannot see (e.g. 'ai may call health').
Exit code 1 when violations are found."""
import argparse, json, pathlib, sys
import yaml
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import topo


def check(docs, t):
    viol = []
    for ns in [d for d in docs if d.get("kind") == "Namespace" and d["metadata"].get("annotations", {}).get("policy.study/expect-mesh") == "true"]:
        name = ns["metadata"]["name"]
        pols = {}
        for d in docs:
            if d.get("kind") == "AuthorizationPolicy" and d["metadata"].get("namespace") == name:
                dst = d["spec"]["selector"]["matchLabels"]["app"]
                pols.setdefault(dst, []).append(d)
        for dep in [d for d in docs if d.get("kind") == "Deployment" and d["metadata"].get("namespace") == name]:
            app = dep["metadata"]["labels"]["app"]
            sa = dep["spec"]["template"]["spec"].get("serviceAccountName", "default")
            if sa != f"sa-{app}":
                viol.append(f"SA_BINDING {name}/{app} runs as {sa!r}, expected 'sa-{app}'")
        for dst in t["services"]:
            if dst not in pols:
                viol.append(f"NO_POLICY {name}/{dst} has no AuthorizationPolicy")
                continue
            allow_all, principals = False, set()
            for p in pols[dst]:
                if p["spec"].get("action", "ALLOW") != "ALLOW":
                    continue
                for r in p["spec"].get("rules", []):
                    if not r:
                        allow_all = True
                    for f in r.get("from", []):
                        principals |= set(f.get("source", {}).get("principals", []))
                        if "requestPrincipals" in f.get("source", {}):
                            allow_all = allow_all or dst in t.get("public", [])
            if dst in t.get("public", []):
                continue
            if allow_all:
                viol.append(f"ALLOW_ALL {name}/{dst} accepts any caller but is not public")
            want = {f"cluster.local/ns/{name}/sa/sa-{c}" for c in topo.callers_of(t, dst)}
            for extra in sorted(principals - want):
                viol.append(f"EXTRA_EDGE {name}/{dst} additionally allows {extra}")
            for miss in sorted(want - principals):
                viol.append(f"MISSING_EDGE {name}/{dst} no longer allows intended caller {miss}")
    return viol


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--topology", default=None)
    a = ap.parse_args()
    t = topo.load(a.topology)
    docs = []
    for f in a.files:
        docs += [d for d in yaml.safe_load_all(open(f)) if d]
    v = check(docs, t)
    for x in v:
        print(x)
    print(f"{len(v)} intent violation(s)")
    sys.exit(1 if v else 0)


if __name__ == "__main__":
    main()
