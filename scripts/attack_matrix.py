#!/usr/bin/env python3
"""E2 security-efficacy tests (run per scenario against a live cluster).

  reach  : full directed matrix: every service + two attacker pods -> every service, with and without a valid user token,
           scored against the intended policy in topology.yaml (precision/recall of enforcement, not just "100% blocked")
  jwt    : forged / expired / tampered / alg=none / key-confusion tokens against the edge and an internal service
  egress : can a compromised service reach arbitrary Internet hosts?
Observed behaviour comes from `kubectl exec ... curl` inside the source pod, i.e. through that pod's own sidecar.
`--model` runs the harness against a simulated cluster to self-test the scoring code (it says nothing about Istio).
"""
import argparse, concurrent.futures as cf, csv, json, math, pathlib, subprocess, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import topo

SCENARIOS = ["a0", "a1", "b", "c", "d"]
ATTACKERS = [("attacker-mesh", "attacker-mesh"), ("attacker-nomesh", "attacker-nomesh")]


def tokens():
    return {f.stem: f.read_text().strip() for f in sorted((ROOT / "keys" / "tokens").glob("*.jwt"))}


class KubectlExec:
    def __init__(self):
        self._pods = {}

    def pod(self, ns, app):
        k = (ns, app)
        if k not in self._pods:
            r = subprocess.run(["kubectl", "get", "pod", "-n", ns, "-l", f"app={app}", "-o", "jsonpath={.items[0].metadata.name}"],
                               capture_output=True, text=True)
            if not r.stdout.strip():
                raise RuntimeError(f"no pod for app={app} in {ns}: {r.stderr.strip()}")
            self._pods[k] = r.stdout.strip()
        return self._pods[k]

    def curl(self, ns, app, url, token=None, timeout=5):
        cmd = ["kubectl", "exec", "-n", ns, self.pod(ns, app), "-c", "app", "--", "curl", "-s", "-o", "/dev/null", "-m", str(timeout), "-w", "%{http_code}"]
        if token:
            cmd += ["-H", f"Authorization: Bearer {token}"]
        r = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=timeout + 20)
        code = r.stdout.strip()[-3:]
        return int(code) if code.isdigit() else 0


class ModelExec:
    """Simulated enforcement semantics of each scenario (self-test only)."""
    def __init__(self, t):
        self.t, self.tok = t, tokens()

    def curl(self, ns, app, url, token=None, timeout=5):
        host = url.split("//")[1].split("/")[0].split(":")[0]
        src = app if ns.startswith("mesh-") else ns
        if "example.com" in host:
            return 200 if ns in ("mesh-a0", "mesh-a1", "mesh-b") else 0
        dst, tns = host.split(".")[0], host.split(".")[1]
        s = tns.split("-")[1]
        valid = token == self.tok["valid"]
        has_tok = bool(token)
        if s in ("a0", "a1"):
            return 200
        if s == "b":
            return 200 if valid else 401
        public = dst in self.t.get("public", [])
        if public:
            if s == "d":
                return 200 if valid else (401 if has_tok else 403)
            return 200
        if src == "attacker-nomesh":
            return 0
        return 200 if topo.intended_allow(self.t, src, dst) else 403


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 4), round(c + h, 4))


def fqdn(dst, ns):
    return f"http://{dst}.{ns}.svc.cluster.local:8080/ping"


def run_scenario(s, ex, t, workers):
    ns = f"mesh-{s}"
    tok = tokens()
    jobs = []
    sources = [(svc, ns, svc) for svc in t["services"]] + [(n, n, "attacker") for n, _ in ATTACKERS]
    for name, sns, app in sources:
        for dst in t["services"]:
            if dst == name:
                continue
            intended = dst in t.get("public", []) if name.startswith("attacker") else topo.intended_allow(t, name, dst)
            for cred in ("none", "valid"):
                jobs.append(("reach", dict(scenario=s, src=name, dst=dst, cred=cred, intended=intended), sns, app, fqdn(dst, ns), tok["valid"] if cred == "valid" else None))
    for target in ("gateway", "ledger"):
        for tname in ["none"] + list(tok):
            jobs.append(("jwt", dict(scenario=s, target=target, token=tname), "attacker-nomesh", "attacker", fqdn(target, ns), None if tname == "none" else tok[tname]))
    for url in ("https://example.com", "http://example.com"):
        jobs.append(("egress", dict(scenario=s, src="ai", url=url), ns, "ai", url, None))

    def do(j):
        kind, meta, sns, app, url, token = j
        try:
            code = ex.curl(sns, app, url, token)
        except Exception as e:
            code, meta = -1, dict(meta, error=str(e)[:80])
        return kind, dict(meta, code=code, allowed=200 <= code < 400 if kind == "egress" else 200 <= code < 300)

    res = {"reach": [], "jwt": [], "egress": []}
    with cf.ThreadPoolExecutor(workers) as pool:
        for kind, row in pool.map(do, jobs):
            res[kind].append(row)
    return res


def summarise(s, res):
    out = {"scenario": s}
    for cred in ("none", "valid"):
        rows = [r for r in res["reach"] if r["cred"] == cred]
        unauth = [r for r in rows if not r["intended"]]
        legit = [r for r in rows if r["intended"]]
        blocked = sum(not r["allowed"] for r in unauth)
        wrong_blocks = sum(not r["allowed"] for r in legit)
        conf = sum(r["allowed"] == r["intended"] for r in rows)
        out[cred] = dict(pairs=len(rows), unauthorized_pairs=len(unauth), blocked_unauthorized=blocked,
                         block_rate=round(blocked / len(unauth), 4), block_rate_ci95=wilson(blocked, len(unauth)),
                         legit_pairs=len(legit), wrongly_blocked_legit=wrong_blocks, false_block_rate=round(wrong_blocks / len(legit), 4),
                         conformance=round(conf / len(rows), 4), conformance_ci95=wilson(conf, len(rows)),
                         errors=sum(1 for r in rows if r["code"] == -1))
    gw = [r for r in res["jwt"] if r["target"] == "gateway" and r["token"] not in ("valid",)]
    bad = [r for r in gw if r["token"] != "none"]
    out["jwt_gateway"] = dict(invalid_tokens_tested=len(bad), invalid_accepted=sum(r["allowed"] for r in bad),
                              no_token_accepted=any(r["allowed"] for r in gw if r["token"] == "none"),
                              valid_accepted=any(r["allowed"] for r in res["jwt"] if r["target"] == "gateway" and r["token"] == "valid"))
    out["egress"] = dict(tested=len(res["egress"]), reachable=sum(r["allowed"] for r in res["egress"]))
    return out


def write(outdir, s, res, summ):
    d = pathlib.Path(outdir) / s
    d.mkdir(parents=True, exist_ok=True)
    for kind, rows in res.items():
        if rows:
            keys = sorted({k for r in rows for k in r})
            with open(d / f"{kind}.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                w.writerows(rows)
    (d / "summary.json").write_text(json.dumps(summ, indent=1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    ap.add_argument("--out", default=str(ROOT / "results" / "e2"))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--model", action="store_true", help="self-test with a simulated cluster")
    a = ap.parse_args()
    t = topo.load()
    ex = ModelExec(t) if a.model else KubectlExec()
    print(f"{'scn':4s} {'cred':6s} {'unauth blocked':>16s} {'legit blocked':>14s} {'conformance':>12s}   jwt-invalid-accepted  egress-reachable")
    for s in a.scenarios.split(","):
        res = run_scenario(s, ex, t, a.workers)
        sm = summarise(s, res)
        write(a.out, s, res, sm)
        for cred in ("none", "valid"):
            c = sm[cred]
            print(f"{s:4s} {cred:6s} {c['blocked_unauthorized']:>7d}/{c['unauthorized_pairs']:<7d} {c['wrongly_blocked_legit']:>6d}/{c['legit_pairs']:<7d} {100 * c['conformance']:11.1f}%"
                  + (f"   {sm['jwt_gateway']['invalid_accepted']}/{sm['jwt_gateway']['invalid_tokens_tested']:<18d} {sm['egress']['reachable']}/{sm['egress']['tested']}" if cred == "valid" else ""))


if __name__ == "__main__":
    main()
