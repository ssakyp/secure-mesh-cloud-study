#!/usr/bin/env python3
"""E3 fault-injection runner (needs kubectl; istioctl for cert observation).

Runs a steady k6 load (arrival-rate) against one scenario, injects ONE fault after a baseline period,
and records an events.jsonl next to the k6 csv time series. Analyse with analysis/resilience.py.

  pod-kill        force-delete one pod of --target (crash, no graceful drain)
  rollout         rolling restart of every Deployment in the namespace (sidecar warm-up window; compare --hold-proxy manifests)
  node-drain      cordon+drain the node hosting most application pods, uncordon afterwards
  istiod-down     scale istiod to 0 for --outage seconds (control-plane loss; optional --with-restart pod churn)
  cert-observe    no fault; log workload-cert NotBefore/NotAfter every 30 s so rotations are *measured*, not assumed
"""
import argparse, datetime, json, os, pathlib, random, subprocess, sys, threading, time
ROOT = pathlib.Path(__file__).resolve().parent.parent
K6 = os.environ.get("K6", "k6")


def sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r.stdout.strip()


class Log:
    def __init__(self, path):
        self.f = open(path, "w")

    def ev(self, event, **kw):
        self.f.write(json.dumps(dict(t=time.time(), event=event, **kw)) + "\n")
        self.f.flush()
        print(f"[{datetime.datetime.now():%H:%M:%S}] {event} {kw if kw else ''}", flush=True)


def inject(a, ns, log):
    if a.fault == "pod-kill":
        pods = sh(["kubectl", "get", "pods", "-n", ns, "-l", f"app={a.target}", "-o", "name"]).split()
        victim = random.Random(a.seed).choice(pods)
        log.ev("fault_start", fault=a.fault, target=victim)
        sh(["kubectl", "delete", victim, "-n", ns, "--grace-period=0", "--force", "--wait=false"])
        time.sleep(5)
        log.ev("fault_end")
    elif a.fault == "rollout":
        log.ev("fault_start", fault=a.fault)
        deps = sh(["kubectl", "get", "deploy", "-n", ns, "-o", "name"]).split()
        for d in deps:
            sh(["kubectl", "rollout", "restart", d, "-n", ns])
        for d in deps:
            sh(["kubectl", "rollout", "status", d, "-n", ns, "--timeout=180s"])
        log.ev("fault_end")
    elif a.fault == "node-drain":
        nodes = sh(["kubectl", "get", "pods", "-n", ns, "-o", "jsonpath={range .items[*]}{.spec.nodeName}{\"\\n\"}{end}"]).split()
        node = max(set(nodes), key=nodes.count)
        log.ev("fault_start", fault=a.fault, node=node)
        sh(["kubectl", "drain", node, "--ignore-daemonsets", "--delete-emptydir-data", "--force", "--timeout=120s"])
        log.ev("fault_end")
        sh(["kubectl", "uncordon", node])
    elif a.fault == "istiod-down":
        log.ev("fault_start", fault=a.fault, outage_s=a.outage)
        sh(["kubectl", "scale", "deploy/istiod", "-n", "istio-system", "--replicas=0"])
        if a.with_restart:
            sh(["kubectl", "rollout", "restart", f"deploy/{a.target}", "-n", ns])
        time.sleep(a.outage)
        sh(["kubectl", "scale", "deploy/istiod", "-n", "istio-system", "--replicas=1"])
        log.ev("fault_end")
    elif a.fault == "cert-observe":
        log.ev("fault_start", fault=a.fault)
        time.sleep(a.hold)
        log.ev("fault_end")


def cert_validity(secret):
    """(not_before, not_after) of the workload leaf certificate from one `istioctl proxy-config secret -o json`
    dynamicActiveSecrets entry. NOTE: JSON layout follows Envoy's SDS dump; confirm against your istioctl version."""
    import base64
    from cryptography import x509
    cc = secret["secret"]["tlsCertificate"]["certificateChain"]
    pem = base64.b64decode(cc["inlineBytes"]) if "inlineBytes" in cc else cc["inlineString"].encode()
    cert = x509.load_pem_x509_certificate(pem)      # first certificate of the chain = workload leaf
    return cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat()


def observe_certs(ns, target, log, stop):
    while not stop.is_set():
        pod = sh(["kubectl", "get", "pods", "-n", ns, "-l", f"app={target}", "-o", "jsonpath={.items[0].metadata.name}"])
        out = sh(["istioctl", "proxy-config", "secret", f"{pod}.{ns}", "-o", "json"])
        try:
            for sec in json.loads(out).get("dynamicActiveSecrets", []):
                if sec.get("name") == "default":
                    nb, na = cert_validity(sec)
                    log.ev("cert_seen", pod=pod, not_before=nb, not_after=na, version=sec.get("versionInfo"))
        except Exception as e:      # never swallow silently: an unobserved rotation invalidates the experiment
            log.ev("cert_seen_error", error=str(e)[:200])
        stop.wait(30)


def wait_healthy(url, chain, token, need=15, timeout=180):
    """A fault test is only meaningful if the system is healthy first: require `need` consecutive HTTP 200s."""
    import urllib.request
    ok, t_end = 0, time.time() + timeout
    while time.time() < t_end:
        req = urllib.request.Request(f"{url}/{chain}", headers={"Authorization": f"Bearer {token}"})
        try:
            ok = ok + 1 if urllib.request.urlopen(req, timeout=3).status == 200 else 0
        except Exception:
            ok = 0
        if ok >= need:
            return True
        time.sleep(0.5)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--fault", required=True, choices=["pod-kill", "rollout", "node-drain", "istiod-down", "cert-observe"])
    ap.add_argument("--target", default="ledger")
    ap.add_argument("--chain", default="c3")
    ap.add_argument("--rate", type=int, required=True, help="requests/s (use ~0.5 x A0 knee)")
    ap.add_argument("--baseline", type=int, default=60)
    ap.add_argument("--after", type=int, default=120)
    ap.add_argument("--outage", type=int, default=60)
    ap.add_argument("--hold", type=int, default=1800, help="cert-observe duration (s)")
    ap.add_argument("--with-restart", action="store_true")
    ap.add_argument("--url", default="")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--tag", default="")
    ap.add_argument("--no-preflight", action="store_true", help="skip the health gate (not recommended)")
    ap.add_argument("--out", default=str(ROOT / "results" / "e3"))
    a = ap.parse_args()
    ns = f"mesh-{a.scenario}"
    scen_idx = ["a0", "a1", "b", "c", "d"].index(a.scenario)
    url = a.url or f"http://{sh(['kubectl', 'get', 'svc', 'gateway-lb', '-n', ns, '-o', 'jsonpath={.status.loadBalancer.ingress[0].ip}'])}:{8100 + scen_idx}"
    run = pathlib.Path(a.out) / f"{a.scenario}-{a.fault}{('-' + a.tag) if a.tag else ''}-{datetime.datetime.now():%Y%m%dT%H%M%S}"
    run.mkdir(parents=True, exist_ok=True)
    log = Log(run / "events.jsonl")
    total = a.baseline + (a.hold if a.fault == "cert-observe" else a.after) + 30
    token = (ROOT / "keys/tokens/valid.jwt").read_text().strip()
    if not a.no_preflight and not wait_healthy(url, a.chain, token):
        sys.exit(f"ABORT: {url}/{a.chain} did not return HTTP 200 fifteen times in a row within 180 s - the system is not healthy, nothing was injected.")
    env = dict(os.environ, K6_CSV_TIME_FORMAT="unix")
    k6 = subprocess.Popen([K6, "run", "--quiet", "--no-usage-report", "--out", f"csv={run / 'k6.csv'}", "-e", f"GATEWAY_URL={url}", "-e", f"CHAIN={a.chain}",
                           "-e", f"RATE={a.rate}", "-e", "WARMUP=0", "-e", f"DURATION={total}", "-e", f"TOKEN={token}", "-e", "MAX_VUS=3000",
                           str(ROOT / "k6" / "steady.js")], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log.ev("load_start", url=url, rate=a.rate)
    stop = threading.Event()
    if a.fault == "cert-observe" and sh(["which", "istioctl"]):
        threading.Thread(target=observe_certs, args=(ns, a.target, log, stop), daemon=True).start()
    time.sleep(a.baseline)
    inject(a, ns, log)
    k6.wait()
    stop.set()
    log.ev("load_end")
    print(f"done -> {run}\nanalyse: python3 analysis/resilience.py {run}")


if __name__ == "__main__":
    main()
