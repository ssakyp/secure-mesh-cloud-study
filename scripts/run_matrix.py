#!/usr/bin/env python3
"""E1 orchestrator: randomised complete-block run order, resumable, one directory per run.

  E1a (rate sweep)   : --chains c3 --rates 0.2,0.4,0.6,0.8,0.9 --knee <A0 knee RPS>
  E1b (depth sweep)  : --chains c0,c1,c2,c3,c4 --rates 0.5 --knee <A0 knee RPS>
Each block (= one repetition) contains every cell once in shuffled order, so slow drift
(noisy neighbours, thermal state, cloud variance) is spread evenly across scenarios.
"""
import argparse, itertools, json, os, pathlib, random, subprocess, sys, threading, time, datetime

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCEN_ORDER = ["a0", "a1", "b", "c", "d"]
K6 = os.environ.get("K6", "k6")


class CpuSampler(threading.Thread):
    """Load-generator CPU utilisation (validity check: generator must not be the bottleneck)."""
    def __init__(self):
        super().__init__(daemon=True)
        self.samples, self.stop_ev = [], threading.Event()

    @staticmethod
    def _read():
        try:
            f = open("/proc/stat").readline().split()[1:]
            v = list(map(int, f))
            idle = v[3] + v[4]
            return sum(v) - idle, sum(v)
        except Exception:
            return None

    def run(self):
        prev = self._read()
        if prev is None:
            return
        while not self.stop_ev.wait(1.0):
            cur = self._read()
            if cur and cur[1] > prev[1]:
                self.samples.append(100.0 * (cur[0] - prev[0]) / (cur[1] - prev[1]))
            prev = cur

    def result(self):
        self.stop_ev.set()
        if not self.samples:
            return None, None
        return round(sum(self.samples) / len(self.samples), 1), round(max(self.samples), 1)


def sh(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:
        return f"ERR {e}"


_url_cache = {}


def gateway_url(s, a):
    if a.url:
        m = dict(kv.split("=", 1) for kv in a.url.split(","))
        if s in m:
            return m[s]
    port = 8100 + SCEN_ORDER.index(s)
    if a.local_lb:
        return f"http://127.0.0.1:{port}"
    if s not in _url_cache:
        ip = sh(["kubectl", "get", "svc", "gateway-lb", "-n", f"mesh-{s}", "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}"]).strip()
        if not ip:
            sys.exit(f"no LoadBalancer IP for mesh-{s}; use --url or --local-lb")
        _url_cache[s] = f"http://{ip}:{port}"
    return _url_cache[s]


def plan(a):
    fr = [float(x) for x in a.rates.split(",")]
    cells = [(s, c, f) for s in a.scenarios.split(",") for c in a.chains.split(",") for f in fr]
    runs = []
    for rep in range(1, a.reps + 1):
        rng = random.Random(f"{a.seed}-{rep}")
        block = cells[:]
        rng.shuffle(block)
        for s, c, f in block:
            rate = max(1, round(f * a.knee))
            runs.append(dict(id=f"{s}-{c}-f{f:g}-rep{rep:02d}", scenario=s, chain=c, rate_frac=f, rate=rate, rep=rep))
    return runs


def kube_snapshot(ns, d):
    (d / "top_pods.txt").write_text(sh(["kubectl", "top", "pods", "-n", ns, "--containers", "--no-headers"]))
    (d / "top_nodes.txt").write_text(sh(["kubectl", "top", "nodes", "--no-headers"]))


def one_run(r, a, k6_version):
    d = pathlib.Path(a.out) / r["id"]
    if (d / "summary.json").exists():
        return "skip"
    d.mkdir(parents=True, exist_ok=True)
    url = gateway_url(r["scenario"], a)
    token = pathlib.Path(a.token_file).read_text().strip() if a.token_file and pathlib.Path(a.token_file).exists() else ""
    meta = dict(r, gateway=url, warmup=a.warmup, duration=a.duration, start=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                host=os.uname().nodename, k6=k6_version, seed=a.seed, knee=a.knee)
    cpu = CpuSampler()
    cpu.start()
    timer = None
    if not a.no_kube:
        timer = threading.Timer(a.warmup + a.duration + 1, kube_snapshot, args=(f"mesh-{r['scenario']}", d))
        timer.start()
    cmd = [K6, "run", "--quiet", "--no-usage-report", "-e", f"GATEWAY_URL={url}", "-e", f"CHAIN={r['chain']}", "-e", f"RATE={r['rate']}",
           "-e", f"WARMUP={a.warmup}", "-e", f"DURATION={a.duration}", "-e", f"TOKEN={token}", "-e", f"MAX_VUS={a.max_vus}",
           "-e", f"SUMMARY_PATH={d / 'summary.json'}", str(ROOT / "k6" / "steady.js")]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    (d / "k6.stdout.txt").write_text(p.stdout + "\n" + p.stderr)
    if timer:
        timer.join()
    meta["gen_cpu_mean"], meta["gen_cpu_max"] = cpu.result()
    meta["wall_s"] = round(time.time() - t0, 1)
    meta["k6_exit"] = p.returncode
    (d / "meta.json").write_text(json.dumps(meta, indent=1))
    time.sleep(a.cooldown)
    return "ok" if (d / "summary.json").exists() else "FAILED"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="a0,a1,b,c")
    ap.add_argument("--chains", default="c3")
    ap.add_argument("--rates", default="0.2,0.4,0.6,0.8,0.9", help="fractions of the A0 knee")
    ap.add_argument("--knee", type=float, required=True, help="A0 knee in requests/s (analysis/knee.py)")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=30)
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--cooldown", type=int, default=15)
    ap.add_argument("--max-vus", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20261008)
    ap.add_argument("--out", default=str(ROOT / "results" / "e1a"))
    ap.add_argument("--token-file", default=str(ROOT / "keys/tokens/valid.jwt"))
    ap.add_argument("--url", default="", help="override per scenario: a0=http://h:p,c=http://...")
    ap.add_argument("--local-lb", action="store_true", help="use 127.0.0.1:810x (k3d port mappings)")
    ap.add_argument("--no-kube", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    runs = plan(a)
    per = a.warmup + a.duration + a.cooldown + 3
    print(f"{len(runs)} runs, ~{len(runs) * per / 3600:.1f} h at {per}s/run")
    if a.dry_run:
        for r in runs[:12]:
            print(" ", r["id"], r["rate"], "rps")
        print("  ...")
        return
    k6v = sh([K6, "version"]).strip()
    done = {"ok": 0, "skip": 0, "FAILED": 0}
    for i, r in enumerate(runs, 1):
        st = one_run(r, a, k6v)
        done[st] += 1
        print(f"[{i}/{len(runs)}] {r['id']:34s} {r['rate']:6d} rps  {st}", flush=True)
    print(done)


if __name__ == "__main__":
    main()
