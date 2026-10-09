#!/usr/bin/env python3
"""End-to-end test of the E3 analyser on the local stack: real k6 load, a service process is killed and restarted mid-run."""
import json, os, pathlib, subprocess, sys, time
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts")); sys.path.insert(0, str(ROOT / "tools"))
import local_stack, topo

K6 = os.environ.get("K6", "k6")
BIN = os.environ.get("MESHSVC_BIN", str(ROOT / "meshsvc"))


def main():
    t = topo.load()
    procs, pm = local_stack.start(t, BIN, 9100)
    run = ROOT / "results" / "e3_local_demo"
    run.mkdir(parents=True, exist_ok=True)
    ev = open(run / "events.jsonl", "w")
    log = lambda e, **k: (ev.write(json.dumps(dict(t=time.time(), event=e, **k)) + "\n"), ev.flush())
    try:
        k6 = subprocess.Popen([K6, "run", "--quiet", "--no-usage-report", "--out", f"csv={run / 'k6.csv'}", "-e", f"GATEWAY_URL=http://127.0.0.1:{pm['gateway']}",
                               "-e", "CHAIN=c3", "-e", "RATE=200", "-e", "WARMUP=0", "-e", "DURATION=45", str(ROOT / "k6/steady.js")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("load_start")
        time.sleep(20)
        log("fault_start", fault="process-kill", target="ledger")
        procs["ledger"].kill()
        time.sleep(6)
        procs["ledger"] = local_stack.spawn_one(t, "ledger", BIN, pm)
        local_stack.wait_healthy(pm["ledger"])
        log("fault_end")
        k6.wait()
        log("load_end")
    finally:
        for p in procs.values():
            p.terminate()
    r = subprocess.run([sys.executable, str(ROOT / "analysis/resilience.py"), str(run)], capture_output=True, text=True)
    print(r.stdout, r.stderr[-400:])
    res = json.load(open(run / "resilience.json"))
    ok = res["min_success"] < 0.5 and res["recovery_s"] is not None and res["recovery_s"] < 25 and res["baseline_success"] > 0.99
    print("RESULT:", "PASS" if ok else "FAIL (expected outage then recovery)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
