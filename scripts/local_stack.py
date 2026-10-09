#!/usr/bin/env python3
"""Run the whole synthetic topology as 12 local processes (no Kubernetes/Istio).
Purpose: dry-run the harness (k6 scripts, analysis, resilience analyser) on a laptop before spending cloud credit.
Gateway listens on --base-port (default 9100); other services on base-port+1.. in topology order."""
import argparse, json, os, pathlib, signal, subprocess, sys, time, urllib.request
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import topo


def ports(t, base):
    return {s: base + i for i, s in enumerate(t["services"])}


def spawn_one(t, s, binary, pm, jwt=False, payload=2048, cpu=1000):
    ups = {n: f"http://127.0.0.1:{p}" for n, p in pm.items()}
    env = dict(os.environ, SERVICE_NAME=s, PORT=str(pm[s]), ROUTES=json.dumps({
        f"/{c}": ({"to": ch[ch.index(s) + 1], "path": f"/{c}"} if ch.index(s) + 1 < len(ch) else {"to": ""})
        for c, ch in t["chains"].items() if s in ch}), UPSTREAMS=json.dumps(ups), PAYLOAD_BYTES=str(payload), CPU_WORK_ITERS=str(cpu))
    if jwt:
        env.update(JWT_MODE="app", JWT_PUBKEY_FILE=str(ROOT / "keys/jwt_public.pem"), JWT_ISS="mesh-study", JWT_AUD="mesh-api")
    return subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_healthy(port):
    for _ in range(100):
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1).status == 200:
                return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not become healthy")


def start(t, binary, base, jwt=False, payload=2048, cpu=1000):
    pm = ports(t, base)
    for name, port in pm.items():     # a stale stack would silently answer the health checks and invalidate every test
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5)
        except Exception:
            continue
        raise RuntimeError(f"port {port} ({name}) already serves traffic: stale stack? run `pkill meshsvc`")
    procs = {s: spawn_one(t, s, binary, pm, jwt, payload, cpu) for s in t["services"]}
    for p in pm.values():
        wait_healthy(p)
    return procs, pm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(ROOT / "meshsvc"))
    ap.add_argument("--base-port", type=int, default=9100)
    ap.add_argument("--jwt", action="store_true")
    a = ap.parse_args()
    t = topo.load()
    procs, pm = start(t, a.binary, a.base_port, a.jwt)
    print("gateway: http://127.0.0.1:%d   (ports: %s)" % (pm["gateway"], pm), flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # run the finally block so children never outlive us
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs.values():
            p.terminate()


if __name__ == "__main__":
    main()
