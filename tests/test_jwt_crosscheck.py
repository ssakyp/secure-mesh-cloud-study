#!/usr/bin/env python3
"""Cross-implementation check: tokens minted by tools/gen_keys.py (Python) must be
judged correctly by the Go verifier in the service (only 'valid' may pass)."""
import os, pathlib, subprocess, sys, time, urllib.request, urllib.error

ROOT = pathlib.Path(__file__).resolve().parent.parent
BIN = os.environ.get("MESHSVC_BIN", str(ROOT / "meshsvc"))
PORT = 9190


def code(url, token=None):
    req = urllib.request.Request(url)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        return urllib.request.urlopen(req, timeout=3).status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    env = dict(os.environ, SERVICE_NAME="gateway", PORT=str(PORT), JWT_MODE="app",
               JWT_PUBKEY_FILE=str(ROOT / "keys/jwt_public.pem"), JWT_ISS="mesh-study", JWT_AUD="mesh-api")
    p = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                if code(f"http://127.0.0.1:{PORT}/healthz") == 200:
                    break
            except Exception:
                time.sleep(0.1)
        url = f"http://127.0.0.1:{PORT}/ping"
        bad = 0
        print(f"{'token':18s} {'http':>5s}  verdict")
        for f in sorted((ROOT / "keys/tokens").glob("*.jwt")):
            name, tok = f.stem, f.read_text().strip()
            c = code(url, tok)
            expect = 200 if name == "valid" else 401
            ok = c == expect
            bad += not ok
            print(f"{name:18s} {c:5d}  {'ok' if ok else 'MISMATCH (expected %d)' % expect}")
        c = code(url)
        print(f"{'(no token)':18s} {c:5d}  {'ok' if c == 401 else 'MISMATCH'}")
        bad += c != 401
        sys.exit(1 if bad else 0)
    finally:
        p.terminate()


if __name__ == "__main__":
    main()
