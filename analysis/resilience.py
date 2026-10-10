#!/usr/bin/env python3
"""E3 analysis: per-second success rate / p95 from a k6 `--out csv` time series plus an events.jsonl log.
Reports: baseline success, minimum success during the fault, failed-request count, time-to-recover
(first second after fault start from which success >= baseline-0.5pp for 10 consecutive seconds)."""
import argparse, json, pathlib, sys
import numpy as np
import pandas as pd


def per_second(csv_path):
    parts = []
    for ch in pd.read_csv(csv_path, usecols=["metric_name", "timestamp", "metric_value"], chunksize=500_000):
        parts.append(ch[ch.metric_name.isin(["http_req_failed", "http_req_duration"])])
    df = pd.concat(parts)
    df["sec"] = df.timestamp.astype(int)
    f = df[df.metric_name == "http_req_failed"].groupby("sec").metric_value.agg(["mean", "count", "sum"])
    d = df[df.metric_name == "http_req_duration"].groupby("sec").metric_value.agg(lambda x: np.percentile(x, 95))
    t = pd.DataFrame({"n": f["count"], "failed": f["sum"], "success": 1 - f["mean"], "p95_ms": d}).reset_index()
    return t


def analyse(t, events, window=10, tol=0.005):
    ev = {e["event"]: e["t"] for e in events}
    fs, fe = ev["fault_start"], ev.get("fault_end", ev["fault_start"])
    # baseline excludes the (partial) second that contains the fault and the first seconds of connection set-up
    base = t[(t.sec < int(fs)) & (t.sec >= t.sec.min() + 3)]
    b_succ, b_p95 = base.success.mean(), base.p95_ms.median()
    during = t[(t.sec >= int(fs)) & (t.sec <= fe + 30)]
    ok = (t.success >= b_succ - tol).astype(int)
    roll = ok.rolling(window).min()
    rec = None
    for i in range(len(t)):
        if t.sec.iloc[i] >= int(fs) + window - 1 and roll.iloc[i] == 1:
            rec = int(t.sec.iloc[i] - window + 1 - int(fs))
            break
    return dict(baseline_success=round(b_succ, 5), baseline_p95_ms=round(float(b_p95), 2), min_success=round(float(during.success.min()), 4),
                failed_requests=int(t[(t.sec >= int(fs)) & (t.sec <= fe + 60)].failed.sum()), seconds_below_baseline=int((during.success < b_succ - tol).sum()),
                max_p95_ms=round(float(during.p95_ms.max()), 1), recovery_s=max(0, rec) if rec is not None else None)


def cert_summary(events):
    """Rotations actually observed (distinct leaf-cert expiry times) and the certificate lifetime in force."""
    import datetime as dt
    seen = [e for e in events if e["event"] == "cert_seen" and e.get("not_after")]
    if not seen:
        return dict(cert_samples=0, cert_errors=sum(e["event"] == "cert_seen_error" for e in events))
    na = sorted({e["not_after"] for e in seen})
    ttl = dt.datetime.fromisoformat(seen[0]["not_after"]) - dt.datetime.fromisoformat(seen[0]["not_before"])
    return dict(cert_samples=len(seen), cert_rotations_observed=len(na) - 1, cert_lifetime_s=int(ttl.total_seconds()),
                cert_errors=sum(e["event"] == "cert_seen_error" for e in events))


def plot(t, events, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    t0 = t.sec.min()
    fig, ax = plt.subplots(2, 1, figsize=(6, 4), sharex=True)
    ax[0].plot(t.sec - t0, 100 * t.success); ax[0].set_ylabel("success (%)")
    ax[1].plot(t.sec - t0, t.p95_ms); ax[1].set_ylabel("p95 (ms)"); ax[1].set_xlabel("seconds")
    for e in events:
        for a in ax:
            a.axvline(e["t"] - t0, color="r", ls="--", lw=.8)
    fig.tight_layout(); fig.savefig(out, dpi=200); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", help="directory with k6.csv and events.jsonl")
    a = ap.parse_args()
    d = pathlib.Path(a.run_dir)
    t = per_second(d / "k6.csv")
    events = [json.loads(l) for l in open(d / "events.jsonl")]
    res = analyse(t, events)
    res["valid"] = bool(res["baseline_success"] >= 0.99)
    if not res["valid"]:
        res["invalid_reason"] = (f"baseline success {res['baseline_success']:.3f} < 0.99: the service was not healthy before the fault, "
                                 "so these numbers say nothing about the fault")
        print("*** INVALID RUN: " + res["invalid_reason"], file=sys.stderr)
    if any(e["event"].startswith("cert_seen") for e in events):
        res.update(cert_summary(events))
    (d / "resilience.json").write_text(json.dumps(res, indent=1))
    plot(t, events, d / "timeline.png")
    print(json.dumps(res, indent=1))
    sys.exit(0 if res["valid"] else 2)


if __name__ == "__main__":
    main()
