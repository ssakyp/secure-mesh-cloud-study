#!/usr/bin/env python3
"""Find the capacity knee of the A0 baseline from a k6 ramp (--out csv=...).

Pre-declared rule: split the ramp into 5-second bins (the last, partly filled bin is discarded). The knee is the
highest achieved rate inside the contiguous healthy prefix of bins, where healthy means
    p95 <= max(2 x reference, reference + 10 ms)   (reference = median p95 of the first 15 % of bins)
    failed requests < 1 %   and   no dropped iterations.
If the ramp never leaves the healthy region the printed KNEE is only a LOWER BOUND: re-run with a higher MAX_RATE."""
import argparse, json
import numpy as np
import pandas as pd


def find_knee(t):
    t = t.iloc[:-1] if len(t) > 3 else t                       # drop the partial final bin
    ref = t.head(max(3, int(0.15 * len(t)))).p95.median()
    limit = max(2 * ref, ref + 10.0)
    healthy = (t.p95 <= limit) & (t.failed < 0.01) & (t.dropped == 0)
    prefix = []
    for ok, rate in zip(healthy, t.rate):
        if not ok:
            break
        prefix.append(rate)
    knee = max(prefix) if prefix else float("nan")
    return knee, ref, limit, len(prefix) == len(t), t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--bin", type=int, default=5)
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    keep = {"http_req_duration", "http_req_failed", "dropped_iterations"}
    parts = []
    for ch in pd.read_csv(a.csv, usecols=["metric_name", "timestamp", "metric_value"], chunksize=500_000):
        parts.append(ch[ch.metric_name.isin(keep)])
    df = pd.concat(parts)
    df["bin"] = ((df.timestamp - df.timestamp.min()) // a.bin).astype(int)
    rows = []
    for b, g in df.groupby("bin"):
        dur = g[g.metric_name == "http_req_duration"].metric_value
        if len(dur) < 20:
            continue
        rows.append(dict(bin=b, rate=len(dur) / a.bin, p95=np.percentile(dur, 95),
                         failed=g[g.metric_name == "http_req_failed"].metric_value.mean(),
                         dropped=g[g.metric_name == "dropped_iterations"].metric_value.sum()))
    knee, ref, limit, never_left, t = find_knee(pd.DataFrame(rows))
    print(t.round(2).to_string(index=False))
    print(f"\nreference p95 (first 15%): {ref:.2f} ms, healthy limit {limit:.2f} ms\nKNEE = {knee:.0f} requests/s  (use --knee {knee:.0f})")
    if never_left:
        print("WARNING: the ramp never left the healthy region - this is only a LOWER BOUND; re-run with a higher MAX_RATE.")
    if a.json:
        json.dump({"knee_rps": knee, "lower_bound_only": bool(never_left), "ref_p95_ms": ref, "limit_ms": limit, "bin_s": a.bin}, open(a.json, "w"))


if __name__ == "__main__":
    main()
