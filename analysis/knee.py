#!/usr/bin/env python3
"""Find the capacity knee of the A0 baseline from a k6 ramp (--out csv=...).
Pre-declared rule: knee = highest 5-second bin rate where p95 <= 2x the median p95 of the
first 15% of the ramp, failures < 1% and no dropped iterations."""
import argparse, json, sys
import numpy as np
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--bin", type=int, default=5)
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    keep = {"http_req_duration", "http_req_failed", "http_reqs", "dropped_iterations"}
    parts = []
    for ch in pd.read_csv(a.csv, usecols=["metric_name", "timestamp", "metric_value"], chunksize=500_000):
        parts.append(ch[ch.metric_name.isin(keep)])
    df = pd.concat(parts)
    t0 = df.timestamp.min()
    df["bin"] = ((df.timestamp - t0) // a.bin).astype(int)
    rows = []
    for b, g in df.groupby("bin"):
        dur = g[g.metric_name == "http_req_duration"].metric_value
        if len(dur) < 20:
            continue
        rows.append(dict(bin=b, rate=len(dur) / a.bin, p95=np.percentile(dur, 95),
                         failed=g[g.metric_name == "http_req_failed"].metric_value.mean(),
                         dropped=g[g.metric_name == "dropped_iterations"].metric_value.sum()))
    t = pd.DataFrame(rows)
    ref = t.head(max(3, int(0.15 * len(t)))).p95.median()
    ok = t[(t.p95 <= 2 * ref) & (t.failed < 0.01) & (t.dropped == 0)]
    # the knee is the end of the *contiguous* healthy prefix, not a lucky late bin
    knee_bin = -1
    for b in t.bin:
        if b in set(ok.bin):
            knee_bin = b
        else:
            break
    knee = float(t[t.bin == knee_bin].rate.iloc[0]) if knee_bin >= 0 else float("nan")
    print(t.round(2).to_string(index=False))
    print(f"\nreference p95 (first 15%): {ref:.2f} ms\nKNEE = {knee:.0f} requests/s  (use --knee {knee:.0f})")
    if a.json:
        json.dump({"knee_rps": knee, "ref_p95_ms": ref, "bin_s": a.bin}, open(a.json, "w"))


if __name__ == "__main__":
    main()
