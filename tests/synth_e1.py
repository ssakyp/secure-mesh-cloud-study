#!/usr/bin/env python3
"""Known-effect test of analysis/analyze.py using SYNTHETIC data (never use these numbers in the article).
Ground truth: p95 = (intercept + slope*hops) * queueing(rate_frac) * lognormal noise. Checks that
  * the true ratios fall inside the reported 95% CIs,
  * A1-vs-A0 style null effects are not flagged,
  * invalid runs (failures, generator saturation) are excluded and listed,
  * per-hop slopes are recovered."""
import json, pathlib, shutil, subprocess, sys
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "synth_e1"
PARAMS = {"a0": (3.0, 2.0), "a1": (3.0, 2.0), "b": (3.0, 3.0), "c": (3.0, 2.0), "d": (3.2, 2.2)}  # (intercept ms, ms/hop)
SIGMA, REPS, KNEE = 0.08, 10, 1000


def q(f):
    return 1.0 / (1.0 - 0.6 * f)


def mk(rid, s, chain, f, rep, p95, failed=0.0, gen_cpu=35.0):
    d = OUT / rid
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({"latency_ms": dict(avg=p95 / 2, min=1, med=p95 / 3, p90=p95 * .8, p95=p95, p99=p95 * 1.5, max=p95 * 3),
                                                 "failed_rate": failed, "requests": 5000, "dropped_iterations": 0}))
    (d / "meta.json").write_text(json.dumps(dict(id=rid, scenario=s, chain=chain, rate_frac=f, rate=int(f * KNEE), rep=rep, gen_cpu_mean=gen_cpu)))
    (d / "top_pods.txt").write_text("gw-1 app 20m 10Mi\ngw-1 istio-proxy 60m 40Mi\n" if s in ("a1", "c", "d") else "gw-1 app 20m 10Mi\n")


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    rng = np.random.default_rng(1)
    cells = [(s, "c3", f) for s in PARAMS for f in (0.2, 0.5, 0.8)] + [(s, f"c{h}", 0.5) for s in PARAMS for h in (0, 1, 2, 4)]
    for s, chain, f in sorted(set(cells)):
        a, b = PARAMS[s]
        hops = int(chain[1:])
        for rep in range(1, REPS + 1):
            p = (a + b * hops) * q(f) * np.exp(rng.normal(0, SIGMA))
            mk(f"{s}-{chain}-f{f:g}-rep{rep:02d}", s, chain, f, rep, p)
    # contaminate: one failed-run in C@0.5 c3 (fast 5xx -> looks FASTER) and one generator-saturated run in A0
    mk("c-c3-f0.5-rep99", "c", "c3", 0.5, 99, 1.0, failed=0.6)
    mk("a0-c3-f0.5-rep99", "a0", "c3", 0.5, 99, 9.0, gen_cpu=97.0)
    r = subprocess.run([sys.executable, str(ROOT / "analysis/analyze.py"), "--in", str(OUT), "--out", str(ROOT / "results/analysis_synth")], capture_output=True, text=True)
    print(r.stdout[-2600:], r.stderr[-500:])
    import pandas as pd
    eff = pd.read_csv(ROOT / "results/analysis_synth/effects.csv")
    bad = 0
    print("\nground-truth check (chain c3):")
    for _, e in eff[eff.chain == "c3"].iterrows():
        ta, tb = PARAMS[e.test], PARAMS[e.ref]
        truth = (ta[0] + ta[1] * 3) / (tb[0] + tb[1] * 3)
        inside = e.lo95 <= truth <= e.hi95
        bad += not inside
        print(f"  {e.test.upper()} vs {e.ref.upper()} @{e.rate_frac}: true={truth:.3f} est={e.ratio:.3f} CI=[{e.lo95:.3f},{e.hi95:.3f}] {'ok' if inside else 'TRUTH OUTSIDE CI'}  verdict={e.verdict}")
    inv = pd.read_csv(ROOT / "results/analysis_synth/invalid_runs.csv")
    print("\ninvalid runs flagged:", sorted(inv.id), "(expected the two contaminated runs)")
    bad += sorted(inv.id) != ["a0-c3-f0.5-rep99", "c-c3-f0.5-rep99"]
    ph = pd.read_csv(ROOT / "results/analysis_synth/per_hop.csv")
    for _, r_ in ph.iterrows():
        truth = PARAMS[r_.scenario][1] * q(0.5)
        ok = r_.lo <= truth <= r_.hi
        bad += not ok
        print(f"  per-hop {r_.scenario}: true={truth:.2f} est={r_.slope_ms_per_hop:.2f} CI=[{r_.lo:.2f},{r_.hi:.2f}] {'ok' if ok else 'OUTSIDE'}")
    print("\nRESULT:", "PASS" if bad == 0 else f"{bad} problem(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
