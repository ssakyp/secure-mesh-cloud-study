#!/usr/bin/env python3
"""E1 statistical analysis (pre-declared in PROTOCOL.md).

Inference unit: one run (its p95). Effect: ratio of median p95 (test / reference) with percentile-bootstrap CIs.
Equivalence is decided from the 90% CI (equivalent to TOST at alpha=0.05); superiority tests use the 95% CI.
Verdicts:  negligible  : 90% CI inside [1/1.10, 1.10]
           exceeds     : 95% CI lower bound > 1.25
           acceptable  : 95% CI upper bound < 1.25 (but not negligible)
           inconclusive: otherwise
Failed runs are reported, never silently dropped; filters are the pre-declared ones and a sensitivity
analysis re-runs every verdict under alternative filters (the Article-1 4.3% result flipped sign with its cutoff).
"""
import argparse, json, pathlib, re, sys, zlib
import numpy as np
import pandas as pd
from scipy import stats

DELTA_NEG, DELTA_ACC, BOOT = 0.10, 0.25, 10000
VARIANTS = {"primary": 0.01, "lenient": 0.05, "strict": 0.001, "none": 1.01}   # max failed-request fraction
MAX_DROPPED, MAX_GEN_CPU = 0.01, 80.0
CONTRASTS = [("c", "a1"), ("c", "a0"), ("a1", "a0"), ("b", "a0"), ("d", "c")]
LABEL = {"a0": "A0 no mesh", "a1": "A1 mesh (permissive)", "b": "B app-layer JWT", "c": "C strict mTLS+AuthZ", "d": "D C+mesh JWT"}


def _units(s):
    m = re.match(r"([\d.]+)(m|Mi|Ki|Gi|n)?", s)
    v, u = float(m.group(1)), m.group(2)
    return v / 1e6 if u == "n" else v


def parse_top(path):
    out = {"proxy_cpu_m": np.nan, "proxy_mem_mi": np.nan, "app_cpu_m": np.nan, "pods": np.nan}
    if not path.exists():
        return out
    px, ap, pods = [], [], set()
    for line in path.read_text().splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        pods.add(p[0])
        (px if p[1] == "istio-proxy" else ap if p[1] == "app" else []).append((_units(p[2]), _units(p[3])))
    if px or ap:
        out.update(proxy_cpu_m=sum(c for c, _ in px) if px else 0.0, proxy_mem_mi=sum(m for _, m in px) if px else 0.0,
                   app_cpu_m=sum(c for c, _ in ap), pods=len(pods))
    return out


def load_runs(indir):
    rows = []
    for d in sorted(pathlib.Path(indir).iterdir()):
        if not (d / "summary.json").exists() or not (d / "meta.json").exists():
            continue
        s, m = json.load(open(d / "summary.json")), json.load(open(d / "meta.json"))
        lat = s["latency_ms"]
        req, drop = s.get("requests") or 0, s.get("dropped_iterations") or 0
        r = dict(id=m["id"], scenario=m["scenario"], chain=m["chain"], hops=int(m["chain"][1:]), rate_frac=m["rate_frac"], rate=m["rate"],
                 rep=m["rep"], p50=lat["med"], p95=lat["p95"], p99=lat["p99"], avg=lat["avg"], failed=s.get("failed_rate") or 0.0,
                 requests=req, dropped_frac=drop / (drop + req) if (drop + req) else 1.0, gen_cpu=m.get("gen_cpu_mean"))
        r.update(parse_top(d / "top_pods.txt"))
        rows.append(r)
    return pd.DataFrame(rows)


def flag_invalid(df, max_fail):
    why = []
    for _, r in df.iterrows():
        w = []
        if r.failed > max_fail:
            w.append(f"failed>{max_fail:g}")
        if r.dropped_frac > MAX_DROPPED:
            w.append("generator-dropped")
        if r.gen_cpu is not None and not pd.isna(r.gen_cpu) and r.gen_cpu > MAX_GEN_CPU:
            w.append("generator-cpu")
        why.append(";".join(w))
    df = df.copy()
    df["invalid_reason"] = why
    return df


def boot_ratio(x, y, seed):
    rng = np.random.default_rng(seed)
    x, y = np.asarray(x, float), np.asarray(y, float)
    ix = rng.integers(0, len(x), (BOOT, len(x)))
    iy = rng.integers(0, len(y), (BOOT, len(y)))
    rat = np.median(x[ix], axis=1) / np.median(y[iy], axis=1)
    pt = np.median(x) / np.median(y)
    q = lambda p: float(np.percentile(rat, p))
    return pt, (q(5), q(95)), (q(2.5), q(97.5))


def verdict(ci90, ci95):
    if ci90[0] >= 1 / (1 + DELTA_NEG) and ci90[1] <= 1 + DELTA_NEG:
        return "negligible"
    if ci95[0] > 1 + DELTA_ACC:
        return "exceeds"
    if ci95[1] < 1 + DELTA_ACC:
        return "acceptable"
    return "inconclusive"


def holm(p):
    p = np.asarray(p, float)
    order = np.argsort(p)
    adj = np.empty_like(p)
    run = 0.0
    for rank, i in enumerate(order):
        run = max(run, (len(p) - rank) * p[i])
        adj[i] = min(1.0, run)
    return adj


def contrasts(df, variant):
    d = flag_invalid(df, VARIANTS[variant])
    valid = d[d.invalid_reason == ""] if variant != "none" else d
    rows = []
    for (chain, frac), g in valid.groupby(["chain", "rate_frac"]):
        for t, ref in CONTRASTS:
            x, y = g[g.scenario == t].p95.values, g[g.scenario == ref].p95.values
            if len(x) < 3 or len(y) < 3:
                continue
            seed = zlib.crc32(f"{t}{ref}{chain}{frac}".encode())
            pt, c90, c95 = boot_ratio(x, y, seed)
            try:
                p = stats.mannwhitneyu(x, y, alternative="two-sided").pvalue
            except ValueError:
                p = 1.0
            rows.append(dict(chain=chain, rate_frac=frac, test=t, ref=ref, n_test=len(x), n_ref=len(y), ratio=pt, lo90=c90[0], hi90=c90[1],
                             lo95=c95[0], hi95=c95[1], p_mwu=p, verdict=verdict(c90, c95),
                             direction="slower" if c95[0] > 1 else "faster" if c95[1] < 1 else "n.s."))
    out = pd.DataFrame(rows)
    if len(out):
        out["p_holm"] = holm(out.p_mwu.values)
    return out


def per_hop(df):
    d = flag_invalid(df, VARIANTS["primary"])
    d = d[d.invalid_reason == ""]
    rows = []
    for frac, g in d.groupby("rate_frac"):
        if g.hops.nunique() < 3:
            continue
        sl = {}
        for s, gs in g.groupby("scenario"):
            if gs.hops.nunique() >= 3:
                sl[s] = gs
        def slope(frame, rng=None):
            if rng is None:
                return np.polyfit(frame.hops, frame.p95, 1)[0]
            parts = [h.sample(len(h), replace=True, random_state=int(rng.integers(1 << 31))) for _, h in frame.groupby("hops")]
            f = pd.concat(parts)
            return np.polyfit(f.hops, f.p95, 1)[0]
        rng = np.random.default_rng(7)
        boots = {s: np.array([slope(f, rng) for f in [sl[s]] * 1000]) for s in sl}
        for s in sl:
            b = boots[s]
            row = dict(rate_frac=frac, scenario=s, slope_ms_per_hop=slope(sl[s]), lo=np.percentile(b, 2.5), hi=np.percentile(b, 97.5))
            if "a0" in boots and s != "a0":
                diff = b - boots["a0"]
                row.update(extra_ms_per_hop_vs_a0=slope(sl[s]) - slope(sl["a0"]), diff_lo=np.percentile(diff, 2.5), diff_hi=np.percentile(diff, 97.5))
            rows.append(row)
    return pd.DataFrame(rows)


def cells(df):
    d = flag_invalid(df, VARIANTS["primary"])
    rows = []
    for (s, chain, frac), g in d.groupby(["scenario", "chain", "rate_frac"]):
        v = g[g.invalid_reason == ""]
        q = v.p95.quantile([0.25, 0.5, 0.75]) if len(v) else pd.Series([np.nan] * 3, index=[0.25, 0.5, 0.75])
        rows.append(dict(scenario=s, chain=chain, rate_frac=frac, rate=int(g.rate.iloc[0]), n_total=len(g), n_valid=len(v), p95_q1=q[0.25], p95_med=q[0.5],
                         p95_q3=q[0.75], p50_med=v.p50.median(), p99_med=v.p99.median(), failed_mean=g.failed.mean(),
                         proxy_cpu_m=v.proxy_cpu_m.mean(), proxy_mem_mi=v.proxy_mem_mi.mean(), app_cpu_m=v.app_cpu_m.mean()))
    return pd.DataFrame(rows)


def esc(s):
    return str(s).replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


def latex(cell, eff):
    L = [r"\begin{table}[t]\centering\caption{Median p95 latency per cell (valid runs; IQR in brackets).}\label{tab:cells}",
         r"\begin{tabular}{llrrr}\toprule Scenario & Rate (RPS) & $n$ & p95 (ms) & failed \\ \midrule"]
    for _, r in cell.sort_values(["chain", "rate_frac", "scenario"]).iterrows():
        L.append(f"{esc(LABEL.get(r.scenario, r.scenario))} & {r.rate} & {r.n_valid}/{r.n_total} & {r.p95_med:.1f} [{r.p95_q1:.1f}, {r.p95_q3:.1f}] & {100 * r.failed_mean:.2f}\\% \\\\")
    L += [r"\bottomrule\end{tabular}\end{table}", ""]
    L += [r"\begin{table}[t]\centering\caption{Ratio of median p95 (test/reference), 95\% bootstrap CI, Holm-adjusted MWU $p$ and pre-declared verdict.}\label{tab:effects}",
          r"\begin{tabular}{llrlrl}\toprule Chain & Rate & Contrast & Ratio [95\% CI] & $p_{Holm}$ & Verdict \\ \midrule"]
    for _, r in eff.sort_values(["chain", "rate_frac", "test", "ref"]).iterrows():
        L.append(f"{r.chain} & {r.rate_frac:g}$\\times$knee & {r.test.upper()} vs {r.ref.upper()} & {r.ratio:.2f} [{r.lo95:.2f}, {r.hi95:.2f}] & {r.p_holm:.3f} & {r.verdict} \\\\")
    L += [r"\bottomrule\end{tabular}\end{table}"]
    return "\n".join(L)


def figures(df, cell, eff, ph, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    out.mkdir(parents=True, exist_ok=True)
    c = cell[cell.chain == cell.chain.iloc[0]]
    if c.rate_frac.nunique() > 1:
        fig, ax = plt.subplots(figsize=(5.2, 3.4))
        for s, g in c.groupby("scenario"):
            g = g.sort_values("rate")
            ax.errorbar(g.rate, g.p95_med, yerr=[g.p95_med - g.p95_q1, g.p95_q3 - g.p95_med], marker="o", capsize=3, label=LABEL.get(s, s))
        ax.set_xlabel("offered rate (requests/s)"); ax.set_ylabel("p95 latency (ms)"); ax.legend(fontsize=7); ax.grid(alpha=.3)
        fig.tight_layout(); fig.savefig(out / "fig_p95_vs_rate.png", dpi=200); fig.savefig(out / "fig_p95_vs_rate.pdf"); plt.close(fig)
    if len(eff):
        e = eff.reset_index(drop=True)
        fig, ax = plt.subplots(figsize=(5.2, 0.28 * len(e) + 1.2))
        y = np.arange(len(e))
        ax.errorbar(e.ratio, y, xerr=[e.ratio - e.lo95, e.hi95 - e.ratio], fmt="o", capsize=3)
        ax.axvline(1, color="k", lw=.8); ax.axvspan(1 / (1 + DELTA_NEG), 1 + DELTA_NEG, color="g", alpha=.12, label="negligible (±10%)")
        ax.axvline(1 + DELTA_ACC, color="r", ls="--", lw=.8, label="acceptable limit (+25%)")
        ax.set_yticks(y); ax.set_yticklabels([f"{r.test.upper()}/{r.ref.upper()} {r.chain} {r.rate_frac:g}x" for r in e.itertuples()], fontsize=6)
        ax.set_xlabel("ratio of median p95"); ax.legend(fontsize=6); ax.grid(alpha=.3)
        fig.tight_layout(); fig.savefig(out / "fig_ratio_forest.png", dpi=200); fig.savefig(out / "fig_ratio_forest.pdf"); plt.close(fig)
    if len(ph):
        fig, ax = plt.subplots(figsize=(4.2, 3))
        p = ph[ph.rate_frac == ph.rate_frac.iloc[0]]
        ax.bar([LABEL.get(s, s) for s in p.scenario], p.slope_ms_per_hop, yerr=[p.slope_ms_per_hop - p.lo, p.hi - p.slope_ms_per_hop], capsize=3)
        ax.set_ylabel("p95 added per hop (ms)"); plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=7)
        fig.tight_layout(); fig.savefig(out / "fig_per_hop.png", dpi=200); fig.savefig(out / "fig_per_hop.pdf"); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", required=True, nargs="+")
    ap.add_argument("--out", default="results/analysis")
    a = ap.parse_args()
    df = pd.concat([load_runs(d) for d in a.indir], ignore_index=True)
    if df.empty:
        sys.exit("no runs found")
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "runs_all.csv", index=False)
    d = flag_invalid(df, VARIANTS["primary"])
    d[d.invalid_reason != ""].to_csv(out / "invalid_runs.csv", index=False)
    cell = cells(df)
    cell.to_csv(out / "cells.csv", index=False)
    eff = {v: contrasts(df, v) for v in VARIANTS}
    eff["primary"].to_csv(out / "effects.csv", index=False)
    sens = None
    for v, e in eff.items():
        if len(e):
            s = e[["chain", "rate_frac", "test", "ref", "ratio", "verdict"]].rename(columns={"ratio": f"ratio_{v}", "verdict": f"verdict_{v}"})
            sens = s if sens is None else sens.merge(s, on=["chain", "rate_frac", "test", "ref"], how="outer")
    if sens is not None:
        vc = [c for c in sens.columns if c.startswith("verdict_")]
        sens["verdict_stable"] = sens[vc].nunique(axis=1) == 1
        sens.to_csv(out / "sensitivity.csv", index=False)
    ph = per_hop(df)
    ph.to_csv(out / "per_hop.csv", index=False)
    (out / "tables.tex").write_text(latex(cell, eff["primary"]) if len(eff["primary"]) else "% no contrasts available\n")
    figures(df, cell, eff["primary"], ph, out / "figures")
    n_bad = int((d.invalid_reason != "").sum())
    print(f"runs: {len(df)} total, {n_bad} invalid under primary filter -> {out}/invalid_runs.csv")
    if len(eff["primary"]):
        print(eff["primary"][["chain", "rate_frac", "test", "ref", "n_test", "n_ref", "ratio", "lo95", "hi95", "p_holm", "verdict"]].round(3).to_string(index=False))
    if sens is not None:
        print(f"\nverdicts stable across filter variants: {int(sens.verdict_stable.sum())}/{len(sens)}")
    if len(ph):
        print("\nper-hop slopes:\n", ph.round(3).to_string(index=False))


if __name__ == "__main__":
    main()
