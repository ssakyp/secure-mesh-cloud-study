import sys, json, glob, re, pathlib
sys.path.insert(0, 'analysis')
import resilience as R
import pandas as pd
rows = []
for d in sorted(glob.glob('results/e3/*/')):
    d = pathlib.Path(d)
    m = re.match(r'^(a0|a1|c)-(.+)-rep(\d+)-(\d{8}T\d{6})$', d.name)
    if not m: continue
    s, f, rep = m.group(1), m.group(2), int(m.group(3))
    try:
        t = R.per_second(d/'k6.csv'); ev = [json.loads(l) for l in open(d/'events.jsonl')]
        r = R.analyse(t, ev); r['valid'] = bool(r['baseline_success'] >= 0.99)
    except Exception as e:
        r = dict(valid=False, err=str(e)[:60])
    rows.append(dict(scenario=s, fault=f, rep=rep, run=d.name, **r))
df = pd.DataFrame(rows); df.to_csv('results/e3_runs.csv', index=False)
v = df[df.valid]
g = v.groupby(['fault', 'scenario']).agg(n=('rep', 'count'), recov_med=('recovery_s', 'median'), failed_med=('failed_requests', 'median'),
                                       minsucc_med=('min_success', 'median'), max_p95_med=('max_p95_ms', 'median')).round(2)
print(g.to_string()); g.to_csv('results/e3_summary.csv')
bad = df[~df.valid]
print("\nInvalid runs:", bad[['run']].to_string(index=False) if len(bad) else "none")
print("\nH3 (C non-inferior to A1: median recovery <= A1+5 s and median failed <= 1.5 x A1):")
for f in sorted(v.fault.unique()):
    a, c = v[(v.fault == f) & (v.scenario == 'a1')], v[(v.fault == f) & (v.scenario == 'c')]
    if len(a) and len(c):
        ra, rc = a.recovery_s.median(), c.recovery_s.median(); fa, fc = a.failed_requests.median(), c.failed_requests.median()
        print(f"  {f:18s} recovery A1={ra} C={rc} | failed A1={fa} C={fc} | non-inferior: {bool(rc <= ra + 5 and fc <= 1.5 * fa)}")
