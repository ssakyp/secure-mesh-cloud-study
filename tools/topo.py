"""Shared helpers for reading topology.yaml."""
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load(path=None):
    t = yaml.safe_load(open(path or ROOT / "topology" / "topology.yaml"))
    svcs = t["services"]
    for src, dsts in t["edges"].items():
        assert src in svcs, src
        for d in dsts:
            assert d in svcs, d
    for name, chain in t["chains"].items():
        for a, b in zip(chain, chain[1:]):
            assert b in t["edges"].get(a, []), f"chain {name}: edge {a}->{b} not allowed by policy"
    return t


def intended_allow(t, src, dst):
    """True if src may call dst under the intended policy."""
    return dst in t.get("public", []) or dst in t["edges"].get(src, [])


def callers_of(t, dst):
    return sorted(s for s, ds in t["edges"].items() if dst in ds)
