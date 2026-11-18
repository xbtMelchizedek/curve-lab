"""python -m curvelab check --tx <base64 | @file> [--policy policy.json] [--rpc URL] [--offline]

Prints a JSON verdict: ALLOW / WARN / DENY with findings. Exit code 0 = ALLOW, 1 = WARN, 2 = DENY.
Curve-Lab holds no keys, signs nothing and sends nothing."""
import argparse
import base64
import json
import os
import sys

from . import policy as pol
from . import simulate as sim_mod
from .rpc import RPC
from .tx import UnsupportedVersion, parse, resolve_lookups


def run(raw, policy, rpc=None):
    try:
        tx = parse(raw)
    except UnsupportedVersion as e:
        return {"verdict": "DENY", "findings": [{"rule": "tx_version", "level": "deny", "detail": str(e)}], "instructions": []}
    if tx.lookups:
        if rpc is None:
            return {"verdict": "DENY", "findings": [{"rule": "lookup_tables", "level": "deny", "detail": "v0 lookups need --rpc to resolve"}]}
        resolve_lookups(tx, sim_mod.fetch_alt(rpc))
    findings, decoded = pol.static_checks(tx, policy)
    sim = None
    if rpc is not None:
        watch = [d["roles"]["user"] for d in decoded if "roles" in d and "user" in d["roles"]]
        sim = sim_mod.simulate(rpc, raw, tx, watch)
        findings += pol.sim_checks(decoded, sim, policy)
    out = {"verdict": pol.verdict(findings), "findings": findings, "fee_payer": tx.fee_payer, "version": tx.version,
           "instructions": decoded}
    if sim:
        out["simulation"] = {k: v for k, v in sim.items() if k != "logs"}
        out["simulation"]["log_tail"] = sim["logs"][-8:]
    return out


def main():
    ap = argparse.ArgumentParser(prog="curvelab")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--tx", required=True, help="base64 tx, or @path to a file holding it")
    c.add_argument("--policy")
    c.add_argument("--rpc", default=os.environ.get("CURVELAB_RPC", "https://api.mainnet-beta.solana.com"))
    c.add_argument("--offline", action="store_true", help="static checks only, no simulation")
    a = ap.parse_args()
    s = open(a.tx[1:]).read().strip() if a.tx.startswith("@") else a.tx
    out = run(base64.b64decode(s), pol.load(a.policy), None if a.offline else RPC(a.rpc))
    print(json.dumps(out, indent=1, default=str))
    sys.exit({"ALLOW": 0, "WARN": 1, "DENY": 2}[out["verdict"]])


if __name__ == "__main__":
    main()
