"""Fetch a few recent successful pump.fun trade txs (public mainnet data) and run Curve-Lab on them.
Read-only: getSignaturesForAddress, getTransaction, simulateTransaction."""
import base64, json, sys, collections
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))
from curvelab.rpc import RPC
from curvelab import pump, policy as pol
from curvelab.__main__ import run
from curvelab.tx import parse

rpc = RPC()
n_want = int(sys.argv[1]) if len(sys.argv) > 1 else 5
sigs = rpc.call("getSignaturesForAddress", [pump.PUMP, {"limit": 200}])
done, verdicts, rules = 0, collections.Counter(), collections.Counter()
for s in sigs:
    if s.get("err") is not None:
        continue
    try:
        t = rpc.call("getTransaction", [s["signature"], {"encoding": "base64", "maxSupportedTransactionVersion": 0}])
    except RuntimeError:
        verdicts["skipped_tx_version_1"] += 1
        continue
    if not t:
        continue
    raw = base64.b64decode(t["transaction"][0])
    tx = parse(raw)
    names = []
    out = run(raw, pol.load(), rpc)
    names = [d.get("name") for d in out["instructions"] if d.get("side")]
    if not names:
        continue
    verdicts[out["verdict"]] += 1
    for f in out["findings"]:
        rules[f["rule"]] += 1
    fills = [d.get("simulated_fill") for d in out["instructions"] if d.get("side")]
    print(json.dumps({"trade_ix": names, "verdict": out["verdict"], "rules": [f["rule"] for f in out["findings"]],
                      "fills": fills, "sim_err": out["simulation"]["err"], "cu": out["simulation"]["units_consumed"]}))
    done += 1
    if done >= n_want:
        break
print(json.dumps({"verdicts": verdicts, "rules": rules}))
