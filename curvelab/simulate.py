"""Read-only simulation via simulateTransaction (sigVerify=false, replaceRecentBlockhash=true).
The transaction is never signed by Curve-Lab and never sent: sendTransaction is not on the RPC allowlist."""
import base64
import struct

from . import pump
from .tx import decode_alt, to_b64


def fetch_alt(rpc):
    cache = {}

    def get(key):
        if key not in cache:
            v = rpc.call("getAccountInfo", [key, {"encoding": "base64"}])["value"]
            cache[key] = decode_alt(base64.b64decode(v["data"][0]))
        return cache[key]
    return get


def token_amount(data_b64):
    raw = base64.b64decode(data_b64)
    return struct.unpack_from("<Q", raw, 64)[0] if len(raw) >= 72 else None


def simulate(rpc, raw_tx: bytes, tx, watch=()):
    payer = tx.fee_payer
    addrs = [payer] + [a for a in watch if a != payer]
    pre = rpc.call("getMultipleAccounts", [addrs, {"encoding": "base64"}])["value"]
    res = rpc.call("simulateTransaction", [to_b64(raw_tx), {
        "encoding": "base64", "sigVerify": False, "replaceRecentBlockhash": True, "innerInstructions": True,
        "accounts": {"encoding": "base64", "addresses": addrs}}])["value"]
    out = {"err": res.get("err"), "units_consumed": res.get("unitsConsumed"), "logs": res.get("logs") or []}
    post = res.get("accounts") or []
    if pre and pre[0] and post and post[0]:
        out["fee_payer_lamport_delta"] = post[0]["lamports"] - pre[0]["lamports"]
    deltas = {}
    for a, p0, p1 in zip(addrs[1:], pre[1:], post[1:]):
        t0 = token_amount(p0["data"][0]) if p0 else 0
        t1 = token_amount(p1["data"][0]) if p1 else None
        if t1 is not None:
            deltas[a] = t1 - (t0 or 0)
    out["token_deltas"] = deltas
    out["trade_events"] = pump.trade_events_from_logs(out["logs"])
    return out
