"""Policy engine: static checks on the decoded tx + checks on the simulation result."""
import json

from . import pump

DEFAULT_POLICY = {
    "allowed_programs": [pump.PUMP, pump.PUMP_AMM, pump.SYSTEM, pump.COMPUTE_BUDGET, pump.TOKEN, pump.TOKEN_2022,
                         pump.ATA, pump.MEMO],
    "deny_instructions": {p: n for p, n in pump.DENY_BY_DEFAULT.items()},
    "allow_unknown_pump_instructions": False,
    "mint_allowlist": [],                 # empty = any mint
    "max_quote_in_per_tx": 1_000_000_000,  # base units of the quote asset (1 SOL for SOL-quoted trades)
    "max_slack_bps": 500,                 # how far the limit (max_in / min_out) may sit from the simulated fill
    "max_jito_tip_lamports": 1_000_000,
    "max_cu_price_microlamports": 2_000_000,
    "max_fee_payer_loss_lamports": 1_100_000_000,
    "require_simulation_success": True,
    "max_system_transfers_to_non_tip": 0,  # plain SOL transfers to anyone but a Jito tip account
}


def load(path=None):
    p = dict(DEFAULT_POLICY)
    if path:
        with open(path) as f:
            p.update(json.load(f))
    return p


def static_checks(tx, policy):
    """Returns (findings, decoded). findings: list of {rule, level, detail}."""
    f, decoded = [], []
    keys = tx.all_keys
    tips = other_transfers = 0
    cu_price = None
    for ix in tx.instructions:
        prog = keys[ix["program_index"]]
        akeys = [keys[i] for i in ix["accounts"]]
        d = {"program": prog}
        if prog not in policy["allowed_programs"]:
            f.append({"rule": "program_allowlist", "level": "deny", "detail": f"program {prog} is not allowed"})
        if prog in (pump.PUMP, pump.PUMP_AMM):
            d = pump.decode_ix(prog, ix["data"], akeys)
            name = d["name"]
            if name in policy["deny_instructions"].get(prog, []):
                f.append({"rule": "deny_instruction", "level": "deny", "detail": f"{name} is denied by policy"})
            elif name is None and not policy["allow_unknown_pump_instructions"]:
                f.append({"rule": "unknown_instruction", "level": "deny", "detail": f"unknown {prog[:4]} instruction {ix['data'][:8].hex()}"})
            if "roles" in d:
                mint = d["roles"].get("mint")
                if policy["mint_allowlist"] and mint not in policy["mint_allowlist"]:
                    f.append({"rule": "mint_allowlist", "level": "deny", "detail": f"mint {mint} not in allowlist"})
                user = d["roles"].get("user")
                if user and user not in tx.signers:
                    f.append({"rule": "user_is_signer", "level": "deny", "detail": "trade user is not a signer of this tx"})
                a = d["args"]
                q_in = a.get("max_sol_cost", a.get("spendable_sol_in", a.get("spendable_quote_in", a.get("max_quote_amount_in"))))
                if d["side"] == "buy" and q_in is not None and q_in > policy["max_quote_in_per_tx"]:
                    f.append({"rule": "max_quote_in_per_tx", "level": "deny", "detail": f"buy limit {q_in} > {policy['max_quote_in_per_tx']}"})
                if d["limit_kind"] == "min_out":
                    m = a.get("min_tokens_out", a.get("min_sol_output", a.get("min_base_amount_out", a.get("min_quote_amount_out"))))
                    if m == 0:
                        f.append({"rule": "zero_min_out", "level": "deny", "detail": f"{name} has min_out = 0 (no slippage protection)"})
        elif prog == pump.COMPUTE_BUDGET:
            d.update(pump.decode_compute_budget(ix["data"]))
            cu_price = d.get("cu_price_microlamports", cu_price)
        elif prog == pump.SYSTEM:
            amt = pump.decode_system_transfer(ix["data"])
            if amt is not None and len(akeys) >= 2:
                d.update(transfer_lamports=amt, to=akeys[1])
                if akeys[1] in pump.JITO_TIP_ACCOUNTS:
                    tips += amt
                else:
                    other_transfers += 1
        decoded.append(d)
    if tips > policy["max_jito_tip_lamports"]:
        f.append({"rule": "max_jito_tip_lamports", "level": "deny", "detail": f"tips {tips} > {policy['max_jito_tip_lamports']}"})
    if other_transfers > policy["max_system_transfers_to_non_tip"]:
        f.append({"rule": "system_transfers", "level": "deny", "detail": f"{other_transfers} SOL transfer(s) to non-tip accounts"})
    if cu_price is not None and cu_price > policy["max_cu_price_microlamports"]:
        f.append({"rule": "max_cu_price", "level": "deny", "detail": f"CU price {cu_price} > {policy['max_cu_price_microlamports']}"})
    return f, decoded


def slack_bps(limit, actual, kind):
    """How loose the agent's limit is relative to the simulated fill, in bps (positive = looser)."""
    if actual <= 0:
        return None
    if kind == "max_in":
        return round((limit - actual) * 10_000 / actual)
    return round((actual - limit) * 10_000 / actual)


def sim_checks(decoded, sim, policy):
    f = []
    if sim.get("err") is not None:
        lvl = "deny" if policy["require_simulation_success"] else "warn"
        f.append({"rule": "simulation", "level": lvl, "detail": f"simulation failed: {json.dumps(sim['err'])}"})
        return f
    loss = sim.get("fee_payer_lamport_delta")
    if loss is not None and -loss > policy["max_fee_payer_loss_lamports"]:
        f.append({"rule": "max_fee_payer_loss", "level": "deny", "detail": f"fee payer loses {-loss} lamports"})
    events = sim.get("trade_events", [])
    for d in [d for d in decoded if d.get("side")]:
        mint = d["roles"].get("mint")
        evs = [e for e in events if e["mint"] == mint and e["is_buy"] == (d["side"] == "buy")]
        if not evs:  # PumpSwap AMM or no event: no fill measured
            d["simulated_fill"] = None
            continue
        tok = sum(e["token_amount"] for e in evs)
        sol = sum(e["sol_amount"] for e in evs)
        fees = sum(e["fee"] + e["creator_fee"] for e in evs)
        a = d["args"]
        approx = True
        if d["limit_kind"] == "min_out" and d["side"] == "buy":
            limit, actual, approx = a.get("min_tokens_out", a.get("min_base_amount_out")), tok, False
        elif d["limit_kind"] == "max_in":
            limit, actual = a.get("max_sol_cost", a.get("max_quote_amount_in")), sol + fees
        else:  # sell, min_out in quote after fees
            limit, actual = a.get("min_sol_output", a.get("min_quote_amount_out")), sol - fees
        s = slack_bps(limit, actual, d["limit_kind"]) if limit is not None else None
        d["simulated_fill"] = {"limit": limit, "actual": actual, "slack_bps": s, "approximate": approx,
                               "events": len(evs), "ix_name": evs[0].get("ix_name")}
        if s is not None and s > policy["max_slack_bps"]:
            f.append({"rule": "max_slack_bps", "level": "deny" if not approx else "warn",
                      "detail": f"{d['name']} limit is {s} bps looser than the simulated fill (max {policy['max_slack_bps']}); a sandwich could take the difference"})
    return f


def verdict(findings):
    return "DENY" if any(x["level"] == "deny" for x in findings) else ("WARN" if findings else "ALLOW")
