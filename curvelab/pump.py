"""pump.fun instruction catalogue. Names and account order follow pump-fun/pump-public-docs idl/pump.json and
idl/pump_amm.json at commit 639b87fb (Nov 2026). Discriminators are sha256("global:<name>")[:8]."""
import base64
import struct

from .tx import anchor_disc, b58encode

PUMP = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
PUMP_AMM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
PUMP_FEES = "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ"
SYSTEM = "11111111111111111111111111111111"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATA = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

# Jito tip accounts (published by Jito Labs; used only to recognise tips, never to send)
JITO_TIP_ACCOUNTS = {
    "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5", "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
    "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY", "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49",
    "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh", "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt",
    "DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL", "3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT",
}

# name -> (program, arg layout, {role: account index})
TRADE = {
    (PUMP, "buy"): ([("amount", "u64"), ("max_sol_cost", "u64")], {"mint": 2, "user": 6}, "buy", "max_in"),
    (PUMP, "buy_v2"): ([("amount", "u64"), ("max_sol_cost", "u64")], {"mint": 1, "quote_mint": 2, "user": 13}, "buy", "max_in"),
    (PUMP, "buy_v3"): ([("amount", "u64"), ("max_sol_cost", "u64")], {"mint": 1, "quote_mint": 2, "user": 8}, "buy", "max_in"),
    (PUMP, "buy_exact_sol_in"): ([("spendable_sol_in", "u64"), ("min_tokens_out", "u64")], {"mint": 2, "user": 6}, "buy", "min_out"),
    (PUMP, "buy_exact_quote_in_v2"): ([("spendable_quote_in", "u64"), ("min_tokens_out", "u64")], {"mint": 1, "quote_mint": 2, "user": 13}, "buy", "min_out"),
    (PUMP, "buy_exact_quote_in_v3"): ([("spendable_quote_in", "u64"), ("min_tokens_out", "u64")], {"mint": 1, "quote_mint": 2, "user": 8}, "buy", "min_out"),
    (PUMP, "sell"): ([("amount", "u64"), ("min_sol_output", "u64")], {"mint": 2, "user": 6}, "sell", "min_out"),
    (PUMP, "sell_v2"): ([("amount", "u64"), ("min_sol_output", "u64")], {"mint": 1, "quote_mint": 2, "user": 13}, "sell", "min_out"),
    (PUMP, "sell_v3"): ([("amount", "u64"), ("min_sol_output", "u64")], {"mint": 1, "quote_mint": 2, "user": 8}, "sell", "min_out"),
    (PUMP_AMM, "buy"): ([("base_amount_out", "u64"), ("max_quote_amount_in", "u64")], {"mint": 3, "quote_mint": 4, "user": 1}, "buy", "max_in"),
    (PUMP_AMM, "buy_exact_quote_in"): ([("spendable_quote_in", "u64"), ("min_base_amount_out", "u64")], {"mint": 3, "quote_mint": 4, "user": 1}, "buy", "min_out"),
    (PUMP_AMM, "sell"): ([("base_amount_in", "u64"), ("min_quote_amount_out", "u64")], {"mint": 3, "quote_mint": 4, "user": 1}, "sell", "min_out"),
}
# Instructions an agent's trading tx should never contain (coin creation, admin, authority changes).
DENY_BY_DEFAULT = {
    PUMP: ["create", "create_v2", "set_creator", "set_params", "admin_cto", "admin_set_idl_authority",
           "admin_update_token_incentives", "set_metaplex_creator", "migrate", "migrate_v2", "update_global_authority",
           "set_quote_control_admin", "add_quote_mint", "remove_quote_mint", "set_max_curve_depth",
           "distribute_fee_to_holders", "multi_hop_curve_swap"],
    PUMP_AMM: ["create_pool", "create_config", "update_admin", "update_fee_config", "disable", "withdraw", "deposit"],
}
OTHER_KNOWN = {PUMP: ["collect_creator_fee", "collect_creator_fee_v2", "claim_cashback", "claim_cashback_v2",
                      "claim_token_incentives", "init_user_volume_accumulator", "close_user_volume_accumulator",
                      "extend_account", "sweep_bonding_curve_fees", "get_minimum_distributable_fee"],
               PUMP_AMM: ["claim_token_incentives", "collect_coin_creator_fee", "init_user_volume_accumulator",
                          "close_user_volume_accumulator", "extend_account"]}

DISC = {}
for (prog, name) in TRADE:
    DISC[(prog, anchor_disc(name))] = name
for prog, names in list(DENY_BY_DEFAULT.items()) + list(OTHER_KNOWN.items()):
    for n in names:
        DISC.setdefault((prog, anchor_disc(n)), n)


def decode_ix(program: str, data: bytes, account_keys):
    name = DISC.get((program, data[:8]))
    out = {"program": program, "name": name}
    if name and (program, name) in TRADE:
        layout, roles, side, limit_kind = TRADE[(program, name)]
        o = 8
        args = {}
        for k, t in layout:
            if len(data) >= o + 8:
                args[k] = struct.unpack_from("<Q", data, o)[0]
            o += 8
        out.update(side=side, args=args, limit_kind=limit_kind,
                   roles={r: account_keys[i] for r, i in roles.items() if i < len(account_keys)})
    return out


def decode_compute_budget(data: bytes):
    if not data:
        return {}
    if data[0] == 2 and len(data) >= 5:
        return {"cu_limit": struct.unpack_from("<I", data, 1)[0]}
    if data[0] == 3 and len(data) >= 9:
        return {"cu_price_microlamports": struct.unpack_from("<Q", data, 1)[0]}
    return {}


def decode_system_transfer(data: bytes):
    if len(data) >= 12 and struct.unpack_from("<I", data, 0)[0] == 2:
        return struct.unpack_from("<Q", data, 4)[0]
    return None


TRADE_EVENT_DISC = __import__("hashlib").sha256(b"event:TradeEvent").digest()[:8]


def decode_trade_event(raw: bytes):
    """Fixed-layout prefix of pump TradeEvent (fields up to ix_name)."""
    if raw[:8] != TRADE_EVENT_DISC:
        return None
    o = 8
    def pk():
        nonlocal o
        v = b58encode(raw[o:o + 32]); o += 32; return v
    def u64():
        nonlocal o
        v = struct.unpack_from("<Q", raw, o)[0]; o += 8; return v
    def b():
        nonlocal o
        v = bool(raw[o]); o += 1; return v
    ev = {"mint": pk(), "sol_amount": u64(), "token_amount": u64(), "is_buy": b(), "user": pk(), "timestamp": u64(),
          "virtual_sol_reserves": u64(), "virtual_token_reserves": u64(), "real_sol_reserves": u64(),
          "real_token_reserves": u64(), "fee_recipient": pk(), "fee_basis_points": u64(), "fee": u64(), "creator": pk(),
          "creator_fee_basis_points": u64(), "creator_fee": u64(), "track_volume": b(), "total_unclaimed_tokens": u64(),
          "total_claimed_tokens": u64(), "current_sol_volume": u64(), "last_update_timestamp": u64()}
    n = struct.unpack_from("<I", raw, o)[0]; o += 4
    ev["ix_name"] = raw[o:o + n].decode(errors="replace")
    return ev


def trade_events_from_logs(logs):
    out = []
    stack = []
    for line in logs or []:
        if line.startswith("Program ") and " invoke [" in line:
            stack.append(line.split()[1])
        elif line.startswith("Program ") and (line.endswith(" success") or " failed" in line):
            if stack:
                stack.pop()
        elif line.startswith("Program data: ") and stack and stack[-1] == PUMP:
            try:
                ev = decode_trade_event(base64.b64decode(line[14:]))
            except Exception:
                ev = None
            if ev:
                out.append(ev)
    return out
