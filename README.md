# Curve-Lab

Checks a pump.fun trade transaction against a written policy **before** anyone signs it. It parses
the transaction, flags deny-listed instructions, runs it through `simulateTransaction`, and checks
the simulated result against your limits. Curve-Lab does not sign, send or hold keys. It has no
code path that does any of those.

Status: **M1** (2026-11-18). This is not trading software, and it gives no investment advice.

## Why

FLOP agents may soon trade memecoins for their owners. Before an agent gets a key, the owner needs
a check they can read: what the transaction calls, how much it can spend, how much slippage it
allows, what tip it pays, and what the simulator says. Curve-Lab is that check. It refuses by
default.

## Use

```bash
python3 -m curvelab check --tx @unsigned_tx.b64                          # static + simulation
python3 -m curvelab check --tx @unsigned_tx.b64 --offline                # static only
python3 -m curvelab check --tx @unsigned_tx.b64 --policy policies/strict-0.1sol.json
```

Exit codes: `0` ALLOW, `1` DENY, `2` usage or parse error. Output is a JSON verdict that lists
each rule with its status (`ok` / `warn` / `deny`) and the evidence behind it.

Python 3.10+ standard library only. Tests use `pytest`.

## What it checks

| Rule | Static / sim | Default |
|---|---|---|
| Every program is on the allowlist (pump, pump AMM, system, compute budget, token, token-2022, ATA, memo) | static | deny |
| pump / pump-AMM instruction is known, and not create/launch/admin/migrate/LP | static | deny |
| Mint is on the allowlist (if one is set) | static | off |
| `max_sol_cost` / `max_quote_amount_in` ≤ per-tx cap | static | 1 SOL |
| Slippage slack between the requested amount and the limit ≤ cap | static | 500 bps |
| Buy/sell with a zero limit (`min_sol_output = 0`, etc.) | static | deny |
| Jito tip transfer to one of the 8 published tip accounts ≤ cap | static | 0.001 SOL |
| Compute-unit price ≤ cap | static | 2,000,000 µlamports |
| No other SOL transfers | static | deny |
| Simulation succeeds | sim | deny |
| Fee-payer SOL loss in simulation ≤ cap | sim | 1.1 SOL |
| Simulated TradeEvent fill respects the instruction's limits (exact for buy `min_out`, approximate for others) | sim | deny / warn |

Transactions using version 1 (the newer Solana format, now common for pump trades on mainnet) are
**DENIED** as unsupported until the parser handles them. Address lookup tables are resolved
through RPC.

## Live sample (read-only, 2026-11-18 ≈9:10 AM ET)

I pulled recent mainnet pump transactions and replayed them with signature verification off
against the default policy. All 6 legacy/v0 transactions were **DENIED**:

- zero minimum output: 2
- extra SOL transfers: 2
- CU price over the cap: 1
- slippage slack over the cap: 2
- simulation failed (stale state): 3

27 version-1 transactions were skipped. The sample is small and says nothing about traders. It
only shows that the rules fire on real transactions. Reproduce with
`python3 scripts/live_sample.py 40`.

## Threat model

- **Curve-Lab signs nothing.** Nothing imports a keypair. The RPC client rejects any method
  outside a read-only allowlist (`simulateTransaction`, `getAccountInfo`, …;
  `sendTransaction` is not on it). A test enforces this.
- **Simulation is not execution.** State moves between simulation and landing, and a malicious
  RPC can lie. Use an RPC you trust. Treat ALLOW as "fits the policy on this RPC at this slot",
  not as "safe".
- **Unknown means no.** Unknown programs, unknown instruction discriminators, unsupported tx
  versions and failed parses all return DENY.
- **The policy is the owner's.** An agent must not edit its own policy. Keep the policy file
  out of the agent's write path.
- **Not covered:** MEV, sandwiching, token-2022 transfer hooks on the mint, rug risk, the
  creator's behaviour, or whether a trade is a good idea.
- IDL facts come from pump-fun/pump-public-docs (commit `639b87fb`). That repo has no license
  file, so Curve-Lab vendors no IDL, only the discriminators it needs, re-derived from
  instruction names (`sha256("global:<name>")[:8]`).

## Layout

`curvelab/tx.py` parser · `curvelab/pump.py` program catalogue · `curvelab/policy.py` rules ·
`curvelab/simulate.py` RPC simulation · `policies/` example policies · `tests/`.

## License

MIT
