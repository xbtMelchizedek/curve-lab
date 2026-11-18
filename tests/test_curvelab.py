import base64
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from curvelab import policy as pol, pump  # noqa: E402
from curvelab.__main__ import run  # noqa: E402
from curvelab.rpc import RPC  # noqa: E402
from curvelab.tx import anchor_disc, b58encode, build_legacy, parse, shortvec, UnsupportedVersion  # noqa: E402


def key(i):
    return b58encode(bytes([i]) * 32)


USER, MINT, OTHER = key(7), key(9), key(11)


def buy_ix(name="buy_exact_sol_in", a=10_000_000, b=1000, user=USER, user_signs=True):
    accts = [(key(20 + i), False, False) for i in range(16)]
    accts[2] = (MINT, False, False)
    accts[6] = (user, user_signs, True)
    return (pump.PUMP, accts, anchor_disc(name) + struct.pack("<QQ", a, b))


def raw(ixs, payer=USER):
    return build_legacy(payer, ixs)


class TestParse(unittest.TestCase):
    def test_roundtrip_legacy(self):
        t = parse(raw([buy_ix()]))
        self.assertEqual(t.fee_payer, USER)
        self.assertEqual(t.version, "legacy")
        self.assertEqual(len(t.instructions), 1)
        self.assertIn(MINT, t.keys)

    def test_v0_with_lookup(self):
        msg = bytes([0x80, 1, 0, 1]) + shortvec(2) + bytes([7]) * 32 + bytes([8]) * 32 + b"\0" * 32
        msg += shortvec(1) + bytes([1]) + shortvec(1) + bytes([2]) + shortvec(1) + b"\x01"
        msg += shortvec(1) + bytes([5]) * 32 + shortvec(1) + bytes([3]) + shortvec(0)
        t = parse(shortvec(1) + b"\0" * 64 + msg)
        self.assertEqual(t.version, 0)
        self.assertEqual(t.lookups[0]["writable"], [3])

    def test_v1_unsupported(self):
        msg = bytes([0x81, 1, 0, 0]) + shortvec(0)
        with self.assertRaises(UnsupportedVersion):
            parse(shortvec(1) + b"\0" * 64 + msg)
        out = run(shortvec(1) + b"\0" * 64 + msg, pol.load())
        self.assertEqual(out["verdict"], "DENY")


class TestStatic(unittest.TestCase):
    def check(self, ixs, **over):
        p = pol.load()
        p.update(over)
        return run(raw(ixs), p)

    def test_clean_buy_allows(self):
        out = self.check([buy_ix()])
        self.assertEqual(out["verdict"], "ALLOW", out["findings"])
        d = out["instructions"][0]
        self.assertEqual(d["name"], "buy_exact_sol_in")
        self.assertEqual(d["args"], {"spendable_sol_in": 10_000_000, "min_tokens_out": 1000})
        self.assertEqual(d["roles"]["mint"], MINT)

    def test_create_coin_denied(self):
        ix = (pump.PUMP, [(MINT, True, True), (USER, True, True)], anchor_disc("create_v2") + b"\0" * 16)
        out = self.check([ix])
        self.assertEqual(out["verdict"], "DENY")
        self.assertIn("deny_instruction", [f["rule"] for f in out["findings"]])

    def test_zero_min_out_denied(self):
        out = self.check([buy_ix(b=0)])
        self.assertIn("zero_min_out", [f["rule"] for f in out["findings"]])

    def test_over_budget_denied(self):
        out = self.check([buy_ix(a=5_000_000_000)])
        self.assertIn("max_quote_in_per_tx", [f["rule"] for f in out["findings"]])

    def test_mint_allowlist(self):
        out = self.check([buy_ix()], mint_allowlist=[OTHER])
        self.assertIn("mint_allowlist", [f["rule"] for f in out["findings"]])
        self.assertEqual(self.check([buy_ix()], mint_allowlist=[MINT])["verdict"], "ALLOW")

    def test_unknown_program_denied(self):
        out = self.check([buy_ix(), (OTHER, [(USER, True, True)], b"\x01")])
        self.assertIn("program_allowlist", [f["rule"] for f in out["findings"]])

    def test_unknown_pump_ix_denied(self):
        out = self.check([(pump.PUMP, [(USER, True, True)], b"\xde\xad\xbe\xef" * 2)])
        self.assertIn("unknown_instruction", [f["rule"] for f in out["findings"]])

    def test_tip_ceiling_and_stray_transfer(self):
        tip = next(iter(pump.JITO_TIP_ACCOUNTS))
        t1 = (pump.SYSTEM, [(USER, True, True), (tip, False, True)], struct.pack("<IQ", 2, 5_000_000))
        out = self.check([buy_ix(), t1])
        self.assertIn("max_jito_tip_lamports", [f["rule"] for f in out["findings"]])
        t2 = (pump.SYSTEM, [(USER, True, True), (OTHER, False, True)], struct.pack("<IQ", 2, 1))
        self.assertIn("system_transfers", [f["rule"] for f in self.check([buy_ix(), t2])["findings"]])

    def test_cu_price(self):
        cb = (pump.COMPUTE_BUDGET, [], bytes([3]) + struct.pack("<Q", 9_000_000))
        self.assertIn("max_cu_price", [f["rule"] for f in self.check([cb, buy_ix()])["findings"]])

    def test_user_must_sign(self):
        out = self.check([buy_ix(user=OTHER, user_signs=False)])
        self.assertIn("user_is_signer", [f["rule"] for f in out["findings"]])


class TestSim(unittest.TestCase):
    def ev(self, tok, sol, fee=0, cfee=0, buy=True):
        return {"mint": MINT, "token_amount": tok, "sol_amount": sol, "fee": fee, "creator_fee": cfee, "is_buy": buy,
                "ix_name": "x"}

    def test_slack(self):
        self.assertEqual(pol.slack_bps(110, 100, "max_in"), 1000)
        self.assertEqual(pol.slack_bps(90, 100, "min_out"), 1000)
        self.assertEqual(pol.slack_bps(100, 100, "min_out"), 0)

    def test_loose_min_out_denied(self):
        _, decoded = pol.static_checks(parse(raw([buy_ix(b=500)])), pol.load())
        f = pol.sim_checks(decoded, {"err": None, "trade_events": [self.ev(1000, 9_000_000)]}, pol.load())
        self.assertEqual([x["rule"] for x in f], ["max_slack_bps"])
        self.assertEqual(f[0]["level"], "deny")

    def test_tight_min_out_ok_and_synthetic_two_part(self):
        _, decoded = pol.static_checks(parse(raw([buy_ix(b=1960)])), pol.load())
        evs = [self.ev(1500, 6_000_000), self.ev(500, 3_000_000)]  # e.g. both parts of a synthetic migration
        self.assertEqual(pol.sim_checks(decoded, {"err": None, "trade_events": evs}, pol.load()), [])
        self.assertEqual(decoded[0]["simulated_fill"]["actual"], 2000)

    def test_sim_failure_denied(self):
        f = pol.sim_checks([], {"err": {"InstructionError": [0, {"Custom": 6002}]}}, pol.load())
        self.assertEqual(f[0]["rule"], "simulation")


class TestNoSend(unittest.TestCase):
    def test_rpc_allowlist_blocks_send(self):
        for m in ("sendTransaction", "requestAirdrop", "sendRawTransaction"):
            with self.assertRaises(PermissionError):
                RPC("http://127.0.0.1:1").call(m, [])

    def test_no_signing_code(self):
        root = os.path.join(os.path.dirname(__file__), "..", "curvelab")
        for fn in os.listdir(root):
            if fn.endswith(".py"):
                src = open(os.path.join(root, fn)).read()
                for bad in ("nacl", "SigningKey", "Keypair", "sendTransaction\"", "secret_key"):
                    self.assertNotIn(bad, src, f"{fn} mentions {bad}")


@unittest.skipUnless(os.environ.get("CURVELAB_LIVE") == "1", "set CURVELAB_LIVE=1 for the mainnet simulateTransaction test")
class TestLive(unittest.TestCase):
    def test_recent_pump_trade_simulates(self):
        rpc = RPC()
        for s in rpc.call("getSignaturesForAddress", [pump.PUMP, {"limit": 100}]):
            if s.get("err"):
                continue
            try:
                t = rpc.call("getTransaction", [s["signature"], {"encoding": "base64", "maxSupportedTransactionVersion": 0}])
            except RuntimeError:
                continue
            out = run(base64.b64decode(t["transaction"][0]), pol.load(), rpc)
            if any(d.get("side") for d in out["instructions"]):
                self.assertIn("simulation", out)
                self.assertIn(out["verdict"], ("ALLOW", "WARN", "DENY"))
                return
        self.skipTest("no legacy/v0 pump trade in the last 100 signatures")


if __name__ == "__main__":
    unittest.main()
