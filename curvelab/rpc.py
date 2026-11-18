"""Minimal read-only Solana JSON-RPC client (stdlib only). No signing, no sending."""
import json
import time
import urllib.request

READ_ONLY_METHODS = {"getProgramAccounts", "getSignaturesForAddress", "getTransaction", "getAccountInfo",
                     "getMultipleAccounts", "getSlot", "simulateTransaction", "getLatestBlockhash"}


class RPC:
    def __init__(self, url="https://api.mainnet-beta.solana.com", min_interval=0.12, retries=6):
        self.url, self.min_interval, self.retries, self._last, self.calls = url, min_interval, retries, 0.0, 0

    def call(self, method, params):
        if method not in READ_ONLY_METHODS:
            raise PermissionError(f"{method} is not on the read-only allowlist")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        delay = 1.0
        for _ in range(self.retries):
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
            self.calls += 1
            try:
                req = urllib.request.Request(self.url, body, {"content-type": "application/json", "user-agent": "curve-lab/0.1"})
                with urllib.request.urlopen(req, timeout=120) as r:
                    j = json.loads(r.read())
                if "error" in j:
                    if j["error"].get("code") in (429, -32429, -32005):
                        raise RuntimeError("rate")
                    raise RuntimeError(f"rpc error {j['error']}")
                return j["result"]
            except Exception as e:  # rate limits / transient
                if "rpc error" in str(e):
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 30)
        raise RuntimeError(f"{method} failed after retries")
