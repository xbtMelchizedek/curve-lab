"""Minimal Solana transaction (legacy + v0) parser. Pure Python, no signing code at all."""
import base64
import hashlib

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def read_shortvec(b, o):
    v = s = 0
    while True:
        x = b[o]
        o += 1
        v |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            return v, o


def shortvec(n):
    out = bytearray()
    while True:
        x = n & 0x7F
        n >>= 7
        if n:
            out.append(x | 0x80)
        else:
            out.append(x)
            return bytes(out)


class UnsupportedVersion(ValueError):
    pass


class Tx:
    def __init__(self):
        self.signatures, self.version, self.header, self.keys = [], "legacy", (0, 0, 0), []
        self.blockhash, self.instructions, self.lookups = b"", [], []
        self.loaded_writable, self.loaded_readonly = [], []

    @property
    def all_keys(self):
        return self.keys + self.loaded_writable + self.loaded_readonly

    @property
    def fee_payer(self):
        return self.keys[0]

    @property
    def signers(self):
        return self.keys[: self.header[0]]

    def is_writable(self, i):
        nsig, ro_signed, ro_unsigned = self.header
        n = len(self.keys)
        if i < nsig:
            return i < nsig - ro_signed
        if i < n:
            return i < n - ro_unsigned
        return i < n + len(self.loaded_writable)


def parse(raw: bytes) -> Tx:
    t, o = Tx(), 0
    nsig, o = read_shortvec(raw, o)
    for _ in range(nsig):
        t.signatures.append(raw[o:o + 64])
        o += 64
    if raw[o] & 0x80:
        t.version = raw[o] & 0x7F
        o += 1
        if t.version != 0:
            raise UnsupportedVersion(f"transaction version {t.version} is not supported (legacy and v0 only)")
    t.header = (raw[o], raw[o + 1], raw[o + 2])
    o += 3
    nk, o = read_shortvec(raw, o)
    for _ in range(nk):
        t.keys.append(b58encode(raw[o:o + 32]))
        o += 32
    t.blockhash = raw[o:o + 32]
    o += 32
    ni, o = read_shortvec(raw, o)
    for _ in range(ni):
        pid = raw[o]
        o += 1
        na, o = read_shortvec(raw, o)
        accts = list(raw[o:o + na])
        o += na
        nd, o = read_shortvec(raw, o)
        t.instructions.append({"program_index": pid, "accounts": accts, "data": raw[o:o + nd]})
        o += nd
    if t.version != "legacy":
        nl, o = read_shortvec(raw, o)
        for _ in range(nl):
            key = b58encode(raw[o:o + 32])
            o += 32
            nw, o = read_shortvec(raw, o)
            w = list(raw[o:o + nw])
            o += nw
            nr, o = read_shortvec(raw, o)
            r = list(raw[o:o + nr])
            o += nr
            t.lookups.append({"table": key, "writable": w, "readonly": r})
    if o != len(raw):
        raise ValueError(f"trailing bytes: parsed {o} of {len(raw)}")
    return t


def resolve_lookups(t: Tx, fetch_table):
    """fetch_table(pubkey) -> list[str] of addresses in that ALT."""
    for lk in t.lookups:
        addrs = fetch_table(lk["table"])
        t.loaded_writable += [addrs[i] for i in lk["writable"]]
    for lk in t.lookups:
        addrs = fetch_table(lk["table"])
        t.loaded_readonly += [addrs[i] for i in lk["readonly"]]
    return t


def decode_alt(data: bytes):
    """Address lookup table account: 56-byte meta, then 32-byte addresses."""
    return [b58encode(data[i:i + 32]) for i in range(56, len(data), 32)]


def build_legacy(fee_payer: str, instructions, blockhash: bytes = b"\0" * 32) -> bytes:
    """Build an UNSIGNED legacy tx (zeroed signature slots). For tests and dry-runs only.
    instructions: list of (program_id, [(pubkey, is_signer, is_writable)], data)."""
    metas = {fee_payer: [True, True]}
    order = [fee_payer]
    for pid, accts, _ in instructions:
        for k, s, w in accts:
            if k not in metas:
                metas[k] = [False, False]
                order.append(k)
            metas[k][0] |= s
            metas[k][1] |= w
        if pid not in metas:
            metas[pid] = [False, False]
            order.append(pid)
    keyset = sorted(order, key=lambda k: (k != fee_payer, not metas[k][0], not metas[k][1]))
    nsig = sum(metas[k][0] for k in keyset)
    ro_signed = sum(metas[k][0] and not metas[k][1] for k in keyset)
    ro_unsigned = sum((not metas[k][0]) and not metas[k][1] for k in keyset)
    idx = {k: i for i, k in enumerate(keyset)}
    msg = bytes([nsig, ro_signed, ro_unsigned]) + shortvec(len(keyset)) + b"".join(b58decode(k).rjust(32, b"\0") for k in keyset)
    msg += blockhash + shortvec(len(instructions))
    for pid, accts, data in instructions:
        msg += bytes([idx[pid]]) + shortvec(len(accts)) + bytes(idx[k] for k, _, _ in accts) + shortvec(len(data)) + data
    return shortvec(nsig) + b"\0" * 64 * nsig + msg


def anchor_disc(name: str) -> bytes:
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()
