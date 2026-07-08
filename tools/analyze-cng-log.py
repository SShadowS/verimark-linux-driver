#!/usr/bin/env python3
r"""analyze-cng-log.py - offline analysis of a win-capture.py CNG log (Windows or Linux).

Turns a captures\win-cng-<pid>.log (the Frida BCrypt dump) into a readable
request/response timeline for the VeriMark/Tudor secure channel, WITHOUT needing
tshark/pyshark or the raw pcaps. Run it right on the Windows RE box:

    python tools\analyze-cng-log.py captures\win-cng-4868.log
    python tools\analyze-cng-log.py captures\win-cng-4868.log --json out.json --limit 40

What it extracts (labels emitted by tools/frida-hook-cng.js):
  symKeySecret     - the AES-256-GCM session keys (one per direction)
  PLAINTEXT-OUT    - outgoing command plaintext   (grabbed pre-encrypt; NEW hook)
  CIPHERTEXT-OUT   - the wire bytes that went out  (post in-place encrypt; NEW hook)
  gcm.nonce/tag.*  - per-record GCM nonce + tag    (NEW hook)
  PLAINTEXT-IN     - incoming response plaintext
  CIPHERTEXT-IN    - the wire bytes that came in

Old logs (before the in-place-GCM fix) only have PLAINTEXT-OUT/-IN, and there the
"PLAINTEXT-OUT" is actually CIPHERTEXT (read after the in-place encrypt) - the tool
detects this by Shannon entropy and says so, so you don't misread random bytes as
a command.

The channel is AES-256-GCM (server-auth TLS 1.2), so payload length is not block
aligned; a stream of high-entropy OUT with structured IN is the normal shape.
"""
import argparse
import collections
import json
import math
import re
import sys

LABELS = (
    "PLAINTEXT-OUT", "CIPHERTEXT-OUT", "PLAINTEXT-IN", "CIPHERTEXT-IN",
    "symKeySecret", "derivedKey", "exportedBlob",
    "gcm.nonce.out", "gcm.tag.out", "gcm.nonce.in", "gcm.tag.in",
)
_LINE = re.compile(r"^\s*(" + "|".join(re.escape(l) for l in LABELS) + r")\s*\((\d+)\):\s*([0-9a-fA-F]*)\s*$")


def shannon(b):
    """Entropy in bits/byte (0..8). >~6.5 on short buffers => looks encrypted/random."""
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parse(path):
    streams = collections.defaultdict(list)   # label -> [bytes]
    order = []                                 # ('OUT'|'IN', bytes) in true temporal order
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _LINE.match(line)
            if not m:
                continue
            label, ln, hx = m.group(1), int(m.group(2)), m.group(3)
            try:
                b = bytes.fromhex(hx)
            except ValueError:
                continue
            streams[label].append(b)
            if label == "PLAINTEXT-OUT":
                order.append(("OUT", b))
            elif label == "PLAINTEXT-IN":
                order.append(("IN", b))
    return streams, order


def pair_by_order(order):
    """Pair each command with the next response in true log order; unmatched INs are
    unsolicited interrupt events. Avoids the stream-zip misalignment when the two
    directions have different counts (events inflate the IN side)."""
    txs, events, pend = [], [], None
    for d, b in order:
        if d == "OUT":
            if pend is not None:
                txs.append((pend, None))    # a command with no response before the next
            pend = b
        else:
            if pend is not None:
                txs.append((pend, b))
                pend = None
            else:
                events.append(b)
    if pend is not None:
        txs.append((pend, None))
    return txs, events


def classify(stream):
    """Return ('structured'|'encrypted'|'-', randomness) for a list of buffers.

    Shannon entropy is capped by log2(len) - a 37-byte random buffer maxes out at
    ~5.2 bits/byte - so we normalize: randomness = H / log2(len) is ~1.0 for
    ciphertext and well under for zero-heavy structured data, at any length.
    """
    if not stream:
        return "-", 0.0
    ratios = [shannon(b) / math.log2(len(b)) for b in stream if len(b) >= 8]
    if not ratios:
        m = sum(shannon(b) for b in stream) / len(stream)
        return ("encrypted" if m > 3.5 else "structured"), m
    r = sum(ratios) / len(ratios)
    return ("encrypted" if r >= 0.85 else "structured"), r


def u32le(b, off):
    return int.from_bytes(b[off:off + 4], "little") if off + 4 <= len(b) else None


def decode_response(b):
    """Light struct view of a response plaintext: first few little-endian u32s."""
    words = []
    for off in range(0, min(len(b), 24), 4):
        w = u32le(b, off)
        if w is not None:
            words.append("%08x" % w)
    return " ".join(words)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="captures/win-cng-<pid>.log")
    ap.add_argument("--limit", type=int, default=30, help="transactions to print (default 30)")
    ap.add_argument("--json", help="write full timeline as JSON here")
    args = ap.parse_args()

    s, order = parse(args.log)
    if not any(s.values()):
        sys.exit("No CNG dump lines found - is this a win-capture.py log?")

    # --- session keys ---
    keys = [k.hex() for k in s["symKeySecret"]]
    distinct = list(dict.fromkeys(keys))
    print("=== session keys (AES-256-GCM) ===")
    print(f"  {len(keys)} imports, {len(distinct)} distinct:")
    # a key that appears immediately before OUT ops vs IN ops => direction; here we
    # just report the distinct keys - the two are client-write / server-write.
    for i, k in enumerate(distinct):
        print(f"    key[{i}] ({len(bytes.fromhex(k))} B): {k}")

    # --- cipher / stream classification ---
    print("\n=== stream classification (Shannon bits/byte) ===")
    for label in ("PLAINTEXT-OUT", "CIPHERTEXT-OUT", "PLAINTEXT-IN", "CIPHERTEXT-IN"):
        if s[label]:
            kind, mean = classify(s[label])
            lens = collections.Counter(len(b) for b in s[label])
            note = ""
            if label == "PLAINTEXT-OUT" and kind == "encrypted" and not s["CIPHERTEXT-OUT"]:
                note = "  <- OLD log: this is actually CIPHERTEXT (pre-fix in-place read)"
            print(f"  {label:15} n={len(s[label]):4} rand~{mean:4.2f} [{kind}]"
                  f"  lens={dict(sorted(lens.items()))}{note}")

    # --- request/response timeline (paired in true log order) ---
    txs, events = pair_by_order(order)
    out_is_plain = bool(s["PLAINTEXT-OUT"]) and classify(s["PLAINTEXT-OUT"])[0] == "structured"
    print(f"\n=== {len(txs)} transactions + {len(events)} unsolicited events "
          f"(OUT={'plaintext' if out_is_plain else 'CIPHERTEXT (old log)'}) ===")
    timeline = []
    for k, (o, r) in enumerate(txs):
        rec = {
            "i": k, "op": (o[0] if o else None),
            "out_len": len(o) if o else 0, "out_hex": o.hex() if o else "",
            "in_len": len(r) if r else 0, "in_hex": r.hex() if r else "",
            "resp_words": decode_response(r) if r else "",
        }
        timeline.append(rec)
        if k < args.limit:
            opc = ("op=0x%02x " % o[0]) if (out_is_plain and o) else ""
            print(f"  [{k:3}] OUT({rec['out_len']:3}) {opc}{(o[:16].hex() if o else '')}"
                  f"{'..' if o and len(o) > 16 else ''}")
            if r is not None:
                print(f"        IN ({len(r):3}) {r[:24].hex()}{'..' if len(r) > 24 else ''}"
                      f"   u32le: {rec['resp_words']}")
            else:
                print("        IN  (none before next command)")
    if len(txs) > args.limit:
        print(f"  ... {len(txs) - args.limit} more (use --limit / --json for all)")

    # --- per-opcode summary (reliable once paired in order) ---
    if out_is_plain:
        print("\n=== per-opcode summary (cmd byte0) ===")
        agg = collections.defaultdict(lambda: {"n": 0, "clens": collections.Counter(),
                                               "rlens": collections.Counter()})
        for o, r in txs:
            if not o:
                continue
            a = agg[o[0]]
            a["n"] += 1
            a["clens"][len(o)] += 1
            if r is not None:
                a["rlens"][len(r)] += 1
        for op in sorted(agg):
            a = agg[op]
            print(f"  0x{op:02x}  x{a['n']:<3} cmdlen={dict(sorted(a['clens'].items()))}"
                  f"  resplen={dict(sorted(a['rlens'].items()))}")

    # --- distinct response shapes ---
    print("\n=== distinct response plaintexts (by first 8 bytes) ===")
    shapes = collections.Counter(b[:8].hex() for b in s["PLAINTEXT-IN"])
    for pfx, cnt in shapes.most_common(15):
        print(f"  x{cnt:3}  {pfx}..")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"keys": distinct, "transactions": timeline}, f, indent=2)
        print(f"\n[+] wrote {len(timeline)} transactions -> {args.json}")


if __name__ == "__main__":
    main()
