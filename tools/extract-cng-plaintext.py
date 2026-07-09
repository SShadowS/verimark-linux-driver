#!/usr/bin/env python3
"""
extract-cng-plaintext.py — turn a Frida CNG plaintext log into a structured JSON transcript.

The Windows capture harness (frida-hook-cng.js) logs the DECRYPTED TLS payloads of the
Synaptics/Tudor command channel as lines:

    PLAINTEXT-OUT (<len>): <hex>     # host -> sensor command
    PLAINTEXT-IN  (<len>): <hex>     # sensor -> host response

This parser pairs each OUT with the immediately-following IN (its response), decodes the
opcode / sub-command / status word, and emits:

  * an ordered `exchanges` list  — the replayable command/response transcript
  * a per-opcode `summary`        — counts, sample payloads, observed statuses

Usage:
    extract-cng-plaintext.py <cng.log> [<cng2.log> ...] -o out.json
    extract-cng-plaintext.py <cng.log>            # prints summary to stdout, no file

Reusable: point it at any future capture. Pure stdlib.
"""
import sys, re, json, argparse

# VCSFW opcode -> name (from synaTudor rev Command enum + findings/21/29/44).
OPCODES = {
    0x01: "GET_VERSION", 0x05: "RESET", 0x07: "PEEK", 0x08: "POKE",
    0x0e: "PROVISION", 0x10: "RESET_OWNERSHIP", 0x14: "SESSION_INIT?",
    0x19: "GET_START_INFO", 0x39: "LED_EX2", 0x3e: "STORAGE_INFO_GET",
    0x3f: "STORAGE_PART_FORMAT", 0x40: "STORAGE_PART_READ", 0x41: "STORAGE_PART_WRITE",
    0x4f: "TAKE_OWNERSHIP_EX2", 0x50: "GET_CERTIFICATE_EX", 0x57: "RESET_SBL_MODE",
    0x7d: "TIDLE_SET", 0x7f: "FRAME_READ", 0x80: "FRAME_ACQ", 0x81: "FRAME_FINISH",
    0x82: "FRAME_STATE_GET", 0x86: "EVENT_CONFIG", 0x87: "EVENT_READ",
    0x8b: "IOTA_FIND", 0x8e: "PAIR?", 0x93: "PAIR", 0x96: "ENROLL",
    0x99: "IDENTIFY", 0x9e: "DB2_GET_DB_INFO", 0x9f: "DB2_GET_OBJ_LIST",
    0xa0: "DB2_GET_OBJ_INFO", 0xa3: "DB2_DELETE_OBJ", 0xa6: "DB2_WRITE_OBJ",
    0xaa: "DB2_GET_OBJ_DATA", 0xae: "DB2_CLEANUP",
}

LINE = re.compile(r'PLAINTEXT-(OUT|IN)\s*\((\d+)\):\s*([0-9a-fA-F]+)')


def parse_records(paths):
    recs = []
    for p in paths:
        with open(p, errors="replace") as f:
            for ln in f:
                m = LINE.search(ln)
                if m:
                    recs.append((m.group(1), int(m.group(2)), m.group(3).lower(), p))
    return recs


def u16le(hexstr, off=0):
    if len(hexstr) < (off + 2) * 2:
        return None
    b = bytes.fromhex(hexstr)
    return b[off] | (b[off + 1] << 8)


def build(paths):
    recs = parse_records(paths)
    exchanges = []
    i = 0
    seq = 0
    while i < len(recs):
        d, ln, hx, src = recs[i]
        if d != "OUT":
            i += 1
            continue
        op = int(hx[0:2], 16) if len(hx) >= 2 else None
        sub = int(hx[2:4], 16) if len(hx) >= 4 else None
        resp = None
        if i + 1 < len(recs) and recs[i + 1][0] == "IN":
            rd, rlen, rhx, _ = recs[i + 1]
            resp = {"len": rlen, "hex": rhx, "status": u16le(rhx)}
            i += 2
        else:
            i += 1  # OUT with no captured response
        exchanges.append({
            "seq": seq, "op": op, "op_name": OPCODES.get(op, "?"),
            "sub": sub, "cmd_len": ln, "cmd_hex": hx, "resp": resp,
            "src": src.split("/")[-1],
        })
        seq += 1

    # per-opcode summary
    summary = {}
    for e in exchanges:
        key = "0x%02x" % e["op"] + (":%02x" % e["sub"] if e["sub"] is not None else "")
        s = summary.setdefault(key, {
            "op": e["op"], "op_name": e["op_name"], "sub": e["sub"],
            "count": 0, "cmd_len": e["cmd_len"], "cmd_sample": e["cmd_hex"],
            "resp_len": (e["resp"] or {}).get("len"),
            "resp_sample": (e["resp"] or {}).get("hex"),
            "statuses": [],
        })
        s["count"] += 1
        st = (e["resp"] or {}).get("status")
        if st is not None and st not in s["statuses"]:
            s["statuses"].append(st)
        # prefer the shortest cmd sample (fixed-header commands)
        if e["cmd_len"] < s["cmd_len"]:
            s["cmd_len"] = e["cmd_len"]; s["cmd_sample"] = e["cmd_hex"]
    for s in summary.values():
        s["statuses"] = ["0x%04x" % x for x in sorted(s["statuses"])]

    return {"sources": [p.split("/")[-1] for p in paths],
            "n_exchanges": len(exchanges),
            "summary": dict(sorted(summary.items())),
            "exchanges": exchanges}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    doc = build(a.logs)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(doc, f, indent=1)
        print("wrote %s  (%d exchanges, %d distinct opcodes)"
              % (a.out, doc["n_exchanges"], len(doc["summary"])))
    else:
        for k, s in doc["summary"].items():
            print("%-9s %-20s n=%-4d cmd_len=%-4s resp_len=%-4s status=%s"
                  % (k, s["op_name"], s["count"], s["cmd_len"], s["resp_len"], s["statuses"]))


if __name__ == "__main__":
    main()
