# Resume prompt — P2 authorization via host cert_type (Fedora/Linux box)

> **⚠⚠ VOID — do NOT run this experiment. See `findings/41-cert-type-experiment-VOID.md`.**
> The premise (patch rev to send `cert_type=0`) is dead: rev **already sends `cert_type=0`+DER** —
> identical to Windows. The `type-2` we end up as is the **sensor's grant** to the second/non-owner
> pairer (first-pairer-wins TOFU); Windows paired first = owner (`type-0`), Linux paired second =
> secondary (`type-2`), and only the owner slot may run `0x96`/`0x99`. We do not control cert_type,
> and reset (`0x10`) is owner-gated (`0x0401`, findings/36). 
>
> **The real decisive, non-destructive test is different:** pair a **factory-fresh 2nd VeriMark unit
> FIRST from Linux** (before any Windows box touches it) → it should grant Linux `type-0` → enroll
> works. That would prove Linux can own a virgin unit; existing Windows-owned units can't be taken
> over without owner-gated reset. This file is kept only for history.

---
_(historical content below — the cert_type patch it describes is a no-op; ignore it)_

Paste the block below into a fresh Claude Code session on the Linux box. It is self-contained:
it names the state, the key finding, the ground-truth bytes (the Windows host_cert, since the raw
captures are git-ignored and stay on the Windows box), the exact experiment, and how to verify.

---

You are resuming a reverse-engineering → driver project: a Linux **libfprint** driver for the
Kensington VeriMark Desktop (USB **`047d:00f2`**, Synaptics "Tudor" silicon). Phases P0/P0b
(transport) and P1 (pairing + TLS) are **DONE and verified**; the current phase is **P2: get MOC
enroll/verify authorized**. `git pull` first — new findings/38, findings/39 and this file were just
pushed from the Windows RE box.

**Read these first (ground truth, live-verified):**
- `findings/39-ownership-opcodes-STATIC-RE.md` — READ THIS FIRST. The whole P2 reframe.
- `findings/38-moc-enroll-DECODED.md` — the decrypted Windows `0x96`/`0x99` enroll sequence.
- `findings/30-P2b-moc-enroll-blocker.md` — prior blocker analysis (now largely superseded by 39).
- `findings/28-P1-pairing-tls-VERIFIED.md` — the P1 pairing that works today.

**The key finding (what to act on):**
On this device, enroll/verify (`0x96`/`0x99`) is gated on the host presenting the right **host
certificate in the `0x93` PAIR command**. There is **no runtime "take ownership" command** —
findings/39 proved the shipping Windows driver has no `0x4f`/`0x10` builder; ownership is
factory-provisioned and the runtime auth is carried by the pair cert. The difference between the
Windows host (enrolls fine) and our `rev`-based pairing (gets `0x0405`):

| host cert field | Windows (authorized) | our `rev` pair() (0x0405) |
|---|---|---|
| magic @0x00 | `3f5f` | `3f5f` (same) |
| cert_type @0x8c | **0** | **2** |
| sign_size @0x8e | **72** | 32 |
| signature @0x90 | **DER ECDSA** (`30 46 0221…`) | raw 32-byte |

Cert layout (fixed 0x190 = 400 B): `magic:u16@0 · curve:u16@2(=0x17) · pub fields · cert_type:u16@0x8c
· sign_size:u16@0x8e · signature@0x90`. (sign_size=72 exactly matches the on-wire DER length, so the
offsets are confirmed.)

**Windows host_cert, full 400 B (hex) — ground truth to compare/parse against `rev`'s Cert class:**
```
3f5f17006b3b740da73f51eefff351d53a1309c96e02f1292b474584546e66ae7579193c000000000000000000000000
0000000000000000000000000000000000000000000000000a7afdd2bf78408672d21113c59fa22af259db530c5e158f
e3cb0cba83c3ae5000000000000000000000000000000000000000000000000000000000000000000000000000004800
3046022100bae4a1c089984b22fea6f9e3488b4ffe50fbf931434e78857e124031d89fe0c0022100f8a2a0a6aca76f31
075f3551f2aa0e2236db3252607a1f25e7f7fac341e62ec4000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000
```
(full 0x190 = 400 B, wrapped at 96 hex chars/line). Signature @0x90 = 72 B DER: `3046022100bae4...e0c0022100f8a2...e62ec4`.

**Hard facts (do NOT re-derive):**
- Transport = EP0 control (findings/27); TLS 1.2 suite `0xC02E`; command set = VCSFW.
- P1 pairing runner: `prototype/p1_pair.py` (sends `0x93 ‖ host_cert(400)`), pairing data persisted
  at `prototype/pdata/<sensorId>.pdata` (git-ignored, holds host EC priv key — keep it).
- MOC runner: `prototype/p2_moc.py` (gets `0x0405` on `0x96`/`0x99` today).
- `rev` = `re/synaTudor-rev/pydrv` (git-ignored clone). Its `tudor` package has the `Cert` class and
  `Sensor.pair()`; findings/28 recorded `rev`'s host_cert as `cert_type=2`, sig 32 B.
- The decoded target enroll sequence (findings/38): `0x99 01` dedup → `0x0509`; `0x96 01` create →
  OK; `0x96 02` add-sample ×N → 82-B progress (coverage bitmask `01→7f`); `0x96 03` commit
  (template-id + SID); `0x96 04` finish. A non-owner sees `0x0405`/`0x0401` instead.

**The experiment (cheap, non-destructive, additive — expected NOT to harm Windows):**
1. In `rev`'s pairing/Cert code, find where the host cert is built in `Sensor.pair()` — the
   `cert_type` field and the signature. Change the host cert to **`cert_type=0`** and emit a
   **DER-encoded ECDSA-P256/SHA-256 signature** (72-ish B) instead of the raw 32-byte sig.
2. First, settle whether Windows' type-0 cert is **self-signed** (so we can mint our own): parse the
   embedded Windows host_cert with `rev`'s `Cert` class, pull its pubkey, and verify its signature
   against its own pubkey over `Cert.signbytes()`. If it verifies → self-signed → we just re-sign our
   own cert with our host key. If not → it's signed by another key; report that (bigger problem).
3. Re-pair from scratch: delete/back up the old `.pdata`, run `p1_pair.py` so a fresh `0x93` goes out
   with the `cert_type=0` host cert; persist the new `.pdata`.
4. Bring up TLS (`sensor.initialize(pdata)`), then run `p2_moc.py` enroll:
   - **Success looks like:** `0x99 01` returns `0x0509` (not `0x0405`); `0x96 01` returns OK;
     `0x96 02` returns the 82-B progress record. That means the gate lifted → implement the full
     enroll/verify per findings/38.
   - **Still `0x0405`:** the cert_type alone wasn't enough. The remaining piece is the first-time
     host-partition provisioning (`0x3f` FORMAT + `0x41` WRITE with Windows' TagVal content), which a
     pre-provisioned host skips. That needs a fresh-host Windows capture — see
     `CROSS-MACHINE-OWNERSHIP-CAPTURE.md` on the Windows box (ask the human to run it).

**Safety:** pairing/host-partition is multi-slot/additive (findings/28/39) — adding our slot should
NOT wipe the Windows enrollment. Keep the `.pdata`. Do not attempt any `0x10`/`0x4f` (they aren't
needed and aren't reproducible). This repo uses the superpowers workflow: brainstorm, then a short
plan, before editing `rev`.

---
