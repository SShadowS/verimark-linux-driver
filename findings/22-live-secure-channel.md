# 22 — Live secure-channel capture (working session, Windows)

**Date:** 2026-07-08. Source: a **live working-session capture** on the Windows RE
box — the VeriMark (047d:00f2) driven by the real Synaptics UMDF driver while a
finger was enrolled + verified. Frida dumped the CNG session keys and the
decrypted record plaintext (`tools/frida-hook-cng.js` via `tools/win-capture.py`);
USBPcap captured the wire in parallel. Offline analysis is dependency-free on
Windows: `tools/analyze-cng-log.py captures/win-cng-<pid>.log`.

Clean-room: behavior only (cipher, framing, status codes) — no vendor code copied.
Raw captures stay **git-ignored**; only this analysis + the tooling are committed.

## Headline: the channel is AES-256-**GCM**, not AES-CBC+HMAC

Static RE (`10-crypto-map.md`, `20-protocol.md`, `21-command-reference.md`) inferred
**AES-CBC + HMAC-SHA256** (69-byte record overhead). The live capture **corrects
that**:

| Evidence | Conclusion |
|---|---|
| **0 of 710** record buffers are 16-byte block aligned | not a block cipher (CBC impossible) |
| `pbIV` is **NULL** on every `BCryptEncrypt/Decrypt`; nonce+tag live in a `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` | **AEAD / AES-GCM** |
| two stable 32-byte keys, one per direction | AES-**256**-GCM, directional (client-write / server-write) |

So the TLS 1.2 suite is an **`*_AES_256_GCM_SHA384`** ECDHE-ECDSA suite (server-auth,
no client cert — consistent with `20`'s handshake shape), **not** a CBC suite. The
`ssiTlsWrap` "69-byte overhead" from static RE was a mis-inference from the CBC path;
the live record overhead is GCM (nonce + 16-byte tag), no HMAC step.

### Session keys (this capture)
```
client-write (OUT): f30f3ec47034122bb5d12d173cbb4469e78872066e813ffff211aa5410f27ab9
server-write (IN):  a7fb02d1a6330d4841690fdaef84d34f25300bd20e58580ca83b6813f3f26107
```
Re-imported via `BCryptGenerateSymmetricKey` **once per record** (355 encrypt + 355
decrypt = 710 imports over the enroll+verify session). Keys are per-session; a fresh
handshake yields new ones.

## Record cadence + response framing

The session is **strict request/response**: 355 OUT records each followed by exactly
one IN record. Response plaintext is cleanly structured (`analyze-cng-log.py` rand
score 0.27), command plaintext is high-entropy (0.97).

**Response framing (from the IN plaintext):**
- **`u16 status` (little-endian) prefix; `0x0000` = OK.** A bare 2-byte `0000` is an
  ACK-only response (112 of 355).
- Non-empty responses are `0000 ‖ <struct>` with 4-byte-aligned fields. Distinct
  response shapes observed (by first 8 bytes):

| count | first 8 bytes | note |
|---|---|---|
| 112 | `0000` (len 2) | bare OK/ACK |
| 86 | `0000000000000000…` | OK + zero body |
| 24 | `0000060000000000…` | status + count/flags `06` |
| 24 | `0000010000000200…` | |
| 24 | `0000000000010000…` | |
| 24 | `0000010000001800…` | e.g. `…0080dead02…` (little-endian handle/id) |
| 20 | `0000010000000100…` | |
| 20 | `0000040000000000…` | |
| 4 | `0000020021000110…` | 68-byte record, sensor caps/status (seen first in session = the open/QueryStatus reply) |

Response lengths seen: `2, 4, 6, 18, 40, 52, 66, 68, 82` — several map onto the
static IOCTL out-sizes in `21` (e.g. 20/40/72 for QueryStatus / CreateEnrollment /
UpdateEnrollment), to be pinned once commands are labeled.

## What this capture gives vs still needs

- **Have now:** both directional session keys; the full **inbound response plaintext**
  stream (decrypted); the outbound **wire ciphertext**; USBPcap of the wire.
- **Capture-tool note (fixed):** `BCrypt{En,De}crypt` run **in-place**
  (`pbInput == pbOutput`). The original hook read the encrypt buffer in `onLeave`, so
  it captured *ciphertext* mislabeled as `PLAINTEXT-OUT`. The hook now reads the
  outbound plaintext in `onEnter` (before the in-place encrypt) and also dumps
  `CIPHERTEXT-OUT` + `gcm.nonce/tag` for wire correlation.
- **Needs one more capture** with the fixed hook to get the **outbound command
  plaintext** (the opcode + args the driver sends) — that closes the byte-map that
  static RE (`21`) left open.

## Correlation / verification path

Each record now yields `key + gcm.nonce + ciphertext + tag`. That is enough to
**independently AES-256-GCM-decrypt the `17 03 03` bodies in the USBPcap** and confirm
they match the Frida plaintext — a cross-check that the extracted keys are right and
that no application-layer wrapping sits under TLS.

## Command opcodes (live, 2nd capture — with the fixed hook)

The second session (open → enroll 2 fingers → verify/sign-in → delete both) captured
the **outbound command plaintext**. Commands are `opcode ‖ args`; responses are the
`u16`-status framing above. Nonces are TLS-1.2 GCM: fixed 4-byte per-direction salt
(`e8f299f0` out / `88104fcf` in) + 8-byte explicit nonce (random per record).

Every operation is bracketed **`0x99` (begin) … `0x9e` (end)**. Opcodes seen (semantics
inferred from position + the known action sequence — not yet from decompiled builders):

| opcode | len | count | where | inferred operation |
|---|---|---|---|---|
| `0x19` | 1 | 2 | session open, verify start | GET_VERSION / caps (resp 68 B) |
| `0x99` | 13 | 3 | starts each op | **BEGIN / arm** (`99 01000000 00000000 0000`) |
| `0x9e` | 2 | 3 | ends each op | **END / finalize** (`9e 01`) |
| `0x80` | 17 | 18 | 1×/capture cycle | capture params / start-frame |
| `0x81` | 1 | 18 | 1×/capture cycle | capture step ack |
| `0x86` | 37 | 102 | capture loop | **frame / sample data** (bulk of enroll) |
| `0x87` | 9 | 50 | capture loop | frame sub-step / poll |
| `0x96` | 5/13 | 18 | 1×/capture cycle | cycle end / progress |
| `0xa0` | 21 | 2 | delete | **DELETE template** (`a0 02000000 ‖ id[16]`) |
| `0xa3` | 21 | 2 | delete | **DELETE confirm/secondary** (`a3 01000000 ‖ id[16]`) |

- **18 capture cycles** (`0x80`/`0x81`/`0x96` ×18) across 2 fingers ≈ 9 samples/finger —
  matches guided enroll. `0x86` (37 B) ×102 is the per-sample frame command.
- **2 delete pairs** (`0xa0`+`0xa3`) at the tail, each carrying a distinct **16-byte
  template id** — the two enrolled fingers. Two-step delete matches the static
  `DeleteRecord` (`0x442034`) + secondary/confirm (`0x442064`) in `21`.
- Response status was `0x0000` (OK) on every bracket/delete command.

Phase segmentation (transaction index): open `[0]` · enroll-f1 `[9]0x99 … [95]0x9e` ·
enroll-f2 `[105]0x99 … [191]0x9e` · verify `[193]0x19 … [212]` · delete `[213–216]` ·
final `[217]0x9e`.

→ This is the outbound half of the byte-map `21` left open. Maps opcode → operation;
the exact arg/response struct fields per opcode are the remaining fill-in.

## Next
1. ~~Re-capture with the fixed hook → outbound command **plaintext + nonce**.~~ ✅ done
   (this session). Opcode table above.
2. Label OUT opcodes against the IOCTL/command surface in `21-command-reference.md`
   (map each request to its `On*` handler by response size + order).
3. Decrypt the USBPcap `17 03 03` records with the dumped key+nonce; confirm ==
   Frida plaintext (validates framing end-to-end).
4. Feed the confirmed command/response byte-maps back into `20`/`21`.
