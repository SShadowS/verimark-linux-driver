# 23 — Tudor command byte-map (from the live decrypted session)

**Date:** 2026-07-08. Source: the decrypted plaintext of the working session in
`22-live-secure-channel.md` (enroll 2 fingers → verify/sign-in → delete both),
analyzed with `tools/analyze-cng-log.py` (per-opcode) and cross-checked byte-for-byte
against the wire by `tools/verify-gcm.py` (480/480). This is the **outbound-command +
response byte-map** that static RE (`21`) could not finish. Clean-room: observed
behavior only.

Every command is `opcode[1] ‖ args`; every response is `u16 status (LE, 0x0000=OK) ‖
body`. Commands ride TLS-1.2-GCM app-data records; 44 unsolicited 2-byte (`0000`)
interrupt-IN **events** are interleaved (finger/keepalive) and paired out separately.

## Command / response table (this session)

| opcode | n | cmd len | resp len | args (template) | role (inferred) |
|---|---|---|---|---|---|
| `0x19` | 2 | 1 | 68 | `19` | **get start-info / version** (session open + verify start) |
| `0x99` | 3 | 13 | 2 / 177 | `99 01000000 00000000 0000` | **read object / enroll record** (177-B record = GUID+SID; status `0x0509` when none) |
| `0x9e` | 3 | 2 | 40 | `9e 01` | **operation finalize** (ends each enroll/verify) |
| `0x80` | 18 | 17 | 2 | `80 LEN 000000 01000000 01000008 010101 00` | **capture/frame config** (byte1 = size, 0x14/0x0c) |
| `0x81` | 18 | 1 | 2 | `81` | **capture step / arm** (ack only) |
| `0x86` | 102 | 37 | 66 | `86 SEQ 00.. SEQ 00..` (mostly zero, small seq at +1/+17) | **frame read / sample** (dominant during enroll; resp 66-B frame metadata) |
| `0x87` | 50 | 9 | 18 | `87 XX 0020 0001 000000` | **frame-state poll** (resp carries a timestamp/counter) |
| `0x96` | 18 | 5/13 | 82 / 6 / 2 | `96 XX 000000 …` | **frame finish / get metrics** (resp 82-B metrics) |
| `0xa0` | 2 | 21 | 52 | `a0 02000000 ‖ id[16]` | **DB2 object query/get-info** (resp: child id[16] + `ffff…` sentinels) |
| `0xa3` | 2 | 21 | 4 | `a3 01000000 ‖ id[16]` | **DB2 delete object** (id = the one `0xa0` returned; resp `00 00 03 00`) |

`n` = count in this session. Response lengths are consistent per opcode once paired in
true log order (the earlier stream-zip mixed events in and looked ragged).

## Decoded structures

**`0x19` start-info response (68 B):**
```
0000            status OK
0200 2100 0110  version / build id (u16 fields)
00…             reserved
9b6beea7        4-byte instance/session id (varies per boot)
00… (pad to 68)
```

**`0x99` object/enroll record (177 B) — the interesting one:**
```
0000                                status OK
34d05fda35a2e89dcd60826d5f433a67    template GUID (16 B)  <-- same id deleted later
2400… 6f00… 0b87… …                 record header / metrics
0105000000000005 15000000
  XXXXXXXX XXXXXXXX XXXXXXXX e9030000   Windows SID  S-1-5-21-<redacted>-1001 (RID 1001)
…
```
(SID bytes redacted — real machine SID. Layout: `01`=rev, `05`=5 subauths,
`…0005`=NT authority, then 5 LE u32 subauthorities ending in RID `e9030000`=1001.)
→ **Templates are stored on-sensor bound to the host user's Windows SID.** For a Linux
port this is host-supplied object metadata: the driver picks the object GUID + a
subject id; the sensor just stores/returns them. Nothing TPM-sealed.

**Delete flow (per finger):** `0xa0 02000000 ‖ objId` → response returns a child id
`3b79344a…`; then `0xa3 01000000 ‖ 3b79344a…` deletes it. Two pairs = the two fingers.
Matches the static `DeleteRecord (0x442034)` + secondary/confirm (`0x442064`) in `21`.

## Operation state machine (observed)

```
open:     0x19 (startinfo)
enroll:   0x99(begin) → { 0x80,0x81,0x86×n,0x87,0x96 }×cycles → 0x9e(finalize)   [×2 fingers]
verify:   0x19 → 0x99 → capture loop → 0x9e
delete:   ( 0xa0 query → 0xa3 delete ) × 2
events:   44× 2-byte 0000 interrupt-IN (finger/keepalive), asynchronous
```
18 capture cycles / ~9 samples per finger (guided enroll). Each cycle: config (`0x80`)
→ arm (`0x81`) → read frames (`0x86`, several) → poll (`0x87`) → finish (`0x96`).

## VCSFW / libfprint cross-reference

The opcodes are the **Synaptics Tudor / VCSFW** MOC command set. Authoritative name +
libfprint-`synaptics` handler mapping is tracked in `24-libfprint-map.md` (from the
`synaTudor` project + libfprint upstream). Key question this answers: how much of the
Linux driver is "establish the TLS-GCM channel, then reuse the existing command set."

## Caveats
- Semantics are inferred from position + payload + the known action sequence, not from
  decompiled command builders; the VCSFW names in `24` are the ground truth to align to.
- Arg **field** meanings (e.g. `0x80`'s config flags, `0x86`'s seq) are partial — a
  second capture varying one action at a time would isolate them.
- Image/feature data never crosses the wire in cleartext (MOC): the 66/82-B frame
  responses are metadata, not the fingerprint image.
