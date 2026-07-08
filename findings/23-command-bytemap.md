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

Symbolic names are the confirmed Synaptics **VCSFW** opcodes (byte-verified against the
`synaTudor@rev` reference — full mapping + evidence in `24-libfprint-map.md`).

| opcode | VCSFW name | n | cmd len | resp len | args (template) |
|---|---|---|---|---|---|
| `0x19` | **GET_START_INFO** | 2 | 1 | 68 | `19` |
| `0x80` | **FRAME_ACQ** | 18 | 17 | 2 | `80 LEN 000000 01000000 01000008 010101 00` (`<BIIHxBBBBB>`) |
| `0x81` | **FRAME_FINISH** | 18 | 1 | 2 | `81` |
| `0x86` | **EVENT_CONFIG** | 102 | 37 | 66 | `86 ‖ mask[32] ‖ u32` — event-mask, re-armed per cycle (`<B8II>`) |
| `0x87` | **EVENT_READ** | 50 | 9 | 18 | `87 seq[2] 2000 01000000` (byte-exact `<BHHI>`) |
| `0x96` | **MOC enroll-step** | 18 | 5/13 | 82 / 6 / 2 | `96 02000000` — enroll capture/update; 82-B resp = coverage bitmask + quality (see below) |
| `0x99` | **MOC identify** | 3 | 13 | 2 / 177 | `99 01000000 00000000 0000` — identify/match; 177-B resp = matched template GUID+SID, `0x0509` = no match (see below) |
| `0x9e` | **DB2_GET_DB_INFO** | 3 | 2 | 40 | `9e 01` (reads DB state after each op — *not* an "end" cmd) |
| `0xa0` | **DB2_GET_OBJ_INFO** | 2 | 21 | 52 | `a0 02000000 ‖ id[16]` (resp: child id[16] + `ffff…` sentinels) |
| `0xa3` | **DB2_DELETE_OBJ** | 2 | 21 | 4 | `a3 01000000 ‖ id[16]` (resp `00 00 03 00`) |

`n` = count in this session. Response lengths are consistent per opcode once paired in
true log order (the earlier stream-zip mixed events in and looked ragged). **`0x96` and
`0x99` are the only two opcodes not in any public RE — the genuine MOC gap to close.**

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

**`0x96` MOC enroll-step (82-B response) — the two "unmapped" MOC opcodes, cracked by
phase-diffing this capture.** Across the 7 enroll samples of one finger, a byte at
resp offset +21 walks `01 → 03 → 07 → 0f → 1f → 3f → 7f` — a **coverage bitmask
filling up** (each accepted sample sets one more region bit; `0x7f` = all 7 regions =
enroll complete). A counter at +25 climbs `0e,1c,2a,39,47,55` and a per-sample quality
at +41 sits ~`0x63` (≈99). On the final (complete) sample the response front-loads real
template feature bytes instead of zeros. So `0x96` is the **guided-enroll capture/update
step**, response = progress feedback — the MOC twin of `UpdateEnrollment (0x442010)` in
`21` (which also carries a region-coverage bitmask).

**`0x99` MOC identify.** Same 13-byte command every time, but the response tells the
function: during **enroll** it returns `0x0509` (LE status = "no match / proceed"),
during **verify** it returns the **177-byte matched template record** (GUID + host SID,
as decoded above). So `0x99` is an **identify/match** run — used for enroll
dedup-check *and* verify — the MOC twin of `IdentifyFeatureSet (0x442058)` in `21`.

→ Both opcodes are now functionally mapped (not just named). Still partial: the exact
field layout of the 82-B/177-B response structs, and confirming a *failed* verify's
no-match response. Neither needs new hardware access to nail down precisely, but a
targeted capture (below) would settle them.

**Handshake:** this enroll/verify capture reused a **cached TLS session** (0 `16 03 03`
records; keys `f30f…`/`a7fb…` persisted across runs). A separate **cold-start** capture
(unplug+replug) then caught the fresh handshake on the wire — cipher suite list,
negotiated **`0xC02E` ECDH_ECDSA_AES256_GCM_SHA384**, 408-B device cert, 65-B
ClientKeyExchange — decoded in `22-live-secure-channel.md`. Still uncaptured: the
one-time **`0x93` PAIR** provisioning (only runs when the device is *unpaired*).

## Operation state machine (observed)

```
open:     0x19 GET_START_INFO
enroll:   0x99(begin MOC) → { EVENT_CONFIG 0x86 → EVENT_READ 0x87 → FRAME_ACQ 0x80 →
                              FRAME_FINISH 0x81 → 0x96(MOC step) }×cycles →
          0x9e DB2_GET_DB_INFO   [×2 fingers]
verify:   0x19 → 0x99 → capture loop → 0x9e
delete:   ( 0xa0 DB2_GET_OBJ_INFO → 0xa3 DB2_DELETE_OBJ ) × 2
events:   44× 2-byte 0000 interrupt-IN (finger/keepalive), asynchronous
```
18 capture cycles / ~9 samples per finger (guided enroll). The capture is
**event-driven**: set the event mask (`EVENT_CONFIG`), read events (`EVENT_READ`),
acquire+finish a frame (`FRAME_ACQ`/`FRAME_FINISH`), with the on-chip MOC step (`0x96`)
and the enroll/identify session (`0x99`) — the two commands no public RE has mapped.

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
