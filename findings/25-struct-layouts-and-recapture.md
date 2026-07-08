# 25 — Struct layouts (offline-extracted) + pre-move recapture checklist

**Date:** 2026-07-08. Everything squeezable from the existing captures without the
device, plus the short list of data that *does* need the dongle — to capture **before
moving it to the Linux box**. Source: `captures/win-cng-4868.log` (enroll 2 + verify +
delete) and the cold-start handshake pcap `win-usb-20260708-103815-hub2.pcap`. Analysis
via `tools/analyze-cng-log.py` + `tools/verify-gcm.py`. Clean-room: observed bytes only.

## Response struct layouts (per opcode)

Offsets are byte offsets into the decrypted response; `u16`/`u32` are little-endian.
All responses start with `u16 status` (`0x0000` = OK).

**`0x19` GET_START_INFO (68 B, constant this FW):**
```
+0  u16 status = 0000
+2  bytes      02 00 21 00 01 10     firmware/version + caps id
+24 u32        9b6beea7              fixed instance/build id (per-FW constant)
+28 …          zero-pad to 68
```

**`0x80` FRAME_ACQ / `0x81` FRAME_FINISH:** `0000` — status-only ack (2 B).

**`0x86` EVENT_CONFIG (66 B) — actually returns an EVENT record:**
```
const block at +36:  06 cc 80 2f … a0 86 01 00 1f 00 00 00   (fixed device/sensor signature)
variable at +2,+5,+18,+21,+64  = event-specific counters/flags
```

**`0x87` EVENT_READ (18 B):**
```
+0  u16 status = 0000
+2  u32 = 00000001
+6..12  event payload (timestamp/seq — varies)
+13 u32 = 0000000a
```

**`0x96` MOC enroll-step (82 B) — guided-enroll progress:**
```
+0   u16 status
+18  u16 = 003c (const; frame geometry?)
+20  u8  COVERAGE BITMASK  (01→03→07→0f→1f→3f→7f as regions fill; 7f = complete)
+24  u8  sample counter    (0e,1c,2a,39,47,55 … ~+14/sample)
+41  u8  per-sample QUALITY (~0x63 ≈ 99)
last sample (coverage=7f): front bytes carry real template feature data instead of zero
```

**`0x99` MOC identify (177 B on match) — template record:**
```
+2   GUID[16]     template object id            (= the id deleted later)
+18  hdr/metrics  24 00.. 6f 00.. 0b 87.. …
+56  ffffffff     (empty/parent sentinel)
+66  GUID[16]     repeated object id
+86  01 00 4c000000 03000000 1c000000
+98  SID          0105000000000005 15.. <subauths> ..-1001   (host user, redacted)
tail 02 00 01 00 00 00 <crc?>
(no-match / enroll-dedup case: 2-byte 0x0509 status)
```

**`0x9e` DB2_GET_DB_INFO (40 B) — template store capacity/usage:**
```
+0  u16 status
+4  u16 = 1      (version)
+8  u16 = 1
+12 u16 = 4
+14 u16 = 528    (0x0210 — store size?)
+16 u16 = 100    MAX TEMPLATE SLOTS
+18 u16 = 48
+22..38  live usage counters (used/free/dirty — change as templates add/delete)
```

**`0xa0` DB2_GET_OBJ_INFO (52 B):**
```
+0  u32 status
+4  16×ff       parent/sentinel (unused)
+20 GUID[16]    the object id being reported (child)
+36 …0          reserved
+48 u32 = 0000910c   handle/flags
```

**`0xa3` DB2_DELETE_OBJ (4 B):** `0000 0300` — status + `0x0003` (remaining/type).

## Handshake (from cold-start pcap)

- **Suite:** ClientHello offers `C005 C02E 003D 008D 00A8 00A9`; server picks
  **`0xC02E` TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384** — **static ECDH** P-256 + ECDSA
  cert. Premaster = ECDH(host-ephemeral-priv, device-cert-key).
- **ClientHello** random `4b51af02…`; **ServerHello** random `00019f56…`, session-id
  len 7.
- **Certificate (400 B) is NOT X.509** — a **custom Synaptics container** (starts `a1 36
  3f…`, ASN.1 context-tag-1; std DER parse fails). Holds the sensor EC public key +
  ECDSA signature; parse with `synaTudor@rev`'s cert code.
- **ClientKeyExchange (65 B):** host P-256 pubkey
  `04 07816884d271…4559` (`04‖X[32]‖Y[32]`).
- Frida did **not** dump this session's derived keys (replug → new WUDFHost; hook was on
  the old PID). Not needed — the handshake is cleartext and a Linux driver derives its
  own keys.

## Pre-move recapture checklist (needs the dongle)

Everything above is now offline-permanent. Capture these **before** the dongle leaves
the Windows box (all non-destructive unless noted). Each: run `python
tools\win-capture.py`, do the action, ENTER, then `analyze-cng-log.py`.

| pri | what | status |
|---|---|---|
| ~~HIGH~~ | **`0x9f` DB2_GET_OBJ_LIST** / **`0xa1` DB2_GET_OBJ_DATA** | **Confirmed NOT UI-reachable** — an add→verify→remove-all session never fired them (Windows enumerates only at internal WBF sync/connect). Use `synaTudor@rev`'s documented format; confirm live on Linux. |
| ✅ done | **`0x39` LED_EX2** | captured incidentally (add-finger LED animation, below) |
| ✅ done | **fresh handshake session keys** | the "Remove feature" restarted the WUDFHost (new PID 62340); Frida caught the **fresh session keys** (`3be9…`/`60b4…`), verified 300/300. The one-time ECDH *derivation* still wasn't dumped (attach beat the per-record keys but not the handshake), but the wire handshake (`22`) already covers structure. |
| MED | **failed verify** (no-match) | swipe an **unenrolled** finger during verify → pins `0x99` no-match (we have the `0x0509` dedup case + a match case) |
| OPT (destructive) | **`0x93` PAIR** | needs `ResetOwnership`/unpair (**loses enrollments**); `synaTudor@rev` implements pairing — skip unless needed |

→ Net: **no offline gap remains that the UI can fill.** `0x9f`/`0xa1` come from
`synaTudor@rev`; the handshake is captured; LED is captured. The device can move to Linux.

## `0x39` LED_EX2 (captured in the add-finger session, PID 62340)

125-byte command, ×24 during one add-finger (LED feedback animation), response `0000`.
Example: `39 00 71 02 00 ffff0000 05 7f 00 20 000000 00 7f7f 0000 0000 0000 ffff 0000 05 …`
— carries LED animation frames (16-bit color/intensity fields). VCSFW `LED_EX2` per
`synaTudor` `comm.py` (0x39). Only needed if the Linux driver drives the LED; the exact
frame struct is not decoded (cosmetic).
