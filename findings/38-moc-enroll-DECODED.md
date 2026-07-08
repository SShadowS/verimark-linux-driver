# findings/38 — MOC enroll/verify (`0x96`/`0x99`) DECODED from a live Windows capture

**Date:** 2026-07-08. **Status: enroll subprotocol fully decoded; authorization gate unchanged.**
First clean, decrypted capture of a *complete successful* Windows MOC enrollment on `047d:00f2`.
This closes the `0x96`/`0x99` RE gap (framing + sequencing + response layouts) that findings/24
(delta #2) and findings/30 called the genuine unknown. It does **not** capture the ownership
transaction (see "What is NOT here").

## How it was captured (tooling that finally worked)
`tools/win-capture.py --early-attach` + the self-selecting `tools/frida-hook-cng.js`.
- **frida spawn-gating is unsupported on Windows** (`enable_spawn_gating` → "not yet supported on
  this OS", frida 17.15.3). So a poll-and-attach loop re-attaches to every WUDFHost the instant it
  (re)spawns; the hook defers arming (watches `LdrLoadDll`) until `synaWudfBioUsb` + `bcrypt` are
  mapped, then dumps the CNG key material + TLS plaintext.
- **Correct capture order (critical — see below):** start capture FIRST, THEN run
  `win-unpair-verimark.ps1` while it is live, THEN enroll. The unpair script's step 3
  (`pnputil /remove-device` + `/scan-devices`) itself re-enumerates the device and fires the fresh
  `0x93` pairing — so if capture is not already running, the pairing happens off-camera. Confirmed
  empirically: a run that started capture *after* unpair caught only a plain TLS re-init.
- Raw artifacts (git-ignored): `captures/win-cng-early-20260708-215515.log` (1881 lines, 2 hosts
  armed, decrypted plaintext), `captures/win-usb-20260708-215515-hub{2,4,5}.pcap` (wire; hold the
  pre-TLS `0x93` + raw frames). Session keys (32-B directional AES-256-GCM + salts) are in the log.

## The enroll/verify subprotocol (decrypted plaintext, all status `0x0000` OK)
Order as issued by the Windows driver during one "Set up fingerprint":

| phase | command (PLAINTEXT-OUT) | response (PLAINTEXT-IN) |
|---|---|---|
| dedup | `99 01` + 11 zero bytes (`99010000000000000000000000`) | `0509` (no-match) |
| begin | `96 01` + 11 zero bytes (`96010000000000000000000000`) | `000000000000` (6 B, OK) |
| add-sample ×7 | `96 02 000000` (5 B) | **82-byte progress record** (see below) |
| commit | `96 03 …` (124 B: template-id + Windows SID) | `0000` |
| finish | `96 04 000000` (5 B) | `0000` |

- **`0x99 01` = identify/dedup**, run *before* enrolling, returns **`0x0509`** ("no match" — finger
  not already enrolled). This is the exact status the Linux host never reaches: on Linux `0x99`
  returns `0x0405` (not authorized). Getting `0x0509` requires being the sensor owner.
- **`0x96 01` = create/begin** enroll session → 6-byte OK.
- **`0x96 02` = add-sample**, called once per captured frame; returns the 82-byte progress record.
- **`0x96 03` = commit/finalize**, 124-byte command carrying the 16-byte template-id and a Windows
  **SID** (`…01 05 00000000 0515 0000 00 <4×u32 subauthorities redacted — the caller's
  S-1-5-21-… account>`). This binds
  the on-chip template to a Windows user account.
- **`0x96 04` = finish** → OK.

### The 82-byte add-sample progress record
Byte pattern (offsets approximate; `..` = per-sample varying):
`0000` status ‖ 16 B (mostly zero; the **template-id** appears here on the final full-coverage
sample) ‖ `3c000000` ‖ **`<coverage>`** ‖ `<u16 progress>` ‖ … ‖ counters.

Observed progression across the 7 add-sample calls (coverage bitmask marches `01→7f`, exactly as
findings/23 predicted; progress climbs to 100; sample counter 1→7):

```
sample 1: coverage=0x01  progress=0x0e(14)   n=1
sample 2: coverage=0x03  progress=0x1c(28)   n=2
sample 3: coverage=0x07  progress=0x2a(42)   n=3
sample 4: coverage=0x0f  progress=0x39(57)   n=4
sample 5: coverage=0x1f  progress=0x47(71)   n=5
sample 6: coverage=0x3f  progress=0x55(85)   n=6
sample 7: coverage=0x7f  progress=0x64(100)  n=7   template-id c86b8f32c9ef452febeeed4f95727103 present
```

Each `0x96 02` is preceded by the frame-capture choreography from findings/29 (`0x80 FRAME_ACQ` /
`0x86`/`0x87` event arm+read / `0x81 FRAME_FINISH`) and interleaved with DB2 bookkeeping
(`0x9e`/`0x9f`/`0xa0`/`0xa3`) and `0x39 LED_EX2` animations. The MOC step consumes the frame
on-chip — no image crosses to the host (consistent with findings/31: Windows never issues `0x7f`).

## What is NOT here — and why (the ownership gate is unchanged)
The capture contains **zero ownership/cert opcodes** (`0x4f` TAKE_OWNERSHIP_EX2, `0x10`
RESET_OWNERSHIP, `0x0e` PROVISION, `0x6c` PairingContext, `0x50` GET_CERTIFICATE_EX). Reason:
**Windows already owns this sensor.** `win-unpair-verimark.ps1` wipes the *host-side* registry
pairing + Hello DB, but **ownership lives in sensor flash** and is single-owner; a host-side unpair
does not drop it. So on re-pair Windows is still the recognized owner and enroll succeeds
(`0x0000`) without re-running provisioning.

⇒ **One of the two P2 gaps is now closed** (how `0x96`/`0x99` work — fully specified above).
⇒ **The other is unchanged**: to *run* these on Linux you must be the sensor owner, and Linux is
`0x0405` (not authorized). Capturing the ownership-establishment needs the sensor to NOT already be
owned by the capturing host — i.e. a destructive `RESET_OWNERSHIP`/`TAKE_OWNERSHIP` (wipes the
current owner's enrollment). See findings/30/34 and the cross-machine capture proposal (below).

## Proposal on file — capturing ownership without reversing NiseCore
Because machine-1 owning the sensor is exactly why ownership never re-runs there, force machine 1's
Windows driver to re-acquire ownership by having a *different* host own it first:
1. Machine 1 (RE box): start `--early-attach` capture; run `win-unpair-verimark.ps1` (host-side).
2. Move sensor to machine 2 (any Windows box with the Synaptics driver): enroll a finger → machine
   2 pairs and becomes the sensor owner.
3. Move sensor back to machine 1 with capture still live; attempt **Set up fingerprint** on machine
   1 → machine 1 is now a foreign/dispossessed host and must run the ownership acquisition path →
   the `0x4f`/`0x10`/`0x0e`/`0x6c` transaction is emitted **on-camera**.

Open questions this would settle: (a) does the sensor permit ownership transfer/second-owner at
all, or hard-reject; (b) is the trigger plug-in or the enroll attempt; (c) is the authorization
sensor-side state we can reproduce, or bound to a runtime secret. Ownership is **not** bound to a
specific Windows install (findings/DECISION: ephemeral self-generated host key, no TPM/DPAPI channel
binding), so machine 2 being "different Windows" is fine — the binding is to the paired keypair /
sensor-flash slot, not the OS instance.
