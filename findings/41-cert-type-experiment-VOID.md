# findings/41 — The `cert_type` P2 experiment is VOID (rev already sends what Windows sends)

**Date:** 2026-07-08. Static + live-bytes analysis on the Fedora box (no sensor write).
**This retracts the actionable premise of findings/39's "cheap Linux cert_type fix" and of
`RESUME-P2-CERTTYPE.md`.** The `0x0405` enroll gate is **not** a host-cert `cert_type` difference we
can patch. Ownership state (first-pairer-wins) stands as the blocker, unchanged from the 2026-07-08
changelog conclusion.

## What findings/39 proposed (and this corrects)
findings/39 diffed the `0x93` host cert and reported:

| host cert field | Windows (authorized) | "rev" (0x0405) |
|---|---|---|
| cert_type @0x8c | 0 | **2** |
| sign_size @0x8e | 72 | **32** |
| signature @0x90 | DER ECDSA `3046…` | raw 32 B |

…and proposed: patch `rev` to emit `cert_type=0` + a DER sig, re-pair, retry enroll.

**The diff is apples-to-oranges.** The Windows column is what Windows **SENT on the wire**
(the 400-B payload after the `93` opcode). The "rev" column is findings/28's value, which is the host
cert the **SENSOR RETURNED** (`resp[2:402]`) and `rev` persisted — a *different field*.

## Ground truth (verified this session)
- **What `rev` SENDS.** `Sensor.pair()` → `SensorCertificate.create_host_cert()`
  (`re/synaTudor-rev/pydrv/tudor/sensor/pair.py:26`) hard-codes `cert_type=0` and signs with the HS
  key via `cryptography`'s `EllipticCurvePrivateKey.sign(…, ECDSA(SHA256))`, which returns a
  **DER-encoded** signature. Built the exact outbound bytes:
  `magic 5f3f · curve 23 · cert_type @0x8c = 0 · sign_size @0x8e = 71 · sig @0x90 = 30 45 02 21 …`
  ⇒ **`rev`'s outbound `0x93` cert is already `cert_type=0` + DER ECDSA (71 B)** — structurally the
  SAME as Windows (`cert_type=0` + DER `3046…` 72 B; the 71-vs-72 is normal DER r/s length variation,
  not meaningful).
- **What the SENSOR returns.** `Sensor.pair()` overwrites its host cert with `resp[2:402]`
  (`sensor.py:203`). Parsing the live `.pdata` (`prototype/pdata/f7007ad929c60000.pdata`) confirms:
  persisted **HOST** cert = `cert_type=2`, sig 32 B (`61 4d…`, raw — not DER); persisted **SENSOR**
  cert = `cert_type=0`, sig 71 B DER. So we sent type-0 and the **sensor handed back type-2.**
- **What TLS presents.** The persisted (sensor-returned) type-2 host cert is the `client_cert`
  presented in every handshake (`tudor/tls/cipher/ecc.py:65-67`), with a CertificateVerify signed by
  our `priv_key` (ecc.py:80). So the sensor sees us as a **type-2 host each session** — but that type
  is *its own grant*, not a value we supply.

## The logical proof the experiment is void
1. Windows SENDS `cert_type=0` (findings/39, wire). rev SENDS `cert_type=0` (verified above, wire).
2. The authorized host (Windows→enrolls) and the unauthorized host (rev→`0x0405`) therefore send the
   **identical** `cert_type`. A field that is equal on both sides **cannot** be the discriminator.
3. The proposed patch changes rev's sent cert_type "2→0", but it is **already 0**. ⇒ **no-op; cannot
   lift `0x0405`.** No sensor write needed to know this.
4. The `cert_type=2` is the **sensor's** decision, encoded in the cert it mints back. We sent 0, got 2.
   We do not control it, and re-sending "0" (which we already do) does not change what comes back.

## What the type-2 grant actually means
`type-0` = owner slot, `type-2` = secondary/non-owner slot, assigned **by the sensor at pair time**
on a first-pairer-wins (TOFU) basis: Windows paired first → owner (type-0); our Linux host paired
second → secondary (type-2). This is exactly the model the changelog already reached and that
`p2_reset.py` confirmed live (`0x10 RESET_OWNERSHIP` → `0x0401` host-not-authorized, findings/36).
The sensor lets only the owner slot run `0x96`/`0x99`; a type-2 host gets `0x0405`. We cannot become
type-0 on this unit because that slot is Windows' and reset is owner-gated.

⇒ **P2 blocker is unchanged: the precondition is an unowned owner-slot, which this Windows-owned unit
cannot give.** cert_type is removed as a candidate lever. The decisive non-destructive test remains a
**factory-fresh 2nd unit paired FIRST from Linux** (should be granted `type-0` → enroll).

## One cheap ground-truth check left (uses data already on the Windows box, no new hardware)
Extract the `0x93` **RESPONSE** (802 B) from the existing capture
(`captures/win-usb-20260708-222731-hub5.pcap`, dev 19) and read the sensor-returned host cert's
`cert_type` (`resp[2:402]`, byte @0x8c).
- If Windows gets **type-0** back (vs our type-2): confirms `cert_type` = the sensor's owner grant,
  reflecting slot ownership — unforgeable from a second host.
- If Windows also gets **type-2** back: `cert_type` is cosmetic and the gate is purely slot-ownership.
Either outcome keeps the Linux cert_type experiment dead; this just tells us *why* precisely.

## Do NOT
- Do **not** re-pair to "try cert_type=0" — rev already sends it; it changes nothing and only re-mints
  our (surviving, additive) slot.
- Do **not** attempt `0x10`/`0x4f` (findings/36/39: owner-gated / no builder).
