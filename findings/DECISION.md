# DECISION — GO/NO-GO for a Linux libfprint driver (Kensington VeriMark Desktop, 047d:00f2)

**Date:** 2026-07-07
**Phases reached:** Web research (§1) **and** static triage of the Windows driver
(Phases 0–2: acquired v6.0.9.1132, mapped the crypto from imports+strings; no
decompilation or dynamic capture yet). Evidence: `research-summary.md`,
`00-inventory.md`, `10-crypto-map.md`.

> ⚠️ This verdict was **revised** after static triage. The web-research-only pass
> concluded "practically NO-GO." Reversing the actual driver overturned the key
> assumption behind that.

---

## Verdict: **conditional GO** on the go/no-go gate.

The gate (`plan.md` §1 / `RESEARCH-PROMPT.md`) was: *is the secure channel
impersonable from a stock Linux host, or is host auth bound to a
Windows/TPM/firmware secret?*

**Static evidence says impersonable — the channel is NOT TPM/host-identity-bound.**
So the single most likely project-killer does **not** apply. The project is
**feasible**; what remains is implementation effort and two unverified runtime
steps — not a cryptographic wall.

This supersedes the earlier NO-GO, which was the correct call on *web evidence
alone* but rested on the (now-refuted-for-this-device) assumption of a TPM/host-
bound host credential.

---

## Why the channel is impersonable (static evidence)

From `synaWudfBioUsb132.dll` (full detail in `10-crypto-map.md`):

1. **No TPM anywhere.** The package imports only `bcrypt` (ephemeral CNG
   primitives) + `crypt32`. **No `ncrypt.dll`, no TBS/TPM, no Platform Crypto
   Provider.** The host handshake key is software, in-memory.
2. **Host key is ephemeral & self-generated.** `tudorSecurityGenHostKeyPair` +
   `BCryptGenerateKeyPair` + "export **ephemeral** ECC public key". There is no
   factory/Windows per-host identity the sensor pre-trusts.
3. **Server(device)-authentication only.** The sensor presents a cert chain rooted
   in *Microsoft ECC Devices Root CA 2017*; the host merely **verifies** it
   (`BCryptVerifySignature`). The host presents no cert.
4. **Trust-on-first-use pairing, state stored in the sensor.** Pairing generates a
   host keypair + a **PSK**, and the authoritative pairing data lives in a
   **partition inside the sensor's flash** (`tudorHostPartitionRead/Write/Format`,
   "update host partition in sensor"). It travels with the dongle. Windows DPAPI
   (`CryptProtectData`) only wraps a *local at-rest copy* — not a channel binding.

A Linux driver can therefore: generate its own ephemeral/host keypair, verify the
sensor cert, complete the Tudor TLS handshake (ECC or PSK suite), and manage its
own pairing copy — no Windows/TPM secret required.

## The device is "Tudor" family — reuse, don't reinvent

The driver's own symbols name the sensor family **"Tudor"** (`tudorSecurity*`,
`tudorTls*`, "Tudor family sensors"). That is exactly the family the community
project **`Popax21/synaTudor`** implements. So the realistic path is **adapt
synaTudor to 047d:00f2**, not a from-scratch RE. The VID difference (047d vs the
06cb synaTudor targeted) is mostly USB-matching, not protocol.

---

## Residual risks (why "conditional", not an unqualified GO)

These are engineering/runtime risks, **not** the crypto-binding blocker:

1. **The secure-enroll step is unverified.** `synaTudor` (on 06cb, via *relinking*
   the Windows driver) reportedly reaches ~90% but stalls at "secure enroll." An
   open reimplementation for 047d might hit the same runtime step. This is now the
   #1 open question — and it's a *protocol* problem, not a key-sealing one.
2. **Pairing collision / partition management.** If the dongle was ever paired on
   Windows, Linux pairing may require unpair/`PARTITION_FORMAT` first — which would
   wipe existing enrollments; the sensor partition is finite ("host partition is
   full"). Needs care.
3. **basic vs advanced security mode**, and "sensor not provisioned" states, change
   the flow; confirm which this unit is in.
4. **Effort.** Full Tudor pairing + custom-TLS + MOC state machine is weeks–months
   even reusing synaTudor. Confirmed feasible ≠ quick.

---

## Recommended next steps (in order)

1. **Evaluate `Popax21/synaTudor` against 047d:00f2 first** — cheapest high-value
   move. Does its Tudor TLS/pairing code drive this VID? How far does enroll/verify
   get? This could collapse most of the work (or expose the secure-enroll wall
   early). *(Linux-side, no Windows needed.)*
2. **Confirm on-wire with a dynamic capture** (`plan.md` §3): Windows VM + dongle
   passthrough → Frida-hook CNG in `WUDFHost.exe` (`tools/frida-hook-cng.js`) to
   dump the ECDH/session key during a real enroll + `usbmon`/USBPcap capture →
   decrypt the `17 03 03` records → read the plaintext MOC command set. This
   verifies §1's static conclusion and feeds §2 (is it Synaptics-MOC-in-TLS?).
3. **If enroll is reachable**, prototype the handshake+enroll in pyusb
   (`prototype/`), then write the libfprint driver (`plan.md` §5).

## Pragmatic fallback (unchanged, if you don't want to build a driver)

- Fingerprint login today: **built-in Synaptics `06cb:0126`** (`fprintd-enroll`).
- VeriMark as a **U2F/`pam-u2f`** tap-key (interface 0).

---

## Open questions (now narrowed)

- Does `synaTudor` drive 047d:00f2, and does an *open* implementation clear the
  secure-enroll step that stalled it on 06cb? **(the crux now)**
- Exact Tudor TLS handshake byte layout + MOC command set (needs decompile/capture).
- Which pairing mode (basic/advanced) and provisioning state is this specific unit
  in, and can it be (re)paired from Linux without bricking Windows enrollment?
- Exact sensor silicon (FS7600 vs FS7605/FS7604) behind the Tudor firmware.
