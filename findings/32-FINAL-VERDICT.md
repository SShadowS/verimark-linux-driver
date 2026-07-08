# findings/32 — Final verdict: a non-destructive Linux driver for 047d:00f2 is not reachable

> **REVISED 2026-07-08 (later):** the *non-destructive* verdict stands, but the user confirmed
> they **do not need Windows use** — a destructive **reset + provision to Linux** is acceptable.
> AND the missing ownership/MOC command constructors were located: **`synaFpAdapter132.dll`**
> (the "niseWrappers" adapter = NiseCore) — it exports `_SensorAdapterResetOwnership`,
> `EngineAdapterCreate/Update/CommitEnrollment`, etc. So `0x10/0x4f/0xe/0x96/0x99` ARE reversible
> offline from a DLL we already have. ⇒ **Route B (MOC after taking ownership) is now being
> actively pursued** (RE in progress → `re/ghidra-out/OWNERSHIP-PROVISION-TRACE.md`). Route A
> (host-side pixels) remains genuinely dead. See below for the standing analysis.

---


**Date:** 2026-07-08. Synthesis of P1–P3. Both routes to a working Linux driver are now
characterized to the end; the conclusion is negative *for a non-destructive driver*, with one
remaining (destructive + more-RE) option.

## What works (large, real progress)
- **Full secure channel from stock Linux:** `0x93` pairing + **live TLS 1.2** session (P1,
  verified); transport = bulk-over-EP0-control (findings/27).
- **Whole command surface mapped & exercised:** DB2 read/write (`0x9e/0x9f/0xa0/0xa3`), events
  (`0x86/0x87` + `0x83` interrupt), frame **capture** choreography, storage partitions
  (`0x3e/0x3f/0x40/0x41`), the MOC enroll/verify opcodes (`0x96/0x99`), and the full
  provisioning/pairing crypto (all plain ECC-P256 + SHA-256, no TPM/fuse).

## Route A — host-side matching (read raw frames, match on host): **DEAD**
Ghidra viability pass (`FRAME-READOUT-132-TRACE.md` §Viability, E1–E5):
- `0x7f FRAME_READ` and `0x8b FRAME_STREAM` have **zero callers** in `synaWudfBioUsb132.dll`
  — generic `tudorCmd` library code `rev` reuses for *other, non-MOC* Tudor sensors; this
  driver never invokes them (matches Windows plaintext: zero `0x7f`).
- The driver's real capture (`tudorCaptureProcess`) returns only a **24-byte image header
  (metrics), no pixels** — the fingerprint image is consumed **on-chip** by the MOC matcher.
- `0x7f → 0x0689` is a *valid* "no host-readable frame" reply, not a fixable error. `FRAME_ACQ`
  (any mode) fills the on-chip matcher buffer, never a host frame buffer. No prerequisite lights
  it up; no other opcode returns pixels. **Not** a tap-vs-swipe issue.
⇒ **This unit never exposes fingerprint pixels to the host.** Host-side matching is impossible.

## Route B — on-chip MOC (`0x96/0x99`): blocked behind a **destructive** ownership step
- MOC is gated on being a **provisioned owner**. Pairing (`0x93`, multi-host, non-destructive —
  we did it, Windows' 3 templates survived) is *not* enough; nor is writing the host partition
  (we wrote it, `0x0405` persisted). The gate is the **NiseCore ownership transaction**
  (`DoPairing`→`0x6c` PairingContext loop → `0x4f TAKE_OWNERSHIP`/`0x10 RESET_OWNERSHIP`/`0xe`),
  which is in **neither** the dumped DLL's command layer **nor** `rev` (findings/30, ADVANCED-PAIR).
- Ownership is **single-owner**; the sensor is currently owned by Windows. Taking ownership from
  Linux **wipes the device's Windows enrollments** (findings/25), and the device would then be
  Linux-only until re-provisioned on Windows (which flips it back — only one OS owns it at a time).
- The exact ownership opcodes/handshake are **not obtainable from what we have** — they need a
  fresh **Windows provisioning capture** (unpair+repair, itself destructive on Windows) or a
  deeper reverse of the NiseCore matcher engine.

## Bottom line
- **Non-destructive Linux driver: not reachable.** The device is MOC-only (no host pixels) and
  MOC needs single-owner ownership we can't take without wiping Windows and don't yet have the
  opcodes for.
- **If the user is willing to make the device Linux-only** (give up its Windows fingerprint use),
  the path is: capture/reverse the ownership transaction → take ownership from Linux → provision
  host partition → drive MOC `0x96/0x99` (enroll/verify choreography already worked up to the
  gate). That's the only route to a *functioning* Linux driver, and it's destructive + more RE.
- The built-in **Synaptics `06cb:0126`** reader remains the working fingerprint device on this
  laptop (unchanged).

## Cleanup
`p3_hostmatch.py`'s `0x7f` loop is a dead path on this unit (keep only as a negative probe).
Deliverables retained: `findings/27–32`, `re/ghidra-out/*TRACE.md` (transport, MOC, provisioning,
advanced-pair, frame-readout), `prototype/` (p0–p3 + GUI), `re/atansmoc-v2/` (newer-product driver,
ref only).
