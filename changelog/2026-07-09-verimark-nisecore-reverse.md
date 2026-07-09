# 2026-07-09 — VeriMark driver: systematic NiseCore reverse → MOC gate CLOSED (no host path)

## Goal
After the owner-key impersonation came back a sound negative (findings/43), the user chose to
**systematically reverse NiseCore** — the engine that would emit any ownership/authorize transaction —
to decide once and for all whether ANY host-side code path can lift the `0x0405`/`0x0401`
host-not-authorized gate on MOC (`0x96`/`0x99`/`0x50`) for a host that pairs SECOND.

## Key reframe
NiseCore is **not a separate binary**: it's statically linked in-process inside
`synaWudfBioUsb132.dll` — the exact DLL we've been reversing (findings/39). We already had a standing
Ghidra project + ~475 decompiled functions, so this was **finish + close**, not acquire-and-reverse.

## Method
Five parallel RE agents over the existing dumps, each owning one axis, plus targeted Ghidra gap-fill
dumps (`re/ghidra-out/gapfill-44/`) of the load-bearing functions to replace inference with decompiled
code. One agent additionally re-parsed the shipped DLL directly (PE/`.text` scan) to ground-truth the
opcode census and caller analysis.

## Result — unanimous: CLOSED WITH EVIDENCE (no host-side authorization path)
- **State machine (A):** no host-writable flag gates MOC. `+0x4f1` = TLS-liveness (dumped
  `SessionStart` proves it — a `palDriverIoControl` TLS bring-up, not an owner check); `+0x1e==3` =
  sensor-reported; `SetOwnershipFailureCount` = a retry counter. Even "reset ownership" (`DoUnpairing`)
  sends nothing to the sensor.
- **Unwired PROVISION (B):** `0x0e` builder `FUN_18005f800` has **zero direct AND indirect callers**
  (PE-scanned for its VA pointer — in no vtable/dispatch). Complete buildable-opcode set re-derived
  from all 27 allocator sites; **`0x4f`/`0x10`/`0x50`/`0x96`/`0x99` have no builder anywhere**.
- **First-time provisioning (C):** a first-ever host emits the **identical** wire sequence
  (`0x93`+STORAGE); partition digest is plain **unkeyed SHA-256**; "advanced" pairing does *less* on
  the wire, not more. No extra first-time step.
- **Gate origin (D):** status = `map(read_u16(decrypted_response))`. Both dumped: the reader is a
  passthrough; **`FUN_180065270` is a pure lookup table** (`0x0401→0xd1`, `0x0405→0x6f`, `0x0509→0x12e`).
  `0x0405`/`0x0401` are sensor **inputs**, never synthesized by the driver → sensor-authoritative.
- **Param blobs (E):** `0x6c` is the engine's own pair/unpair **continuation blob** (symmetric for
  pair+unpair), not a credential; no engine param is sourced from a factory/DPAPI/attestation secret.

## Mechanism + notable detail
Ownership = sensor-internal first-pairer-wins TOFU set at the first `0x93` on a virgin sensor. The DLL
carries the string **`VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP`** — "OTP" (one-time-programmable/fuse)
implies the ownership slots are fuse-backed and finite, explaining why reset is owner-gated and
irreversible from a non-owner host. First and second hosts emit identical wire bytes; only the
sensor's pre-existing internal state differs. The one latent lever — calling `0x0e` PROVISION
ourselves — is a blind guess (unknown u32 arg) and destructive on an owned OTP sensor.

## Consequence
Static host-side RE is now **exhausted and closed** (converted "no path found" → "no path exists"). A
complete reverse cannot yield an un-own primitive the driver itself lacks — the ownership decision is
firmware. Remaining routes unchanged: fresh-Windows t=0 capture (to learn the `0x0e`/`0x4f`/`0x10` arg
bytes), sensor firmware RE, or the ~$50 2nd-unit pair-first-from-Linux GO path (findings/32). Built-in
Synaptics `06cb:0126` still works.

## Artifacts
`findings/44-nisecore-full-reverse-CLOSED.md`; `re/ghidra-out/gapfill-44/*` (6 newly-dumped functions).
Note: ran Ghidra headless as user `sshadows` (project owner); one accidental root run overwrote
`verimark.rep/idata/~index.dat`, restored via chown from the `~index.bak`.
