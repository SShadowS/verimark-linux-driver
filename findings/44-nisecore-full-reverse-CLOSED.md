# findings/44 — Systematic NiseCore reverse: no host-side MOC-authorization path (CLOSED WITH EVIDENCE)

> **⚠️ SUPERSEDED (2026-07-09, findings/49):** the enroll "ownership gate" (0x0405) was a 2-byte truncated command, not sensor-side ownership. See findings/49.

**Date:** 2026-07-09. Goal: settle, by a complete reverse of the in-process NiseCore engine, whether
ANY code path in the shipping Windows driver can confer MOC enroll authorization (`0x96`/`0x99`,
gate `0x0405`; `0x50` cert, gate `0x0401`) on a host that pairs SECOND into an already-owned sensor —
and fully map the ownership/provisioning state machine. **Verdict: CLOSED — no such path exists.**

NiseCore is **not** a separate binary: it is statically linked in-process inside
`synaWudfBioUsb132.dll` (Ghidra image base `0x180000000`). We already had a standing Ghidra project +
~475 decompiled functions. This pass = 5 parallel RE agents over those dumps (+ one independent PE
re-parse of the DLL) + targeted Ghidra gap-fill dumps of the load-bearing functions (`gapfill-44/`).

## Headline
Every ownership/authorization variable, opcode, engine param, and dispatch path in the DLL was
enumerated. **The `0x0405`/`0x0401` gate is a sensor-authoritative verdict the driver merely relays;
no host action — replayable from Linux — can change it.** The driver's entire "ownership" surface is
`0x93` PAIR + STORAGE, all of which our Linux host already reproduces. This is the static ceiling:
host-side RE is exhausted **and closed**, not just stuck.

## Five axes, all converging

### A — Ownership/authorization STATE machine
No host-writable flag gates MOC. Every state var is (a) session liveness, (b) local bookkeeping, or
(c) a read-only echo of sensor-granted mode:
- `CBiometricDevice+0x4f1` = "secure channel live." Its sole writer **`CBiometricDevice::SessionStart`**
  (dumped, `gapfill-44/`) just calls `palDriverIoControl(hSensor, security_type, &out)` (TLS bring-up)
  and sets the byte = `(out==1)`. **Not** an owner check — Linux already flips it (P1 live TLS).
- `SetOwnershipFailureCount` (`+0xb0`, mirrored to registry) = a **retry counter** bumped when the
  *sensor* refuses; one of five `*FailureCount` registry values. Not an accountant of ownership slots.
- `hSensor+0x1e == 3` (provisioned) = **sensor-reported**, host cannot write it; gates only TLS.
- `hSensor+0x25 == 1` (pairing-data-present) = set by our own `0x93`; gates TLS, not MOC.
- `+0x84`/`+0x89`/`+0x80` = init/connect/async-pair bookkeeping, all reproducible.
Even the driver's **"reset ownership" IOCTL** (`OnResetOwnership` → `DoUnpairing`) sends **nothing** to
the sensor — TLS close + clear a local registry blob. It never emits `0x10`.

### B — The unwired PROVISION path + ownership opcodes (PE-verified)
- **`0x0e` PROVISION builder `FUN_18005f800`**: forms `[0e][arg:u32]` (5 B) → 2-B status. **Zero direct
  callers AND zero indirect references** — a scan for its 8-byte VA pointer across `.rdata`/`.data`
  found it in no vtable / dispatch array / callback slot (only its own `.pdata` unwind record). Dead code.
- **Complete buildable-opcode set** (re-derived from all 27 `tudorCmdAlloc` `FUN_180063fe0` call
  sites): `01 05 07 08 0e 19 39 3e 3f 40 41 57 7d 7f 80 81 82 86 87 8b 8e 93 a6 aa ae`. The allocator
  (dumped) only does `buf=alloc(len); memset0; buf[0]=opcode` — no side channel, census is complete.
- **`0x4f` TAKE_OWNERSHIP_EX2 / `0x10` RESET_OWNERSHIP / `0x50` GET_CERTIFICATE_EX / `0x96` / `0x99`:
  NO builder anywhere** — they exist only as case labels in the opcode-name logger `FUN_1800640b0`
  and as static strings (`VCSFW_CMD_*`). Their wire layouts are unrecoverable from this binary.

### C — First-time provisioning sequence
A first-ever host emits the **identical** wire sequence as any later host: `0x93` PAIR + STORAGE
(`0x3e` info / `0x40` read / `0x3f` format / `0x41` write). A pre-provisioned host skips only the
`0x3f`/`0x41` writes. **No opcode outside `0x93`+STORAGE is ever emitted.** The host-partition digest
is `palCryptoDigest` = **plain unkeyed SHA-256** (DigestInit/Update/Final, no key/salt/secret); the
version tag is a hardcoded `01 00 00 00` hashed — fully reproducible (matches findings/37: the sensor
stored our byte-exact write verbatim). The "advanced" security-mode branch our sensor takes does
**less** on the wire (single `0x93`), not more; "basic" is the heavier PSK path we don't use.

### D — The `0x0405` gate origin (sensor-authoritative, not driver-local)
Every command funnels through `FUN_180063bb0`; the returned status is
`FUN_180065270( FUN_1800a3ef0( *response_body ) )` — i.e. **read the first u16 off the decrypted
response and map it**. Both dumped: `FUN_1800a3ef0` is `return param_1` (passthrough);
**`FUN_180065270` is a pure lookup table** (`0x0401→0xd1`, `0x0405→0x6f`, `0x0509→0x12e`, `0x0000→0`,
default→`0xca`). `0x0405`/`0x0401` are **inputs from the sensor**, never synthesized by the driver.
No dumped path assigns them locally (the only `0x401` literal in the DLL is a DER cert-length
constant). MOC opcodes reach this same relay via `tudorSendAnyCommand` (opcode = first byte of the
IOCTL blob). OnConnectSecure builds only host-local state (TLS, cached host cert template, matcher
context) — nothing the sensor re-checks. **The verdict is minted by sensor firmware; host code cannot
flip it.**

### E — Matcher-engine param blobs (`vfmSetParamBlob`)
The old "`0x6c` = PairingContext = something we lack" reading is **refuted**. `0x6c` = engine
**selector 10** = the matcher's own pair/unpair **continuation blob**: produced by the engine, stashed
to a local `PairingContext`/`UnpairingContext` property, read back to resume — used **symmetrically for
pair and unpair** (you don't restore an ownership credential to *un*pair). Every engine param the
driver sets is engine-produced (`0x6c`, reads), host-pairing-derived (`0x65` = our `.pdata` material),
or live-TLS (`0x69` wrap/unwrap). **None is sourced from a factory / DPAPI / attestation secret.**
`vfmSecurityDoPair` (`FUN_18001df30`, dumped) dispatches engine **selector 9** (→`0x93`) and nothing
else; `vfmSecurityUnPair` (`FUN_18001e2c0`) is the same shape with selector 10.

## Why the gate is un-openable from the host (the mechanism)
Ownership is **sensor-internal first-pairer-wins TOFU**: the first `0x93` on a virgin (unowned) sensor
seats that host as owner in sensor flash; thereafter `0x96`/`0x99`/`0x50` are gated on that internal
identity. A second host's `0x93` re-keys TLS but does not seat ownership → `0x0405`/`0x0401`. The DLL
carries the string **`VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP`** — "OTP" (one-time-programmable/fuse)
strongly implies the ownership slots are fuse-backed and finite, which explains why `0x10`
RESET_OWNERSHIP is owner-gated and returned `0x0401` even to us (findings/36) and why this is
genuinely irreversible from a non-owner host. First-time host and second host emit **identical** wire
bytes; the only difference is the sensor's pre-existing internal state.

## The one latent lever (and why it isn't a path)
`0x0e` PROVISION (`FUN_18005f800`) is a real, reachable function — a Linux host *could* send
`[0e][arg:u32]` directly, as we already send `0x96`/`0x99`. But its single u32 arg is **never
populated by any reachable code and never appears in any capture**, so firing it is a blind guess, and
PROVISION on an already-owned OTP sensor is exactly the destructive/irreversible operation to avoid.
`0x4f`/`0x10` have no builder at all → the binary reveals neither their arg layout nor any
challenge-response a foreign host could satisfy. There is no discoverable host-side ownership exploit.

## Consequence
**Static host-side RE is exhausted and definitively closed** — this pass converts "we haven't found a
path" into "there is no path in the shipping driver." A complete, correct reverse cannot yield an
un-own primitive the driver itself does not possess (the ownership decision is firmware). The
remaining routes are unchanged and all heavy:
1. **Fresh-Windows t=0 "add-this-machine" capture** (Frida CNG plaintext) — the only way to learn the
   `0x0e`/`0x4f`/`0x10` argument bytes, IF Windows ever emits them (it doesn't at steady state; may on
   a truly first provisioning). Needs the dongle back on Windows.
2. **Sensor firmware RE** (FW 10.1) — the only thing that could reveal a host-triggerable un-own if one
   exists; firmware likely signed/encrypted, may need hardware glitching. Weeks.
3. **Factory-fresh 2nd unit paired FIRST from Linux** (findings/32) — sidesteps ownership; ~$50;
   decisive GO for the driver, doesn't crack this unit.
Built-in Synaptics `06cb:0126` remains the working reader.

## Empirical confirmation (2026-07-09) — the `0x14` session-init lead is closed
The decrypted Windows captures showed one command our Linux client had never sent: `0x14`
SESSION_INIT (`1400000c` + a fresh 12-B nonce), the first wrapped command every from-boot Windows
session — a plausible "channel-arm" that could have gated everything else. Tested live
(`p2_moc.py sessioninit`): `0x14` **itself returns `0x0401`** on Linux (Windows-verbatim bytes,
fresh nonce, and zero nonce all identical), and it did **not** lift `0x50`/`0x99 01`/`0x96 01`
(all still `0x0401`/`0x0405`). ⇒ `0x14` is not an arm; it is another member of the **`0x04xx`
host-authorization family** (`0x14`/`0x50`/`0x96`/`0x99`). Windows' `0x14` succeeds (16-B nonce-echo)
only because it is already authorized. This closes the last "did you send everything Windows sends"
thread: **no host-sendable command lifts the gate.** Full command inventory + responses (both hosts)
preserved in `reference/protocol/command-reference.json`.

## Artifacts
`re/ghidra-out/gapfill-44/` (dumped `SessionStart`, `FUN_18001df30` vfmSecurityDoPair, `FUN_18001e2c0`
vfmSecurityUnPair, `FUN_180065270` status-map, `FUN_1800a3ef0` status-read, `FUN_180063fe0`
tudorCmdAlloc). Analysis corroborated across `OWNERSHIP-*`, `ADVANCED-PAIR-`, `HOST-PROVISION-`,
`PAIRING-DELTA-TRACE.md`. Corrects findings/30's "per-host partition" (it is shared; findings/43) and
its "NiseCore ownership transaction" framing (there is none at runtime; findings/39).
