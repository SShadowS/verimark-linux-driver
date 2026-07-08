# findings/39 — Ownership opcodes: static RE verdict + reframe of the P2 blocker

**Date:** 2026-07-08. Read-only static RE of the shipping Windows driver on the RE box
(capstone 5.0.7 + pefile over `synaWudfBioUsb132.dll`), cross-checked against the live captures
(findings/38, the machine-1 return-leg capture `win-cng-early-20260708-222730.log`).
**This corrects findings/30's "NiseCore ownership transaction" hypothesis.**

## Headline
**The shipping WBF driver contains NO command builder for `0x4f` TAKE_OWNERSHIP_EX2 or `0x10`
RESET_OWNERSHIP. It never sends them at runtime.** It knows their opcode *names* (for the "CMD SEND"
debug log) and can parse their responses, but never *constructs* the commands. Ownership on this
sensor was established **once by an OEM/factory provisioning utility (or firmware) that is not part
of this driver package.** The runtime driver only ever issues **PAIR (`0x93`)** + the STORAGE and
operational command set.

## How this was determined (authoritative)
- **NiseCore is in-process** inside `synaWudfBioUsb132.dll` (the `synaLib`/`tudor*` layer, statically
  linked) — NOT a separate engine. Image base `0x180000000` = Ghidra's, so findings addresses are
  directly usable here.
- Opcode→name map decoded from the driver's own logger switch (`sub_1800640b0`, jump table
  @`0x180065128`, index = opcode-1) — matches every live-captured opcode. `0x0e`/`0x10`/`0x4f`/`0x50`
  are all real names.
- Every wire command is built via one of three `tudorCmdAlloc(u16 opcode,u32 len)` instances
  (`0x180063fe0` sensor, `0x1800874b0` DB2, `0x18007da40` MOC) → filled → `tudorTransceive`
  (`0x180063bb0`). Enumerating all allocator callers + scanning `.text` for every `mov cx,imm16`
  opcode load found **no builder** for `0x4f`, `0x10`, or a standalone `0x50`.

## Per-opcode result
| opcode | name | finding |
|---|---|---|
| `0x93` | PAIR | **Builder recovered** (`0x180069dc0`): `93 ‖ host_pairing_data[400]` = 401 B (padded to 408 on the wire), resp maxlen `0x322`=802. THE one-time provisioning command the driver sends. Payload starts with `3f5f` cert magic. Captured live on the wire (machine 1 return leg). |
| `0x0e` | PROVISION | **Builder recovered** (`0x18005f800`): `0e ‖ u32(arg)` = 5 B, resp 2 B. **But zero callers — compiled in, unwired in this build.** Never fires. |
| `0x4f` | TAKE_OWNERSHIP_EX2 | **No builder.** Appears once, only as a WPP trace value in `InitAndGetState`. Not recoverable from any shipping binary. |
| `0x10` | RESET_OWNERSHIP | **No builder.** `OnResetOwnership` (`0x180012e74`) gates on `[this+0x4f1]` then delegates to `DoUnpairing` (`0x1800036cc`), which does not emit `0x10`. |
| `0x50` | GET_CERTIFICATE_EX | **Never sent as a command.** `_tudorSecurityGetCertificate` (`0x18006b570`) returns a *cached* 400-B cert populated by the PAIR/TLS handshake. |
| `0x6c` | (was "PairingContext") | **Not a wire opcode.** It's a `vfmSetParamBlob` paramId (matcher/engine API selector), per findings/20/21. Nothing to byte-map. |

Command-build structs (for byte-mapping any command that *is* built here): `cmdDesc = {u32 len; u32
pad; void* buf}`, `respDesc = {u32 maxlen; u32 pad; void* buf}`.
Scratchpad has working DLL copies + the capstone/pefile scripts (`reh.py`, `allocallers.py`,
`cxscan.py`, …) for re-running against any future binary (e.g. the OEM tool).

## Reframe of the P2 blocker (this is the important part)
Because the driver never sends `0x4f`/`0x10`, and a **truly first-time foreign host (machine 2)
enrolled successfully** using only the shipping driver (see CROSS-MACHINE doc), authorization is
**not** a special ownership command. It is carried by:
1. the **`0x93` PAIR payload content** (the 400-byte host blob), and/or
2. the **first-time host-PARTITION provisioning** — `0x3f` STORAGE_PART_FORMAT + `0x41`
   STORAGE_PART_WRITE with the correct (Windows/TagVal) content. A pre-provisioned host (machine 1)
   **skips** these — confirmed: machine 1's return-leg capture shows no `0x3f`/`0x41`.

This matches findings/30's H2 (authorization lives in pairing/partition, not a runtime take), and
findings/30's earlier `provision` attempt failed only because it wrote **rev's** blob, not Windows'
content.

**Consequences:**
- The Linux `0x0405` gate is a **pairing/partition-CONTENT difference**, not a missing opcode.
- It is **reproducible** (host key is ephemeral/self-generated, no TPM/factory secret — findings/
  DECISION) and **non-destructive/additive** (machine 2 provisioned without dispossessing machine 1)
  — overturning the "ownership is destructive" conclusion in findings/30/34.

## Next (what actually unblocks Linux)
- **Cheap, no hardware:** diff the captured Windows `0x93` 400-byte payload (have it) against `rev`'s
  `0x93` host_cert (`prototype/p1_pair.py`, findings/28). A structural difference (e.g. cert_type,
  TagVal wrapper) may be the whole fix.
- **Fresh-host capture (reframed target):** a machine that never enrolled this sensor, rig-first,
  first-ever enroll — to capture the first-time `0x3f`/`0x41` host-partition writes with correct
  content (the "TagVal container" findings/30 needed). NOT `0x4f`/`0x10` (they don't exist at
  runtime). See CROSS-MACHINE-OWNERSHIP-CAPTURE.md.
