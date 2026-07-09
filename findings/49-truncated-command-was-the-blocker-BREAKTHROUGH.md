# findings/49 — BREAKTHROUGH: the `0x0405` enroll "gate" was a 2-byte truncated command, not ownership

**Date:** 2026-07-09. Live on the Linux box, non-destructive (no sensor writes, no finger, no `0x93`).
A byte-diff of our MOC enroll commands against the known-good Windows successful-enroll capture found
that two of our command literals were **2 bytes short**. Fixing them makes the "ownership-gated"
`0x96 01` create-enroll return **status `0x0000`** — under BOTH a non-owner and an owner Linux
identity. This **overturns** the long-standing sensor-side-ownership / first-pairer-wins-TOFU /
OTP-fuse / "need a 2nd unit or a virgin-Windows capture" model for the enroll path (findings/36, 39,
42, 43, 44, 45, 47).

## The bug
`prototype/p2_moc.py` built the two enroll-transaction openers from hex string literals whose trailing
field was `"0000"` (2 bytes) where Windows sends `"00000000"` (4 bytes). The constants' own comments
already said **"13 B"** — this was an off-by-2 typo in the hex string, producing **11-byte** commands.

Byte-diff source: `captures/win-cng-early-20260708-222730.log`, lines **356** (`0x99 01`) and **384**
(`0x96 01`) — the decrypted Windows successful-enroll stream.

| constant | opcode | before (11 B, TRUNCATED) | after (13 B, matches Windows) |
|---|---|---|---|
| `C_BEGIN_ID` | `0x99 01` begin-identify / dedup | `9901000000` `0000` `0000` | `9901000000` `00000000` `00000000` = `99010000000000000000000000` |
| `C_ENR_CREATE` | `0x96 01` create-enroll | `9601000000` `0000` `0000` | `9601000000` `00000000` `00000000` = `96010000000000000000000000` |

**Fix:** trailing `"0000"` → `"00000000"` on both (`prototype/p2_moc.py` lines 37–38). They now
serialize byte-identical to the Windows wire.

## The retest (decisive)
Non-destructive `ownertest` mode: TLS established, then a **cold** `0x96 01` create-enroll — no finger,
no `0x96 02` sample loop, no `0x96 04` commit, no `0x93` write. Run under two identities:

| identity | pdata | `0x96 01` result | log |
|---|---|---|---|
| **NON-OWNER** (default Linux) | `prototype/pdata/f7007ad929c60000.pdata` | `status=0x0000` (`raw=000000000000`) | `scratchpad/fixcmd-nonowner.log` |
| **OWNER** (DPAPI-extracted) | `prototype/pdata/…ownerpair.pdata` | `status=0x0000` (`raw=000000000000`) | `scratchpad/fixcmd-owner.log` |

Verbatim from both runs: `0x96 01 create-enroll -> status=0x0000 ... raw=000000000000`.

## Interpretation
`0x0405` = `VCS_RESULT_GEN_BAD_PARAM` (per findings/47) was triggered by the **malformed, 2-byte-short
command**, not by an ownership/authorization check. The **non-owner** identity returning `0x0000` is
the load-bearing evidence: a genuine sensor-side ownership gate would reject a non-owner regardless of
command length. It did not. The transaction opens for both identities once the command is well-formed.

This is consistent with — and now empirically confirms — the findings/47 reframing that `0x04xx` are
generic `BAD_CMD`/`BAD_PARAM`, not the firmware's OTP-ownership codes (`OUT_OF_OTP_OWNERSHIP`=207 /
`NEED_TO_RESET_OWNER`=204, which never fired on our wire).

## Scope / limits (do not overclaim)
- **Proven:** a cold `0x96 01` create-enroll returns `0x0000` (transaction opens) for **owner AND
  non-owner** pdata. The `0x99 01` dedup opener was truncated the same way and is now fixed, but was
  **not** separately re-tested in isolation.
- **NOT yet proven end-to-end:** a **full** enroll — `0x99 01` dedup → `0x96 01` create → `0x96 02`
  sample loop to coverage `0x7f` → `0x96 04` commit → committed template, then `0x99` verify matching.
  That requires the user physically tapping the sensor. It is the immediate next step and is expected
  to work now that the transaction opens.
- **Out of scope:** `0x50` GET_CERT (`0x0401`) and `0x14` SESSION_INIT (`0x0401`) are **separate**
  commands, built inline at correct length, and are **not on the enroll critical path** (Windows' enroll
  does not require `0x50`; enroll uses `0x99`/`0x96`). The truncation does **not** explain those — they
  remain as scoped in findings/47 (`SENSOR_BAD_CMD`, likely command-framing/unsupported, not needed for
  enroll).

## Consequences
- **The MOC enroll gate is solved from Linux.** The blocker on the enroll path was a client-side
  command-serialization typo, fixed entirely in our own code.
- **The driver project is GO for enroll.** No hardware acquisition, no owner-key theft, no virgin
  capture is needed to open the enroll transaction.
- **Moot for enroll:** the fresh-2nd-unit path (findings/32), the owner-key impersonation route
  (findings/42/43), and the virgin-Windows t=0 capture (`RUNBOOK-VIRGIN-CAPTURE.md`) are no longer the
  critical path. Keep the runbook only as a contingency if the full guided enroll+verify unexpectedly
  fails.
- **Overturned for the enroll path:** the sensor-side-ownership / first-pairer-wins-TOFU / OTP-fuse /
  irreversible model — findings/36 (reset-ownership attempt), 39 (ownership opcodes), 42/43 (owner-key
  extraction/impersonation), 44 (NiseCore "CLOSED, no host-side path exists"), 45 (prior-art "none
  exists"). findings/47's "generic BAD_PARAM, not ownership" reframing is now confirmed empirically,
  not just by review-swarm argument.
- **Next steps:** (1) run the **full guided enroll** with the user tapping — `0x99` dedup → `0x96 01`
  create → `0x96 02` sample loop to coverage `0x7f` → `0x96 04` commit — then `0x99` **verify** the
  committed template; (2) on success, **port** the enroll/verify choreography to the C libfprint driver
  (`driver/verimark.c`).

## Artifacts
`prototype/p2_moc.py` (fix at lines 37–38; `ownertest` mode), `captures/win-cng-early-20260708-222730.log`
(byte-diff source, lines 356/384), `scratchpad/fixcmd-nonowner.log`, `scratchpad/fixcmd-owner.log`,
`prototype/pdata/f7007ad929c60000.pdata` (non-owner), `prototype/pdata/…ownerpair.pdata` (owner),
findings/47 (status-code decode), findings/29 (MOC choreography).
