# findings/47 — CORRECTION: 0x04xx are BAD_PARAM/BAD_CMD, NOT ownership codes

> **⚠️ SUPERSEDED (2026-07-09, findings/49):** the enroll "ownership gate" (0x0405) was a 2-byte truncated command, not sensor-side ownership. See findings/49.

**Date:** 2026-07-09. A review pass (challenge-the-framing) overturned a load-bearing label the project
had carried since findings/30: that `0x0401`/`0x0404`/`0x0405` form a "host-not-authorized /
ownership" family. **They do not.** This finding records the correction and the cheap experiment it
implies. Corrects findings/30, findings/44 (mechanism), findings/45, and `command-reference.json`
(`gated_family_0x04xx`).

## What the codes actually decode to
From the driver's own status→name lookup (`re/ghidra-out/gapfill-44/FUN_180065270.c`) cross-referenced
with the VCS_RESULT string table in `synaWudfBioUsb132.dll` (strings @ file 0x136e10–0x137758):

| sensor status | seen on | internal | **VCS_RESULT name** |
|---|---|---|---|
| `0x0401` | `0x50` GET_CERT, `0x14` SESSION_INIT | 209 | **`VCS_RESULT_SENSOR_BAD_CMD`** |
| `0x0404` | `0x96 02` add-sample | 104 | **`VCS_RESULT_GEN_OPERATION_DENIED`** |
| `0x0405/6/7` | `0x96 01`, `0x99 01` | 111 | **`VCS_RESULT_GEN_BAD_PARAM`** |
| `0x0509` | Windows `0x99` dedup | 302 | `VCS_RESULT_MATCHER_MATCH_FAILED` |

**The firmware's dedicated ownership codes are `VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP` (207) and
`VCS_RESULT_SENSOR_NEED_TO_RESET_OWNER` (204) — and neither is ever emitted by the decode table on our
failures.** findings/44/45 built the "OTP-fuse ownership, irreversible" mechanism on the mere *presence*
of the `OUT_OF_OTP_OWNERSHIP` string in the binary; that is not the code we receive. Retract that
mechanism as unproven.

## Three recorded facts that contradict the ownership reading
1. **The verified owner keypair did NOT lift it (findings/43).** Linux presented Windows' real DPAPI
   owner EC keypair; the sensor cryptographically verified proof-of-possession (wrong-priv → TLS alert
   `ILLEGAL_PARAMETER`) → we authenticated *as the owner* → `0x96 01` still `0x0405`, `0x50` still
   `0x0401`. An identity/ownership gate opens for the verified owner. This didn't → **not identity-based.**
2. **`0x0405` is also returned for a wrong sub-arg on a working command (findings/29 l.83):** over the
   authorized Linux TLS session, `0x9f 02000000` → `0x0405` while `0x9f 01` → success. Pure
   `GEN_BAD_PARAM`, no ownership relevance.
3. **rev treats `0x405–0x407` as an argument-format signal** (`re/synaTudor-rev/pydrv/tudor/sensor/
   event.py:95`): on `EVENT_READ` it catches these and falls back to the legacy request layout — i.e.
   upstream semantics = "wrong parameters/format for this command," not "not the owner."

Also: the project lumped three *distinct* failure modes (`BAD_CMD` on 0x50/0x14; `BAD_PARAM` on
0x96/0x99; `OPERATION_DENIED` on 0x96 02) into one false "family," manufacturing a unity that made
"one ownership gate" look parsimonious. And `0x14 SESSION_INIT` is a red herring — the decrypted
Windows enroll capture (`captures/win-cng-4868.log`) contains **no `0x14`** (first wrapped cmd is
`0x19`), and Windows never sends `0x50` either.

## The better-supported framing
Windows' `0x99` reaches the **matcher** (`0x0509` MATCH_FAILED); Linux's byte-identical `0x99` is
rejected **earlier**, at parameter validation (`0x0405` BAD_PARAM). ⇒ Windows' session carries a
per-session **enroll state/mode** the sensor requires for MOC that a foreign host's identical commands
lack — and that state is demonstrably **not** the TLS host identity (owner key didn't help) and **not**
the host-partition content (writing pid-2 didn't help; findings/30/43). Most plausible carrier: the
**NiseCore engine handshake / `0x6c` PairingContext continuation**, established at driver-load, that
neither our steady-state capture nor `rev` reproduces. It is *effectively* an enroll precondition, but
it is enforced as generic state-validation, is not the firmware's ownership code, and does not track
the owner keypair — so "we don't own the sensor" is an over-specific, partly-refuted label.

## Cheapest untested experiment (free, local, non-destructive) — DO THIS
**Full guided enroll choreography while loaded with the OWNER pdata.** The untested cell:
- findings/43 tested owner identity + **cold** `0x96 01` (no frame choreography).
- findings/30 tested the **full** choreography (real finger → `0x86` arm → `0x80` FRAME_ACQ → `0x81`
  → `0x99` dedup → `0x96 01`) but as a **non-owner**.
- **Never run:** owner pdata + full choreography together.
Load owner pdata via `VERIMARK_PDATA`, run the real-finger enroll flow in `p2_moc.py`. If it still
`0x0405` → final nail (enroll state is neither identity nor choreography we can drive). If it changes →
the "need a fresh unit / it's locked" conclusion reopens. Either way it's decisive and costs nothing.

The heavier decisive artifact is unchanged in identity but changed in *purpose*: a fresh-Windows t=0
capture of **driver-load → first enroll** — now to find the **state/mode-entry sequence**, not to
"prove ownership."

## Artifacts
`re/ghidra-out/gapfill-44/FUN_180065270.c`, `re/synaTudor-rev/rev/proto.txt` (l.177–185),
`re/synaTudor-rev/pydrv/tudor/sensor/event.py:95`,
`re/synaTudor-rev/.../drivers/synaptics/bmkt.h` (VCS_RESULT names), `findings/43`, `findings/29` (l.83),
`findings/30`, `captures/win-cng-4868.log`, `reference/protocol/command-reference.json`.
