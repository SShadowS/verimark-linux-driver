# findings/51 — MOC enroll + verify WORKING end-to-end from Linux

**Date:** 2026-07-10. Live on-device (Kensington VeriMark `047d:00f2`), from the clean-room
`rev`-based prototype. **Status: the project goal is DONE for the prototype — a finger enrolls
and then verifies (matches) on-chip, entirely from Linux, no Windows in the loop.**

> Numbering note: this doc is the "findings/50 MOC-working" milestone from the task brief; the
> number **51** is used because `50-ghidra-pass-scope.md` (a 2026-07-07 scoping doc) already
> occupies 50. All cross-refs elsewhere to "findings/50 (enroll+verify)" mean this file.

This completes what findings/49 unblocked (the truncated-command fix that opened the `0x96 01`
transaction) and closes the enroll/verify path that findings/38 decoded and flagged as still-untested
end-to-end. See findings/29 (MOC choreography decode), findings/38 (enroll subprotocol + the finalize
gap it noted), findings/49 (truncated-command breakthrough).

## What works now (on-device evidence)
One guided run on the physical sensor, all TLS-wrapped over the P1 session:

- **Enroll** — `0x99 01` dedup → `0x96 01` create → event-gated frame capture + `0x96 02` add-sample
  loop, **coverage climbed `0x01` → `0x7f` across 7 accepted samples, per-sample quality 92–99**,
  sensor minted a template-id at coverage-complete → `0x96 03` **finalize OK** → `0x96 04` **commit
  OK**. The `0x9f` DB object-list grew by one slot.
- **Verify** — `0x99` identify against the just-enrolled finger returned **status `0x0000`** (match)
  on the **first attempt**, and the returned template-id **equalled the minted id** from the enroll
  (mint == verify — internally consistent).

That is a full match-on-chip enroll+verify cycle driven from the Linux prototype.

## The three bugs found & fixed this session (all in `prototype/p2_moc.py`)

### 1. Truncated command (already recorded — findings/49)
`C_BEGIN_ID` (`0x99 01`) and `C_ENR_CREATE` (`0x96 01`) built **11-byte** commands where Windows
sends **13** (trailing hex `"0000"` → `"00000000"`). This produced `0x0405` (`GEN_BAD_PARAM`),
misread for weeks as an "ownership gate." Fixed → `0x96 01` returns `0x0000` even for a non-owner
Linux host. Full detail in **findings/49**; it is the precondition for everything below.

### 2. Frame-capture was not event-gated → empty frames (`0x050b`)
Enroll/verify used a blind capture (`FRAME_ACQ` → `sleep 50 ms` → `FRAME_FINISH`) that never waited
for the sensor to report a frame ready. Every frame came back empty, so `0x99` / `0x96 02` returned
**`0x050b`** (no usable frame) and coverage never left `0x00`.

**Fix — `moc_capture()` + new `wait_intr_event()` helper.** The correct model on this device:
- The **finger PRESS edge** is delivered on the **INTERRUPT endpoint (`0x83`)** — the `0x87`
  `EVENT_READ` poll does **not** surface the press edge on `047d:00f2`.
- The **frame-ready event (type `0x18`)** is delivered via `0x87` `EVENT_READ` (Windows' channel).
- So the sequence is: arm press mask → wait PRESS (`0x01`) on the interrupt EP → arm frame mask →
  `FRAME_ACQ` → wait frame-ready (`0x18`) via `EVENT_READ` → `FRAME_FINISH`, leaving a valid frame
  on-chip for the next MOC step. `mode_verify` retries the capture up to 8×.
- **Presentation:** this is a touch/area sensor — the user must **press-and-hold (~2 s), tap not
  swipe**.

### 3. Missing `0x96 03` ENROLL_FINALIZE + two parse-offset bugs
Enroll jumped from the add-sample loop straight to `0x96 04` commit, **skipping the 124-byte
`0x96 03` finalize that Windows always sends**. Result: the template was stored but **unbound** →
verify returned `0x0509` (no-match) for **every** finger, including the one just enrolled.

**Fix — `build_finalize()` / `WIN_FINALIZE`.** We send `0x96 03` before commit, built by splicing our
sensor-minted template-id into the verbatim Windows finalize command. Source: capture
`win-cng-early-20260708-222730.log` line **1798**. The 124-byte layout:

| bytes | field |
|---|---|
| `[0:19]` | header (`96 03` + fixed prefix from the capture) |
| `[19:35]` | **template-id** — overwritten with our minted id (the final add-sample `resp[2:18]`) |
| `[35:49]` | fixed tail bytes (verbatim) |
| `[49:77]` | **Windows-capture user SID** — opaque match-label (see open items) |
| `[77:124]` | fixed tail bytes (verbatim) |

`build_finalize(id)` = `WIN_FINALIZE[:19] + id + WIN_FINALIZE[35:]`.

Two response-offset corrections (diagnosed by byte-diffing our responses against the Windows success
capture `222730`):
- **add-sample quality** read at offset **41 → 42** (offset 41 is a pad byte, which is why quality
  had been reported as a bogus `0`).
- **minted template-id / GUID** read at **`[4:20]` → `[2:18]`** (the correct 16-byte field).

## Frame-capture event model (summary)
```
PRESS   = interrupt EP 0x83, event 0x01   (NOT visible on 0x87 EVENT_READ here)
FRAME   = 0x87 EVENT_READ, event type 0x18 (frame-ready)
capture: arm[press] -> wait 0x01 on 0x83 ; arm[frame] -> FRAME_ACQ -> wait 0x18 on 0x87 -> FRAME_FINISH
```

## Open / minor items
- **SID in `WIN_FINALIZE[49:77]` must be genericized before sharing.** It is the Windows-capture
  machine's user SID (opaque match-label per RE; matching worked with it verbatim). It is
  machine-identifying → **redact/genericize before committing `p2_moc.py` to any shared repo.**
  **Untested:** whether a zero/generic SID also matches — worth checking (may let us drop the
  captured SID entirely).
- **Minted id vs `0x9f` list id mismatch (cosmetic).** The mint/verify template-id (e.g. `abac73…`)
  differs from the GUID the `0x9f` DB object-list reports for that slot (e.g. `adf2dd…`). Internally
  consistent (mint == verify), so matching is unaffected; the `0x9f` list may report a
  derived/hashed id. Noted for later.
- **Test DB cruft.** ~8 templates have accumulated from iterative test enrolls; clean via
  `p2_moc.py delete <guid>`.

## Next step
Port the fixed command path to the **C libfprint driver** (`driver/verimark.c`):
- the **13-byte** `0x96 01` / `0x99` command literals,
- the `moc_capture` **event-gated frame capture** (press via the interrupt EP `0x83`, frame-ready via
  `0x87` `EVENT_READ` type `0x18`),
- the `0x96 03` **finalize** (with the template-id splice; SID genericized),
- the corrected response offsets (quality `42`, minted-id `[2:18]`).

## Artifacts
`prototype/p2_moc.py` (`moc_capture`, `wait_intr_event`, `build_finalize`/`WIN_FINALIZE`,
`mode_enroll`, `mode_verify`; the corrected offsets), capture
`captures/win-cng-early-20260708-222730.log` line 1798 (finalize source) and the `222730` stream
(byte-diff reference), findings/49 (truncated-command fix), findings/38 (enroll decode + flagged
finalize gap), findings/29 (MOC choreography).
