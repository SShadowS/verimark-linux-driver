# findings/31 — Pivot to host-side matching: viability + frame-readout gap

**Date:** 2026-07-08. After MOC enroll was found to need a destructive ownership transaction
(findings/30), we pivoted P2→P3 to **host-side matching** (`rev`'s architecture: read raw
frames, match on host). This records what's proven and the one remaining protocol gap.

## Proven viable
- **`0x7f FRAME_READ` is NOT ownership-gated.** Cold it returns `0x0689` ("no frame yet"), not
  the `0x0405`/`0x0401` owner gate. `0x80 FRAME_ACQ`/`0x81 FRAME_FINISH` work. (`0x8b
  FRAME_STREAM` *is* gated `0x0401`, but host-side matching doesn't need it.) ⇒ raw frame
  readout needs only our existing TLS pairing — **no ownership, no risk to Windows.**
- **`libnative.so` is present & built** (`re/synaTudor-rev/pydrv/tudor/sensor/libnative/`), and
  our `product_id=0x41 (PROD_ID5)` is supported by `rev`'s `frame_to_image` converter.
- **Live-capture UX solved** (`prototype/p3_gui.py`): a Tk status window (run as the desktop
  user on `DISPLAY=:0`) polls `images/status.json` written by the root capture process and shows
  big colour-coded state (WAITING/READING/CAPTURED) + the latest PNG. Fixes the "can't see
  buffered prompts / miss the tap" problem. notify-send from root→user session also works
  (`sudo -u sshadows DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus …`).

## The gap: 132-family frame readout ≠ rev's 104 path
`prototype/p3_hostmatch.py` (`capture` + `diagread`) drives: wait finger-press → `FRAME_ACQ`
→ `FRAME_READ` → `FRAME_FINISH` → `frame_to_image`. Results:
- **MOC-mode `FRAME_ACQ` (arg=0x14)** signals frame-ready (event `0x18`) but `FRAME_READ`
  returns a 2-B error (frame is reserved for on-chip consumption).
- **Readout-mode `FRAME_ACQ` (arg=0, rev's `<BIIHxBBBBB>` format)** does NOT signal frame-ready;
  `FRAME_READ` stays `0x0689` for the whole hold; `diagread` saw only RELEASE events (`0x02`)
  after acquire. So readout-acquire isn't capturing a host-readable frame via this choreography.
- `rev`'s `capture_frames` waits on `get_event_data()[5]&0x7` (byte 5) — but this device's
  interrupt layout is `[type][…][seq]` with seq at **byte 6** (not 5), and `rev` targets the
  **104** driver; our device is **132**. The readout ACQ params / ready-signal / seq handling
  are 132-specific and not yet pinned.

## Next (offline, no swipes): RE the 132 frame-readout protocol
Compare `synaWudfBioUsb132.dll`'s `FRAME_ACQ 0x80` / `FRAME_READ 0x7f` / `FRAME_STREAM 0x8b`
builders (opcode-builders already dumped) + the readout state machine, vs `rev`'s 104 code, to
get: the exact readout `FRAME_ACQ` arg/flags, the frame-ready signal (interrupt vs `0x87`
event + which seq byte), and the `FRAME_READ` seq/flags loop (multi-frame, "last"/"finger
lifted" bits). Then update `p3_hostmatch.capture`. Also settle whether the sensor is a
**tap/area** or **swipe** part (affects how many frames + user motion).

## UPDATE — 132 readout fix applied; frame-ready fires but 0x7f still "no frame"
Applied `FRAME-READOUT-132-TRACE.md`: `FRAME_ACQ` mode-1 host readout
(`80 14000000 01000000 0100 00 08 00 01 00 00`), arm event `0x18`, `FRAME_READ` 10-B header,
seq loop. Live result (`diagread`, finger held firmly ~5 s):
- **frame-ready event `0x18` now fires** (via `0x87`, once) — the acquire/arm path is right.
- **but `FRAME_READ 0x7f` returns `0x0689` ("no frame") at seq 0..3 for the whole window** —
  no readable frame is produced.
- during the hold the `0x83` interrupts are **all type `0x02`** (finger-off / heartbeat),
  incrementing byte[6] (0x80,0x81…), never a sustained press. `0x87` event payload for the
  `0x18`: `…180080036d720248…`.
⇒ Either (a) the sensor needs finger **motion/swipe** (not a static hold) to build a frame,
or (b) an `FRAME_ACQ` param is still off — the agent flagged `arg1` `0x14`↔`0x0c`, `p4`
`1`↔`0`, and tap-vs-swipe as **live unknowns**. Next: parameter-sweep the ACQ (p4=0, arg1=0x0c)
and try a **swipe** gesture; if still `0x0689`, re-examine the `0x18` event payload for the read
key / a required post-acq step. Texts fixed (WAITING="PRESS & HOLD…", READING="KEEP HOLDING…").

## KEY REFRAME (2026-07-08, from a USB the user provided): Windows is MOC-ONLY on this device
- The enroll/verify plaintext log (`captures/win-cng-4868.log`) contains **zero `0x7f`
  FRAME_READ** commands. Windows drives `047d:00f2` with **on-chip MOC (`0x96`/`0x99`) only** and
  **never reads frames to the host**. ⇒ the `0x7f` host-readout path has **no Windows reference
  on this device**; it's a path `rev` uses for OTHER (non-MOC) Tudor sensors. This is the likely
  reason `0x7f` stays `0x0689`: host readout may be vestigial/unsupported on this MOC firmware.
- The user's USB also held the **newest official driver, `AtansMocFp v10.103.22621.143`
  (2026-01-13)** — but it's a **Realtek `RtsMocWbdi`** driver for **VeriMark IT/Desktop *2.0*
  (`047d:8226/8227/8228`)**, a *different, newer product*. **Not our `00f2`** (Synaptics). Saved
  (ref only) at `re/atansmoc-v2/` (git-ignored). The "2.0" line moved to Realtek MOC silicon.
- ⇒ Re-engaged the RE agent (findings task #7) to answer the **viability** question: is `0x7f`
  host readout achievable on this MOC-configured `00f2` at all, and if so the exact prerequisite —
  or is it a dead path (which would mean neither MOC-enroll nor host-readout is reachable
  non-destructively, and the honest verdict is "Linux driver blocked without taking ownership").

## Tooling added this phase
`prototype/p3_hostmatch.py` (`capture`/`diagread`, host-readout + native image + PNG writer +
status-file), `prototype/p3_gui.py` (live Tk status window). `prototype/images/` = PNG output.
