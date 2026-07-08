# findings/29 — MOC enroll/verify protocol (`0x96`/`0x99`) + DB2 reads

**Date:** 2026-07-08. The two opcodes no public RE mapped, cracked byte-for-byte from the
decrypted oracle `captures/win/win-cng-4868.log` (Windows: enroll 2 fingers → verify →
delete both), and the DB2 read path **verified live on Linux** over the P1 TLS session
(`prototype/p2_dbinfo.py`). Clean-room: observed behaviour only. Corrects the coverage
offset given in findings/23 (+21) and /25 (+20) — **it is +22**.

## Opcode sub-command dispatch (the key insight)
Both MOC opcodes are dispatched by the **first u32 argument**:

| cmd | bytes | meaning | resp |
|---|---|---|---|
| `0x99` begin-identify | `99 01000000 00000000 0000` (13 B) | start a MOC match run | `0x0509` (no-match/"proceed") **or** 177-B match record |
| `0x96` create-enroll | `96 01000000 00000000 0000` (13 B) | open enrollment context | 6 B `000000000000` |
| `0x96` add-sample | `96 02000000` (5 B) | feed the just-captured frame to on-chip enroll | 82-B progress record |
| `0x96` commit | `96 04000000` (5 B) | finalize + store template | 2 B `0000` |

The 8 trailing zero bytes of the 13-B forms are a context/subject field left zero by
Windows here (see "GUID/SID" below).

## Enroll state machine (per finger, verified byte-exact)
```
0x99 01…  begin-identify        -> 0x0509  (dedup check: not enrolled yet, proceed)
0x96 01…  create-enroll         -> 000000000000
repeat until coverage == 0x7f:
    [ capture cycle ]           frame acquisition, finger down (see below)
    0x96 02000000  add-sample   -> 82-B progress (coverage bitmask grows 01→7f)
0x9e 01   DB2_GET_DB_INFO       -> 40-B (store state; informational)
0x96 04000000  commit           -> 0000   (template now stored; GUID was minted)
```
7 accepted samples in this capture (coverage `01,03,07,0f,1f,3f,7f`). The **capture
cycle** between add-samples (byte-exact, tx11–21):
```
0x86 EVENT_CONFIG mask=06  -> arm finger events   (last resp byte = event seq)
0x87 EVENT_READ           -> event
0x86 EVENT_CONFIG mask=00 (trailer u32=4)
0x86 EVENT_CONFIG mask=04
0x87 EVENT_READ
0x86 mask=00 ; 0x86 mask=01(+u32=1)
0x80 FRAME_ACQ  = 80 0c000000 01000000 01000008 010101 00   (<BIIHxBBBBB>, arg=0x0c)
0x87 EVENT_READ
0x86 mask=00
0x81 FRAME_FINISH = 81
```
NB the MOC path **never issues `0x7f FRAME_READ`** — the image stays on-chip; only
`0x96 02` consumes it. (rev's `capture_frames()` DOES read `0x7f` because it does
host-side matching; for MOC we drop that step.) `FRAME_ACQ` arg differs run-to-run
(`0x14` first cycle, `0x0c` after) — likely a timeout/flags field, not yet pinned.

## `0x96` add-sample response (82 B)
```
+0   u16 status
+18  u16 = 003c        const (frame geometry?)
+22  u8  COVERAGE BITMASK   01→03→07→0f→1f→3f→7f  (7f = enroll complete)   ← verified
+24  u8  sample counter     0e,1c,2a,39,47,55,64  (~+14/sample)
+41  u8  per-sample quality  ~0x63 (≈99)
On the FINAL sample (coverage=7f): +4 carries the newly-minted 16-B template GUID
   (e.g. d90b407de01859f4fc18e18063b32d3b) — this is how the host learns the GUID.
```

## `0x99` identify response
- **enroll-time / no match:** 2-B status `0x0509`.
- **verify match:** 177-B record. Layout (findings/25, condensed):
  `+2 GUID[16]` (matched template) · header/metrics · `+66 GUID[16]` (repeat) ·
  `+98 Windows SID` (host-supplied subject) · tail `02 00 01 00 00 00 <crc>`.

## GUID / SID ownership (important for the Linux port)
The template GUID is **minted by the sensor** and returned in the final add-sample
response; the host does **not** supply it (grep of the whole enroll OUT stream: the GUID
only ever appears later, echoed back in the `0xa0` delete lookup). The Windows **SID** in
the verify record is host-supplied *subject* metadata — for libfprint we substitute our
own subject id (or leave zero); nothing is TPM-sealed. ⇒ enroll needs no host-generated
identifiers; the driver stores the sensor's GUID in `fpi_print` data and matches on it.

## DB2 read path — VERIFIED LIVE on Linux (p2_dbinfo.py, read-only, over P1 TLS)
- **`0x9e DB2_GET_DB_INFO`** `9e 01` → 40 B, status OK: version 1, store_size 528,
  **max_slots 100**, usage words `3 8 116 2 8 1 4 8 13`.
- **`0x9f DB2_GET_OBJ_LIST` — cracked here** (findings/25 had marked it "not UI-reachable,
  use rev format"): `9f 01` → `u16 status ‖ u16 count ‖ GUID[16]×count`. Live result:
  **count=3**, GUIDs `65c289d968742a80fc3279e588a7c1c7`,
  `81593c868558494266992596f27cdd58`, `005f70dc9c8f663bddfa308909819bbb` (current
  Windows-side objects). `9f 02000000` → error `0x0405` (wrong subtype; `01` is the list).
- **`0xa0 DB2_GET_OBJ_INFO`** `a0 02000000 ‖ GUID[16]` → 52 B (findings/25).
- **`0xa3 DB2_DELETE_OBJ`** `a3 01000000 ‖ GUID[16]` → 4 B `0000 0300`.

## Delete flow (reversal / cleanup, verified)
Per template: `0xa0 02000000 ‖ parentGUID` → returns a **child** GUID; then
`0xa3 01000000 ‖ childGUID`. (In the capture, parent `34d05fda…` → child `f7ba25db…`.)
This is how a Linux-created enrollment gets rolled back.

## Open (needs the live device + finger swipes — P2b/P2c)
- Confirm the sensor accepts our enroll choreography (event/frame timing) and mints a
  GUID; nail `FRAME_ACQ`'s variable arg.
- Confirm a **failed** verify's no-match response (unenrolled finger) — expected `0x0509`.
- Decide `0x99`/`0x96` subject field: leave zero vs. embed a libfprint user id.
