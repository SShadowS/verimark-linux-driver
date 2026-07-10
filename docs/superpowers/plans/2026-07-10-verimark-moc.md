# VeriMark MOC Operations Layer Implementation Plan (P3–P6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pure-helper tasks are offline-TDD (green now, no device). SSM/USB tasks are DEVICE-DEFERRED — implement cleanly, but their on-device verification steps are marked `[DEFERRED: device]`.

**Goal:** Build the match-on-chip (MOC) operations layer of the C libfprint VeriMark driver — the capture SSM (P3), enroll SSM (P4), verify/identify SSM (P5), and storage ops list/delete/clear (P6) — as a self-contained `driver/verimark-moc.{c,h}` module of `FpiSsm` state machines, plus the thin `FpDevice` vfunc glue in `verimark.c` that kicks each one off. The wire choreography is a 1:1 port of the proven Python prototype `prototype/p2_moc.py` (enroll+verify working end-to-end, findings/51). All the *pure* framing logic (command literals, response parsing, finalize/SID splicing) is factored into offline, GTest-unit-testable functions validated against the exact byte literals in `p2_moc.py`; the async SSM control-flow + USB/interrupt I/O is device-tested.

**Architecture:** `verimark-moc.c` owns MOC *choreography* only (SOLID: separate from the `FpDevice` GObject glue in `verimark.c`, from the TLS channel in `verimark-tls.c`, and from the EP0 transport in `verimark.c`). It sits ON TOP of two layers being implemented concurrently, whose intended APIs it consumes:

```
 verimark.c  FpDevice vfuncs (dev_enroll/verify/identify/list/delete/clear_storage)
      │  kick off an SSM from verimark-moc.c, own progress/complete callbacks
 ┌────▼──────────────────────────────────────────────────────────┐
 │ verimark-moc.c   ── THIS PLAN ──                               │
 │  • pure helpers: build 13-B literals, parse sample/verify/list │  (offline TDD)
 │  • capture SSM (P3, reused by enroll+verify — DRY)             │
 │  • enroll / verify-identify / list / delete / clear SSMs       │  (device-deferred)
 └────┬──────────────────────────────────────────────────────────┘
      │  verimark_cmd_async()  — wrap → EP0-write → EP0-read → unwrap
 ┌────▼───────────────────────┐   ┌──────────────────────────────┐
 │ verimark-tls.{c,h}         │   │ verimark.c EP0 transport      │
 │  wrap/unwrap (AES-256-GCM) │   │  async control 0x40/0x16 WR,  │
 │  (verimark-tls-crypto core │   │  0xc0/0x17 RD; intr-IN 0x83   │
 │   already impl+tested)     │   │                               │
 └────────────────────────────┘   └──────────────────────────────┘
```

Every MOC command, once TLS is up, is sent **wrapped** (`verimark_tls_wrap` → EP0 write; EP0 read → `verimark_tls_unwrap`). The MOC layer never touches raw crypto or raw USB directly — it calls the intended `verimark_cmd_async()` combinator (transport + TLS, provided by `verimark.c`) and an interrupt-event waiter `verimark_intr_wait_async()`. Those two combinators are being written in the transport/TLS plans; where this plan depends on their exact signature, the task's first step is an extraction/confirmation against the landed code.

**Tech Stack:** C11, GLib-2.0 (GObject, `FpiSsm`, GVariant, GTest), libfprint (`fpi-device.h`, `fpi-ssm.h`, `fpi-print.h`, `fpi-usb-transfer.h`), meson/ninja. Pure-helper tests reuse the standalone `driver/tests/` meson project from the TLS-core plan. Ground-truth oracle: `prototype/p2_moc.py`; libfprint MOC shape reference: `re/synaTudor-rev/libfprint/libfprint/libfprint/drivers/goodixmoc/goodix.c`.

## Global Constraints

- **13-byte MOC command literals are mandatory (findings/49).** `0x99 01` begin-identify/dedup and `0x96 01` create-enroll MUST serialize to exactly 13 bytes (`96 01 000000 00000000 00000000`). An 11-byte (2-short) command returns `0x0405` `BAD_PARAM` and was the entire historic "ownership gate". The builders below encode the full 13 bytes; a unit test asserts length == 13 and byte-equality with the `p2_moc.py` literal.
- **Capture requires the `0x18` frame-ready gate (findings/51).** A frame is only usable after event type `0x18` is observed; feeding `0x96 02`/`0x99` before that yields `0x050b`/no-usable-frame.
- **Interrupt/event split on 047d:00f2 (p2_moc.py::moc_capture).** Finger PRESS (`0x01`) arrives on **interrupt EP `0x83`**; frame-ready (`0x18`) arrives via the **`0x87 EVENT_READ`** poll (NOT the interrupt EP). Arm the event mask with `0x86 EVENT_CONFIG`: `[1,2]` (mask `0x06`) for press/release, `[24]` (mask `0x01000000`) for frame-ready.
- **Touch/area sensor = press-and-hold, not swipe.** Finger must stay DOWN through `FRAME_ACQ` for the scan to integrate. Enroll is guided taps (~7 accepted samples); libfprint stage count is `VERIMARK_ENROLL_STAGES` (8, `verimark.h`).
- **Coverage completion at `0x7f`.** Enroll add-sample loop runs until `resp[22] == 0x7f`; the sensor mints the template id at completion (`resp[2:18]`). The host supplies no id.
- **Response status is u16 LE at `resp[0:2]`.** `0x0000` ok; `0x0509` verify/identify no-match; `0x0405`/`0x0401` = generic BAD_PARAM/BAD_CMD (findings/47/49); `0x050b` no usable frame.
- **Corrected offsets (findings/51):** add-sample coverage `resp[22]`, counter `resp[24]`, quality `resp[42]` (NOT 41 — 41 is a pad byte); minted id `resp[2:18]` (NOT `[4:20]`).
- **Every MOC command is TLS-wrapped** once the session is up — the MOC layer emits plaintext command bytes to `verimark_cmd_async()`, which wraps/unwraps transparently.
- Pure helpers: no GLib main loop, no USB, no device — deterministic byte-in/byte-out, unit-tested offline. SSM control-flow + I/O: device-tested (deferred), plus a mock-transport SSM smoke test.
- One commit per task; each pure-helper task ends with a green `meson test`.

---

## File structure

| File | Responsibility |
|---|---|
| `driver/verimark-moc.h` | Public API: the pure framing helpers (builders + parsers + SID synth) and the SSM entry points (`verimark_moc_enroll/verify/list/delete/clear`, `verimark_moc_capture_ssm_new`) that the `verimark.c` vfuncs call. |
| `driver/verimark-moc.c` | Implementation: pure helpers + the five `FpiSsm` state machines (capture reused by enroll+verify — DRY). Consumes `verimark_cmd_async`/`verimark_intr_wait_async` (transport+TLS combinators from `verimark.c`). |
| `driver/verimark.c` | (Modified) the thin `FpDevice` vfunc glue: `dev_enroll`/`dev_verify`/`dev_identify`/`dev_list`/`dev_delete`/`dev_clear_storage` each build+start the matching MOC SSM and own the libfprint completion/report callbacks + `FpPrint`↔id mapping. |
| `driver/tests/test_moc.c` | GLib-GTest runner for the pure helpers, asserting against the `p2_moc.py` byte literals (added to the standalone `driver/tests/` meson project). |
| `driver/tests/mock_transport.c` (+ `.h`) | A synchronous stub of `verimark_cmd_async`/`verimark_intr_wait_async` that replays scripted responses, for an offline SSM smoke test (mirrors the TLS-core plan's mock approach). |

Naming note: `verimark-moc.h` is a NEW module. The opcode `#define`s (`VERIMARK_CMD_*`) already live in `verimark.h` (read them there — this plan does not redefine them). `verimark-moc.c` includes both `verimark.h` (opcodes, `FpiDeviceVerimark`) and `verimark-tls.h` (wrap/unwrap, consumed indirectly via `verimark_cmd_async`).

### `verimark-moc.h` public API (authoritative signatures)

```c
/*
 * verimark-moc.h — Match-on-chip (MOC) operations layer for the VeriMark driver.
 * Port of prototype/p2_moc.py (findings/49, findings/51). SOLID: choreography only.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#pragma once
#include "fpi-device.h"
#include "fpi-ssm.h"
#include <glib.h>
#include <sys/types.h>   /* uid_t */

/* ---- Pure framing helpers (unit-tested offline against p2_moc.py literals) ---- */

/* FRAME_ACQ acquisition kind (p2_moc.py C_FRAME_ACQ / C_FRAME_ACQ14). */
#define VERIMARK_ACQ_ENROLL  0x0c   /* enroll add-sample frames  */
#define VERIMARK_ACQ_VERIFY  0x14   /* dedup + verify/identify frames */

/* Command-literal builders. Each writes the exact wire bytes and returns the
 * length. The 13-byte length of begin-id / enroll-create is load-bearing
 * (findings/49) — do not shorten. */
gsize verimark_moc_build_begin_id      (guint8 out[13]);   /* 0x99 01 (13 B) */
gsize verimark_moc_build_enroll_create (guint8 out[13]);   /* 0x96 01 (13 B) */
gsize verimark_moc_build_enroll_sample (guint8 out[5]);    /* 0x96 02 (5 B)  */
gsize verimark_moc_build_enroll_commit (guint8 out[5]);    /* 0x96 04 (5 B)  */
gsize verimark_moc_build_frame_acq     (guint8 out[17], guint8 acq_kind); /* 0x80 (17 B) */
gsize verimark_moc_build_frame_finish  (guint8 out[1]);    /* 0x81 (1 B)     */

/* 0x96 03 finalize (124 B): splice template_id into [19:35] and sid (28 B) into
 * [49:77] of the WIN_FINALIZE template. Returns FALSE on bad args. */
gboolean verimark_moc_build_finalize (const guint8 template_id[16],
                                      const guint8 sid[28],
                                      guint8 out[124], GError **error);

/* Synthesize the 28-byte binary SID (S-1-5-21-a-b-c-rid) for the local user.
 * a/b/c derived from a stable per-install seed (machine-id); rid from uid.
 * See §5 open question — the scheme is provisional until on-device confirmed. */
gboolean verimark_moc_synth_sid (uid_t uid, const guint8 machine_seed[16],
                                 guint8 out[28], GError **error);

/* Parse an add-sample (0x96 02) response. */
typedef struct {
  guint16 status;               /* resp[0:2] LE */
  guint8  template_id[16];      /* resp[2:18]   (valid once coverage==0x7f) */
  guint8  coverage;             /* resp[22]     */
  guint8  counter;              /* resp[24]     */
  guint8  quality;              /* resp[42]     */
} VerimarkMocSample;
gboolean verimark_moc_parse_sample (const guint8 *resp, gsize len,
                                    VerimarkMocSample *out, GError **error);

/* Parse a verify/identify (0x99 01) 177-byte record. */
typedef struct {
  guint16  status;              /* resp[0:2] — 0x0000 match, 0x0509 no-match */
  gboolean matched;
  guint8   template_id[16];     /* resp[2:18] when matched */
} VerimarkMocMatch;
gboolean verimark_moc_parse_verify (const guint8 *resp, gsize len,
                                    VerimarkMocMatch *out, GError **error);

/* Parse a 0x9f DB2_GET_OBJ_LIST response: status‖count(u16 LE)‖GUID[16]×count.
 * *out_ids = g_array of 16-byte GUIDs (element size 16); caller g_array_unref. */
gboolean verimark_moc_parse_obj_list (const guint8 *resp, gsize len,
                                      guint16 *status, GArray **out_ids,
                                      GError **error);

/* Parse a 0xa0 DB2_GET_OBJ_INFO response → child/leaf id at resp[20:36]. */
gboolean verimark_moc_parse_obj_info (const guint8 *resp, gsize len,
                                      guint8 child_id[16], GError **error);

/* ---- SSM entry points (device-tested; called by verimark.c vfuncs) ---- */

/* Capture SSM shared by enroll (acq=0x0c) and verify/identify (acq=0x14) — DRY.
 * On success leaves a valid frame on-chip for the next MOC step to consume.
 * The parent SSM jumps to this as a sub-SSM (fpi_ssm_start_subsm). */
FpiSsm *verimark_moc_capture_ssm_new (FpDevice *dev, guint8 acq_kind);

/* Operation entry points: build the task SSM and start it. Each reports/completes
 * via the libfprint fpi_device_* callbacks from within verimark-moc.c. */
void verimark_moc_enroll (FpDevice *dev);   /* 0x99 dedup→0x96 01→sample loop→0x96 03→0x96 04 */
void verimark_moc_verify (FpDevice *dev);   /* capture→0x99 01; verify + identify share this */
void verimark_moc_list   (FpDevice *dev);   /* 0x9f */
void verimark_moc_delete (FpDevice *dev);   /* 0xa0 lookup child → 0xa3 delete */
void verimark_moc_clear  (FpDevice *dev);   /* 0xa5 DB2_FORMAT */
```

Intended transport combinator (provided by `verimark.c`; the MOC SSMs consume it — confirm the exact signature when it lands, see Task 6 Step 1):

```c
/* async: wrap(cmd) → EP0 WRITE → EP0 READ → unwrap → cb(dev, resp, resp_len, error).
 * The MOC SSM stores its FpiSsm in FpiDeviceVerimark.task_ssm and resumes via
 * fpi_ssm_next_state()/fpi_ssm_mark_failed() from cb. */
typedef void (*VerimarkCmdCb) (FpDevice *dev, const guint8 *resp, gsize resp_len,
                               GError *error, gpointer user_data);
void verimark_cmd_async (FpDevice *dev, const guint8 *cmd, gsize cmd_len,
                         gsize resp_hint, VerimarkCmdCb cb, gpointer user_data);

/* async: arm intr-IN on 0x83, resolve when byte[0]==want_type or timeout. */
typedef void (*VerimarkIntrCb) (FpDevice *dev, gboolean got, guint8 seq,
                                GError *error, gpointer user_data);
void verimark_intr_wait_async (FpDevice *dev, guint8 want_type, guint timeout_ms,
                               VerimarkIntrCb cb, gpointer user_data);
```

---

## Task 1: Command-literal builders (P3/P4 framing) — OFFLINE TDD

**Files:**
- Create: `driver/verimark-moc.h` (paste the full API block above).
- Create: `driver/verimark-moc.c` (builders only for now).
- Create: `driver/tests/test_moc.c`.
- Modify: `driver/tests/meson.build` (add a `test_moc` executable + `moc_framing` test).

**Interfaces:** Produces the six `verimark_moc_build_*` functions. Golden bytes are the literals in `prototype/p2_moc.py` lines 37–42, 289.

- [ ] **Step 1: Extract the exact literals from `prototype/p2_moc.py:37-42,289`** and record them as the test's expected vectors:
  - `C_BEGIN_ID`   (l.37) = `99 01 00000000 00000000 00000000` → **13 B** `99010000000000000000000000`
  - `C_ENR_CREATE` (l.38) = **13 B** `96010000000000000000000000`
  - `C_ENR_SAMPLE` (l.39) = **5 B** `9602000000`
  - `C_ENR_COMMIT` (l.40) = **5 B** `9604000000`
  - `C_FRAME_ACQ`  (l.41) = **17 B** `800c000000010000000100000801010100` (arg `0x0c` at byte 1)
  - `C_FRAME_ACQ14`(l.289)= **17 B** `8014000000010000000100000801010100` (arg `0x14` at byte 1)
  - `C_FRAME_FIN`  (l.42) = **1 B** `81`

- [ ] **Step 2: Write the failing test** — create `driver/tests/test_moc.c`:

```c
#include <glib.h>
#include <string.h>
#include "../verimark-moc.h"

static void hexchk (const guint8 *got, gsize got_len, const char *hex)
{
  gsize want_len = strlen (hex) / 2;
  g_assert_cmpuint (got_len, ==, want_len);
  for (gsize i = 0; i < want_len; i++)
    {
      guint b; sscanf (hex + 2 * i, "%02x", &b);
      g_assert_cmpuint (got[i], ==, b);
    }
}

static void test_build_begin_id (void)
{ guint8 b[13]; gsize n = verimark_moc_build_begin_id (b);
  g_assert_cmpuint (n, ==, 13);   /* findings/49: 13 B is load-bearing */
  hexchk (b, n, "99010000000000000000000000"); }

static void test_build_enroll_create (void)
{ guint8 b[13]; gsize n = verimark_moc_build_enroll_create (b);
  g_assert_cmpuint (n, ==, 13);
  hexchk (b, n, "96010000000000000000000000"); }

static void test_build_enroll_sample (void)
{ guint8 b[5]; hexchk (b, verimark_moc_build_enroll_sample (b), "9602000000"); }

static void test_build_enroll_commit (void)
{ guint8 b[5]; hexchk (b, verimark_moc_build_enroll_commit (b), "9604000000"); }

static void test_build_frame_acq_enroll (void)
{ guint8 b[17]; hexchk (b, verimark_moc_build_frame_acq (b, VERIMARK_ACQ_ENROLL),
                        "800c000000010000000100000801010100"); }

static void test_build_frame_acq_verify (void)
{ guint8 b[17]; hexchk (b, verimark_moc_build_frame_acq (b, VERIMARK_ACQ_VERIFY),
                        "8014000000010000000100000801010100"); }

static void test_build_frame_finish (void)
{ guint8 b[1]; hexchk (b, verimark_moc_build_frame_finish (b), "81"); }

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/verimark/moc/build/begin_id",      test_build_begin_id);
  g_test_add_func ("/verimark/moc/build/enroll_create", test_build_enroll_create);
  g_test_add_func ("/verimark/moc/build/enroll_sample", test_build_enroll_sample);
  g_test_add_func ("/verimark/moc/build/enroll_commit", test_build_enroll_commit);
  g_test_add_func ("/verimark/moc/build/acq_enroll",    test_build_frame_acq_enroll);
  g_test_add_func ("/verimark/moc/build/acq_verify",    test_build_frame_acq_verify);
  g_test_add_func ("/verimark/moc/build/frame_finish",  test_build_frame_finish);
  return g_test_run ();
}
```

- [ ] **Step 3: Add the test target to `driver/tests/meson.build`** (the module needs only glib for the pure helpers — no libfprint/USB):

```meson
moc_test = executable('test_moc',
  ['test_moc.c', '../verimark-moc.c'],
  dependencies : [glib_dep])
test('moc_framing', moc_test, args : ['-p', '/verimark/moc/build'])
```

> Note: `../verimark-moc.c` in the pure-helper tasks must **not** pull in `fpi-*.h`/USB at file scope, or the standalone (non-libfprint) test project won't link. Keep the SSM code (which needs libfprint) behind `#ifndef VERIMARK_MOC_PURE_ONLY`, OR split the SSMs into a separate `.c`. **Decision (Step 4):** guard the SSM/vfunc code with `#ifdef VERIMARK_MOC_HAVE_LIBFPRINT` and have `driver/tests/meson.build` compile the pure part only. Confirm this compiles standalone before proceeding.

- [ ] **Step 4: Run, expect link failure** — `meson test -C driver/tests/build moc_framing -v` → `undefined reference to 'verimark_moc_build_begin_id'`.

- [ ] **Step 5: Implement the builders** in `driver/verimark-moc.c`:

```c
/* verimark-moc.c — see verimark-moc.h. SPDX-License-Identifier: LGPL-2.1-or-later */
#include "verimark-moc.h"
#include <string.h>

/* p2_moc.py l.37-42,289 — literal wire bytes. */
gsize verimark_moc_build_begin_id (guint8 out[13])
{ static const guint8 v[13] = {0x99,0x01,0,0,0,0,0,0,0,0,0,0,0};
  memcpy (out, v, 13); return 13; }

gsize verimark_moc_build_enroll_create (guint8 out[13])
{ static const guint8 v[13] = {0x96,0x01,0,0,0,0,0,0,0,0,0,0,0};
  memcpy (out, v, 13); return 13; }

gsize verimark_moc_build_enroll_sample (guint8 out[5])
{ static const guint8 v[5] = {0x96,0x02,0,0,0}; memcpy (out, v, 5); return 5; }

gsize verimark_moc_build_enroll_commit (guint8 out[5])
{ static const guint8 v[5] = {0x96,0x04,0,0,0}; memcpy (out, v, 5); return 5; }

gsize verimark_moc_build_frame_acq (guint8 out[17], guint8 acq_kind)
{ /* 80 <kind> 000000 01000000 01000008 01010100 — kind at byte 1 */
  static const guint8 v[17] = {0x80,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
                               0x01,0x00,0x00,0x08,0x01,0x01,0x01,0x00};
  memcpy (out, v, 17); out[1] = acq_kind; return 17; }

gsize verimark_moc_build_frame_finish (guint8 out[1])
{ out[0] = 0x81; return 1; }
```

- [ ] **Step 6: Run, expect PASS** — all seven `/verimark/moc/build/*` `OK`; `moc_framing` `OK`.

- [ ] **Step 7: Commit** — `git commit -m "verimark-moc: MOC command-literal builders (13-B literals, findings/49)"`.

---

## Task 2: Response parsers — sample / verify / obj-list / obj-info — OFFLINE TDD

**Files:** Modify `driver/verimark-moc.{c,h}`, `driver/tests/test_moc.c`, `driver/tests/meson.build`.

**Interfaces:** Produces `verimark_moc_parse_sample/verify/obj_list/obj_info` + the `VerimarkMocSample`/`VerimarkMocMatch` structs. Golden offsets from `p2_moc.py` (`_run_enroll` l.204, `mode_verify` l.256-260, `_list` l.849-853, `mode_delete` l.865-866) and findings/51 (quality `42`, id `[2:18]`).

- [ ] **Step 1: Extract the offsets** and hand-build response vectors:
  - **sample** (`0x96 02`, `_run_enroll` l.204: `new_cov, counter, quality = resp[22], resp[24], resp[42]`; id `resp[2:18]` l.212): status `resp[0:2]` LE; build a 82-byte vector with status `0000`, a known 16-byte id at `[2:18]`, coverage `0x7f` at `[22]`, counter `0x05` at `[24]`, quality `0x63` at `[42]`.
  - **verify** (`0x99 01`, `mode_verify` l.256-260): 177-byte record; match = status `0x0000` + id `[2:18]`; no-match = status `0x0509`. Build both.
  - **obj_list** (`0x9f`, `_list` l.850-853): `st=u16(r,0)`, `count=u16(r,2)`, `GUID[i]=r[4+i*16:20+i*16]`. Build status `0000`, count `2`, two 16-byte GUIDs.
  - **obj_info** (`0xa0`, `mode_delete` l.866): `child = r[20:36]`. Build a 52-byte vector with a known child id at `[20:36]`.

- [ ] **Step 2: Write failing tests** in `driver/tests/test_moc.c` (new funcs + `main` registrations under `/verimark/moc/parse/*`; add a `moc_parse` meson `test(...)` with `-p /verimark/moc/parse`). Each builds a `guint8[]` with the bytes at the documented offsets and asserts the parsed struct fields (e.g. `s.coverage==0x7f`, `s.quality==0x63`, `memcmp(s.template_id, want, 16)==0`; `m.matched==TRUE`/status `0x0509`→`matched==FALSE`; `ids->len==2` and element bytes; `memcmp(child, want, 16)==0`). Include a **too-short buffer** negative case per parser (returns FALSE, sets `error`).

- [ ] **Step 3: Run, expect link failure.**

- [ ] **Step 4: Implement the parsers** in `driver/verimark-moc.c`:

```c
static inline guint16 rd_u16le (const guint8 *p) { return (guint16) p[0] | ((guint16) p[1] << 8); }

gboolean
verimark_moc_parse_sample (const guint8 *resp, gsize len, VerimarkMocSample *out, GError **error)
{
  if (len < 43) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "sample response too short"); return FALSE; }
  out->status = rd_u16le (resp);          /* [0:2]  */
  memcpy (out->template_id, resp + 2, 16); /* [2:18] */
  out->coverage = resp[22];               /* findings/51 */
  out->counter  = resp[24];
  out->quality  = resp[42];               /* findings/51: 42, not 41 (41 is pad) */
  return TRUE;
}

gboolean
verimark_moc_parse_verify (const guint8 *resp, gsize len, VerimarkMocMatch *out, GError **error)
{
  if (len < 2) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "verify response too short"); return FALSE; }
  out->status = rd_u16le (resp);
  if (out->status == 0x0000)
    {
      if (len < 18) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                        "match record missing id"); return FALSE; }
      out->matched = TRUE;
      memcpy (out->template_id, resp + 2, 16);
    }
  else { out->matched = FALSE; memset (out->template_id, 0, 16); }  /* 0x0509 = no-match */
  return TRUE;
}

gboolean
verimark_moc_parse_obj_list (const guint8 *resp, gsize len, guint16 *status,
                             GArray **out_ids, GError **error)
{
  if (len < 4) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "obj-list too short"); return FALSE; }
  *status = rd_u16le (resp);
  guint16 count = rd_u16le (resp + 2);
  if (len < (gsize) 4 + (gsize) count * 16)
    { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
        "obj-list truncated for count"); return FALSE; }
  GArray *ids = g_array_sized_new (FALSE, FALSE, 16, count);
  for (guint16 i = 0; i < count; i++)
    g_array_append_vals (ids, resp + 4 + i * 16, 1);   /* element size 16 */
  *out_ids = ids;
  return TRUE;
}

gboolean
verimark_moc_parse_obj_info (const guint8 *resp, gsize len, guint8 child_id[16], GError **error)
{
  if (len < 36) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "obj-info too short"); return FALSE; }
  memcpy (child_id, resp + 20, 16);   /* p2_moc.py mode_delete l.866 */
  return TRUE;
}
```

- [ ] **Step 5: Run, expect PASS** (all `/verimark/moc/parse/*` `OK`).
- [ ] **Step 6: Commit** — `git commit -m "verimark-moc: response parsers (sample/verify/obj-list/obj-info) vs p2_moc.py offsets"`.

---

## Task 3: Finalize splicer + SID synthesis (P4 + §5) — OFFLINE TDD

**Files:** Modify `driver/verimark-moc.{c,h}`, `driver/tests/test_moc.c`, `driver/tests/meson.build`.

**Interfaces:** Produces `verimark_moc_build_finalize` + `verimark_moc_synth_sid`. Ground truth: `p2_moc.py::WIN_FINALIZE` (l.52-53, 124 B), `build_finalize` (l.56-60: `WIN_FINALIZE[:19] + template_id + WIN_FINALIZE[35:]`), and the SID note (l.47-51: `[49:77]` is a 28-byte Windows SID, placeholder `S-1-5-21-0-0-0-1001`).

- [ ] **Step 1 (extraction): copy the 124-byte `WIN_FINALIZE` hex from `prototype/p2_moc.py:53`** verbatim into `verimark-moc.c` as `static const guint8 WIN_FINALIZE[124]`. Also **extract the exact `[49:77]` SID sub-layout** from that same constant to derive the binary-SID field order for `synth_sid`: bytes are `01`(rev) `05`(subauth count) `00 00 00 00 00 05`(authority=5), then 5 LE u32 subauthorities `21, a, b, c, rid` — in the placeholder `a=b=c=0, rid=0x03e9 (1001)`. Confirm this by slicing `WIN_FINALIZE[49:77]` and asserting it equals `010500000000000515000000` + `00000000 00000000 00000000` + `e9030000`. (This assertion is itself a unit test — Step 2.)

- [ ] **Step 2: Write failing tests:**
  - `test_finalize_splice`: pick a nonzero 16-byte `tid` and a 28-byte `sid`; call `verimark_moc_build_finalize(tid, sid, out, &e)`; assert `out[0]==0x96 && out[1]==0x03`, `memcmp(out+19, tid, 16)==0`, `memcmp(out+49, sid, 28)==0`, and that bytes `[0:19]` and `[35:49]` and `[77:124]` equal the corresponding `WIN_FINALIZE` slices (i.e. only the two windows changed).
  - `test_finalize_matches_python`: with `tid = WIN_FINALIZE[19:35]` and `sid = WIN_FINALIZE[49:77]` (the placeholder values), assert `out` == `WIN_FINALIZE` byte-for-byte (proves the splicer reproduces `build_finalize`'s identity when fed the original slices).
  - `test_synth_sid_layout`: call `verimark_moc_synth_sid(1001, seed, sid, &e)` with a fixed 16-byte `seed`; assert `sid[0]==0x01`, `sid[1]==0x05`, `sid[2:8]=={0,0,0,0,0,5}`, first subauth u32 LE at `sid[8:12]` == `21`, and `rid` u32 LE at `sid[24:28]` == `1001`. Assert two different seeds give different `a/b/c` but same header/rid (determinism + seed-sensitivity).

- [ ] **Step 3: Run, expect link failure.**

- [ ] **Step 4: Implement:**

```c
/* p2_moc.py:53 — 124 B. [19:35]=template-id, [49:77]=SID (both spliced at build). */
static const guint8 WIN_FINALIZE[124] = {
  /* EXTRACTION: paste the 124 bytes decoded from p2_moc.py:53 here, in order. */
};

gboolean
verimark_moc_build_finalize (const guint8 template_id[16], const guint8 sid[28],
                             guint8 out[124], GError **error)
{
  G_STATIC_ASSERT (sizeof WIN_FINALIZE == 124);
  memcpy (out, WIN_FINALIZE, 124);
  memcpy (out + 19, template_id, 16);   /* [19:35] */
  memcpy (out + 49, sid, 28);           /* [49:77] */
  (void) error;
  return TRUE;
}

gboolean
verimark_moc_synth_sid (uid_t uid, const guint8 machine_seed[16], guint8 out[28], GError **error)
{
  /* Binary SID S-1-5-21-a-b-c-rid (28 B). Header + authority = first 8 bytes;
   * 5 subauthorities as LE u32: {21, a, b, c, rid}. a/b/c from machine_seed so the
   * SID is stable per install; rid from uid. §5: provisional until on-device OK. */
  out[0] = 0x01;                          /* revision */
  out[1] = 0x05;                          /* subauthority count = 5 */
  out[2]=0; out[3]=0; out[4]=0; out[5]=0; out[6]=0; out[7]=0x05;   /* authority = 5 */
  guint32 sub[5];
  sub[0] = 21;
  sub[1] = ((guint32) machine_seed[0])  | ((guint32) machine_seed[1]  << 8)
         | ((guint32) machine_seed[2]  << 16) | ((guint32) machine_seed[3]  << 24);
  sub[2] = ((guint32) machine_seed[4])  | ((guint32) machine_seed[5]  << 8)
         | ((guint32) machine_seed[6]  << 16) | ((guint32) machine_seed[7]  << 24);
  sub[3] = ((guint32) machine_seed[8])  | ((guint32) machine_seed[9]  << 8)
         | ((guint32) machine_seed[10] << 16) | ((guint32) machine_seed[11] << 24);
  sub[4] = (guint32) uid;                 /* rid */
  for (int i = 0; i < 5; i++)
    { guint32 v = sub[i]; guint8 *p = out + 8 + i * 4;
      p[0]=v & 0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }
  (void) error;
  return TRUE;
}
```

> The driver will source `machine_seed` from `/etc/machine-id` (16 bytes) and `uid` from the enrolling user (`fpi_device` context / `getuid()`), wired in the P4 vfunc. Keeping `synth_sid` a pure function of (uid, seed) is what makes it unit-testable.

- [ ] **Step 5: Run, expect PASS.**
- [ ] **Step 6: Commit** — `git commit -m "verimark-moc: 0x96 03 finalize splicer + SID synthesis (§5) vs p2_moc.py"`.

---

## Task 4: Capture SSM (P3) — DEVICE-DEFERRED (+ mock smoke test)

**Files:** Modify `driver/verimark-moc.{c,h}`; create `driver/tests/mock_transport.{c,h}` + a `moc_capture_mock` test.

**Mirrors:** `p2_moc.py::moc_capture` (l.305-331), `wait_intr_event` (l.292-302), `evt_read` (l.266-284); event arming `set_event_mask` → `0x86 EVENT_CONFIG`, polling `0x87 EVENT_READ`.

- [ ] **Step 1 (extraction): confirm the intended transport combinators** `verimark_cmd_async` / `verimark_intr_wait_async` signatures against `driver/verimark.c` as it lands (they may differ from the provisional decls above). Also confirm how `0x86 EVENT_CONFIG` payload encodes the mask: from `p2_moc.py`/`event.py`, press/release = `set_event_mask([1,2])` (mask bit1|bit2 = `0x06`), frame-ready = `set_event_mask([24])` (bit24 = `0x01000000`). Extract the exact `0x86` command bytes for both masks from the rev `event.py::set_event_mask` builder (cited in PORTING-PLAN P3).

- [ ] **Step 2: Implement the capture SSM** `verimark_moc_capture_ssm_new(dev, acq_kind)` with these states (1:1 with `moc_capture`):
  - `CAP_ARM_PRESS`   — `0x86 EVENT_CONFIG` mask `0x06`.
  - `CAP_WAIT_PRESS`  — `verimark_intr_wait_async(0x83, want=0x01)`; on timeout → fail with `FP_DEVICE_RETRY_TOO_SHORT`/retry semantics.
  - `CAP_ARM_FRAME`   — `0x86 EVENT_CONFIG` mask `0x01000000`.
  - `CAP_FRAME_ACQ`   — `0x80 FRAME_ACQ` (`verimark_moc_build_frame_acq(out, acq_kind)`).
  - `CAP_WAIT_FRAME`  — poll `0x87 EVENT_READ`; treat status `0x0405/6/7` as "none yet, retry" (timer via `fpi_device_add_timeout`, not sleep); look for event type `0x18` in the record (`types[i] = r[6 + i*12]`, `evt_read` l.279). Advance `event_seq_num` by the number of events.
  - `CAP_FRAME_FINISH`— `0x86` mask clear (`[]`) then `0x81 FRAME_FINISH`.
  - Success iff `0x18` seen. The frame stays on-chip for the caller (`fpi_ssm_start_subsm` returns to the parent enroll/verify SSM).

- [ ] **Step 3: Write the mock-transport smoke test** — `driver/tests/mock_transport.c` provides synchronous stubs of `verimark_cmd_async`/`verimark_intr_wait_async` that pop scripted `(cmd_matcher → response)` pairs from a queue and invoke the callback immediately. Script a happy path: press(0x01) → `0x80` ok → EVENT_READ returns a record whose `[6]==0x18` → `0x81` ok, and assert the capture SSM completes success. Script a no-frame path (EVENT_READ never yields `0x18` before timeout) and assert it fails. This validates the state ordering offline without a device. Register as `moc_capture_mock` in meson (needs the SSM code, so this test target links libfprint stubs — if that is too heavy, keep the mock test as a **plain state-order assertion** over an extracted transition table and mark full-SSM exercise `[DEFERRED: device]`).

- [ ] **Step 4 `[DEFERRED: device]`: on-device capture trace.** Reproduce `p2_moc.py events`/`probe1`: press-and-hold, confirm `0x18` frame-ready observed and the SSM completes. Diff against the Python `moc_capture` verbose log.

- [ ] **Step 5: Commit** — `git commit -m "verimark-moc: capture SSM (P3, 0x18-gated) + mock smoke test [device steps deferred]"`.

---

## Task 5: Enroll SSM (P4) — DEVICE-DEFERRED

**Files:** Modify `driver/verimark-moc.{c,h}`, `driver/verimark.c` (`dev_enroll` glue + `FpPrint` store — but the store detail is Task 8).

**Mirrors:** `p2_moc.py::_run_enroll` (l.163-237); goodixmoc `fp_enroll_sm_run_state` for the libfprint enroll shape + `fpi_device_enroll_progress`/`complete`.

- [ ] **Step 1: Implement the enroll SSM** using the Task 1–3 helpers and the Task 4 capture sub-SSM:
  - `ENR_DEDUP_CAPTURE` — `verimark_moc_capture_ssm_new(dev, VERIMARK_ACQ_VERIFY)` (dedup uses the `0x14` acq, `_run_enroll` l.177-178).
  - `ENR_DEDUP`        — `0x99 01` begin-id (13 B); expect `0x0509` no-match/proceed (l.180-181).
  - `ENR_CREATE`       — `0x96 01` create (13 B); require status `0x0000` (l.184-186).
  - `ENR_SAMPLE_CAPTURE` (loop head) — capture sub-SSM `VERIMARK_ACQ_ENROLL` (`0x0c`).
  - `ENR_SAMPLE`       — `0x96 02` add-sample; `verimark_moc_parse_sample`. If `status != 0` OR coverage unchanged → don't count, re-loop (l.201-208). Else emit `fpi_device_enroll_progress(dev, ++stage, NULL, NULL)` (map coverage→stage; simplest: increment on each accepted sample, cap at `VERIMARK_ENROLL_STAGES`). Repeat until `coverage == 0x7f`; capture the minted id `sample.template_id` (l.211-213).
  - `ENR_FINALIZE`     — build SID (`verimark_moc_synth_sid(getuid()-equiv, machine_seed)`), `verimark_moc_build_finalize(minted_id, sid, ...)`, send `0x96 03`; require `0x0000` (l.219-222).
  - `ENR_COMMIT`       — `0x96 04` (5 B); require `0x0000` (l.224-227).
  - `ENR_STORE`        — stash `minted_id` in the `FpPrint` (Task 8) and `fpi_device_enroll_complete(dev, g_object_ref(print), NULL)`.
  - Errors at any step → `fpi_ssm_mark_failed`; the vfunc's completion cb calls `fpi_device_enroll_complete(dev, NULL, error)`.

- [ ] **Step 2: Wire `dev_enroll` in `verimark.c`** — get the enrolling `FpPrint` (`fpi_device_get_enroll_data`), stash on `self->enroll_print`, `verimark_moc_enroll(dev)`. Source `machine_seed` from `/etc/machine-id`, `uid` from the fprintd caller/`getuid()`.

- [ ] **Step 3 `[DEFERRED: device]`: on-device enroll.** `fprintd-enroll` (or `p2_moc.py enroll` cross-check): tap to coverage `0x7f` (~7 samples), confirm `0x9f` list grows by one, `FpPrint` persists with the id. Diff wire bytes vs `_run_enroll`.

- [ ] **Step 4: Commit** — `git commit -m "verimark-moc: enroll SSM (P4, dedup→create→sample loop→finalize→commit) [device deferred]"`.

---

## Task 6: Verify / identify SSM (P5) — DEVICE-DEFERRED

**Files:** Modify `driver/verimark-moc.{c,h}`, `driver/verimark.c` (`dev_verify`/`dev_identify` glue).

**Mirrors:** `p2_moc.py::mode_verify` (l.240-263); goodixmoc `fp_verify_sm_run_state` + `fpi_device_verify_report`/`identify_report` (goodix.c l.428-449).

- [ ] **Step 1: Implement the shared verify/identify SSM:**
  - `VFY_CAPTURE` — capture sub-SSM `VERIMARK_ACQ_VERIFY` (`0x14`, `mode_verify` l.249).
  - `VFY_MATCH`   — `0x99 01` begin-id, `resp_hint` 177 (l.254); `verimark_moc_parse_verify`.
  - `VFY_REPORT`  — resolve the matched `template_id` against the gallery:
    - **verify:** compare `match.template_id` to the single enrolled `FpPrint`'s stored id (Task 8 `parse_print_data`); `fpi_device_verify_report(dev, FPI_MATCH_SUCCESS/FAIL, print, error)` then `fpi_device_verify_complete`.
    - **identify:** iterate `fpi_device_get_identify_data(dev, &gallery)`; on a stored-id equal to `match.template_id`, `fpi_device_identify_report(dev, matched_print, matched_print, error)`; else `fpi_device_identify_report(dev, NULL, NULL, error)`; then `fpi_device_identify_complete`.
    - `status == 0x0509` (or `match.matched == FALSE`) → `FPI_MATCH_FAIL` / NULL identify. (goodix.c l.438-449 is the exact shape.)

- [ ] **Step 2: Wire `dev_verify` + `dev_identify`** in `verimark.c` to `verimark_moc_verify(dev)` (one SSM, branch on `fpi_device_get_current_action`), matching goodixmoc's shared verify/identify handler.

- [ ] **Step 3 `[DEFERRED: device]`: on-device verify/identify.** `fprintd-verify`: enrolled finger matches (minted id echoes, findings/51: verify returned the **minted** id, not the `0x9f` id — so matching keys on the stored minted id); a different finger → `0x0509` no-match. Multi-finger identify against a 2+ print gallery.

- [ ] **Step 4: Commit** — `git commit -m "verimark-moc: verify/identify SSM (P5, 0x99 177-B record) [device deferred]"`.

---

## Task 7: Storage ops — list / delete / clear (P6) — DEVICE-DEFERRED

**Files:** Modify `driver/verimark-moc.{c,h}`, `driver/verimark.c` (`dev_list`/`dev_delete`/`dev_clear_storage` glue).

**Mirrors:** `p2_moc.py::_list` (l.848-853, `0x9f`), `mode_delete` (l.860-871, `0xa0`→`0xa3`), `0xa5 DB2_FORMAT` for clear; goodixmoc `fp_template_list_cb`/`fp_template_delete_cb` (goodix.c l.1164-1262) for the libfprint list/delete shape.

- [ ] **Step 1: List SSM** — send `0x9f` (`struct.pack("<BB", 0x9f, 1)`, l.849); `verimark_moc_parse_obj_list`; for each 16-byte GUID build an `FpPrint` via the goodixmoc pattern (Task 8 layout), `g_ptr_array_add`; `fpi_device_list_complete(dev, array, error)`.
  - **§5 minted-vs-list-id (BLOCKS correct delete/list):** the `0x9f` GUID differs from the minted/verify id (findings/51). See Step 1a.
- [ ] **Step 1a `[DEFERRED: device]` — resolve the id mapping.** Run `0xa0 GET_OBJ_INFO` on a `0x9f` GUID and inspect whether it returns BOTH the list id and the child/minted id (`mode_delete` reads `child = resp[20:36]`). Hypothesis (findings/51 + PORTING-PLAN §5): `0xa0` maps list-id → child (minted) id. Until confirmed, **store both ids** in `fpi-data` (Task 8) so list-built prints carry the `0x9f` id and enroll-built prints carry the minted id, and delete resolves via `0xa0`.
- [ ] **Step 2: Delete SSM** — from the `FpPrint`'s stored id: `0xa0 GET_OBJ_INFO` (`struct.pack("<BI", 0xa0, 2) + guid`, l.865) → `verimark_moc_parse_obj_info` → child id → `0xa3 DELETE_OBJ` (`struct.pack("<BI", 0xa3, 1) + child`, l.869) → `fpi_device_delete_complete`.
- [ ] **Step 3: Clear-storage SSM** — `0xa5 DB2_FORMAT` → `fpi_device_clear_storage_complete`. (Extract the exact `0xa5` payload from rev `comm.py`/`p2_moc.py` note; PORTING-PLAN P6 cites `0xa5` for clear — confirm arg bytes at implementation time.)
- [ ] **Step 4 `[DEFERRED: device]`:** `fprintd-list`/`-delete`; list matches `p2_moc.py list`; delete removes one slot; clear empties. Verify the id mapping resolved in Step 1a makes list+delete address the same slot enroll stored.
- [ ] **Step 5: Commit** — `git commit -m "verimark-moc: storage ops list/delete/clear (P6) + id-mapping resolution [device deferred]"`.

---

## Task 8: FpPrint ↔ template-id mapping (§5) — partial offline, resolution device-deferred

**Files:** Modify `driver/verimark.c` (the `FpPrint` (de)serialization helpers); optional pure helper in `verimark-moc.c`.

**Mirrors:** goodixmoc `goodix.c` — enroll-commit store (l.936-968), `parse_print_data` (l.1116-1160), list-build (l.1238-1257).

- [ ] **Step 1: Store on enroll** — follow goodixmoc exactly:
  ```c
  user_id = fpi_print_generate_user_id (print);           /* description/user label */
  uid  = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, user_id, user_id_len, 1);
  tid  = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, minted_id, 16, 1);
  data = g_variant_new ("(y@ay@ay)", finger, tid, uid);   /* finger, tid(16), user_id */
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", data, NULL);
  ```
  **§5 both-ids variant:** until the minted-vs-list mapping is confirmed (Task 7 Step 1a), extend the GVariant to carry both ids, e.g. `(y@ay@ay@ay)` = finger, minted_tid(16), list_gid(16), user_id — OR keep `(y@ay@ay)` with `tid` = minted id and rely on `0xa0` to translate at delete time. **Pick one after Step 1a resolves; document the choice in the commit.**
- [ ] **Step 2: Parse on verify/identify/delete** — port `parse_print_data`: `g_object_get(print, "fpi-data", &data)`, `g_variant_get("(y@ay@ay)", ...)`, extract finger + tid(16) + user_id. Verify/identify compares `match.template_id` to the stored **minted** tid (findings/51: mint==verify). Delete uses the id `0xa0` expects (resolved in Task 7 Step 1a).
- [ ] **Step 3: Build on list** — for each `0x9f` GUID, build an `FpPrint` with `fpi_print_set_type(FPI_PRINT_RAW)`, `fpi_print_set_device_stored(TRUE)`, `fpi_print_fill_from_user_id`/description, storing the list GUID (and, per Step 1, the mapping to minted id if known).
- [ ] **Step 4 `[DEFERRED: device]`:** enroll a finger, `fprintd-list`, `fprintd-verify`, `fprintd-delete` round-trip; confirm the stored id survives and addresses the right slot. This is the acceptance test for the §5 mapping decision.
- [ ] **Step 5: Commit** — `git commit -m "verimark: FpPrint<->template-id mapping (goodixmoc pattern; §5 minted-vs-list)"`.

---

## Testing strategy

- **Pure-helper GTests (offline, green now):** Tasks 1–3 (builders, parsers, finalize/SID) run under `driver/tests/` with `meson test` — no device, no libfprint main loop, no USB. Every vector is a literal from `p2_moc.py`; every assertion is `g_assert_cmpuint`/`memcmp` against those bytes. These are the regression guard for the wire framing (the historic `0x0405` bug was exactly a framing-length regression, findings/49 — the `n == 13` assertions catch it).
- **Mock-transport SSM smoke test (offline):** Task 4 scripts `verimark_cmd_async`/`verimark_intr_wait_async` responses to exercise the capture state ordering without hardware (mirrors the TLS-core plan's mock). Extend to enroll/verify happy+sad paths if the libfprint-linked test harness proves cheap; otherwise those stay device-deferred.
- **On-device SSM behavior (deferred):** Tasks 4–8 `[DEFERRED: device]` steps — press-and-hold capture (`0x18`), guided enroll to `0x7f`, match/no-match, list/delete/clear. Manual, needs the user at the sensor.
- **Differential vs `p2_moc.py` (deferred):** for every phase, run the matching `p2_moc.py` mode and byte-diff the wire; the Python prototype is ground truth. Keep `p2_moc.py delete` handy to clean the ~8 accumulated test templates (findings/51).

---

## Risks & open questions

- **Minted-id vs `0x9f` list-id (§5, BLOCKS correct delete/list).** The id minted at enroll / echoed by verify differs from the `0x9f` DB list id (findings/51). Must resolve the mapping (likely `0xa0 GET_OBJ_INFO` returns both) before list/delete are correct — Task 7 Step 1a. Mitigation until then: store BOTH ids in `fpi-data` (Task 8 Step 1).
- **SID synthesis (§5, untested).** Whether a driver-built `S-1-5-21-…` SID (from machine-id + uid) enrolls+verifies, or the sensor requires a specific/stable value, is unverified — the Python prototype used a zeroed placeholder whose match-validity is itself untested (findings/51 l.85-89). `verimark_moc_synth_sid` is unit-tested for *layout*; its *acceptance* is a device-deferred decision (Task 5 Step 3).
- **Enroll cancellation / half-open context.** No explicit enroll-discard opcode exists in the prototype. `dev_cancel` must abort in-flight interrupt reads and discard a half-open `0x96 01` context — investigate whether `0x96` has an abort sub-op or whether a session reset (re-handshake) is the only clean discard (PORTING-PLAN §7). Deferred; note it in `dev_cancel`.
- **Multi-finger identify gallery.** The `0x99` path returns one matched id; identify must resolve it against a multi-print gallery (goodixmoc `identify_report` shape, Task 6). Correctness of the gallery walk is device-deferred.
- **Transport-combinator signatures.** `verimark_cmd_async`/`verimark_intr_wait_async` are being written concurrently in `verimark.c`; their exact signatures may shift. Each SSM task's first step re-confirms them (Task 4 Step 1). The MOC layer is otherwise decoupled — it only needs "send bytes wrapped, get bytes back" and "wait for interrupt type".
- **`0xa5` clear + `0x86`/`0x87` event payloads.** The exact arg bytes for `0xa5 DB2_FORMAT` and the `0x86 EVENT_CONFIG` mask encodings are not in the pure-helper vectors; they are extracted from rev (`comm.py`/`event.py`) at implementation time (Task 4 Step 1, Task 7 Step 3).

---

## Self-review

**Coverage vs PORTING-PLAN P3–P6 + §5:**
- P3 capture SSM (press 0x83 → arm frame → `0x80` acq → `0x87` poll for `0x18` → `0x81`) — Task 4. ✔
- P4 enroll SSM (`0x99 01` dedup → `0x96 01` create → `0x96 02` sample loop to `0x7f` → `0x96 03` finalize → `0x96 04` commit) + progress cb — Task 5 (+ builders Task 1, parse Task 2, finalize/SID Task 3). ✔
- P5 verify/identify SSM (`0x99 01` 177-B → match/no-match report) — Task 6. ✔
- P6 list/delete/clear (`0x9f`, `0xa0`→`0xa3`, `0xa5`) — Task 7. ✔
- §5 print/template mapping (goodixmoc `(y@ay@ay)`, `FPI_PRINT_RAW`, device-stored) + minted-vs-list resolution + SID synth — Task 8 (+ Task 3 SID, Task 7 Step 1a mapping). ✔
- DRY: capture SSM reused by enroll+verify (`verimark_moc_capture_ssm_new`). ✔ SOLID: MOC choreography in `verimark-moc.c`, GObject/report glue in `verimark.c`, TLS/transport untouched. ✔

**Placeholder scan:** The only deferred-to-extraction items are explicitly marked as a task's first step: (a) the 124-byte `WIN_FINALIZE` array body + `[49:77]` SID sub-layout (Task 3 Step 1, from `p2_moc.py:53`); (b) the `verimark_cmd_async`/`verimark_intr_wait_async` signatures + `0x86` mask bytes (Task 4 Step 1); (c) the `0xa5` clear arg bytes (Task 7 Step 3). All other bytes/offsets are inlined from cited `p2_moc.py` lines. No unmarked TBDs.

**API-name consistency:** Opcodes referenced (`0x96/0x99/0x80/0x81/0x86/0x87/0x9f/0xa0/0xa3/0xa5`) match `verimark.h` `VERIMARK_CMD_*` (`ENROLL`=0x96, `IDENTIFY`=0x99, `FRAME_ACQ`=0x80, `FRAME_FINISH`=0x81, `EVENT_CONFIG`=0x86, `EVENT_READ`=0x87, `DB2_GET_OBJ_LIST`=0x9f, `DB2_GET_OBJ_INFO`=0xa0, `DB2_DELETE_OBJ`=0xa3, `DB2_FORMAT`=0xa5). The MOC layer's dependency on the TLS layer is via `verimark_cmd_async` (wrap/unwrap handled there); it consumes `verimark_tls_wrap`/`verimark_tls_unwrap` transitively, consistent with the TLS-core plan's `driver/verimark-tls-crypto.h` and the `driver/verimark-tls.h` channel API. Offsets (coverage 22, counter 24, quality 42, id [2:18], child [20:36], list GUIDs at 4+16i) match findings/51 and `p2_moc.py`. ✔
