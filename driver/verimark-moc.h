/*
 * verimark-moc.h — Match-on-chip (MOC) operations layer for the VeriMark driver.
 *
 * Port of prototype/p2_moc.py (findings/49, findings/51). SOLID: this module
 * owns MOC *choreography* only — command framing, response parsing, and the
 * FpiSsm state machines that drive capture/enroll/verify/identify/list/
 * delete/clear. It is separate from the TLS channel (verimark-tls.{c,h}), the
 * EP0 transport (verimark-transport.{c,h}), and the FpDevice GObject glue
 * (verimark.c, which owns dev_open/dev_enroll/etc and simply calls the entry
 * points declared at the bottom of this file).
 *
 * Two halves, deliberately split by an #ifndef:
 *
 *   - "Pure framing helpers" (builders + parsers + finalize/SID synthesis):
 *     no GLib main loop, no USB, no device, no libfprint headers. Compiled
 *     and unit-tested completely offline (driver/tests/test_moc.c) against
 *     byte literals taken verbatim from prototype/p2_moc.py. This half is
 *     ALWAYS available, with or without libfprint.
 *
 *   - "SSM entry points": FpiSsm state machines consumed by verimark.c's
 *     FpDevice vfuncs. These need fpi-device.h/fpi-ssm.h (libfprint's driver
 *     API), which the standalone glib-only test project deliberately does
 *     NOT depend on (see driver/tests/meson.build) so the pure half stays
 *     buildable without a full libfprint checkout. Guarded behind
 *     !VERIMARK_MOC_PURE_ONLY; driver/tests/meson.build compiles this file
 *     with -DVERIMARK_MOC_PURE_ONLY to get only the pure half.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#pragma once

#include <glib.h>
#include <sys/types.h>   /* uid_t */

#ifndef VERIMARK_MOC_PURE_ONLY
#include "fpi-device.h"
#include "fpi-ssm.h"
#endif

G_BEGIN_DECLS

/* Module-owned GError domain (no GIO dependency — glib only, matching
 * verimark-tls-crypto.h's VERIMARK_TLS_CRYPTO_ERROR pattern, so the
 * standalone pure-helper test project doesn't need to link gio-2.0). */
#define VERIMARK_MOC_ERROR (verimark_moc_error_quark ())
GQuark verimark_moc_error_quark (void);

typedef enum {
  VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
  VERIMARK_MOC_ERROR_INVALID_DATA,
} VerimarkMocError;

/* ============================================================================
 * Pure framing helpers — offline-TDD (driver/tests/test_moc.c).
 * ========================================================================= */

/* FRAME_ACQ acquisition kind (p2_moc.py C_FRAME_ACQ / C_FRAME_ACQ14). */
#define VERIMARK_ACQ_ENROLL  0x0c   /* enroll add-sample frames  */
#define VERIMARK_ACQ_VERIFY  0x14   /* dedup + verify/identify frames */

/* Command-literal builders. Each writes the exact wire bytes and returns the
 * length. The 13-byte length of begin-id / enroll-create is load-bearing
 * (findings/49) — do not shorten; an 11-byte (2-short) command returns
 * 0x0405 BAD_PARAM and was the entire historic "ownership gate" bug. */
gsize verimark_moc_build_begin_id      (guint8 out[13]);   /* 0x99 01 (13 B) */
gsize verimark_moc_build_enroll_create (guint8 out[13]);   /* 0x96 01 (13 B) */
gsize verimark_moc_build_enroll_sample (guint8 out[5]);    /* 0x96 02 (5 B)  */
gsize verimark_moc_build_enroll_commit (guint8 out[5]);    /* 0x96 04 (5 B)  */
gsize verimark_moc_build_frame_acq     (guint8 out[17], guint8 acq_kind); /* 0x80 (17 B) */
gsize verimark_moc_build_frame_finish  (guint8 out[1]);    /* 0x81 (1 B)     */

/* 0x96 03 finalize (124 B): splice template_id into [19:35] and sid (28 B) into
 * [49:77] of the WIN_FINALIZE template (p2_moc.py:52-53, build_finalize).
 * Returns FALSE on bad args (NULL template_id/sid/out). */
gboolean verimark_moc_build_finalize (const guint8 template_id[16],
                                      const guint8 sid[28],
                                      guint8 out[124], GError **error);

/* Synthesize the 28-byte binary SID (S-1-5-21-a-b-c-rid) for the local user.
 * a/b/c derived from a stable per-install seed (e.g. /etc/machine-id's first
 * 16 bytes); rid from uid. p2_moc.py used a zeroed placeholder
 * (S-1-5-21-0-0-0-1001) whose match-validity is itself unverified — see
 * findings/51 and PORTING-PLAN.md §5. The scheme here is provisional until
 * confirmed on-device (Task 5 Step 3, deferred). */
gboolean verimark_moc_synth_sid (uid_t uid, const guint8 machine_seed[16],
                                 guint8 out[28], GError **error);

/* Parse an add-sample (0x96 02) response. Offsets per findings/51 (coverage
 * 22, counter 24, quality 42 — NOT 41, which is a pad byte). */
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

/* Parse a 0xa0 DB2_GET_OBJ_INFO response → child/leaf id at resp[20:36]
 * (p2_moc.py::mode_delete l.866). */
gboolean verimark_moc_parse_obj_info (const guint8 *resp, gsize len,
                                      guint8 child_id[16], GError **error);

/* Capture SSM (P3) state-order contract — p2_moc.py::moc_capture (l.305-331):
 * arm press/release events, wait for a press, arm frame-ready, trigger
 * FRAME_ACQ, poll for the 0x18 frame-ready event, clear the event mask,
 * FRAME_FINISH. Deliberately a plain enum (no libfprint types) rather than
 * the FpiSsm itself, so this ordering is offline-testable
 * (driver/tests/test_moc.c) without a device or a libfprint checkout — the
 * actual FpiSsm below (VERIMARK_MOC_PURE_ONLY-guarded) is built from this
 * exact enum, so the two can never drift apart. This is the "plain
 * state-order assertion over an extracted transition table" mentioned in
 * the plan's Task 4 Step 3 as the offline fallback for a full mock-transport
 * SSM smoke test (which needs a real libfprint build to link, unavailable
 * in this environment — [DEFERRED: device] covers exercising it for real). */
typedef enum {
  VERIMARK_CAP_ARM_PRESS,
  VERIMARK_CAP_WAIT_PRESS,
  VERIMARK_CAP_ARM_FRAME,
  VERIMARK_CAP_FRAME_ACQ,
  VERIMARK_CAP_WAIT_FRAME,
  VERIMARK_CAP_EVENT_CLEAR,
  VERIMARK_CAP_FRAME_FINISH,
  VERIMARK_CAP_N_STATES,
} VerimarkCapState;

#ifndef VERIMARK_MOC_PURE_ONLY

/* ============================================================================
 * Wrapped-command combinator — the primitive every MOC SSM sends through.
 * ========================================================================= */

/**
 * VerimarkMocRespCallback:
 * @dev: the device
 * @status: MOC status word (resp[0:2] LE) — 0x0000 ok, 0x0509 no-match, etc.
 *   Only meaningful when @error is %NULL and @resp_len >= 2; 0 otherwise.
 * @resp: (nullable): decrypted plaintext response body (owned by the
 *   callback's caller — do not free; copy out what you need before returning)
 * @resp_len: length of @resp
 * @error: (transfer full) (nullable): %NULL on success
 * @user_data: as passed to verimark_moc_send()
 */
typedef void (*VerimarkMocRespCallback) (FpDevice     *dev,
                                         guint16       status,
                                         const guint8 *resp,
                                         gsize         resp_len,
                                         GError       *error,
                                         gpointer      user_data);

/**
 * verimark_moc_send:
 * @dev: the device (must have an established #VerimarkTls in
 *   FpiDeviceVerimark.tls — the integration pass's dev_open()/pairing sets
 *   this up; this layer only consumes it)
 * @plain_cmd: plaintext MOC command bytes (e.g. from
 *   verimark_moc_build_enroll_create())
 * @plain_len: length of @plain_cmd
 * @resp_hint: maximum decrypted response bytes expected (sized like
 *   p2_moc.py's send_command() `resp_size` argument, e.g. 13/82/177/0x400)
 * @cancellable: (nullable): cancellable for the whole wrap→send→unwrap
 * @callback: called exactly once with the result
 * @user_data: passed through to @callback
 *
 * The one primitive every MOC SSM state uses to talk to the sensor once TLS
 * is up: verimark_tls_wrap() the plaintext, verimark_cmd() it out over EP0,
 * verimark_tls_unwrap() the raw reply, and hand the caller the decrypted
 * plaintext + parsed status word. Mirrors control_comm.py's
 * send_command()/LogCommunicationProxy, minus logging.
 */
void verimark_moc_send (FpDevice                *dev,
                        const guint8             *plain_cmd,
                        gsize                     plain_len,
                        gsize                     resp_hint,
                        GCancellable             *cancellable,
                        VerimarkMocRespCallback   callback,
                        gpointer                  user_data);

/* ============================================================================
 * SSM entry points — device-tested (deferred); called by verimark.c vfuncs.
 * ========================================================================= */

/* Capture SSM shared by enroll (acq=VERIMARK_ACQ_ENROLL) and verify/identify
 * (acq=VERIMARK_ACQ_VERIFY) — DRY. On success leaves a valid frame on-chip
 * for the next MOC step to consume. The parent SSM jumps to this as a
 * sub-SSM (fpi_ssm_start_subsm). [DEFERRED: device] — implemented per
 * p2_moc.py::moc_capture, not yet exercised against real hardware. */
FpiSsm *verimark_moc_capture_ssm_new (FpDevice *dev, guint8 acq_kind);

/* Operation entry points: build the task SSM and start it. Each reports/
 * completes via the libfprint fpi_device_* callbacks from within
 * verimark-moc.c — verimark.c's vfuncs just call these and return.
 * [DEFERRED: device] for all on-device behavior; wire framing/choreography
 * is implemented per prototype/p2_moc.py. */
void verimark_moc_enroll   (FpDevice *dev);   /* 0x99 dedup→0x96 01→sample loop→0x96 03→0x96 04 */
void verimark_moc_verify   (FpDevice *dev);   /* capture→0x99 01; FPI_DEVICE_ACTION_VERIFY path */
void verimark_moc_identify (FpDevice *dev);   /* capture→0x99 01; FPI_DEVICE_ACTION_IDENTIFY path */
void verimark_moc_list     (FpDevice *dev);   /* 0x9f */
void verimark_moc_delete   (FpDevice *dev);   /* 0xa0 lookup child → 0xa3 delete */
void verimark_moc_clear    (FpDevice *dev);   /* 0xa5 DB2_FORMAT */

#endif /* !VERIMARK_MOC_PURE_ONLY */

G_END_DECLS
