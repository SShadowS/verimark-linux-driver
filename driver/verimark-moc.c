/*
 * verimark-moc.c — see verimark-moc.h.
 *
 * Pure framing helpers below the `#ifndef VERIMARK_MOC_PURE_ONLY` line are
 * offline-TDD (driver/tests/test_moc.c); everything from that line down
 * needs libfprint (fpi-device.h/fpi-ssm.h) and is device-tested (deferred —
 * see verimark-moc.h and the plan's [DEFERRED: device] markers below).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "verimark-moc.h"
#include <string.h>

GQuark
verimark_moc_error_quark (void)
{
  return g_quark_from_static_string ("verimark-moc-error-quark");
}

/* ============================================================================
 * Pure framing helpers — literals/offsets taken verbatim from
 * prototype/p2_moc.py (findings/49, findings/51).
 * ========================================================================= */

static inline guint16
rd_u16le (const guint8 *p)
{
  return (guint16) p[0] | ((guint16) p[1] << 8);
}

/* p2_moc.py:37 C_BEGIN_ID — 0x99 begin-identify (13 B). Also used, unchanged,
 * for the dedup check during enroll (_run_enroll). The 13-byte length is
 * load-bearing (findings/49) — an 11-byte command reads as 0x0405 BAD_PARAM. */
gsize
verimark_moc_build_begin_id (guint8 out[13])
{
  static const guint8 v[13] = { 0x99, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  memcpy (out, v, 13);
  return 13;
}

/* p2_moc.py:38 C_ENR_CREATE — 0x96 01 create-enroll (13 B). */
gsize
verimark_moc_build_enroll_create (guint8 out[13])
{
  static const guint8 v[13] = { 0x96, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  memcpy (out, v, 13);
  return 13;
}

/* p2_moc.py:39 C_ENR_SAMPLE — 0x96 02 add-sample (5 B). */
gsize
verimark_moc_build_enroll_sample (guint8 out[5])
{
  static const guint8 v[5] = { 0x96, 0x02, 0, 0, 0 };

  memcpy (out, v, 5);
  return 5;
}

/* p2_moc.py:40 C_ENR_COMMIT — 0x96 04 commit (5 B). */
gsize
verimark_moc_build_enroll_commit (guint8 out[5])
{
  static const guint8 v[5] = { 0x96, 0x04, 0, 0, 0 };

  memcpy (out, v, 5);
  return 5;
}

/* p2_moc.py:41,289 C_FRAME_ACQ / C_FRAME_ACQ14 — 0x80 FRAME_ACQ (17 B); the
 * acquisition-kind byte (VERIMARK_ACQ_ENROLL=0x0c or VERIMARK_ACQ_VERIFY=
 * 0x14) sits at byte offset 1, everything else is a fixed literal. */
gsize
verimark_moc_build_frame_acq (guint8 out[17], guint8 acq_kind)
{
  static const guint8 v[17] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x01, 0x00
  };

  memcpy (out, v, 17);
  out[1] = acq_kind;
  return 17;
}

/* p2_moc.py:42 C_FRAME_FIN — 0x81 FRAME_FINISH (1 B). */
gsize
verimark_moc_build_frame_finish (guint8 out[1])
{
  out[0] = 0x81;
  return 1;
}

/* p2_moc.py:52-53 WIN_FINALIZE — 124 B. [19:35] carries the sensor-minted
 * template-id (overwritten at build time); [49:77] carries a 28-byte
 * Windows SID (also overwritten). Everything else is an opaque, unexplained
 * Windows-captured literal that must be reproduced byte-for-byte. */
static const guint8 WIN_FINALIZE[124] = {
  0x96, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x45, 0x2d, 0xec, 0x91, 0x88,
  0x13, 0x90, 0xe4, 0x14, 0xeb, 0x6a, 0x58, 0x12, 0x8e, 0x41, 0x21, 0x01,
  0x00, 0x4c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00,
  0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0xe9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
  0x00, 0x00, 0x00, 0xf5,
};

G_STATIC_ASSERT (sizeof (WIN_FINALIZE) == 124);

gboolean
verimark_moc_build_finalize (const guint8 template_id[16],
                             const guint8 sid[28],
                             guint8       out[124],
                             GError     **error)
{
  if (template_id == NULL || sid == NULL || out == NULL)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
                           "verimark_moc_build_finalize: NULL argument");
      return FALSE;
    }

  memcpy (out, WIN_FINALIZE, 124);
  memcpy (out + 19, template_id, 16);   /* [19:35] */
  memcpy (out + 49, sid, 28);           /* [49:77] */
  return TRUE;
}

gboolean
verimark_moc_synth_sid (uid_t         uid,
                        const guint8  machine_seed[16],
                        guint8        out[28],
                        GError      **error)
{
  guint32 sub[5];
  int     i;

  if (machine_seed == NULL || out == NULL)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
                           "verimark_moc_synth_sid: NULL argument");
      return FALSE;
    }

  /* Binary SID S-1-5-21-a-b-c-rid (28 B): 1 B revision, 1 B subauthority
   * count (5), 6 B authority (big-endian 48-bit value = 5), then 5
   * subauthorities as LE u32: {21, a, b, c, rid}. a/b/c come from
   * machine_seed so the SID is stable per install; rid from uid. This
   * layout is confirmed against the WIN_FINALIZE placeholder slice
   * ([49:77] == S-1-5-21-0-0-0-1001, i.e. a=b=c=0, rid=1001=0x3e9) —
   * see driver/tests/test_moc.c test_finalize_matches_python. Whether a
   * *driver-synthesized* (non-placeholder) SID is accepted by the sensor
   * is unverified (PORTING-PLAN.md §5, device-deferred). */
  out[0] = 0x01;                                  /* revision */
  out[1] = 0x05;                                  /* subauthority count = 5 */
  out[2] = 0; out[3] = 0; out[4] = 0;
  out[5] = 0; out[6] = 0; out[7] = 0x05;          /* authority = 5 */

  sub[0] = 21;
  sub[1] = ((guint32) machine_seed[0])
         | ((guint32) machine_seed[1]  << 8)
         | ((guint32) machine_seed[2]  << 16)
         | ((guint32) machine_seed[3]  << 24);
  sub[2] = ((guint32) machine_seed[4])
         | ((guint32) machine_seed[5]  << 8)
         | ((guint32) machine_seed[6]  << 16)
         | ((guint32) machine_seed[7]  << 24);
  sub[3] = ((guint32) machine_seed[8])
         | ((guint32) machine_seed[9]  << 8)
         | ((guint32) machine_seed[10] << 16)
         | ((guint32) machine_seed[11] << 24);
  sub[4] = (guint32) uid;                         /* rid */

  for (i = 0; i < 5; i++)
    {
      guint32 v = sub[i];
      guint8 *p = out + 8 + i * 4;

      p[0] = (guint8) (v & 0xff);
      p[1] = (guint8) ((v >> 8) & 0xff);
      p[2] = (guint8) ((v >> 16) & 0xff);
      p[3] = (guint8) ((v >> 24) & 0xff);
    }

  return TRUE;
}

/* p2_moc.py::_run_enroll l.204: `new_cov, counter, quality = resp[22], resp[24], resp[42]`;
 * id resp[2:18] l.212. findings/51 corrected quality from 41 (a pad byte) to 42. */
gboolean
verimark_moc_parse_sample (const guint8      *resp,
                           gsize              len,
                           VerimarkMocSample *out,
                           GError           **error)
{
  if (resp == NULL || out == NULL)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
                           "verimark_moc_parse_sample: NULL argument");
      return FALSE;
    }
  if (len < 43)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_DATA,
                           "sample response too short");
      return FALSE;
    }

  out->status = rd_u16le (resp);           /* [0:2]  */
  memcpy (out->template_id, resp + 2, 16); /* [2:18] */
  out->coverage = resp[22];
  out->counter  = resp[24];
  out->quality  = resp[42];
  return TRUE;
}

/* p2_moc.py::mode_verify l.256-260: status resp[0:2]; on 0x0000 match, GUID
 * at resp[2:18]; 0x0509 = no-match. */
gboolean
verimark_moc_parse_verify (const guint8      *resp,
                           gsize              len,
                           VerimarkMocMatch  *out,
                           GError           **error)
{
  if (resp == NULL || out == NULL)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
                           "verimark_moc_parse_verify: NULL argument");
      return FALSE;
    }
  if (len < 2)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_DATA,
                           "verify response too short");
      return FALSE;
    }

  out->status = rd_u16le (resp);
  if (out->status == 0x0000)
    {
      if (len < 18)
        {
          g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_DATA,
                               "match record missing id");
          return FALSE;
        }
      out->matched = TRUE;
      memcpy (out->template_id, resp + 2, 16);
    }
  else
    {
      /* 0x0509 = no-match; other nonzero statuses are also "not matched"
       * from this parser's point of view — the caller decides whether an
       * unexpected status is itself an error. */
      out->matched = FALSE;
      memset (out->template_id, 0, 16);
    }
  return TRUE;
}

/* p2_moc.py::_list l.848-853: struct.pack("<BB", 0x9f, 1) request;
 * st=u16(r,0), count=u16(r,2), GUID[i]=r[4+i*16:20+i*16]. */
gboolean
verimark_moc_parse_obj_list (const guint8  *resp,
                             gsize          len,
                             guint16       *status,
                             GArray       **out_ids,
                             GError       **error)
{
  guint16    count;
  GArray    *ids;
  guint16    i;

  if (resp == NULL || status == NULL || out_ids == NULL)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
                           "verimark_moc_parse_obj_list: NULL argument");
      return FALSE;
    }
  if (len < 4)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_DATA,
                           "obj-list response too short");
      return FALSE;
    }

  *status = rd_u16le (resp);
  count = rd_u16le (resp + 2);

  if (len < (gsize) 4 + (gsize) count * 16)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_DATA,
                           "obj-list response truncated for count");
      return FALSE;
    }

  ids = g_array_sized_new (FALSE, FALSE, 16, count);
  for (i = 0; i < count; i++)
    g_array_append_vals (ids, resp + 4 + (gsize) i * 16, 1);   /* element size 16 */

  *out_ids = ids;
  return TRUE;
}

/* p2_moc.py::mode_delete l.865-866: struct.pack("<BI", 0xa0, 2) + guid
 * request; child = r[20:36]. */
gboolean
verimark_moc_parse_obj_info (const guint8  *resp,
                             gsize          len,
                             guint8         child_id[16],
                             GError       **error)
{
  if (resp == NULL || child_id == NULL)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_ARGUMENT,
                           "verimark_moc_parse_obj_info: NULL argument");
      return FALSE;
    }
  if (len < 36)
    {
      g_set_error_literal (error, VERIMARK_MOC_ERROR, VERIMARK_MOC_ERROR_INVALID_DATA,
                           "obj-info response too short");
      return FALSE;
    }

  memcpy (child_id, resp + 20, 16);
  return TRUE;
}

#ifndef VERIMARK_MOC_PURE_ONLY

/* ============================================================================
 * SSM half — libfprint-dependent (fpi-device.h/fpi-ssm.h/fpi-usb-transfer.h).
 * Everything below [DEFERRED: device] unless noted otherwise: implemented
 * cleanly per prototype/p2_moc.py's wire choreography and the goodixmoc
 * driver's FpiSsm shape (re/synaTudor-rev/.../drivers/goodixmoc/goodix.c),
 * but not yet built or exercised against real hardware — this environment
 * has no libfprint headers installed (see driver/tests/meson.build, which
 * deliberately never links this half). The integration pass builds this
 * against a real libfprint checkout.
 * ========================================================================= */

#include "verimark.h"
#include "verimark-tls.h"
#include "verimark-transport.h"
#include "fpi-usb-transfer.h"
#include "fpi-print.h"
#include <string.h>
#include <stdio.h>    /* sscanf() */
#include <unistd.h>   /* getuid() */

/* ---------------------------------------------------------------------------
 * Tunables. Values mirror the *shape* of prototype/p2_moc.py's deadlines
 * (overall_deadline=150s enroll, 45s verify/8 attempts, 5s frame window,
 * 15ms EVENT_READ not-ready poll) — the exact numbers are not wire-critical,
 * just how patient the SSMs are before giving up.
 * ------------------------------------------------------------------------- */
#define VERIMARK_CAPTURE_PRESS_TIMEOUT_MS   30000
#define VERIMARK_CAPTURE_FRAME_TIMEOUT_MS    5000
#define VERIMARK_CAPTURE_FRAME_POLL_DELAY_MS   15
#define VERIMARK_ENROLL_OVERALL_TIMEOUT_MS 150000
#define VERIMARK_VERIFY_MAX_ATTEMPTS             8
#define VERIMARK_VERIFY_OVERALL_TIMEOUT_MS   45000

/* Interrupt-EP event bytes (p2_moc.py FINGER_PRESS/FINGER_REMOVE, l.101). */
#define VERIMARK_EVT_FINGER_PRESS  0x01
#define VERIMARK_EVT_FRAME_READY   0x18   /* EVENT_READ event-type byte, not an intr-EP byte */

/* EVENT_READ "no events yet" status band (evt_read, p2_moc.py:266-284). */
#define VERIMARK_EVTREAD_NOTREADY_LO 0x0405
#define VERIMARK_EVTREAD_NOTREADY_HI 0x0407

/* set_event_mask() bit patterns (tudor/sensor/event.py:39-54). */
#define VERIMARK_EVTMASK_FINGER 0x00000006u   /* bit1|bit2 = FINGER_PRESS|FINGER_REMOVE */
#define VERIMARK_EVTMASK_FRAME  0x01000000u   /* bit24 = frame-ready (event type 0x18)  */
#define VERIMARK_EVTMASK_NONE   0x00000000u

static inline void
wr_u16le (guint8 *p, guint16 v)
{
  p[0] = (guint8) (v & 0xff);
  p[1] = (guint8) ((v >> 8) & 0xff);
}

static inline void
wr_u32le (guint8 *p, guint32 v)
{
  p[0] = (guint8) (v & 0xff);
  p[1] = (guint8) ((v >> 8) & 0xff);
  p[2] = (guint8) ((v >> 16) & 0xff);
  p[3] = (guint8) ((v >> 24) & 0xff);
}

static inline guint16
moc_rd_u16le (const guint8 *p)
{
  return (guint16) p[0] | ((guint16) p[1] << 8);
}

/* tudor/sensor/event.py:47 `struct.pack("<B8II", EVENT_CONFIG, mask*8, extra)`
 * — 1 (opcode) + 8*4 (mask replicated) + 4 (extra: 0 if mask!=0 else 4) = 37 B.
 * Response (event.py:48, resp_size 0x42=66): new event_seq_num is a u16 at
 * offset 64 (`struct.unpack("<64xH", resp)`). */
#define VERIMARK_EVENT_CONFIG_CMD_LEN  37
#define VERIMARK_EVENT_CONFIG_RESP_LEN 0x42

static gsize
build_event_config (guint8 out[VERIMARK_EVENT_CONFIG_CMD_LEN], guint32 mask)
{
  int i;

  out[0] = VERIMARK_CMD_EVENT_CONFIG;
  for (i = 0; i < 8; i++)
    wr_u32le (out + 1 + i * 4, mask);
  wr_u32le (out + 33, mask != 0 ? 0 : 4);
  return VERIMARK_EVENT_CONFIG_CMD_LEN;
}

/* p2_moc.py::evt_read l.269 `struct.pack("<BHHI", EVENT_READ, seq, 32, 1)`
 * (9 B); response (resp_size 390): status[0:2], num_evts[2:4] u16,
 * num_pending[4:6] u16, then num_evts * 12-byte records, type at record
 * offset 0 (`r[6 + i*12]`). */
#define VERIMARK_EVENT_READ_CMD_LEN  9
#define VERIMARK_EVENT_READ_RESP_LEN 390

static gsize
build_event_read (guint8 out[VERIMARK_EVENT_READ_CMD_LEN], guint16 seq)
{
  out[0] = VERIMARK_CMD_EVENT_READ;
  wr_u16le (out + 1, seq);
  wr_u16le (out + 3, 32);
  wr_u32le (out + 5, 1);
  return VERIMARK_EVENT_READ_CMD_LEN;
}

/* ============================================================================
 * verimark_moc_send — wrap → EP0 → unwrap combinator. Every MOC opcode above
 * (0x86/0x87/0x80/0x81/0x96/0x99/0x9f/0xa0/0xa3/0xa5) goes through this once
 * TLS is up (self->tls, set by the integration pass's dev_open()/pairing).
 * ========================================================================= */

typedef struct
{
  VerimarkMocRespCallback callback;
  gpointer                 user_data;
} VerimarkMocSendCtx;

static void
on_moc_raw_resp (FpDevice *dev, GByteArray *response, GError *error, gpointer user_data)
{
  VerimarkMocSendCtx *ctx = user_data;
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  guint8 *plain = NULL;
  gsize plain_len = 0;
  guint16 status = 0;

  if (error != NULL)
    {
      ctx->callback (dev, 0, NULL, 0, error, ctx->user_data);
      g_free (ctx);
      return;
    }

  if (!verimark_tls_unwrap (self->tls, response->data, response->len,
                            &plain, &plain_len, &error))
    {
      g_byte_array_unref (response);
      ctx->callback (dev, 0, NULL, 0, error, ctx->user_data);
      g_free (ctx);
      return;
    }
  g_byte_array_unref (response);

  if (plain_len >= 2)
    status = moc_rd_u16le (plain);

  ctx->callback (dev, status, plain, plain_len, NULL, ctx->user_data);
  g_free (plain);
  g_free (ctx);
}

void
verimark_moc_send (FpDevice                *dev,
                   const guint8             *plain_cmd,
                   gsize                     plain_len,
                   gsize                     resp_hint,
                   GCancellable             *cancellable,
                   VerimarkMocRespCallback   callback,
                   gpointer                  user_data)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkMocSendCtx *ctx;
  guint8 *record = NULL;
  gsize record_len = 0;
  GError *error = NULL;

  g_return_if_fail (FP_IS_DEVICE (dev));
  g_return_if_fail (callback != NULL);

  if (!verimark_tls_wrap (self->tls, plain_cmd, plain_len, &record, &record_len, &error))
    {
      callback (dev, 0, NULL, 0, error, user_data);
      return;
    }

  ctx = g_new0 (VerimarkMocSendCtx, 1);
  ctx->callback = callback;
  ctx->user_data = user_data;

  /* +64: TLS record framing overhead (5-B header + 8-B nonce + 16-B tag,
   * verimark-tls.h) plus slack, so a good decrypted reply of up to
   * resp_hint bytes is never truncated by verimark_cmd()'s resp_max_len. */
  verimark_cmd (dev, record, record_len, resp_hint + 64, cancellable,
               on_moc_raw_resp, ctx);
  g_free (record);
}

/* ============================================================================
 * Capture SSM (P3) — p2_moc.py::moc_capture (l.305-331). Shared sub-SSM for
 * enroll (acq=VERIMARK_ACQ_ENROLL) and verify/identify (acq=VERIMARK_ACQ_VERIFY).
 * [DEFERRED: device] — see verimark-moc.h banner.
 * ========================================================================= */

/* Reuses the pure, offline-tested VerimarkCapState enum (verimark-moc.h) as
 * the FpiSsm's actual state numbering — the state-order regression test
 * (driver/tests/test_moc.c) and this SSM can never drift apart. */
#define CAP_ARM_PRESS    VERIMARK_CAP_ARM_PRESS
#define CAP_WAIT_PRESS   VERIMARK_CAP_WAIT_PRESS
#define CAP_ARM_FRAME    VERIMARK_CAP_ARM_FRAME
#define CAP_FRAME_ACQ    VERIMARK_CAP_FRAME_ACQ
#define CAP_WAIT_FRAME   VERIMARK_CAP_WAIT_FRAME
#define CAP_EVENT_CLEAR  VERIMARK_CAP_EVENT_CLEAR
#define CAP_FRAME_FINISH VERIMARK_CAP_FRAME_FINISH
#define CAP_N_STATES     VERIMARK_CAP_N_STATES

typedef struct
{
  guint8        acq_kind;
  gint64        frame_deadline_us;   /* set once CAP_FRAME_ACQ has fired */
  gboolean      frame_got;
  GCancellable *cancellable;         /* borrowed from fpi_device_get_cancellable() */
} VerimarkCaptureCtx;

static void
on_cap_event_config_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                          GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  (void) status;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  /* event.py:51 — new event_seq_num is a u16 at response offset 64. */
  if (resp_len >= VERIMARK_EVENT_CONFIG_RESP_LEN)
    self->event_seq_num = moc_rd_u16le (resp + 64);

  fpi_ssm_next_state (ssm);
}

static void
on_cap_wait_press_done (FpDevice *dev, gboolean got, guint8 seq, GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) seq;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!got)
    {
      /* p2_moc.py:314-315 `if wait_intr_event(...) is None: return False` —
       * no press before the deadline; report as a retry-able condition
       * rather than a hard protocol error (mirrors goodixmoc's
       * FP_DEVICE_RETRY_GENERAL capture-failure idiom). */
      fpi_ssm_mark_failed (ssm, fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                                          "no finger detected"));
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_cap_frame_acq_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                       GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  VerimarkCaptureCtx *ctx = fpi_ssm_get_data (ssm);

  (void) dev;
  (void) status;   /* p2_moc.py:320 `comm.send_command(acq, 2)` — return value unused */
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  ctx->frame_deadline_us = g_get_monotonic_time ()
    + (gint64) VERIMARK_CAPTURE_FRAME_TIMEOUT_MS * 1000;
  fpi_ssm_next_state (ssm);
}

static void
on_cap_wait_frame_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                        GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  VerimarkCaptureCtx *ctx = fpi_ssm_get_data (ssm);
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  gboolean past_deadline;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  past_deadline = g_get_monotonic_time () >= ctx->frame_deadline_us;

  if (status >= VERIMARK_EVTREAD_NOTREADY_LO && status <= VERIMARK_EVTREAD_NOTREADY_HI)
    {
      /* evt_read l.278-279 — "no events yet", retry (bounded). */
      if (past_deadline)
        {
          ctx->frame_got = FALSE;
          fpi_ssm_next_state (ssm);
          return;
        }
      fpi_ssm_jump_to_state_delayed (ssm, CAP_WAIT_FRAME,
                                     VERIMARK_CAPTURE_FRAME_POLL_DELAY_MS);
      return;
    }
  if (status != 0x0000)
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "EVENT_READ status 0x%04x", status));
      return;
    }

  if (resp_len >= 6)
    {
      guint16 num_evts = moc_rd_u16le (resp + 2);
      guint16 i;
      gboolean saw_frame_ready = FALSE;

      for (i = 0; i < num_evts && (gsize) (6 + (i + 1) * 12) <= resp_len; i++)
        if (resp[6 + i * 12] == VERIMARK_EVT_FRAME_READY)
          saw_frame_ready = TRUE;

      /* event.py:89 — host-side sequence number tracks how many events were
       * consumed, regardless of which types they were. */
      self->event_seq_num = (guint16) (self->event_seq_num + num_evts);

      if (saw_frame_ready)
        {
          ctx->frame_got = TRUE;
          fpi_ssm_next_state (ssm);
          return;
        }
    }

  if (past_deadline)
    {
      ctx->frame_got = FALSE;
      fpi_ssm_next_state (ssm);
      return;
    }
  fpi_ssm_jump_to_state_delayed (ssm, CAP_WAIT_FRAME,
                                 VERIMARK_CAPTURE_FRAME_POLL_DELAY_MS);
}

static void
on_cap_frame_finish_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                          GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  VerimarkCaptureCtx *ctx = fpi_ssm_get_data (ssm);

  (void) dev;
  (void) status;
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (ctx->frame_got)
    fpi_ssm_mark_completed (ssm);
  else
    fpi_ssm_mark_failed (ssm, fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                                        "no usable frame (0x18 not observed)"));
}

static void
capture_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  VerimarkCaptureCtx *ctx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_ARM_PRESS:
      {
        guint8 cmd[VERIMARK_EVENT_CONFIG_CMD_LEN];
        gsize len = build_event_config (cmd, VERIMARK_EVTMASK_FINGER);

        verimark_moc_send (dev, cmd, len, VERIMARK_EVENT_CONFIG_RESP_LEN,
                           ctx->cancellable, on_cap_event_config_done, ssm);
        break;
      }

    case CAP_WAIT_PRESS:
      verimark_intr_wait_async (dev, VERIMARK_EVT_FINGER_PRESS,
                                VERIMARK_CAPTURE_PRESS_TIMEOUT_MS,
                                ctx->cancellable, on_cap_wait_press_done, ssm);
      break;

    case CAP_ARM_FRAME:
      {
        guint8 cmd[VERIMARK_EVENT_CONFIG_CMD_LEN];
        gsize len = build_event_config (cmd, VERIMARK_EVTMASK_FRAME);

        verimark_moc_send (dev, cmd, len, VERIMARK_EVENT_CONFIG_RESP_LEN,
                           ctx->cancellable, on_cap_event_config_done, ssm);
        break;
      }

    case CAP_FRAME_ACQ:
      {
        guint8 cmd[17];
        gsize len = verimark_moc_build_frame_acq (cmd, ctx->acq_kind);

        verimark_moc_send (dev, cmd, len, 2, ctx->cancellable, on_cap_frame_acq_done, ssm);
        break;
      }

    case CAP_WAIT_FRAME:
      {
        guint8 cmd[VERIMARK_EVENT_READ_CMD_LEN];
        FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
        gsize len = build_event_read (cmd, self->event_seq_num);

        verimark_moc_send (dev, cmd, len, VERIMARK_EVENT_READ_RESP_LEN,
                           ctx->cancellable, on_cap_wait_frame_done, ssm);
        break;
      }

    case CAP_EVENT_CLEAR:
      {
        guint8 cmd[VERIMARK_EVENT_CONFIG_CMD_LEN];
        gsize len = build_event_config (cmd, VERIMARK_EVTMASK_NONE);

        verimark_moc_send (dev, cmd, len, VERIMARK_EVENT_CONFIG_RESP_LEN,
                           ctx->cancellable, on_cap_event_config_done, ssm);
        break;
      }

    case CAP_FRAME_FINISH:
      {
        guint8 cmd[1];
        gsize len = verimark_moc_build_frame_finish (cmd);

        verimark_moc_send (dev, cmd, len, 2, ctx->cancellable, on_cap_frame_finish_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

FpiSsm *
verimark_moc_capture_ssm_new (FpDevice *dev, guint8 acq_kind)
{
  VerimarkCaptureCtx *ctx;
  FpiSsm *ssm;

  ctx = g_new0 (VerimarkCaptureCtx, 1);
  ctx->acq_kind = acq_kind;
  ctx->cancellable = fpi_device_get_cancellable (dev);

  ssm = fpi_ssm_new (dev, capture_ssm_handler, CAP_N_STATES);
  fpi_ssm_set_data (ssm, ctx, g_free);
  return ssm;
}

/* ============================================================================
 * FpPrint ↔ template-id mapping (§5, Task 8) — goodixmoc pattern
 * (re/synaTudor-rev/.../drivers/goodixmoc/goodix.c l.936-968, 1116-1160).
 *
 * §5 open question (findings/51, PORTING-PLAN.md §5): the id minted at
 * enroll / echoed by verify (16 B, "minted_tid") differs from the id the
 * 0x9f DB2_GET_OBJ_LIST enumerates ("list_gid") — the mapping between them
 * (hypothesised to be exactly what 0xa0 GET_OBJ_INFO resolves) is
 * [DEFERRED: device] (Task 7 Step 1a). Mitigation until resolved: store
 * BOTH ids, zero-filled where not known at construction time:
 *   - enroll-built prints know minted_tid (list_gid unknown until a
 *     subsequent list() correlates it — not attempted here);
 *   - list-built prints know list_gid (minted_tid unknown without a 0xa0
 *     lookup — not attempted here either, kept as a documented gap).
 * Verify/identify match on minted_tid (findings/51: mint==verify echo).
 * Delete resolves via 0xa0 on whichever id is present, preferring
 * list_gid since that's what mode_delete's wire flow expects as input.
 * ========================================================================= */

#define VERIMARK_PRINT_DATA_FORMAT "(y@ay@ay@ay)"

static GVariant *
verimark_build_print_data (guint8 finger, const guint8 minted_tid[16],
                           const guint8 list_gid[16],
                           const guint8 *user_id, gsize user_id_len)
{
  GVariant *tid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, minted_tid, 16, 1);
  GVariant *gid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, list_gid, 16, 1);
  GVariant *uid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, user_id, user_id_len, 1);

  return g_variant_new (VERIMARK_PRINT_DATA_FORMAT, finger, tid, gid, uid);
}

static gboolean
verimark_parse_print_data (GVariant      *data,
                           guint8        *finger,
                           const guint8 **minted_tid, gsize *minted_tid_len,
                           const guint8 **list_gid, gsize *list_gid_len,
                           const guint8 **user_id, gsize *user_id_len)
{
  g_autoptr (GVariant) tid_var = NULL;
  g_autoptr (GVariant) gid_var = NULL;
  g_autoptr (GVariant) uid_var = NULL;

  g_return_val_if_fail (data != NULL, FALSE);

  if (!g_variant_check_format_string (data, VERIMARK_PRINT_DATA_FORMAT, FALSE))
    return FALSE;

  g_variant_get (data, VERIMARK_PRINT_DATA_FORMAT, finger, &tid_var, &gid_var, &uid_var);

  *minted_tid = g_variant_get_fixed_array (tid_var, minted_tid_len, 1);
  *list_gid   = g_variant_get_fixed_array (gid_var, list_gid_len, 1);
  *user_id    = g_variant_get_fixed_array (uid_var, user_id_len, 1);

  return *minted_tid_len == 16 && *list_gid_len == 16;
}

/* /etc/machine-id is 32 lowercase hex chars — decode the first 16 bytes as
 * the SID-synthesis seed (verimark_moc_synth_sid). Falls back to an
 * all-zero seed (matching p2_moc.py's zeroed placeholder) if unreadable —
 * SID acceptance is device-deferred either way (see verimark-moc.h). */
static void
verimark_read_machine_seed (guint8 seed[16])
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gsize i;

  memset (seed, 0, 16);

  if (!g_file_get_contents ("/etc/machine-id", &contents, &len, NULL))
    return;

  for (i = 0; i < 16 && (2 * i + 1) < len; i++)
    {
      guint hi, lo;

      if (sscanf (contents + 2 * i, "%1x", &hi) != 1)
        break;
      if (sscanf (contents + 2 * i + 1, "%1x", &lo) != 1)
        break;
      seed[i] = (guint8) ((hi << 4) | lo);
    }
}

/* ============================================================================
 * Enroll SSM (P4) — p2_moc.py::_run_enroll (l.163-237). [DEFERRED: device].
 * ========================================================================= */

enum
{
  ENR_DEDUP_CAPTURE,
  ENR_DEDUP,
  ENR_CREATE,
  ENR_SAMPLE_CAPTURE,
  ENR_SAMPLE,
  ENR_FINALIZE,
  ENR_COMMIT,
  ENR_N_STATES,
};

typedef struct
{
  gint64        overall_deadline_us;   /* p2_moc.py:172 overall_deadline = now+150 */
  GCancellable *cancellable;
} VerimarkEnrollCtx;

/* Bypasses fpi_ssm_start_subsm() on purpose: a capture failure during the
 * sample loop must retry (p2_moc.py:191-193 `if not moc_capture(...):
 * continue`), not abort the whole enroll like the default subsm-failure
 * propagation would. self->task_ssm is the enroll ssm (set by
 * verimark_moc_enroll() before starting it) — recovered here because
 * FpiSsmCompletedCallback doesn't carry a user_data/parent pointer. */
static void
on_enr_sample_capture_done (FpiSsm *capture_ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  FpiSsm *ssm = self->task_ssm;
  VerimarkEnrollCtx *ectx = fpi_ssm_get_data (ssm);

  (void) capture_ssm;

  if (error != NULL)
    {
      if (g_get_monotonic_time () >= ectx->overall_deadline_us)
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      fpi_device_enroll_progress (dev, self->enroll_stage, NULL, error);
      fpi_ssm_jump_to_state (ssm, ENR_SAMPLE_CAPTURE);
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_enr_dedup_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                   GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) resp;
  (void) resp_len;
  /* p2_moc.py:180-181 — status is logged, not enforced: 0x0509 (no-match)
   * is the expected "proceed" case, but nothing else here raises either. */
  (void) status;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_enr_create_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                    GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (status != 0x0000)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "create-enroll failed: 0x%04x", status));
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_enr_sample_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                    GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkEnrollCtx *ectx = fpi_ssm_get_data (ssm);
  VerimarkMocSample sample;
  GError *perr = NULL;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  /* p2_moc.py:198-208 — a rejected sample (nonzero status) or one that
   * didn't move coverage forward is NOT a hard failure: reposition and
   * capture again, bounded by the overall enroll deadline. */
  if (status != 0x0000 || !verimark_moc_parse_sample (resp, resp_len, &sample, &perr) ||
      sample.coverage == self->enroll_coverage)
    {
      g_clear_error (&perr);
      if (g_get_monotonic_time () >= ectx->overall_deadline_us)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "enroll: add-sample not progressing (last status 0x%04x)",
                                                              status));
          return;
        }
      fpi_ssm_jump_to_state (ssm, ENR_SAMPLE_CAPTURE);
      return;
    }

  self->enroll_coverage = sample.coverage;
  if (self->enroll_stage < VERIMARK_ENROLL_STAGES)
    self->enroll_stage++;
  fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);

  if (sample.coverage == 0x7f)
    {
      /* p2_moc.py:211-213 — sensor mints the template id at coverage
       * completion; the host supplies none. */
      memcpy (self->enroll_template_id, sample.template_id, 16);
      fpi_ssm_next_state (ssm);
      return;
    }

  fpi_ssm_jump_to_state (ssm, ENR_SAMPLE_CAPTURE);
}

static void
on_enr_finalize_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                      GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (status != 0x0000)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "finalize (0x96 03) failed: 0x%04x", status));
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_enr_commit_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                    GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (status != 0x0000)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "commit (0x96 04) failed: 0x%04x", status));
      return;
    }
  fpi_ssm_mark_completed (ssm);
}

static void
enroll_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkEnrollCtx *ectx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENR_DEDUP_CAPTURE:
      /* Hard-fail like p2_moc.py:177-179's `raise SystemExit("no finger for
       * dedup frame")` — the default fpi_ssm_start_subsm() propagation is
       * exactly right here (unlike ENR_SAMPLE_CAPTURE below). */
      fpi_ssm_start_subsm (ssm, verimark_moc_capture_ssm_new (dev, VERIMARK_ACQ_VERIFY));
      break;

    case ENR_DEDUP:
      {
        guint8 cmd[13];
        gsize len = verimark_moc_build_begin_id (cmd);

        verimark_moc_send (dev, cmd, len, 2, ectx->cancellable, on_enr_dedup_done, ssm);
        break;
      }

    case ENR_CREATE:
      {
        guint8 cmd[13];
        gsize len = verimark_moc_build_enroll_create (cmd);

        verimark_moc_send (dev, cmd, len, 6, ectx->cancellable, on_enr_create_done, ssm);
        break;
      }

    case ENR_SAMPLE_CAPTURE:
      fpi_ssm_start (verimark_moc_capture_ssm_new (dev, VERIMARK_ACQ_ENROLL),
                     on_enr_sample_capture_done);
      break;

    case ENR_SAMPLE:
      {
        guint8 cmd[5];
        gsize len = verimark_moc_build_enroll_sample (cmd);

        verimark_moc_send (dev, cmd, len, 82, ectx->cancellable, on_enr_sample_done, ssm);
        break;
      }

    case ENR_FINALIZE:
      {
        guint8 seed[16], sid[28], cmd[124];
        GError *error = NULL;

        verimark_read_machine_seed (seed);
        if (!verimark_moc_synth_sid ((uid_t) getuid (), seed, sid, &error) ||
            !verimark_moc_build_finalize (self->enroll_template_id, sid, cmd, &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        verimark_moc_send (dev, cmd, sizeof (cmd), 2, ectx->cancellable, on_enr_finalize_done, ssm);
        break;
      }

    case ENR_COMMIT:
      {
        guint8 cmd[5];
        gsize len = verimark_moc_build_enroll_commit (cmd);

        verimark_moc_send (dev, cmd, len, 2, ectx->cancellable, on_enr_commit_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
verimark_enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  FpPrint *print = NULL;

  (void) ssm;
  self->task_ssm = NULL;

  if (error != NULL)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);

  {
    g_autofree gchar *user_id = fpi_print_generate_user_id (print);
    static const guint8 zero16[16] = { 0 };
    /* §5: list_gid unknown at enroll time (Task 7 Step 1a, deferred) —
     * stored zeroed; delete falls back to the minted id when list_gid is
     * absent (verimark_moc_delete() below). */
    GVariant *data = verimark_build_print_data (1, self->enroll_template_id, zero16,
                                                (const guint8 *) user_id, strlen (user_id));

    fpi_print_set_type (print, FPI_PRINT_RAW);
    fpi_print_set_device_stored (print, TRUE);
    g_object_set (print, "fpi-data", data, "description", user_id, NULL);
  }

  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

void
verimark_moc_enroll (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkEnrollCtx *ectx;
  FpiSsm *ssm;

  self->enroll_stage = 0;
  self->enroll_coverage = 0;
  memset (self->enroll_template_id, 0, 16);

  ectx = g_new0 (VerimarkEnrollCtx, 1);
  ectx->overall_deadline_us = g_get_monotonic_time ()
    + (gint64) VERIMARK_ENROLL_OVERALL_TIMEOUT_MS * 1000;
  ectx->cancellable = fpi_device_get_cancellable (dev);

  ssm = fpi_ssm_new (dev, enroll_ssm_handler, ENR_N_STATES);
  fpi_ssm_set_data (ssm, ectx, g_free);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, verimark_enroll_ssm_done);
}

/* ============================================================================
 * Verify / identify SSM (P5) — p2_moc.py::mode_verify (l.240-263); reporting
 * shape from goodixmoc fp_verify_cb/fp_verify_ssm_done (goodix.c l.383-450,
 * 495-527). [DEFERRED: device].
 * ========================================================================= */

enum
{
  VFY_CAPTURE,
  VFY_MATCH,
  VFY_N_STATES,
};

typedef struct
{
  gboolean      is_identify;
  guint         attempt;              /* p2_moc.py:249 `for attempt in range(8)` */
  gint64        overall_deadline_us;  /* p2_moc.py:248 deadline = now+45      */
  GCancellable *cancellable;
} VerimarkVerifyCtx;

/* Same rationale as on_enr_sample_capture_done(): bypass fpi_ssm_start_subsm()
 * so a capture failure retries (bounded) instead of aborting verify/identify
 * outright, mirroring mode_verify's attempt loop. */
static void
on_vfy_capture_done (FpiSsm *capture_ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  FpiSsm *ssm = self->task_ssm;
  VerimarkVerifyCtx *vctx = fpi_ssm_get_data (ssm);

  (void) capture_ssm;

  if (error != NULL)
    {
      vctx->attempt++;
      if (vctx->attempt >= VERIMARK_VERIFY_MAX_ATTEMPTS ||
          g_get_monotonic_time () >= vctx->overall_deadline_us)
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      g_error_free (error);
      fpi_ssm_jump_to_state (ssm, VFY_CAPTURE);
      return;
    }
  fpi_ssm_next_state (ssm);
}

/* Looks up @tid (16 B) among @print's stored ids (minted_tid preferred —
 * findings/51: mint==verify echo). Returns TRUE on a match. */
static gboolean
print_matches_tid (FpPrint *print, const guint8 tid[16])
{
  g_autoptr (GVariant) data = NULL;
  guint8 finger;
  const guint8 *minted_tid = NULL, *list_gid = NULL, *user_id = NULL;
  gsize minted_tid_len = 0, list_gid_len = 0, user_id_len = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (data == NULL)
    return FALSE;
  if (!verimark_parse_print_data (data, &finger, &minted_tid, &minted_tid_len,
                                  &list_gid, &list_gid_len, &user_id, &user_id_len))
    return FALSE;

  (void) finger;
  (void) list_gid;
  (void) list_gid_len;
  (void) user_id;
  (void) user_id_len;

  return minted_tid_len == 16 && memcmp (minted_tid, tid, 16) == 0;
}

static void
on_vfy_match_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                   GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  VerimarkVerifyCtx *vctx = fpi_ssm_get_data (ssm);
  VerimarkMocMatch m;
  GError *perr = NULL;
  FpPrint *matched_print = NULL;
  gboolean success = FALSE;

  (void) status;   /* verimark_moc_parse_verify() re-derives it from resp[0:2] */

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!verimark_moc_parse_verify (resp, resp_len, &m, &perr))
    {
      fpi_ssm_mark_failed (ssm, perr);
      return;
    }

  if (m.matched)
    {
      if (!vctx->is_identify)
        {
          FpPrint *print = NULL;

          fpi_device_get_verify_data (dev, &print);
          if (print != NULL && print_matches_tid (print, m.template_id))
            {
              success = TRUE;
              matched_print = print;
            }
        }
      else
        {
          GPtrArray *prints = NULL;
          guint i;

          fpi_device_get_identify_data (dev, &prints);
          for (i = 0; prints != NULL && i < prints->len; i++)
            {
              FpPrint *print = g_ptr_array_index (prints, i);

              if (print_matches_tid (print, m.template_id))
                {
                  matched_print = print;
                  success = TRUE;
                  break;
                }
            }
        }
    }

  if (!vctx->is_identify)
    fpi_device_verify_report (dev, success ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                              matched_print, NULL);
  else
    fpi_device_identify_report (dev, success ? matched_print : NULL,
                                success ? matched_print : NULL, NULL);

  fpi_ssm_mark_completed (ssm);
}

static void
verify_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  VerimarkVerifyCtx *vctx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VFY_CAPTURE:
      fpi_ssm_start (verimark_moc_capture_ssm_new (dev, VERIMARK_ACQ_VERIFY),
                     on_vfy_capture_done);
      break;

    case VFY_MATCH:
      {
        guint8 cmd[13];
        gsize len = verimark_moc_build_begin_id (cmd);

        verimark_moc_send (dev, cmd, len, 177, vctx->cancellable, on_vfy_match_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

/* Mirrors goodixmoc's fp_verify_ssm_done (goodix.c l.495-527): a RETRY-domain
 * failure is surfaced as a report (FPI_MATCH_ERROR / NULL-NULL) *and* as the
 * completion error; anything else is completion-error-only (no report). */
static void
verimark_verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkVerifyCtx *vctx = fpi_ssm_get_data (ssm);
  gboolean is_identify = vctx->is_identify;

  self->task_ssm = NULL;

  if (error != NULL && error->domain == FP_DEVICE_RETRY)
    {
      if (!is_identify)
        fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, g_steal_pointer (&error));
      else
        fpi_device_identify_report (dev, NULL, NULL, g_steal_pointer (&error));
    }

  if (!is_identify)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);
}

static void
verimark_moc_verify_identify_start (FpDevice *dev, gboolean is_identify)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkVerifyCtx *vctx;
  FpiSsm *ssm;

  vctx = g_new0 (VerimarkVerifyCtx, 1);
  vctx->is_identify = is_identify;
  vctx->attempt = 0;
  vctx->overall_deadline_us = g_get_monotonic_time ()
    + (gint64) VERIMARK_VERIFY_OVERALL_TIMEOUT_MS * 1000;
  vctx->cancellable = fpi_device_get_cancellable (dev);

  ssm = fpi_ssm_new (dev, verify_ssm_handler, VFY_N_STATES);
  fpi_ssm_set_data (ssm, vctx, g_free);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, verimark_verify_ssm_done);
}

void
verimark_moc_verify (FpDevice *dev)
{
  verimark_moc_verify_identify_start (dev, FALSE);
}

void
verimark_moc_identify (FpDevice *dev)
{
  verimark_moc_verify_identify_start (dev, TRUE);
}

/* ============================================================================
 * Storage ops (P6) — list (0x9f) / delete (0xa0→0xa3) / clear (0xa5).
 * p2_moc.py::_list (l.848-853), mode_delete (l.860-871). [DEFERRED: device].
 * ========================================================================= */

enum { LIST_GET, LIST_N_STATES };

typedef struct
{
  GPtrArray *prints;   /* owned; stolen into fpi_device_list_complete() on success */
} VerimarkListCtx;

static void
verimark_list_ctx_free (VerimarkListCtx *ctx)
{
  g_clear_pointer (&ctx->prints, g_ptr_array_unref);
  g_free (ctx);
}

static void
on_list_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
             GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  VerimarkListCtx *ctx = fpi_ssm_get_data (ssm);
  guint16 st;
  GArray *ids = NULL;
  GError *perr = NULL;
  guint i;

  (void) status;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!verimark_moc_parse_obj_list (resp, resp_len, &st, &ids, &perr))
    {
      fpi_ssm_mark_failed (ssm, perr);
      return;
    }
  if (st != 0x0000)
    {
      g_array_unref (ids);
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "0x9f object-list status 0x%04x", st));
      return;
    }

  ctx->prints = g_ptr_array_new_with_free_func (g_object_unref);
  for (i = 0; i < ids->len; i++)
    {
      const guint8 *gid = (const guint8 *) &g_array_index (ids, guint8, i * 16);
      static const guint8 zero16[16] = { 0 };
      g_autofree gchar *label = NULL;
      FpPrint *print;
      GVariant *data;
      gsize j;
      GString *hex = g_string_sized_new (32);

      for (j = 0; j < 16; j++)
        g_string_append_printf (hex, "%02x", gid[j]);
      label = g_strdup_printf ("verimark-%s", hex->str);
      g_string_free (hex, TRUE);

      /* §5: minted_tid unknown from a bare 0x9f entry (would need a 0xa0
       * lookup per GUID, deferred — Task 7 Step 1a); stored zeroed. */
      print = fp_print_new (dev);
      data = verimark_build_print_data (1, zero16, gid, (const guint8 *) label, strlen (label));
      fpi_print_set_type (print, FPI_PRINT_RAW);
      fpi_print_set_device_stored (print, TRUE);
      g_object_set (print, "fpi-data", data, "description", label, NULL);
      fpi_print_fill_from_user_id (print, label);
      g_ptr_array_add (ctx->prints, g_object_ref_sink (print));
    }
  g_array_unref (ids);

  fpi_ssm_mark_completed (ssm);
}

static void
list_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case LIST_GET:
      {
        guint8 cmd[2] = { VERIMARK_CMD_DB2_GET_OBJ_LIST, 0x01 };   /* p2_moc.py:849 */

        verimark_moc_send (dev, cmd, sizeof (cmd), 0x400, fpi_device_get_cancellable (dev),
                           on_list_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
verimark_list_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkListCtx *ctx = fpi_ssm_get_data (ssm);

  self->task_ssm = NULL;

  if (error != NULL)
    {
      fpi_device_list_complete (dev, NULL, error);
      return;
    }
  fpi_device_list_complete (dev, g_steal_pointer (&ctx->prints), NULL);
}

void
verimark_moc_list (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkListCtx *ctx;
  FpiSsm *ssm;

  ctx = g_new0 (VerimarkListCtx, 1);
  ssm = fpi_ssm_new (dev, list_ssm_handler, LIST_N_STATES);
  fpi_ssm_set_data (ssm, ctx, (GDestroyNotify) verimark_list_ctx_free);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, verimark_list_ssm_done);
}

enum { DEL_INFO, DEL_DELETE, DEL_N_STATES };

typedef struct
{
  guint8 target_gid[16];   /* the 0x9f-visible id to resolve via 0xa0 */
  guint8 child[16];        /* resolved child/leaf id, from 0xa0's response */
} VerimarkDeleteCtx;

static void
on_del_info_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                  GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  VerimarkDeleteCtx *ctx = fpi_ssm_get_data (ssm);
  GError *perr = NULL;

  (void) dev;
  (void) status;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!verimark_moc_parse_obj_info (resp, resp_len, ctx->child, &perr))
    {
      fpi_ssm_mark_failed (ssm, perr);
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_del_delete_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
                    GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) status;   /* p2_moc.py:869-870 doesn't assert a status on 0xa3 */
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fpi_ssm_mark_completed (ssm);
}

static void
delete_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  VerimarkDeleteCtx *ctx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DEL_INFO:
      {
        guint8 cmd[21];   /* p2_moc.py:865 struct.pack("<BI", 0xa0, 2) + guid */

        cmd[0] = VERIMARK_CMD_DB2_GET_OBJ_INFO;
        wr_u32le (cmd + 1, 2);
        memcpy (cmd + 5, ctx->target_gid, 16);
        verimark_moc_send (dev, cmd, sizeof (cmd), 0x34, fpi_device_get_cancellable (dev),
                           on_del_info_done, ssm);
        break;
      }

    case DEL_DELETE:
      {
        guint8 cmd[21];   /* p2_moc.py:869 struct.pack("<BI", 0xa3, 1) + child */

        cmd[0] = VERIMARK_CMD_DB2_DELETE_OBJ;
        wr_u32le (cmd + 1, 1);
        memcpy (cmd + 5, ctx->child, 16);
        verimark_moc_send (dev, cmd, sizeof (cmd), 4, fpi_device_get_cancellable (dev),
                           on_del_delete_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
verimark_delete_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  (void) ssm;
  self->task_ssm = NULL;
  fpi_device_delete_complete (dev, error);
}

void
verimark_moc_delete (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  FpPrint *print = NULL;
  g_autoptr (GVariant) data = NULL;
  guint8 finger;
  const guint8 *minted_tid = NULL, *list_gid = NULL, *user_id = NULL;
  gsize minted_tid_len = 0, list_gid_len = 0, user_id_len = 0;
  static const guint8 zero16[16] = { 0 };
  VerimarkDeleteCtx *ctx;
  FpiSsm *ssm;
  gboolean have_target = FALSE;
  guint8 target[16] = { 0 };

  fpi_device_get_delete_data (dev, &print);
  if (print != NULL)
    g_object_get (print, "fpi-data", &data, NULL);

  if (data != NULL &&
      verimark_parse_print_data (data, &finger, &minted_tid, &minted_tid_len,
                                 &list_gid, &list_gid_len, &user_id, &user_id_len))
    {
      (void) finger;
      (void) user_id;
      (void) user_id_len;
      /* §5 (Task 7 Step 1a, deferred): prefer the 0x9f-visible list_gid — it's
       * what 0xa0 GET_OBJ_INFO expects as input (mode_delete l.865). Fall
       * back to the minted id (enroll-built prints, list_gid unknown) on
       * the unverified hypothesis that the sensor accepts either as a
       * top-level object id. */
      if (list_gid_len == 16 && memcmp (list_gid, zero16, 16) != 0)
        {
          memcpy (target, list_gid, 16);
          have_target = TRUE;
        }
      else if (minted_tid_len == 16 && memcmp (minted_tid, zero16, 16) != 0)
        {
          memcpy (target, minted_tid, 16);
          have_target = TRUE;
        }
    }

  if (!have_target)
    {
      fpi_device_delete_complete (dev,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "no usable on-device id stored for this print"));
      return;
    }

  ctx = g_new0 (VerimarkDeleteCtx, 1);
  memcpy (ctx->target_gid, target, 16);

  ssm = fpi_ssm_new (dev, delete_ssm_handler, DEL_N_STATES);
  fpi_ssm_set_data (ssm, ctx, g_free);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, verimark_delete_ssm_done);
}

enum { CLR_FORMAT, CLR_N_STATES };

static void
on_clr_done (FpDevice *dev, guint16 status, const guint8 *resp, gsize resp_len,
            GError *error, gpointer user_data)
{
  FpiSsm *ssm = user_data;

  (void) dev;
  (void) status;
  (void) resp;
  (void) resp_len;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fpi_ssm_mark_completed (ssm);
}

static void
clear_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLR_FORMAT:
      {
        /* UNCONFIRMED (PORTING-PLAN.md §7 / this plan's risk list): no
         * captured 0xa5 DB2_FORMAT payload exists anywhere in
         * prototype/p2_moc.py or the rev tree — it has never been sent
         * live. Follows the same "opcode + sub-op 1" shape as the other
         * DB2_* commands (0x9e/0x9f) as a best-effort guess; confirm
         * against a real capture before relying on this. [DEFERRED: device] */
        guint8 cmd[2] = { VERIMARK_CMD_DB2_FORMAT, 0x01 };

        verimark_moc_send (dev, cmd, sizeof (cmd), 4, fpi_device_get_cancellable (dev),
                           on_clr_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
verimark_clear_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  (void) ssm;
  self->task_ssm = NULL;
  fpi_device_clear_storage_complete (dev, error);
}

void
verimark_moc_clear (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, clear_ssm_handler, CLR_N_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, verimark_clear_ssm_done);
}

#endif /* !VERIMARK_MOC_PURE_ONLY */
