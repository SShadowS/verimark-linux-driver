/*
 * Kensington VeriMark Desktop (Synaptics "Tudor" MOC) libfprint driver — SKELETON.
 *
 * Transport: iface 1, EP0 vendor control transfers (bulk-over-EP0-control per
 * findings/27), interrupt-IN reads on EP 0x83 for events. Command choreography
 * (open/pair/TLS/enroll/verify/list/delete) is not yet ported — see
 * driver/PORTING-PLAN.md for the phased plan (P0-P7) and the exact prototype
 * function each phase mirrors.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Source of truth: prototype/p2_moc.py + findings/49, findings/51. Being rebuilt
 * per driver/PORTING-PLAN.md. Earlier contents were derived from the Windows IOCTL
 * surface (findings/21) before the wire protocol was known and were fictional —
 * removed. */

#define FP_COMPONENT "verimark"

#include <string.h>

#include "drivers_api.h"
#include "verimark.h"
#include "verimark-transport-framing.h"  /* pure chunk/pad framing math, reused
                                          * synchronously below (P1/P2 bring-up);
                                          * verimark_cmd() itself (verimark-transport.h)
                                          * is not called directly from this file --
                                          * verimark-moc.c is the sole caller, via
                                          * verimark_moc_send(). */
#include "verimark-transport.h"          /* verimark_intr_drain_sync() --
                                          * phantom-press flush at dev_open() */
#include "verimark-tls.h"
#include "verimark-pairing.h"
#include "verimark-moc.h"

G_DEFINE_TYPE (FpiDeviceVerimark, fpi_device_verimark, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = VERIMARK_VID, .pid = VERIMARK_PID },
  { .vid = 0, .pid = 0, },
};

/* =============================================================================
 * SYNCHRONOUS EP0 CONTROL I/O — used ONLY for dev_open()'s one-time P1/P2
 * bring-up (sid resolution, 0x93 pairing, TLS handshake). Everything AFTER
 * open (enroll/verify/identify/list/delete/clear) goes through the real async
 * transport (verimark_cmd(), verimark-transport.c) via verimark_moc_send()
 * (verimark-moc.c) instead -- this sync path is not reused there.
 *
 * PORTING-PLAN.md §3 #2 chose option (b) for the handshake: a couple of
 * round-trips is cheap to do synchronously at open time rather than modeling
 * the handshake as its own FpiSsm, and fpi-device.h's own doc comment agrees
 * it is "entirely fine to ignore cancellation requests for short operations
 * (e.g. open/close)". We still thread fpi_device_get_cancellable(dev) through
 * every blocking call below so a cancelled open unblocks promptly rather than
 * literally ignoring it.
 *
 * Reuses the SAME chunk/pad framing math as the async transport
 * (verimark_frame_padded_len/write_chunks/read_chunk_next,
 * verimark-transport-framing.h -- pure, unit-tested, unmodified here) and the
 * SAME not-ready retry policy as verimark-transport.c's
 * VERIMARK_CTRL_READ_MAX_RETRIES/_RETRY_DELAY_MS (control_comm.py:80,96-97);
 * those constants are `static` there so they are redefined (not shared) here
 * under different names for the same values, from the same source.
 * ============================================================================= */

#define VERIMARK_SYNC_READ_MAX_RETRIES    25
#define VERIMARK_SYNC_READ_RETRY_DELAY_US 20000

/* control_comm.py:60-78 (_ctrl_write), synchronous form of
 * verimark-transport.c's VERIMARK_CMD_STATE_WRITE_CHUNK. Uses gusb's
 * synchronous g_usb_device_control_transfer() (declared in
 * <gusb/gusb-device.h>, pulled in transitively via fpi-device.h's <gusb.h> --
 * confirmed signature: direction, request_type, recipient, request, value,
 * idx, data, length, actual_length (out), timeout, cancellable, error). */
static gboolean
verimark_ctrl_write_sync (FpDevice *dev, const guint8 *cmd, gsize cmd_len,
                          GCancellable *cancellable, GError **error)
{
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  gsize padded_len = verimark_frame_padded_len (cmd_len);
  g_autofree guint8 *wbuf = NULL;
  VerimarkWriteChunk chunks[VERIMARK_WRITE_CHUNKS_MAX];
  guint n_chunks, i;

  if (padded_len > 0)
    {
      wbuf = g_malloc0 (padded_len);
      if (cmd_len > 0)
        memcpy (wbuf, cmd, cmd_len);
      /* bytes [cmd_len, padded_len) are the zero pad (control_comm.py:62),
       * already zero courtesy of g_malloc0(). */
    }
  n_chunks = verimark_frame_write_chunks (cmd_len, chunks);

  for (i = 0; i < n_chunks; i++)
    {
      VerimarkWriteChunk *chunk = &chunks[i];
      guint8 dummy = 0;
      guint8 *data_ptr = chunk->len > 0 ? wbuf + chunk->offset : &dummy;
      gsize actual = 0;

      /* bmRequestType 0x40 = HOST_TO_DEVICE|VENDOR|DEVICE, bRequest 0x16
       * (VERIMARK_CTRL_REQ_WRITE, verimark.h) — control_comm.py:65,76. */
      if (!g_usb_device_control_transfer (usb,
                                          G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                          G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                          G_USB_DEVICE_RECIPIENT_DEVICE,
                                          VERIMARK_CTRL_REQ_WRITE,
                                          chunk->wvalue, 0,
                                          data_ptr, chunk->len,
                                          &actual,
                                          VERIMARK_CTRL_TIMEOUT_MS,
                                          cancellable, error))
        return FALSE;
    }
  return TRUE;
}

/* control_comm.py:80-105 (_ctrl_read), synchronous form of
 * verimark-transport.c's VERIMARK_CMD_STATE_READ_CHUNK, including the
 * not-ready retry (control_comm.py:95-97) and short-read-ends-the-transfer
 * early exit (control_comm.py:102-103). */
static gboolean
verimark_ctrl_read_sync (FpDevice *dev, gsize resp_max_len, GCancellable *cancellable,
                         guint8 **out_buf, gsize *out_len, GError **error)
{
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  gsize rmax = MAX (resp_max_len, (gsize) 1);   /* control_comm.py:82 */
  GByteArray *acc = g_byte_array_sized_new ((guint) MIN (rmax, (gsize) G_MAXUINT));
  gboolean first = TRUE;
  guint retries = 0;

  while (acc->len < rmax)
    {
      gsize want;
      guint16 wvalue;
      guint8 chunk_buf[VERIMARK_CTRL_MAXCHUNK];
      gsize actual = 0;
      GError *local_error = NULL;

      verimark_frame_read_chunk_next (rmax - acc->len, first, &want, &wvalue);

      /* bmRequestType 0xc0 = DEVICE_TO_HOST|VENDOR|DEVICE, bRequest 0x17
       * (VERIMARK_CTRL_REQ_READ, verimark.h) — control_comm.py:92. */
      if (!g_usb_device_control_transfer (usb,
                                          G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                          G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                          G_USB_DEVICE_RECIPIENT_DEVICE,
                                          VERIMARK_CTRL_REQ_READ,
                                          wvalue, 0,
                                          chunk_buf, want,
                                          &actual,
                                          VERIMARK_CTRL_TIMEOUT_MS,
                                          cancellable, &local_error))
        {
          if (g_error_matches (local_error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
              retries < VERIMARK_SYNC_READ_MAX_RETRIES)
            {
              retries++;
              g_clear_error (&local_error);
              g_usleep (VERIMARK_SYNC_READ_RETRY_DELAY_US);
              continue;
            }
          g_byte_array_unref (acc);
          g_propagate_error (error, local_error);
          return FALSE;
        }

      /* A chunk answered (not a not-ready timeout) — retry budget is
       * per-chunk in the reference, so reset it (mirrors
       * verimark-transport.c's on_read_chunk_done()). */
      retries = 0;
      g_byte_array_append (acc, chunk_buf, (guint) actual);
      first = FALSE;

      if (actual < want)
        break;   /* short read -> transfer complete, control_comm.py:102-103 */
    }

  *out_len = acc->len;
  *out_buf = g_byte_array_free (acc, FALSE);
  return TRUE;
}

/* send_command()'s write-then-read, synchronous form (control_comm.py:107-120,
 * minus TLS wrap/unwrap and status parsing -- same division of labour as the
 * async verimark_cmd(), see verimark-transport.h). The one small reusable
 * helper both the TLS and pairing I/O callbacks below are built on. */
static gboolean
verimark_ctrl_cmd_sync (FpDevice *dev, const guint8 *cmd, gsize cmd_len,
                        gsize resp_max_len, GCancellable *cancellable,
                        guint8 **out_buf, gsize *out_len, GError **error)
{
  if (!verimark_ctrl_write_sync (dev, cmd, cmd_len, cancellable, error))
    return FALSE;
  return verimark_ctrl_read_sync (dev, resp_max_len, cancellable, out_buf, out_len, error);
}

/* VerimarkTlsIo (verimark-tls.h): frames `out` as a TLS_DATA (0x44) command
 * and round-trips it. Wire framing per re/synaTudor-rev/pydrv/tudor/tls/
 * session.py:108 `send_tls_data_command`: struct.pack("<Bxxx",
 * Command.TLS_DATA) + tdata -- i.e. opcode(1) ‖ zero-pad(3) ‖ record-bytes,
 * NOT just opcode+data. Response cap 0x100 (256 B) is the same line's
 * send_command() resp_size; only used for the pre-established 2-round-trip
 * handshake (session.py:67) -- steady-state application data after the
 * handshake goes through verimark_moc_send()'s 0x964-byte cap instead
 * (session.py:33), a different code path (verimark-moc.c) this file does not
 * touch. */
#define VERIMARK_TLS_DATA_HDR_LEN       4
#define VERIMARK_TLS_HANDSHAKE_RESP_MAX 0x100

static gboolean
verimark_tls_io_sync (gpointer io_ctx, const guint8 *out, gsize out_len,
                      guint8 **in, gsize *in_len, GError **error)
{
  FpDevice *dev = FP_DEVICE (io_ctx);
  g_autofree guint8 *framed = g_malloc (VERIMARK_TLS_DATA_HDR_LEN + out_len);

  framed[0] = VERIMARK_CMD_TLS_DATA;
  framed[1] = framed[2] = framed[3] = 0x00;
  if (out_len > 0)
    memcpy (framed + VERIMARK_TLS_DATA_HDR_LEN, out, out_len);

  return verimark_ctrl_cmd_sync (dev, framed, VERIMARK_TLS_DATA_HDR_LEN + out_len,
                                 VERIMARK_TLS_HANDSHAKE_RESP_MAX,
                                 fpi_device_get_cancellable (dev),
                                 in, in_len, error);
}

/* VerimarkPairIo (verimark-pairing.h): unlike the TLS callback above, @out is
 * ALREADY the full wire command here (0x93 ‖ 400-B host cert, 401 B total --
 * built by verimark_pairing_do() itself, sensor.py:187-206) -- no extra
 * framing needed. The reply is always exactly 802 B; verimark_pairing_do()
 * validates that itself, resp_max_len here is just the read loop's cap. */
static gboolean
verimark_pair_io_sync (gpointer io_ctx, const guint8 *out, gsize out_len,
                       guint8 **in, gsize *in_len, GError **error)
{
  FpDevice *dev = FP_DEVICE (io_ctx);

  return verimark_ctrl_cmd_sync (dev, out, out_len, 802,
                                 fpi_device_get_cancellable (dev),
                                 in, in_len, error);
}

/* GET_VERSION (0x01) response layout, prototype/p0_ctrl.py:101-107 (struct
 * "<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", 38 B total, verified by hand and by
 * simulating the format string): status(2) at [0:2], fw_build(4) at [6:10],
 * fw_major(1) [10], fw_minor(1) [11], product_id(1) [13], sensor id(6) at
 * [18:24]. That 6-byte sensor id is the P1/P2 "sid" that keys the pdata
 * filename (verimark_pairing_path(), verimark-pairing.h) -- it is NOT the
 * MOC finalize SID (a different, 28-byte, Windows-style value synthesized by
 * verimark_moc_synth_sid(), verimark-moc.h). Raw (pre-pairing, pre-TLS)
 * command, like GET_START_INFO in the existing PORTING-PLAN.md P1 notes. */
#define VERIMARK_GET_VERSION_RESP_LEN   38
#define VERIMARK_GET_VERSION_SID_OFFSET 18
#define VERIMARK_GET_VERSION_SID_LEN    6

static gboolean
verimark_resolve_sid_sync (FpDevice *dev, GCancellable *cancellable,
                           gchar **sid_out, GError **error)
{
  guint8 cmd = VERIMARK_CMD_GET_VERSION;
  g_autofree guint8 *resp = NULL;
  gsize resp_len = 0;
  GString *hex;
  guint i;

  if (!verimark_ctrl_cmd_sync (dev, &cmd, 1, 256, cancellable, &resp, &resp_len, error))
    return FALSE;

  if (resp_len < VERIMARK_GET_VERSION_RESP_LEN)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                  "GET_VERSION: short reply (%" G_GSIZE_FORMAT " bytes, wanted >= %d)",
                  resp_len, VERIMARK_GET_VERSION_RESP_LEN);
      return FALSE;
    }
  if (resp[0] != 0x00 || resp[1] != 0x00)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                  "GET_VERSION: status 0x%02x%02x", resp[1], resp[0]);
      return FALSE;
    }

  hex = g_string_sized_new (2 * VERIMARK_GET_VERSION_SID_LEN);
  for (i = 0; i < VERIMARK_GET_VERSION_SID_LEN; i++)
    g_string_append_printf (hex, "%02x", resp[VERIMARK_GET_VERSION_SID_OFFSET + i]);

  *sid_out = g_string_free (hex, FALSE);
  return TRUE;
}

/* =============================================================================
 * OPEN / CLOSE
 *
 * dev_open(): claim + endpoint discovery (unchanged shell, see below), THEN
 * the P1/P2 bring-up added by this integration pass: resolve the 6-byte
 * sensor id, load-or-create the TOFU pairing, run the TLS handshake. NEVER
 * re-pairs when a pdata file already exists and loads successfully.
 *
 * Endpoint discovery mirrors uru4000.c's dev_init() interface-lookup idiom
 * (re/synaTudor-rev/libfprint/libfprint/libfprint/drivers/uru4000.c:1260-1340):
 * enumerate g_usb_device_get_interfaces() to find the interface by number, then
 * g_usb_interface_get_endpoints() to confirm the endpoint address, THEN claim.
 * uru4000.c notes endpoint verification "does not seem easily possible with
 * GUsb" in its `#if 0` block — that was against an older libgusb without
 * g_usb_interface_get_endpoints()/g_usb_endpoint_get_address() (both declared in
 * <gusb/gusb-interface.h>/<gusb/gusb-endpoint.h>, pulled in transitively via
 * fpi-device.h's <gusb.h>); this driver uses the modern API instead of
 * hardcoding blindly like goodixmoc's `#define EP_IN` does.
 * ============================================================================= */

/* Shared open-failure path: release whatever was claimed and complete the
 * open with @error (consumed). Only valid once self->iface has been set by
 * the claim below (every call site below is after that point). */
static void
verimark_open_fail (FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);

  g_clear_pointer (&self->tls, verimark_tls_free);
  g_usb_device_release_interface (usb, self->iface, 0, NULL);
  self->iface = 0;
  self->ep_intr_in = 0;

  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  g_autoptr(GPtrArray) interfaces = NULL;
  GUsbInterface *iface = NULL;
  GError *error = NULL;
  guint8 ep_intr_in = 0;
  guint i;

  interfaces = g_usb_device_get_interfaces (usb, &error);
  if (interfaces == NULL)
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  for (i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *cur = g_ptr_array_index (interfaces, i);

      if (g_usb_interface_get_number (cur) == VERIMARK_IFACE)
        {
          iface = cur;
          break;
        }
    }

  if (iface == NULL)
    {
      fpi_device_open_complete (dev,
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "could not find vendor interface %d",
                                                          VERIMARK_IFACE));
      return;
    }

  {
    g_autoptr(GPtrArray) endpoints = g_usb_interface_get_endpoints (iface);
    guint j;

    for (j = 0; endpoints != NULL && j < endpoints->len; j++)
      {
        GUsbEndpoint *ep = g_ptr_array_index (endpoints, j);

        if (g_usb_endpoint_get_address (ep) == VERIMARK_EP_INTR_IN)
          {
            ep_intr_in = VERIMARK_EP_INTR_IN;
            break;
          }
      }
  }

  if (ep_intr_in == 0)
    {
      fpi_device_open_complete (dev,
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "could not find interrupt-IN endpoint 0x%02x on interface %d",
                                                          VERIMARK_EP_INTR_IN, VERIMARK_IFACE));
      return;
    }

  /* Command bytes go OUT/IN over EP0 control transfers (findings/27); no
   * bulk/OUT endpoint is claimed or needed — iface 1 only exposes the
   * interrupt-IN endpoint we just verified above. */
  if (!g_usb_device_claim_interface (usb, VERIMARK_IFACE, 0, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  self->iface = VERIMARK_IFACE;
  self->ep_intr_in = ep_intr_in;
  self->tls = NULL;
  self->pairing = NULL;
  self->sid = NULL;
  /* Superseded by the typed self->pairing set below; kept unused (see
   * verimark.h) rather than removed. */
  self->pairing_data = NULL;
  self->pairing_len = 0;

  /* Phantom-press fix (verimark-transport.h): flush any interrupt-IN (0x83)
   * events already queued from before this open (e.g. a leftover press from
   * whatever last touched the sensor) so the first real capture's
   * press-wait can't be satisfied by stale data. */
  verimark_intr_drain_sync (dev);

  /* ---- P1/P2 bring-up: resolve sid -> load-or-pair -> TLS handshake ----
   * Mirrors prototype/p1_pair.py end-to-end: (1) construct/reset (here:
   * GET_VERSION far enough to read the sid — GET_START_INFO itself carries no
   * information this path needs, PORTING-PLAN.md P1); (2) load an existing
   * pdata for that sid, or TOFU-pair (0x93) and persist a new one if none
   * exists yet; (3) bring up the TLS channel and confirm it establishes. */
  {
    GCancellable *cancellable = fpi_device_get_cancellable (dev);
    g_autofree gchar *sid = NULL;
    g_autofree VerimarkPairing *pd = g_new0 (VerimarkPairing, 1);
    GError *load_error = NULL;

    if (!verimark_resolve_sid_sync (dev, cancellable, &sid, &error))
      {
        verimark_open_fail (dev, error);
        return;
      }

    if (!verimark_pairing_load_file (sid, pd, &load_error))
      {
        if (!g_error_matches (load_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
          {
            /* A real (non-"missing file") error — e.g. permission denied or a
             * corrupt/short pdata file — is not silently papered over with a
             * fresh pair; propagate it. */
            verimark_open_fail (dev, load_error);
            return;
          }
        g_clear_error (&load_error);

        /* No stored pdata for this sid — first open, or a fresh sensor.
         * TOFU-pair now (sensor.py:187-206) and persist the result. NEVER
         * re-pair when a pdata file already exists and loads OK (the branch
         * above already returned in that case). */
        if (!verimark_pairing_do (verimark_pair_io_sync, dev, pd, &error) ||
            !verimark_pairing_save_file (pd, sid, &error))
          {
            verimark_open_fail (dev, error);
            return;
          }
      }

    self->tls = verimark_tls_new (verimark_tls_io_sync, dev);
    verimark_tls_set_pairing (self->tls, pd);
    if (!verimark_tls_handshake (self->tls, &error))
      {
        verimark_open_fail (dev, error);
        return;
      }

    /* Everything succeeded — transfer ownership from the g_autofree locals
     * into the device struct (freed at dev_close()). */
    self->sid = g_steal_pointer (&sid);
    self->pairing = g_steal_pointer (&pd);
  }

  fpi_device_open_complete (dev, NULL);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  GError *error = NULL;

  if (self->tls != NULL)
    {
      verimark_tls_close (self->tls);   /* best-effort close_notify (verimark-tls.h) */
      g_clear_pointer (&self->tls, verimark_tls_free);
    }
  g_clear_pointer (&self->pairing, g_free);
  g_clear_pointer (&self->sid, g_free);
  /* Vestigial (see verimark.h); dev_open() never writes these anymore. */
  g_clear_pointer (&self->pairing_data, g_free);
  self->pairing_len = 0;

  g_usb_device_release_interface (usb, self->iface, 0, &error);
  self->iface = 0;
  self->ep_intr_in = 0;

  fpi_device_close_complete (dev, error);
}

/* =============================================================================
 * ENROLL / VERIFY / IDENTIFY / LIST / DELETE / CLEAR_STORAGE
 *
 * Thin wiring only: each vfunc hands off to the matching verimark_moc_*()
 * entry point (verimark-moc.h/.c), which owns the full choreography (command
 * framing, response parsing, the FpiSsm state machines, and the matching
 * fpi_device_*_complete() call) — ported from prototype/p2_moc.py's
 * `_run_enroll`, `mode_verify`, `_list`, `mode_delete` per PORTING-PLAN.md
 * P4/P5/P6. On-device behavior is [DEFERRED: device] per verimark-moc.h's own
 * banner; the wire framing itself is implemented and offline-tested
 * (driver/tests/test_moc.c).
 * ============================================================================= */
static void
dev_enroll (FpDevice *dev)
{
  verimark_moc_enroll (dev);
}

static void
dev_verify (FpDevice *dev)
{
  verimark_moc_verify (dev);
}

static void
dev_identify (FpDevice *dev)
{
  verimark_moc_identify (dev);
}

static void
dev_list (FpDevice *dev)
{
  verimark_moc_list (dev);
}

static void
dev_delete (FpDevice *dev)
{
  verimark_moc_delete (dev);
}

static void
dev_clear_storage (FpDevice *dev)
{
  verimark_moc_clear (dev);
}

static void
dev_cancel (FpDevice *dev)
{
  (void) dev;

  /* Deliberately near-empty. Every in-flight transfer already carries
   * fpi_device_get_cancellable(dev) as its GCancellable — verimark_cmd() /
   * verimark_intr_wait_async() (verimark-transport.c) and verimark_moc_send()
   * (verimark-moc.c) all take it directly, and it IS the same GCancellable
   * object the base FpDevice class is reacting to right now:
   * fpi_device_get_cancellable() returns g_task_get_cancellable() on the
   * current action's GTask (fpi-device.c:562-582), i.e. exactly the
   * cancellable the caller passed to fp_device_enroll/verify/... — and it is
   * that same object's "cancelled" signal which invoked this very vfunc
   * (fp-device.c's fp_device_cancelled_cb()/maybe_cancel_on_cancelled()).
   * g_cancellable_cancel() has therefore already fired for every pending
   * FpiUsbTransfer by the time dev_cancel() runs; each one's completion
   * callback sees the cancellation error on its own and unwinds its FpiSsm
   * (fpi_ssm_mark_failed()) exactly like any other transport failure — there
   * is nothing left here to actively abort.
   *
   * This differs from goodixmoc's dev_cancel (goodix.c: g_cancellable_cancel
   * + g_clear_object + g_cancellable_new on a private `self->cancellable`),
   * which threads its OWN cancellable through its transfers instead of
   * fpi_device_get_cancellable() and therefore must explicitly cancel-and-
   * replace it on every cancel — a step that is a no-op here because this
   * driver deliberately reuses the device's own action cancellable
   * everywhere (verimark-moc.c/-transport.c already do this consistently;
   * DRY). self->task_ssm (verimark-moc.c) needs no separate action either:
   * FpiSsm has no public abort entry point beyond that same cancellable
   * (fpi-ssm.h), and every verimark_moc_*() entry point already clears
   * self->task_ssm back to NULL from its own completed-callback once the
   * unwind above runs. */
}

/* =============================================================================
 * GObject / class boilerplate
 * ============================================================================= */
static void
fpi_device_verimark_init (FpiDeviceVerimark *self)
{
  (void) self;
}

static void
fpi_device_verimark_class_init (FpiDeviceVerimarkClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id               = "verimark";
  dev_class->full_name        = "Kensington VeriMark Desktop (Synaptics Tudor MOC)";
  dev_class->type             = FP_DEVICE_TYPE_USB;
  dev_class->id_table         = id_table;
  dev_class->scan_type        = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = VERIMARK_ENROLL_STAGES;
  /* NB: FP_DEVICE_FEATURE_STORAGE_LIST is deliberately NOT advertised. With it,
   * fprintd's check_local_storage() (src/device.c) runs after any *no-match*
   * verify and deletes every host print whose fpi-data isn't byte-equal to a
   * device-listed print. Enroll stores the id in the minted_tid field while
   * list returns it as list_gid (and the two GUIDs even differ, findings/51),
   * so fp_print_equal never matches and a single no-match PURGES the just-
   * enrolled template. Until enroll/list emit reconcilable fpi-data (needs the
   * unverified 0xa0 minted<->list GUID bridge), withholding STORAGE_LIST keeps
   * the no-match non-destructive. dev_list stays wired for explicit callers;
   * STORAGE_DELETE/CLEAR remain for user-initiated deletes. */
  dev_class->features         = FP_DEVICE_FEATURE_IDENTIFY |
                                FP_DEVICE_FEATURE_VERIFY |
                                FP_DEVICE_FEATURE_STORAGE |
                                FP_DEVICE_FEATURE_STORAGE_DELETE |
                                FP_DEVICE_FEATURE_STORAGE_CLEAR;

  dev_class->open           = dev_open;
  dev_class->close          = dev_close;
  dev_class->enroll         = dev_enroll;
  dev_class->verify         = dev_verify;
  dev_class->identify       = dev_identify;
  dev_class->list           = dev_list;
  dev_class->delete         = dev_delete;
  dev_class->clear_storage  = dev_clear_storage;
  dev_class->cancel         = dev_cancel;
}
