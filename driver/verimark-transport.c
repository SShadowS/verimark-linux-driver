/*
 * verimark-transport.c — async EP0 bulk-over-control transport (findings/27).
 *
 * Async, FpiSsm/FpiUsbTransfer port of prototype/control_comm.py::ControlComm
 * (chunk/pad math delegated to verimark-transport-framing.c, unit-tested
 * separately):
 *
 *   _ctrl_write  control_comm.py:60-78   -> VERIMARK_CMD_STATE_WRITE_CHUNK
 *   _ctrl_read   control_comm.py:80-105  -> VERIMARK_CMD_STATE_READ_CHUNK
 *   send_command control_comm.py:107-120 -> verimark_cmd() (write, then read;
 *                                            unlike send_command this layer
 *                                            does NOT wrap/unwrap TLS or
 *                                            parse the status word — that is
 *                                            the caller's job, see
 *                                            verimark-transport.h banner)
 *
 * Async pattern mirrors re/synaTudor-rev/libfprint/libfprint/libfprint/
 * drivers/uru4000.c's write_regs()/read_regs() (fpi_usb_transfer_new +
 * fpi_usb_transfer_fill_control + fpi_usb_transfer_submit for EP0 control
 * transfers) and the FpiSsm loop-via-jump_to_state idiom used throughout
 * libfprint drivers for variable-length command sequences (e.g. goodixmoc's
 * capture loop, goodix.c).
 *
 * The chunked-write count is known up front (verimark_frame_write_chunks()
 * plans it all before any I/O happens), so VERIMARK_CMD_STATE_WRITE_CHUNK
 * simply loops itself via fpi_ssm_jump_to_state() until the plan is
 * exhausted. The chunked-read count is NOT known up front (a short read ends
 * it early, control_comm.py:102-103, only knowable from what the device
 * actually returns), so VERIMARK_CMD_STATE_READ_CHUNK recomputes its next
 * request via verimark_frame_read_chunk_next() each time it loops.
 *
 * Not-ready retry (control_comm.py:90-97, `errno == 110` / ETIMEDOUT ->
 * `time.sleep(0.02)` and retry, up to `retries=25`, control_comm.py:80) is
 * implemented with fpi_ssm_jump_to_state_delayed(), which is libfprint's
 * canonical wrapper around fpi_device_add_timeout() for "re-enter this SSM
 * state after N ms" (see fpi-ssm.c:262) — the idiomatic way to get a timed
 * retry without blocking, rather than calling fpi_device_add_timeout()
 * directly and hand-rolling the state re-entry.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <string.h>

#include "verimark.h"
#include "verimark-transport.h"

/* control_comm.py:80 `def _ctrl_read(self, maxlen, timeout, retries=25):` */
#define VERIMARK_CTRL_READ_MAX_RETRIES    25
/* control_comm.py:96-97 `if getattr(e, "errno", None) == 110: # not ready
 * yet — retry` / `time.sleep(0.02); continue` */
#define VERIMARK_CTRL_READ_RETRY_DELAY_MS 20

enum
{
  VERIMARK_CMD_STATE_WRITE_CHUNK,
  VERIMARK_CMD_STATE_READ_CHUNK,
  VERIMARK_CMD_N_STATES,
};

typedef struct
{
  /* write side — the full chunk plan is computed once, up front, by the
   * pure helper; WRITE_CHUNK just walks it. */
  guint8              *wbuf;              /* zero-padded write buffer, owned */
  VerimarkWriteChunk   wchunks[VERIMARK_WRITE_CHUNKS_MAX];
  guint                wchunk_count;
  guint                wchunk_idx;

  /* read side — recomputed per chunk; total length is not known up front
   * (control_comm.py:102-103, a short read ends the transfer early). */
  GByteArray          *rbuf;
  gsize                rmax;
  gboolean             rfirst;
  guint                rretries;

  GCancellable        *cancellable;       /* owned (extra ref), nullable */
  VerimarkCmdCallback  callback;
  gpointer             user_data;
} VerimarkCmdCtx;

static void
verimark_cmd_ctx_free (VerimarkCmdCtx *ctx)
{
  g_clear_pointer (&ctx->wbuf, g_free);
  g_clear_pointer (&ctx->rbuf, g_byte_array_unref);
  g_clear_object (&ctx->cancellable);
  g_free (ctx);
}

static void
on_write_chunk_done (FpiUsbTransfer *transfer, FpDevice *dev,
                     gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  VerimarkCmdCtx *ctx = fpi_ssm_get_data (ssm);

  (void) transfer;
  (void) dev;

  if (error != NULL)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  ctx->wchunk_idx++;
  if (ctx->wchunk_idx < ctx->wchunk_count)
    fpi_ssm_jump_to_state (ssm, VERIMARK_CMD_STATE_WRITE_CHUNK);
  else
    fpi_ssm_next_state (ssm);
}

static void
on_read_chunk_done (FpiUsbTransfer *transfer, FpDevice *dev,
                    gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  VerimarkCmdCtx *ctx = fpi_ssm_get_data (ssm);

  (void) dev;

  if (error != NULL)
    {
      /* control_comm.py:95-97 — errno 110 (ETIMEDOUT / not-ready) retries;
       * anything else (or retry exhaustion) is a hard failure. GUsb surfaces
       * a USB control-transfer timeout as G_USB_DEVICE_ERROR_TIMED_OUT. */
      if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
          ctx->rretries < VERIMARK_CTRL_READ_MAX_RETRIES)
        {
          ctx->rretries++;
          g_clear_error (&error);
          fpi_ssm_jump_to_state_delayed (ssm, VERIMARK_CMD_STATE_READ_CHUNK,
                                         VERIMARK_CTRL_READ_RETRY_DELAY_MS);
          return;
        }

      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  /* A chunk answered (not a not-ready timeout) — retry budget is per-chunk
   * in the reference (control_comm.py:91 `for _ in range(retries)` is
   * re-entered fresh every `while remaining > 0` iteration), so reset it. */
  ctx->rretries = 0;
  g_byte_array_append (ctx->rbuf, transfer->buffer, (guint) transfer->actual_length);

  if (transfer->actual_length < transfer->length)
    {
      /* short read -> transfer complete, control_comm.py:102-103 */
      fpi_ssm_mark_completed (ssm);
      return;
    }

  if (ctx->rbuf->len >= ctx->rmax)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  ctx->rfirst = FALSE;
  fpi_ssm_jump_to_state (ssm, VERIMARK_CMD_STATE_READ_CHUNK);
}

static void
cmd_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  VerimarkCmdCtx *ctx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIMARK_CMD_STATE_WRITE_CHUNK:
      {
        VerimarkWriteChunk *chunk = &ctx->wchunks[ctx->wchunk_idx];
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

        /* bmRequestType 0x40 = HOST_TO_DEVICE|VENDOR|DEVICE, bRequest 0x16
         * (VERIMARK_CTRL_REQ_WRITE, verimark.h) — control_comm.py:65,76. */
        fpi_usb_transfer_fill_control (transfer,
                                       G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                       G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                       G_USB_DEVICE_RECIPIENT_DEVICE,
                                       VERIMARK_CTRL_REQ_WRITE,
                                       chunk->wvalue, 0,
                                       chunk->len);
        if (chunk->len > 0)
          memcpy (transfer->buffer, ctx->wbuf + chunk->offset, chunk->len);

        fpi_usb_transfer_submit (transfer, VERIMARK_CTRL_TIMEOUT_MS,
                                 ctx->cancellable, on_write_chunk_done, ssm);
        break;
      }

    case VERIMARK_CMD_STATE_READ_CHUNK:
      {
        gsize remaining = ctx->rmax - ctx->rbuf->len;
        gsize want;
        guint16 wvalue;
        FpiUsbTransfer *transfer;

        verimark_frame_read_chunk_next (remaining, ctx->rfirst, &want, &wvalue);

        /* bmRequestType 0xc0 = DEVICE_TO_HOST|VENDOR|DEVICE, bRequest 0x17
         * (VERIMARK_CTRL_REQ_READ, verimark.h) — control_comm.py:92. */
        transfer = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_control (transfer,
                                       G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                       G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                       G_USB_DEVICE_RECIPIENT_DEVICE,
                                       VERIMARK_CTRL_REQ_READ,
                                       wvalue, 0,
                                       want);
        /* short_is_error stays FALSE (the default) — a short read is our
         * *success* signal (control_comm.py:102-103), not an error. */
        fpi_usb_transfer_submit (transfer, VERIMARK_CTRL_TIMEOUT_MS,
                                 ctx->cancellable, on_read_chunk_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
cmd_ssm_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  VerimarkCmdCtx *ctx = fpi_ssm_get_data (ssm);

  if (error != NULL)
    {
      ctx->callback (dev, NULL, error, ctx->user_data);
      return;
    }

  /* Steal rbuf out of ctx before verimark_cmd_ctx_free() runs (it happens
   * right after this completed-callback returns, via the ssm_data destroy
   * notify passed to fpi_ssm_set_data() in verimark_cmd()). */
  ctx->callback (dev, g_steal_pointer (&ctx->rbuf), NULL, ctx->user_data);
}

void
verimark_cmd (FpDevice             *dev,
              const guint8         *cmd,
              gsize                 cmd_len,
              gsize                 resp_max_len,
              GCancellable         *cancellable,
              VerimarkCmdCallback   callback,
              gpointer              user_data)
{
  VerimarkCmdCtx *ctx;
  FpiSsm *ssm;
  gsize wbuf_len;

  g_return_if_fail (FP_IS_DEVICE (dev));
  g_return_if_fail (cmd != NULL || cmd_len == 0);
  g_return_if_fail (callback != NULL);

  ctx = g_new0 (VerimarkCmdCtx, 1);

  wbuf_len = verimark_frame_padded_len (cmd_len);
  if (wbuf_len > 0)
    {
      ctx->wbuf = g_malloc0 (wbuf_len);
      if (cmd_len > 0)
        memcpy (ctx->wbuf, cmd, cmd_len);
      /* bytes [cmd_len, wbuf_len) are the zero pad (control_comm.py:62) and
       * are already zero courtesy of g_malloc0(). */
    }
  ctx->wchunk_count = verimark_frame_write_chunks (cmd_len, ctx->wchunks);
  ctx->wchunk_idx = 0;

  ctx->rmax = MAX (resp_max_len, (gsize) 1);   /* control_comm.py:82 */
  ctx->rbuf = g_byte_array_sized_new ((guint) MIN (ctx->rmax, (gsize) G_MAXUINT));
  ctx->rfirst = TRUE;
  ctx->rretries = 0;

  ctx->cancellable = cancellable != NULL ? g_object_ref (cancellable) : NULL;
  ctx->callback = callback;
  ctx->user_data = user_data;

  ssm = fpi_ssm_new (dev, cmd_ssm_handler, VERIMARK_CMD_N_STATES);
  fpi_ssm_set_data (ssm, ctx, (GDestroyNotify) verimark_cmd_ctx_free);
  fpi_ssm_start (ssm, cmd_ssm_completed);
}

/* =============================================================================
 * verimark_intr_wait_async — async port of prototype/p2_moc.py::wait_intr_event
 * / read_intr (p2_moc.py:91-98, 292-302). ADDITIVE (PORTING-PLAN.md P3): the
 * MOC capture SSM (verimark-moc.c) needs to block on the interrupt-IN
 * endpoint for a FINGER_PRESS (0x01) event without blocking the GLib main
 * loop, so this reuses the same FpiSsm-driven bounded-retry idiom as
 * verimark_cmd()'s not-ready retry above, applied to a single-packet
 * interrupt transfer instead of an EP0 control transfer.
 * ============================================================================= */

/* Per-attempt submit timeout — mirrors p2_moc.py::read_intr's default
 * (800ms) / wait_intr_event's inner read_intr(comm.proxied, 500). Bounded
 * so the SSM re-checks its overall deadline and stays cancellable instead
 * of blocking in one huge libusb call. */
#define VERIMARK_INTR_ATTEMPT_MS 500

enum
{
  VERIMARK_INTR_STATE_READ,
  VERIMARK_INTR_N_STATES,
};

typedef struct
{
  guint8                ep;             /* interrupt-IN endpoint address */
  guint8                want_type;
  gint64                deadline_us;    /* G_MAXINT64 => no timeout (wait forever) */

  gboolean              got;
  guint8                seq;

  GCancellable         *cancellable;    /* owned (extra ref), nullable */
  VerimarkIntrCallback  callback;
  gpointer              user_data;
} VerimarkIntrCtx;

static void
verimark_intr_ctx_free (VerimarkIntrCtx *ctx)
{
  g_clear_object (&ctx->cancellable);
  g_free (ctx);
}

static void
on_intr_read_done (FpiUsbTransfer *transfer, FpDevice *dev,
                   gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  VerimarkIntrCtx *ctx = fpi_ssm_get_data (ssm);
  gint64 now;

  (void) dev;

  if (error != NULL)
    {
      /* A per-attempt timeout is expected/normal — it just means no event
       * arrived in this window; loop until the overall deadline, exactly
       * like p2_moc.py's `while time.time() < deadline: ev = read_intr(...)`. */
      if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
        {
          g_clear_error (&error);
          now = g_get_monotonic_time ();
          if (ctx->deadline_us != G_MAXINT64 && now >= ctx->deadline_us)
            {
              ctx->got = FALSE;
              fpi_ssm_mark_completed (ssm);
              return;
            }
          fpi_ssm_jump_to_state (ssm, VERIMARK_INTR_STATE_READ);
          return;
        }

      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (transfer->actual_length >= 1 && transfer->buffer[0] == ctx->want_type)
    {
      ctx->got = TRUE;
      ctx->seq = transfer->actual_length > 6 ? transfer->buffer[6] : 0;
      fpi_ssm_mark_completed (ssm);
      return;
    }

  /* Some other event type (or a short/empty read) — ignore it and keep
   * waiting, mirroring p2_moc.py's `if ev and ... ev[0] == kind: return ...`
   * (anything else just loops). */
  now = g_get_monotonic_time ();
  if (ctx->deadline_us != G_MAXINT64 && now >= ctx->deadline_us)
    {
      ctx->got = FALSE;
      fpi_ssm_mark_completed (ssm);
      return;
    }
  fpi_ssm_jump_to_state (ssm, VERIMARK_INTR_STATE_READ);
}

static void
intr_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  VerimarkIntrCtx *ctx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIMARK_INTR_STATE_READ:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
        guint            attempt_ms = VERIMARK_INTR_ATTEMPT_MS;

        if (ctx->deadline_us != G_MAXINT64)
          {
            gint64 remaining_us = ctx->deadline_us - g_get_monotonic_time ();

            if (remaining_us <= 0)
              {
                fpi_usb_transfer_unref (transfer);
                ctx->got = FALSE;
                fpi_ssm_mark_completed (ssm);
                return;
              }
            attempt_ms = (guint) MIN ((gint64) VERIMARK_INTR_ATTEMPT_MS,
                                      (remaining_us + 999) / 1000);
          }

        fpi_usb_transfer_fill_interrupt (transfer, ctx->ep, VERIMARK_INTR_MAXPKT);
        fpi_usb_transfer_submit (transfer, attempt_ms,
                                 ctx->cancellable, on_intr_read_done, ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
intr_ssm_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  VerimarkIntrCtx *ctx = fpi_ssm_get_data (ssm);

  if (error != NULL)
    {
      ctx->callback (dev, FALSE, 0, error, ctx->user_data);
      return;
    }

  ctx->callback (dev, ctx->got, ctx->seq, NULL, ctx->user_data);
}

void
verimark_intr_wait_async (FpDevice             *dev,
                          guint8                want_type,
                          guint                 timeout_ms,
                          GCancellable         *cancellable,
                          VerimarkIntrCallback  callback,
                          gpointer              user_data)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  VerimarkIntrCtx *ctx;
  FpiSsm *ssm;

  g_return_if_fail (FP_IS_DEVICE (dev));
  g_return_if_fail (callback != NULL);

  ctx = g_new0 (VerimarkIntrCtx, 1);
  ctx->ep = self->ep_intr_in != 0 ? self->ep_intr_in : VERIMARK_EP_INTR_IN;
  ctx->want_type = want_type;
  ctx->deadline_us = timeout_ms == 0
    ? G_MAXINT64
    : g_get_monotonic_time () + (gint64) timeout_ms * 1000;
  ctx->got = FALSE;
  ctx->seq = 0;
  ctx->cancellable = cancellable != NULL ? g_object_ref (cancellable) : NULL;
  ctx->callback = callback;
  ctx->user_data = user_data;

  ssm = fpi_ssm_new (dev, intr_ssm_handler, VERIMARK_INTR_N_STATES);
  fpi_ssm_set_data (ssm, ctx, (GDestroyNotify) verimark_intr_ctx_free);
  fpi_ssm_start (ssm, intr_ssm_completed);
}

/* =============================================================================
 * verimark_intr_drain_sync — phantom-press fix (see verimark-transport.h).
 *
 * Stale queued 0x83 events (typically a leftover FINGER_PRESS from the
 * previous swipe settling, or FINGER_REMOVE) sit in the kernel/libusb
 * interrupt-transfer queue until read. verimark_intr_wait_async() above
 * accepts the very first matching event it sees, so a stale one satisfies it
 * instantly (0 ms) — the capture SSM then arms a frame wait for a finger
 * that is no longer present, and burns the full
 * VERIMARK_CAPTURE_FRAME_TIMEOUT_MS dead before the caller retries. Draining
 * synchronously right before arming a fresh wait (and once at dev_open())
 * ensures only a truly fresh press can satisfy it.
 * ============================================================================= */

/* Per-read timeout while draining — short because we are only harvesting
 * events that are ALREADY queued; a real "nothing queued" timeout here is
 * the normal/expected way this loop ends. */
#define VERIMARK_INTR_DRAIN_TIMEOUT_MS 8
/* Bounded so a misbehaving device (or a genuine flood of events) can never
 * make this spin forever. */
#define VERIMARK_INTR_DRAIN_MAX_READS  16

void
verimark_intr_drain_sync (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  guint8 ep = self->ep_intr_in != 0 ? self->ep_intr_in : VERIMARK_EP_INTR_IN;
  guint  i;

  g_return_if_fail (FP_IS_DEVICE (dev));

  for (i = 0; i < VERIMARK_INTR_DRAIN_MAX_READS; i++)
    {
      guint8 buf[VERIMARK_INTR_MAXPKT];
      gsize actual_length = 0;
      GError *error = NULL;
      gboolean ok;

      ok = g_usb_device_interrupt_transfer (usb, ep, buf, sizeof (buf),
                                            &actual_length,
                                            VERIMARK_INTR_DRAIN_TIMEOUT_MS,
                                            NULL, &error);
      if (!ok)
        {
          /* Timeout (nothing queued, the expected/normal end of the drain)
           * or any other transport error — either way, stop draining rather
           * than risk masking a real fault as a busy-loop. */
          g_clear_error (&error);
          break;
        }

      if (actual_length == 0)
        break;
    }
}
