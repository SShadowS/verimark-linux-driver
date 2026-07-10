/*
 * verimark-transport-framing.c — PURE EP0 control-transfer framing math.
 * See verimark-transport-framing.h for the contract; every constant/branch
 * below is cited against prototype/control_comm.py.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "verimark-transport-framing.h"

/* control_comm.py:20 `MAXCHUNK = 0x1000  # 4096 — WinUsb control data-stage
 * cap per chunk`. Also documented (not redefined) as VERIMARK_CTRL_MAXCHUNK
 * in verimark.h — this .c file is the one place that actually needs the
 * numeric value, kept private/local so this TU stays glib-only (see the
 * header banner for why). */
#define FRAME_MAXCHUNK ((gsize) 0x1000)

/* control_comm.py:62 `buf = bytes(data) + b"\x00" * ((-truelen) % 8)` —
 * i.e. round up to the next multiple of 8. */
gsize
verimark_frame_padded_len (gsize unpadded_len)
{
  gsize pad = (gsize) ((-(gssize) unpadded_len) % 8);

  /* C's %, unlike Python's, can hand back a value with the sign of the
   * dividend; unpadded_len is unsigned so -(gssize)unpadded_len is <= 0 and
   * the result is in (-8, 0], normalize to [0, 8) like Python's %. */
  if (((gssize) pad) < 0)
    pad += 8;

  return unpadded_len + pad;
}

/* control_comm.py:60-78 (_ctrl_write). */
guint
verimark_frame_write_chunks (gsize                unpadded_len,
                              VerimarkWriteChunk  *chunks_out)
{
  gsize total = verimark_frame_padded_len (unpadded_len);
  gsize off;
  gboolean first;
  guint n = 0;

  g_return_val_if_fail (chunks_out != NULL, 0);

  /* control_comm.py:64-66 — total == 0 (i.e. unpadded_len == 0, since
   * padding an empty payload is a no-op) is a single zero-length transfer
   * carrying only the (always-zero) low bits of the unpadded length. */
  if (total == 0)
    {
      chunks_out[0].offset = 0;
      chunks_out[0].len = 0;
      chunks_out[0].wvalue = (guint16) (unpadded_len & 7);
      return 1;
    }

  off = 0;
  first = TRUE;
  while (off < total && n < VERIMARK_WRITE_CHUNKS_MAX)
    {
      gsize remaining_total = total - off;
      gsize chunklen = MIN (remaining_total, FRAME_MAXCHUNK);
      gboolean islast = (off + chunklen) >= total;
      guint16 wvalue = first ? 0x0000 : 0x4000;

      if (islast)
        wvalue |= (guint16) (unpadded_len & 7);
      else if (chunklen == FRAME_MAXCHUNK)
        wvalue |= 0x8000;

      chunks_out[n].offset = off;
      chunks_out[n].len = chunklen;
      chunks_out[n].wvalue = wvalue;
      n++;

      off += chunklen;
      first = FALSE;
    }

  return n;
}

/* control_comm.py:80-105 (_ctrl_read), specifically the per-iteration
 * `want`/`wValue` computation (lines 84-89); the short-read early-exit
 * (lines 102-103) is inherently a runtime decision the caller (the async
 * transport) makes from the actual bytes received, not something this pure
 * function can predict. */
void
verimark_frame_read_chunk_next (gsize     remaining,
                                 gboolean  first,
                                 gsize    *want_out,
                                 guint16  *wvalue_out)
{
  gsize want;
  guint16 wvalue;

  g_return_if_fail (want_out != NULL);
  g_return_if_fail (wvalue_out != NULL);

  want = MIN (remaining, FRAME_MAXCHUNK);
  wvalue = first ? 0x0000 : 0x4000;
  if (want == FRAME_MAXCHUNK)
    wvalue |= 0x8000;

  *want_out = want;
  *wvalue_out = wvalue;
}
