/*
 * test_transport_framing.c — TDD unit tests for the PURE EP0 framing helpers
 * in verimark-transport.c (verimark_frame_padded_len / _write_chunks /
 * _read_chunk_next). No GUsb/FpiSsm/device needed — only glib.
 *
 * Expected values below were cross-checked against prototype/control_comm.py
 * (`_ctrl_write` / `_ctrl_read`, lines 60-105) by running the same arithmetic
 * in Python directly against MAXCHUNK = 0x1000 (control_comm.py:20); see the
 * scratch computation cited in changelog for this session — every case here
 * reproduces its output exactly.
 *
 * Written FIRST (red: verimark-transport.c did not yet exist), then made to
 * pass (green) by implementing the helpers per this spec.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <glib.h>
#include <string.h>
#include "../verimark-transport-framing.h"

/* Mirrors control_comm.py:20 `MAXCHUNK = 0x1000` / verimark.h's documented
 * (but, post-split, unused-by-the-pure-layer) VERIMARK_CTRL_MAXCHUNK — kept
 * as a local test constant rather than a shared macro so this test binary
 * only needs <glib.h>, not verimark.h's fpi-device.h/fpi-usb-transfer.h
 * (gusb) chain. */
#define TEST_MAXCHUNK 0x1000

/* ---- verimark_frame_padded_len -------------------------------------------
 * control_comm.py:62 `buf = bytes(data) + b"\x00" * ((-truelen) % 8)`.
 * ------------------------------------------------------------------------- */
static void
test_padded_len (void)
{
  g_assert_cmpuint (verimark_frame_padded_len (0), ==, 0);
  g_assert_cmpuint (verimark_frame_padded_len (1), ==, 8);
  g_assert_cmpuint (verimark_frame_padded_len (7), ==, 8);
  g_assert_cmpuint (verimark_frame_padded_len (8), ==, 8);
  g_assert_cmpuint (verimark_frame_padded_len (9), ==, 16);
  g_assert_cmpuint (verimark_frame_padded_len (200), ==, 200);
  g_assert_cmpuint (verimark_frame_padded_len (4200), ==, 4200);
  g_assert_cmpuint (verimark_frame_padded_len (5001), ==, 5008);
}

/* Helper: assert a single-chunk write plan (the common case: payload fits in
 * one control-WRITE, i.e. padded length <= TEST_MAXCHUNK). */
static void
assert_single_chunk (gsize unpadded_len, gsize expect_len, guint16 expect_wvalue)
{
  VerimarkWriteChunk chunks[VERIMARK_WRITE_CHUNKS_MAX];
  guint n;

  n = verimark_frame_write_chunks (unpadded_len, chunks);
  g_assert_cmpuint (n, ==, 1);
  g_assert_cmpuint (chunks[0].offset, ==, 0);
  g_assert_cmpuint (chunks[0].len, ==, expect_len);
  g_assert_cmphex (chunks[0].wvalue, ==, expect_wvalue);
}

/* ---- verimark_frame_write_chunks — single-chunk cases --------------------
 * Reference (control_comm.py::_ctrl_write, lines 60-78), computed for
 * MAXCHUNK = 0x1000 (control_comm.py:20):
 *   len=0   -> padded 0   -> [(off=0, len=0,   wValue=0x0000)]  (special
 *                             zero-length transfer, control_comm.py:64-66)
 *   len=1   -> padded 8   -> [(0, 8,   0x0001)]
 *   len=7   -> padded 8   -> [(0, 8,   0x0007)]
 *   len=8   -> padded 8   -> [(0, 8,   0x0000)]   (8 & 7 == 0)
 *   len=9   -> padded 16  -> [(0, 16,  0x0001)]
 *   len=200 -> padded 200 -> [(0, 200, 0x0000)]   (200 & 7 == 0)
 * ------------------------------------------------------------------------- */
static void
test_write_chunks_single (void)
{
  assert_single_chunk (0, 0, 0x0000);
  assert_single_chunk (1, 8, 0x0001);
  assert_single_chunk (7, 8, 0x0007);
  assert_single_chunk (8, 8, 0x0000);
  assert_single_chunk (9, 16, 0x0001);
  assert_single_chunk (200, 200, 0x0000);
}

/* ---- verimark_frame_write_chunks — >MAXCHUNK (multi-chunk) cases ---------
 * Reference:
 *   len=4200 -> padded 4200 (4200 % 8 == 0) ->
 *     [(off=0,    len=4096, wValue=0x8000),   # first chunk, full, more follows
 *      (off=4096, len=104,  wValue=0x4000)]   # continuation, last, (4200&7)=0
 *   len=5001 -> padded 5008 (pad = 7) ->
 *     [(off=0,    len=4096, wValue=0x8000),
 *      (off=4096, len=912,  wValue=0x4001)]   # continuation, last, (5001&7)=1
 * ------------------------------------------------------------------------- */
static void
test_write_chunks_multi (void)
{
  VerimarkWriteChunk chunks[VERIMARK_WRITE_CHUNKS_MAX];
  guint n;

  n = verimark_frame_write_chunks (4200, chunks);
  g_assert_cmpuint (n, ==, 2);
  g_assert_cmpuint (chunks[0].offset, ==, 0);
  g_assert_cmpuint (chunks[0].len, ==, 0x1000);
  g_assert_cmphex (chunks[0].wvalue, ==, 0x8000);
  g_assert_cmpuint (chunks[1].offset, ==, 0x1000);
  g_assert_cmpuint (chunks[1].len, ==, 104);
  g_assert_cmphex (chunks[1].wvalue, ==, 0x4000);

  n = verimark_frame_write_chunks (5001, chunks);
  g_assert_cmpuint (n, ==, 2);
  g_assert_cmpuint (chunks[0].offset, ==, 0);
  g_assert_cmpuint (chunks[0].len, ==, 0x1000);
  g_assert_cmphex (chunks[0].wvalue, ==, 0x8000);
  g_assert_cmpuint (chunks[1].offset, ==, 0x1000);
  g_assert_cmpuint (chunks[1].len, ==, 912);
  g_assert_cmphex (chunks[1].wvalue, ==, 0x4001);
}

/* All chunk offsets/lens must tile [0, padded_len) with no gaps/overlap, for
 * every case above — a property check on top of the exact-value checks. */
static void
test_write_chunks_tile_exactly (void)
{
  const gsize lens[] = { 0, 1, 7, 8, 9, 200, 4200, 5001, 4096, 4097, 8192, 8193 };
  guint i;

  for (i = 0; i < G_N_ELEMENTS (lens); i++)
    {
      VerimarkWriteChunk chunks[VERIMARK_WRITE_CHUNKS_MAX];
      gsize padded = verimark_frame_padded_len (lens[i]);
      gsize expect_off = 0;
      guint n = verimark_frame_write_chunks (lens[i], chunks);
      guint j;

      g_assert_cmpuint (n, >=, 1);
      for (j = 0; j < n; j++)
        {
          g_assert_cmpuint (chunks[j].offset, ==, expect_off);
          g_assert_cmpuint (chunks[j].len, <=, TEST_MAXCHUNK);
          expect_off += chunks[j].len;
        }
      /* len=0 is the special zero-length-transfer case: it "tiles" a
       * zero-length padded buffer, i.e. contributes no bytes. */
      if (lens[i] == 0)
        g_assert_cmpuint (expect_off, ==, 0);
      else
        g_assert_cmpuint (expect_off, ==, padded);

      /* Only the last chunk may fold in the unpadded-length low bits or be
       * short; every non-last chunk must be exactly MAXCHUNK. */
      for (j = 0; j + 1 < n; j++)
        g_assert_cmpuint (chunks[j].len, ==, TEST_MAXCHUNK);
    }
}

/* ---- verimark_frame_read_chunk_next --------------------------------------
 * Reference (control_comm.py::_ctrl_read, lines 80-105), MAXCHUNK = 0x1000:
 *   remaining=1,    first=TRUE  -> want=1,    wValue=0x0000
 *   remaining=2,    first=TRUE  -> want=2,    wValue=0x0000
 *   remaining=8,    first=TRUE  -> want=8,    wValue=0x0000
 *   remaining=4096, first=TRUE  -> want=4096, wValue=0x8000
 *   remaining=5000, first=TRUE  -> want=4096, wValue=0x8000   (clamped)
 *   remaining=904,  first=FALSE -> want=904,  wValue=0x4000
 *   remaining=8192, first=FALSE -> want=4096, wValue=0xC000   (0x4000|0x8000)
 * ------------------------------------------------------------------------- */
static void
assert_read_next (gsize remaining, gboolean first, gsize expect_want, guint16 expect_wvalue)
{
  gsize want;
  guint16 wvalue;

  verimark_frame_read_chunk_next (remaining, first, &want, &wvalue);
  g_assert_cmpuint (want, ==, expect_want);
  g_assert_cmphex (wvalue, ==, expect_wvalue);
}

static void
test_read_chunk_next (void)
{
  assert_read_next (1, TRUE, 1, 0x0000);
  assert_read_next (2, TRUE, 2, 0x0000);
  assert_read_next (8, TRUE, 8, 0x0000);
  assert_read_next (4096, TRUE, 4096, 0x8000);
  assert_read_next (5000, TRUE, 4096, 0x8000);
  assert_read_next (904, FALSE, 904, 0x4000);
  assert_read_next (8192, FALSE, 4096, 0xC000);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/verimark/transport/padded-len", test_padded_len);
  g_test_add_func ("/verimark/transport/write-chunks/single", test_write_chunks_single);
  g_test_add_func ("/verimark/transport/write-chunks/multi", test_write_chunks_multi);
  g_test_add_func ("/verimark/transport/write-chunks/tile-exactly", test_write_chunks_tile_exactly);
  g_test_add_func ("/verimark/transport/read-chunk-next", test_read_chunk_next);

  return g_test_run ();
}
