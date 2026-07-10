/*
 * verimark-transport-framing.h — PURE EP0 control-transfer framing math.
 *
 * Reproduces the chunk/pad/wValue arithmetic of
 * prototype/control_comm.py::ControlComm._ctrl_write/_ctrl_read
 * (control_comm.py:60-105) as plain, side-effect-free byte math: no GUsb, no
 * FpiSsm, no FpDevice — only <glib.h> for the guint8/gsize/guint16 types.
 * This is what makes it unit-testable offline in
 * driver/tests/test_transport_framing.c without a device, libfprint, or
 * gusb linked in.
 *
 * verimark-transport.c (the async EP0 transport, which DOES need
 * FpiUsbTransfer/FpiSsm/GUsb) is the sole real consumer — it drives these
 * functions to decide what each control-WRITE/-READ call should look like,
 * then does the actual I/O. Kept as a separate header/TU precisely so that
 * boundary is enforced by the includes, not just by convention (SOLID:
 * single responsibility — this module computes framing, it does not do I/O).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

/**
 * VerimarkWriteChunk:
 * @offset: offset into the zero-padded write buffer where this chunk starts
 * @len: length of this chunk in bytes (<= the transport's 4096-byte control
 *   data-stage cap, control_comm.py:20 `MAXCHUNK = 0x1000`; also documented
 *   as %VERIMARK_CTRL_MAXCHUNK in verimark.h — kept as an internal constant
 *   here rather than a shared macro so this header stays glib-only)
 * @wvalue: wValue to send on the control-WRITE (0x40/0x16) for this chunk
 *
 * One physical EP0 control-WRITE call, as planned by
 * verimark_frame_write_chunks().
 */
typedef struct
{
  gsize   offset;
  gsize   len;
  guint16 wvalue;
} VerimarkWriteChunk;

/* Max chunks a single verimark_frame_write_chunks() call can plan for. A
 * command body is never remotely close to this many chunks in practice
 * (4096 B/chunk, commands are at most a few KB); this just bounds the
 * caller-supplied output array. */
#define VERIMARK_WRITE_CHUNKS_MAX 8

/**
 * verimark_frame_padded_len:
 * @unpadded_len: true (unpadded) payload length
 *
 * Padded length control_comm.py's _ctrl_write() would send: @unpadded_len
 * rounded up to a multiple of 8 (control_comm.py:62,
 * `buf = bytes(data) + b"\x00" * ((-truelen) % 8)`).
 *
 * Returns: the padded length.
 */
gsize verimark_frame_padded_len (gsize unpadded_len);

/**
 * verimark_frame_write_chunks:
 * @unpadded_len: true (unpadded) payload length being written
 * @chunks_out: (out caller-allocates): array of at least
 *   %VERIMARK_WRITE_CHUNKS_MAX entries to receive the chunk plan
 *
 * Plans the sequence of EP0 control-WRITE calls control_comm.py::_ctrl_write
 * (control_comm.py:60-78) would issue for a payload of @unpadded_len bytes:
 * pad to a multiple of 8, split at the 4096-byte chunk boundary, and compute
 * each chunk's wValue — continuation-chunk flag 0x4000 on every chunk but
 * the first (control_comm.py:71), full-chunk-more-follows flag 0x8000
 * (control_comm.py:75), and the unpadded length's low 3 bits folded into the
 * *last* chunk's wValue (control_comm.py:73).
 *
 * @unpadded_len == 0 is the degenerate case control_comm.py handles as a
 * single zero-length transfer (control_comm.py:64-66) — this still yields
 * exactly one chunk (len 0, wvalue 0) so callers never need to special-case
 * "no payload".
 *
 * The actual chunk *bytes* (@chunks_out[i].offset/.len into the caller's own
 * zero-padded buffer, sized verimark_frame_padded_len(@unpadded_len)) are
 * left to the caller; this function only computes the framing.
 *
 * Returns: the number of chunks written to @chunks_out (always >= 1, never
 *   more than %VERIMARK_WRITE_CHUNKS_MAX for any realistic command size).
 */
guint verimark_frame_write_chunks (gsize                unpadded_len,
                                    VerimarkWriteChunk  *chunks_out);

/**
 * verimark_frame_read_chunk_next:
 * @remaining: bytes still wanted (control_comm.py's `remaining`, already
 *   floored to >= 1 by the caller per control_comm.py:82,
 *   `remaining = max(maxlen, 1)`)
 * @first: %TRUE if this is the first control-READ of the response
 * @want_out: (out): requested length for this control-READ call
 * @wvalue_out: (out): wValue to send on the control-READ (0xc0/0x17)
 *
 * Plans the *next* EP0 control-READ call control_comm.py::_ctrl_read
 * (control_comm.py:80-105) would issue, given how many bytes are still
 * wanted and whether a chunk has already been read. Unlike the write side,
 * the full read plan cannot be computed up front — a short read ends the
 * transfer early (control_comm.py:102-103) and that is only known once the
 * device actually answers — so this is a per-call "what next" helper rather
 * than a full plan; the async transport (verimark-transport.c) calls it once
 * per control-READ, driven by the actual bytes received so far.
 */
void verimark_frame_read_chunk_next (gsize     remaining,
                                      gboolean  first,
                                      gsize    *want_out,
                                      guint16  *wvalue_out);

G_END_DECLS
