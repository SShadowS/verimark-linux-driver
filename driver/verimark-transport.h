/*
 * verimark-transport.h — async EP0 bulk-over-control transport (findings/27).
 *
 * Reproduces prototype/control_comm.py::ControlComm._ctrl_write/_ctrl_read/
 * send_command (see verimark-transport.c banner for exact line citations) as
 * an async, FpiSsm-driven primitive. This module knows nothing about TLS
 * records or MOC opcodes — it moves raw bytes out over EP0 control-WRITE
 * (0x40/0x16) and raw bytes back over EP0 control-READ (0xc0/0x17), chunked
 * and padded exactly like the Python reference, with not-ready retry on the
 * read side. That keeps it reusable, unmodified, by both the (unencrypted)
 * P1 commands, the TLS handshake's raw record I/O (verimark-tls.c, separate
 * track), and the steady-state MOC command layer (PORTING-PLAN.md §2).
 *
 * The chunk/pad arithmetic itself lives in verimark-transport-framing.h/.c —
 * pure functions, unit-tested in driver/tests/test_transport_framing.c —
 * this header/module is the async I/O driver on top of them.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fpi-device.h"
#include "verimark-transport-framing.h"

G_BEGIN_DECLS

/**
 * VerimarkCmdCallback:
 * @dev: the device the command was sent to
 * @response: (transfer full) (nullable): accumulated raw response bytes on
 *   success, caller must g_byte_array_unref(); %NULL on error
 * @error: (transfer full) (nullable): %NULL on success
 * @user_data: as passed to verimark_cmd()
 */
typedef void (*VerimarkCmdCallback) (FpDevice   *dev,
                                     GByteArray *response,
                                     GError     *error,
                                     gpointer    user_data);

/**
 * verimark_cmd:
 * @dev: the device
 * @cmd: (nullable): raw bytes to write (already-assembled opcode+payload for
 *   an unencrypted P1 command, or an already TLS-wrapped record once
 *   verimark-tls.c exists — this function does not care which)
 * @cmd_len: length of @cmd (0 is valid — a read-only probe)
 * @resp_max_len: maximum bytes to read back (mirrors control_comm.py's
 *   send_command() `resp_size`, control_comm.py:107-120); the transport
 *   stops early on a short read exactly like the reference
 * @cancellable: (nullable): cancellable for the whole write+read sequence
 * @callback: called exactly once with the result
 * @user_data: passed through to @callback
 *
 * Runs one full command/response round-trip over the EP0 bulk-over-control
 * transport: chunked+padded WRITE (0x40/0x16) of @cmd, then chunked READ
 * (0xc0/0x17) of up to @resp_max_len bytes, retrying individual read chunks
 * on a device-not-ready (%G_USB_DEVICE_ERROR_TIMED_OUT) response — see
 * verimark-transport.c for the state machine and retry-count/delay
 * constants. Owns and drives its own internal #FpiSsm; the caller does not
 * need to create or manage one.
 */
void verimark_cmd (FpDevice             *dev,
                    const guint8         *cmd,
                    gsize                 cmd_len,
                    gsize                 resp_max_len,
                    GCancellable         *cancellable,
                    VerimarkCmdCallback   callback,
                    gpointer              user_data);

/**
 * VerimarkIntrCallback:
 * @dev: the device
 * @got: %TRUE if an interrupt-IN (0x83) event of the requested type arrived
 *   before @timeout_ms elapsed; %FALSE on a clean timeout (not an error —
 *   mirrors prototype/p2_moc.py::wait_intr_event returning %None)
 * @seq: the event's sequence byte (mirrors p2_moc.py `ev[6] if len(ev) > 6
 *   else 0`); only meaningful when @got is %TRUE
 * @error: (transfer full) (nullable): non-%NULL only on a real transport
 *   failure (not on timeout, which reports via @got instead)
 * @user_data: as passed to verimark_intr_wait_async()
 */
typedef void (*VerimarkIntrCallback) (FpDevice *dev,
                                      gboolean  got,
                                      guint8    seq,
                                      GError   *error,
                                      gpointer  user_data);

/**
 * verimark_intr_wait_async:
 * @dev: the device
 * @want_type: the interrupt-EP event byte[0] to wait for (e.g. FINGER_PRESS
 *   = 0x01, per prototype/p2_moc.py FINGER_PRESS/FINGER_REMOVE)
 * @timeout_ms: overall bound on how long to wait; 0 means "wait forever"
 *   (mirrors VERIMARK_INTR_TIMEOUT_MS's "0 = no timeout" convention,
 *   verimark.h) — used as the *submit* timeout on the very first attempt in
 *   that case (no libusb infinite-control-transfer primitive is used; the
 *   loop just keeps resubmitting bounded reads until cancelled)
 * @cancellable: (nullable): cancellable for the whole wait
 * @callback: called exactly once with the result
 * @user_data: passed through to @callback
 *
 * Async port of prototype/p2_moc.py::wait_intr_event / read_intr: repeatedly
 * submits a single bounded interrupt-IN transfer on %VERIMARK_EP_INTR_IN
 * (self->ep_intr_in), ignoring any event whose byte[0] != @want_type (mirrors
 * the Python `if ev and len(ev) >= 1 and ev[0] == kind`), until either a
 * matching event arrives or the overall @timeout_ms budget is exhausted.
 * Individual per-attempt reads use a bounded sub-timeout (mirrors
 * read_intr()'s 500/800ms) so the SSM stays responsive to cancellation.
 */
void verimark_intr_wait_async (FpDevice             *dev,
                               guint8                want_type,
                               guint                 timeout_ms,
                               GCancellable         *cancellable,
                               VerimarkIntrCallback  callback,
                               gpointer              user_data);

G_END_DECLS
