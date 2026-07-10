/*
 * verimark-pairing.h — TOFU pairing (command 0x93) + 868-byte pdata persistence.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Oracle: re/synaTudor-rev/pydrv/tudor/sensor/{sensor.py::pair,pair.py} + findings/46.
 *
 * SOLID split from verimark-tls.{c,h}: this file owns provisioning + disk I/O
 * (changes when persistence/ownership changes); verimark-tls.c owns per-session
 * channel crypto (changes when the handshake changes).
 */
#pragma once
#include <glib.h>
#include "verimark-tls-crypto.h"   /* VerimarkPairing, VerimarkCert */

G_BEGIN_DECLS

/* Same shape as VerimarkTlsIo, but the command opcode is 0x93 (PAIR), not 0x44:
 * send `out` (0x93 ‖ host_cert, 401 bytes) as a raw command, return the 802-byte
 * response (status(2) ‖ new host cert(400) ‖ sensor cert(400)). */
typedef gboolean (*VerimarkPairIo) (gpointer io_ctx,
                                    const guint8 *out, gsize out_len,
                                    guint8 **in, gsize *in_len, GError **error);

/* Perform first-pairer-wins pairing (sensor.py:187-206): generate a fresh host EC
 * keypair, sign the host cert with the global HS key (findings/46), send 0x93,
 * parse the 802-byte reply, and fill in @pd (including @pd->priv_scalar = the
 * generated private key — NOT anything the sensor returns). */
gboolean verimark_pairing_do (VerimarkPairIo io, gpointer io_ctx,
                              VerimarkPairing *pd, GError **error);

/* Filesystem persistence. path = $VERIMARK_PDATA_DIR/<sid>.pdata if the
 * VERIMARK_PDATA_DIR env var is set (test seam), else
 * /var/lib/fprint/verimark/<sid>.pdata. File mode 0600, dir mode 0700 — the
 * blob contains the host private scalar. Caller g_free()s the returned path. */
gchar   *verimark_pairing_path      (const gchar *sid);
gboolean verimark_pairing_save_file (const VerimarkPairing *pd, const gchar *sid, GError **error);

/* Named _load_file (not _load) to avoid colliding with the crypto core's
 * in-memory verimark_pairing_load(buf[868], ...) codec — see
 * docs/superpowers/plans/2026-07-10-verimark-tls-channel.md Risks/T7 Step 3. */
gboolean verimark_pairing_load_file (const gchar *sid, VerimarkPairing *pd, GError **error);

#ifdef VERIMARK_TESTING
/* Test-only seam exposing the host-cert build/sign logic (HS-key derivation +
 * VerimarkCert build + sign + serialize) with an EXPLICIT private key, instead
 * of verimark_pairing_do()'s internally-generated one. Lets a unit test build a
 * deterministic host cert to compare against a golden vector. */
gboolean verimark_pairing__test_build_host_cert (const guint8 priv[32],
                                                 VerimarkCert *cert, guint8 buf400[400],
                                                 GError **error);
/* Test-only seam exposing the HS-key scalar derivation (findings/46). */
gboolean verimark_pairing__test_hs_key_scalar (guint8 out_be[32], GError **error);
#endif

G_END_DECLS
