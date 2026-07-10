/*
 * verimark-tls.h — Synaptics "Tudor" custom TLS 1.2 secure channel (handshake SM +
 * record layer). Non-standard TLS 1.2; primitives from verimark-tls-crypto.h.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Oracle: re/synaTudor-rev/pydrv/tudor/tls/{session,handshake,record}.py + cipher/{ecc,encr}.py
 *
 * Implements docs/superpowers/plans/2026-07-10-verimark-tls-channel.md Tasks 2-6.
 * Finalizes the previous placeholder API (see git history) now that the handshake
 * is actually implemented.
 */
#pragma once
#include <glib.h>
#include "verimark-tls-crypto.h"   /* VerimarkPairing, VerimarkTlsKeys, PRF/ECDH/ECDSA/GCM */

G_BEGIN_DECLS

typedef struct _VerimarkTls VerimarkTls;   /* opaque; defined in verimark-tls.c */

/* One handshake round-trip: send `out_len` TLS record bytes to the sensor as a raw
 * TLS_DATA (command 0x44) transfer and return the response record bytes. The
 * implementation (verimark.c, later phase) frames `out` as command 0x44 and calls
 * the async EP0 primitive (verimark_cmd()); `in` is g_malloc'd by the callee, freed
 * by the channel. Returns FALSE + sets `error` on transport failure. Called exactly
 * twice per handshake (session.py::establish's 2-round-trip loop). */
typedef gboolean (*VerimarkTlsIo) (gpointer io_ctx,
                                   const guint8 *out, gsize out_len,
                                   guint8 **in, gsize *in_len,
                                   GError **error);

VerimarkTls *verimark_tls_new  (VerimarkTlsIo io, gpointer io_ctx);
void         verimark_tls_free (VerimarkTls *tls);

/* Install the loaded 868-byte pairing (from verimark_pairing_load_file()). Copies it
 * in; the channel uses pd->priv_scalar (CertVerify), pd->host_cert (client
 * Certificate), pd->sensor_cert (ECDH peer). */
void verimark_tls_set_pairing (VerimarkTls *tls, const VerimarkPairing *pd);

/* Run the custom 2-round-trip handshake (session.py::establish). Requires a pairing
 * set via verimark_tls_set_pairing() first. On success the channel is established
 * and wrap/unwrap are usable. */
gboolean verimark_tls_handshake (VerimarkTls *tls, GError **error);

/* Steady-state application_data record wrap (encr_seq++) — full TLS record bytes
 * (5-byte header ‖ nonce(8) ‖ ciphertext ‖ tag(16)). The MOC layer sends this via
 * the raw transport. Before the channel is established, passes @plain through
 * unmodified (session.py::wrap: `if not established: return pdata`). */
gboolean verimark_tls_wrap (VerimarkTls *tls,
                            const guint8 *plain, gsize plain_len,
                            guint8 **record, gsize *record_len, GError **error);

/* Steady-state unwrap of the raw transport reply (one or more records; decr_seq++).
 * Concatenates application_data fragments; fails on an alert record. Before the
 * channel is established, passes @record through unmodified. */
gboolean verimark_tls_unwrap (VerimarkTls *tls,
                              const guint8 *record, gsize record_len,
                              guint8 **plain, gsize *plain_len, GError **error);

gboolean verimark_tls_is_established (VerimarkTls *tls);
void     verimark_tls_close (VerimarkTls *tls);   /* best-effort: send close_notify via io */

#ifdef VERIMARK_TESTING
/* Test-only determinism seam (docs/superpowers/plans/2026-07-10-verimark-tls-channel.md
 * Task 5 Step 3). Pins the values that would otherwise be generated randomly, so the
 * handshake byte-for-byte matches rev-generated golden vectors. NULL leaves a field
 * un-pinned. Not part of the production API; only declared when compiled with
 * -DVERIMARK_TESTING (see driver/tests/meson.build). */
void verimark_tls__test_pin (VerimarkTls *tls,
                             const guint8 *client_random /* [32] */,
                             const guint8 *eph_priv       /* [32] */,
                             const guint8 *gcm_nonce       /* [8]  */);

/* ECDSA signing (CertificateVerify) draws a fresh random nonce every call by
 * design (that's what makes it secure) — so an independently-computed
 * CertificateVerify signature can NEVER be expected to byte-match a
 * previously-captured golden vector, even given identical inputs, and the
 * transcript digest used by both Finished messages depends on those exact
 * signature bytes. To let the offline mock-server round-trip (Task 5) be
 * deterministic, this seam injects a fixed, pre-computed DER signature instead
 * of calling verimark_ecdsa_sign_prehashed(); NULL/0 falls back to real
 * signing (the production path, always used outside tests). */
void verimark_tls__test_pin_cert_verify_sig (VerimarkTls *tls,
                                             const guint8 *sig_der, gsize sig_len);

/* Test-only seams onto the internal per-task handshake steps (isolate ClientHello
 * build / RT1 parse / RT2 build from the full 2-round-trip verimark_tls_handshake()
 * for finer-grained TDD coverage per
 * docs/superpowers/plans/2026-07-10-verimark-tls-channel.md Tasks 2-4). */
void     verimark_tls__test_build_client_hello (VerimarkTls *tls, guint8 **out, gsize *out_len);
gboolean verimark_tls__test_process_rt1 (VerimarkTls *tls, const guint8 *resp, gsize resp_len,
                                         guint8 server_random_out[32], GError **error);
gboolean verimark_tls__test_build_rt2 (VerimarkTls *tls, guint8 **out, gsize *out_len,
                                       guint8 master_secret_out[48], GError **error);
#endif

G_END_DECLS
