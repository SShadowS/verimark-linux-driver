/*
 * verimark-tls.h — Synaptics "Tudor" secure-channel (custom server-auth TLS 1.2).
 * From findings/10-crypto-map.md + 20-protocol.md. SPDX: LGPL-2.1-or-later
 *
 * Record wire format (post-handshake app data):
 *   17 03 03 | len16 | IV[16] | AES-CBC(payload) | HMAC-SHA256[32]   (overhead 0x45)
 * Handshake: 2-RTT, server-authenticated (server Certificate, NO client cert),
 *   ECDHE-P256 + ECDSA(server) OR PSK; master secret 48 B; TLS1.2 PRF.
 * Crypto via OpenSSL (ECDH P-256, ECDSA verify, AES-CBC, HMAC-SHA256) — no TPM.
 */
#pragma once
#include <glib.h>

typedef struct _VerimarkTls VerimarkTls;

/* Emit `out` bytes to the sensor / read `in` bytes — supplied by the driver so the
 * handshake can drive the USB transport (control-out / interrupt-in). */
typedef gboolean (*VerimarkTlsIo) (gpointer io_ctx,
                                   const guint8 *out, gsize out_len,
                                   guint8 **in, gsize *in_len,
                                   GError **error);

VerimarkTls *verimark_tls_new (VerimarkTlsIo io, gpointer io_ctx);
void         verimark_tls_free (VerimarkTls *tls);

/* Run the 2-RTT handshake. `pairing`/`pairing_len`: host P-256 key + PSK from
 * pairing (NULL -> anonymous ECC handshake first-time). Verifies the server cert
 * chain to the Microsoft ECC Devices Root CA 2017. */
gboolean verimark_tls_handshake (VerimarkTls *tls,
                                 const guint8 *pairing, gsize pairing_len,
                                 GError **error);

/* Wrap a plaintext command into a 17 03 03 app-data record (+0x45 overhead). */
gboolean verimark_tls_wrap (VerimarkTls *tls,
                            const guint8 *plain, gsize plain_len,
                            guint8 **record, gsize *record_len,
                            GError **error);

/* Unwrap an app-data record to plaintext (verify HMAC, AES-CBC decrypt). */
gboolean verimark_tls_unwrap (VerimarkTls *tls,
                              const guint8 *record, gsize record_len,
                              guint8 **plain, gsize *plain_len,
                              GError **error);

gboolean verimark_tls_is_established (VerimarkTls *tls);
void     verimark_tls_close (VerimarkTls *tls);   /* send close_notify alert */
