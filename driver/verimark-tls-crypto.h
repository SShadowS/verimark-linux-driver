/*
 * verimark-tls-crypto.h — offline crypto core of the Synaptics "Tudor" custom
 * TLS 1.2 secure channel. Primitives only (libcrypto EVP/EC); NOT a TLS stack.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Oracle: re/synaTudor-rev/pydrv/tudor/tls (tls) + tudor/sensor/pair.py.
 */
#pragma once
#include <glib.h>
#include <openssl/evp.h>

/* Module-owned GError domain (no GIO dependency — glib + libcrypto only). */
#define VERIMARK_TLS_CRYPTO_ERROR (verimark_tls_crypto_error_quark ())
GQuark verimark_tls_crypto_error_quark (void);

typedef enum {
  VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA,
  VERIMARK_TLS_CRYPTO_ERROR_FAILED,
} VerimarkTlsCryptoError;

/* TLS 1.2 PRF (P_hash), rev crypto.py::tls_prf. `md` = EVP_sha256() or EVP_sha384().
 * inp = ascii(label) || seed; A(1)=HMAC(secret,inp); A(i+1)=HMAC(secret,A(i));
 * out += HMAC(secret, A(i) || inp); truncated to out_len. Returns TRUE on success. */
gboolean verimark_tls_prf (const EVP_MD *md,
                           const guint8 *secret, gsize secret_len,
                           const char *label,
                           const guint8 *seed, gsize seed_len,
                           guint8 *out, gsize out_len);

/* AEAD key material (suite 0xC02E): key_size=32, iv_size=4. */
typedef struct {
  guint8 encr_key[32];
  guint8 decr_key[32];
  guint8 encr_iv[4];
  guint8 decr_iv[4];
} VerimarkTlsKeys;

/* master_secret[48] = PRF-SHA384(premaster, "master secret", client_random||server_random, 48).
 * Seed order client||server (encr.py:13-17). */
gboolean verimark_tls_derive_master_secret (const guint8 *premaster, gsize premaster_len,
                                            const guint8 client_random[32],
                                            const guint8 server_random[32],
                                            guint8 master_secret[48]);

/* key block = PRF-SHA384(master_secret, "key expansion", client_random||server_random, 72):
 * encr_key[32] | decr_key[32] | encr_iv[4] | decr_iv[4] (encr.py:113-117). */
gboolean verimark_tls_derive_keys (const guint8 master_secret[48],
                                   const guint8 client_random[32],
                                   const guint8 server_random[32],
                                   VerimarkTlsKeys *keys);

/* SensorCertificate (sensor/pair.py). Wire form is 400 bytes. */
typedef struct {
  guint8  cert_type;
  guint8  pub_x[32];       /* big-endian */
  guint8  pub_y[32];       /* big-endian */
  guint16 sign_size;
  guint8  signature[256];  /* DER, sign_size significant */
} VerimarkCert;

/* SensorPairingData (sensor/pair.py). Wire form is 868 bytes. */
typedef struct {
  guint8       priv_scalar[32];  /* big-endian */
  VerimarkCert host_cert;
  VerimarkCert sensor_cert;
} VerimarkPairing;

gboolean verimark_cert_parse     (const guint8 buf[400], VerimarkCert *cert, GError **error);
gboolean verimark_cert_serialize (const VerimarkCert *cert, guint8 buf[400], GError **error);
gboolean verimark_cert_signbytes (const VerimarkCert *cert, guint8 out[142], GError **error);
gboolean verimark_pairing_load   (const guint8 buf[868], VerimarkPairing *pd, GError **error);
gboolean verimark_pairing_save   (const VerimarkPairing *pd, guint8 buf[868], GError **error);

#define VERIMARK_TLS_CT_APPDATA 0x17   /* TLS content type 23 (application_data) */

/* AES-256-GCM record wrap. out = g_malloc'd nonce(8)||ciphertext||tag(16); caller g_free. */
gboolean verimark_tls_gcm_wrap (const guint8 key[32], const guint8 fixed_iv[4],
                                guint64 seq, guint8 content_type,
                                const guint8 nonce[8],
                                const guint8 *plain, gsize plain_len,
                                guint8 **out, gsize *out_len, GError **error);

/* AES-256-GCM record unwrap (auth-verifies tag). out = g_malloc'd plaintext; caller g_free. */
gboolean verimark_tls_gcm_unwrap (const guint8 key[32], const guint8 fixed_iv[4],
                                  guint64 seq, guint8 content_type,
                                  const guint8 *frag, gsize frag_len,
                                  guint8 **out, gsize *out_len, GError **error);

/* Load a 256-byte .tsk sensor public key: X=LE(buf[0:0x44]), Y=LE(buf[0x44:0x88]). */
gboolean verimark_load_tsk_pubkey (const guint8 buf[256],
                                   guint8 pub_x[32], guint8 pub_y[32], GError **error);

/* ECDH premaster (SECP256R1) = X coord of eph_priv * peer, 32 bytes big-endian. */
gboolean verimark_ecdh_premaster (const guint8 eph_priv[32],
                                  const guint8 peer_x[32], const guint8 peer_y[32],
                                  guint8 premaster[32], GError **error);

/* Derive the SECP256R1 public point (x,y big-endian) from a private scalar. */
gboolean verimark_pub_from_priv (const guint8 priv[32],
                                 guint8 pub_x[32], guint8 pub_y[32], GError **error);

/* Verify ECDSA-SHA256 (DER sig) over msg with pub (x,y). TRUE iff signature valid. */
gboolean verimark_ecdsa_verify (const guint8 pub_x[32], const guint8 pub_y[32],
                                const guint8 *msg, gsize msg_len,
                                const guint8 *sig_der, gsize sig_len, GError **error);

/* Sign msg with ECDSA-SHA256 using priv scalar; *sig_der = g_malloc'd DER, caller g_free. */
gboolean verimark_ecdsa_sign (const guint8 priv[32],
                              const guint8 *msg, gsize msg_len,
                              guint8 **sig_der, gsize *sig_len, GError **error);

/* Sign a PRE-HASHED 32-byte digest with ECDSA — no internal hashing. Needed for the
 * TLS channel's CertificateVerify (ecc.py:80, ECDSA(Prehashed(SHA256())) — signs the
 * transcript digest directly, unlike verimark_ecdsa_sign() which hashes its input).
 * Additive primitive (driver/PORTING-PLAN.md's TLS-channel plan, not the original
 * crypto-core plan). *sig_der = g_malloc'd DER, caller g_free. */
gboolean verimark_ecdsa_sign_prehashed (const guint8 priv[32],
                                        const guint8 digest[32],
                                        guint8 **sig_der, gsize *sig_len, GError **error);
