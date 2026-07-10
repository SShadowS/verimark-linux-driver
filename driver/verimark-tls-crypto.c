/* verimark-tls-crypto.c — see verimark-tls-crypto.h. SPDX-License-Identifier: LGPL-2.1-or-later */
#include "verimark-tls-crypto.h"
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

GQuark
verimark_tls_crypto_error_quark (void)
{
  return g_quark_from_static_string ("verimark-tls-crypto-error-quark");
}

gboolean
verimark_tls_prf (const EVP_MD *md,
                  const guint8 *secret, gsize secret_len,
                  const char *label,
                  const guint8 *seed, gsize seed_len,
                  guint8 *out, gsize out_len)
{
  gsize label_len = strlen (label);
  gsize inp_len = label_len + seed_len;
  guint8 *inp = g_malloc (inp_len);
  guint8 *tmp = g_malloc (EVP_MAX_MD_SIZE + inp_len);   /* A(i) || inp scratch */
  guint8 a[EVP_MAX_MD_SIZE];
  guint8 block[EVP_MAX_MD_SIZE];
  unsigned int a_len = 0, block_len = 0;
  gsize done = 0;
  gboolean ok = FALSE;

  memcpy (inp, label, label_len);
  memcpy (inp + label_len, seed, seed_len);

  /* A(1) = HMAC(secret, inp) */
  if (!HMAC (md, secret, (int) secret_len, inp, inp_len, a, &a_len))
    goto out;

  while (done < out_len)
    {
      /* block = HMAC(secret, A(i) || inp) */
      memcpy (tmp, a, a_len);
      memcpy (tmp + a_len, inp, inp_len);
      if (!HMAC (md, secret, (int) secret_len, tmp, a_len + inp_len, block, &block_len))
        goto out;

      gsize n = MIN ((gsize) block_len, out_len - done);
      memcpy (out + done, block, n);
      done += n;

      /* A(i+1) = HMAC(secret, A(i)) */
      if (!HMAC (md, secret, (int) secret_len, a, a_len, a, &a_len))
        goto out;
    }
  ok = TRUE;

out:
  g_free (inp);
  g_free (tmp);
  return ok;
}

gboolean
verimark_tls_derive_master_secret (const guint8 *premaster, gsize premaster_len,
                                   const guint8 client_random[32],
                                   const guint8 server_random[32],
                                   guint8 master_secret[48])
{
  guint8 seed[64];
  memcpy (seed, client_random, 32);
  memcpy (seed + 32, server_random, 32);
  return verimark_tls_prf (EVP_sha384 (), premaster, premaster_len,
                           "master secret", seed, sizeof seed, master_secret, 48);
}

gboolean
verimark_tls_derive_keys (const guint8 master_secret[48],
                          const guint8 client_random[32],
                          const guint8 server_random[32],
                          VerimarkTlsKeys *keys)
{
  guint8 seed[64];
  guint8 block[72];
  memcpy (seed, client_random, 32);
  memcpy (seed + 32, server_random, 32);
  if (!verimark_tls_prf (EVP_sha384 (), master_secret, 48,
                         "key expansion", seed, sizeof seed, block, sizeof block))
    return FALSE;
  memcpy (keys->encr_key, block +  0, 32);
  memcpy (keys->decr_key, block + 32, 32);
  memcpy (keys->encr_iv,  block + 64, 4);
  memcpy (keys->decr_iv,  block + 68, 4);
  return TRUE;
}

/* ---- little-endian wire field <-> big-endian 32-byte scalar ---- */
static gboolean
le_field_to_be32 (const guint8 *le, gsize field_len, guint8 out_be[32], GError **error)
{
  for (gsize i = 32; i < field_len; i++)
    if (le[i] != 0)
      {
        g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA,
                             "EC value exceeds 32 bytes");
        return FALSE;
      }
  for (gsize i = 0; i < 32; i++)
    out_be[i] = le[31 - i];
  return TRUE;
}

static void
be32_to_le_field (const guint8 be[32], guint8 *le, gsize field_len)
{
  memset (le, 0, field_len);
  for (gsize i = 0; i < 32; i++)
    le[i] = be[31 - i];
}

gboolean
verimark_cert_parse (const guint8 buf[400], VerimarkCert *cert, GError **error)
{
  guint16 magic = (guint16) buf[0] | ((guint16) buf[1] << 8);   /* LE */
  guint16 curve = (guint16) buf[2] | ((guint16) buf[3] << 8);   /* LE */
  if (magic != 0x5f3f || curve != 23)
    {
      g_set_error (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA,
                   "bad cert magic/curve (0x%04x/%u)", magic, curve);
      return FALSE;
    }
  if (!le_field_to_be32 (buf + 4,  68, cert->pub_x, error)) return FALSE;
  if (!le_field_to_be32 (buf + 72, 68, cert->pub_y, error)) return FALSE;
  cert->cert_type = buf[141];
  cert->sign_size = (guint16) buf[142] | ((guint16) buf[143] << 8);   /* LE */
  if (cert->sign_size > 256)
    {
      g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA, "sign_size > 256");
      return FALSE;
    }
  memcpy (cert->signature, buf + 144, 256);
  return TRUE;
}

gboolean
verimark_cert_serialize (const VerimarkCert *cert, guint8 buf[400], GError **error)
{
  (void) error;
  memset (buf, 0, 400);
  buf[0] = 0x3f; buf[1] = 0x5f;   /* magic 0x5f3f LE */
  buf[2] = 23;   buf[3] = 0;      /* curve 23 LE */
  be32_to_le_field (cert->pub_x, buf + 4,  68);
  be32_to_le_field (cert->pub_y, buf + 72, 68);
  /* buf[140] pad stays 0 */
  buf[141] = cert->cert_type;
  buf[142] = (guint8) (cert->sign_size & 0xff);
  buf[143] = (guint8) (cert->sign_size >> 8);
  memcpy (buf + 144, cert->signature, 256);
  return TRUE;
}

gboolean
verimark_cert_signbytes (const VerimarkCert *cert, guint8 out[142], GError **error)
{
  guint8 full[400];
  if (!verimark_cert_serialize (cert, full, error))
    return FALSE;
  memcpy (out, full, 142);   /* HH68s68sxB == cert[0:142] */
  return TRUE;
}

gboolean
verimark_pairing_load (const guint8 buf[868], VerimarkPairing *pd, GError **error)
{
  if (!le_field_to_be32 (buf, 0x44, pd->priv_scalar, error)) return FALSE;
  if (!verimark_cert_parse (buf + 0x44,       &pd->host_cert,   error)) return FALSE;
  if (!verimark_cert_parse (buf + 0x44 + 400, &pd->sensor_cert, error)) return FALSE;
  return TRUE;
}

gboolean
verimark_pairing_save (const VerimarkPairing *pd, guint8 buf[868], GError **error)
{
  memset (buf, 0, 868);
  be32_to_le_field (pd->priv_scalar, buf, 0x44);
  if (!verimark_cert_serialize (&pd->host_cert,   buf + 0x44,       error)) return FALSE;
  if (!verimark_cert_serialize (&pd->sensor_cert, buf + 0x44 + 400, error)) return FALSE;
  return TRUE;
}

static void
gcm_build_aad (guint64 seq, guint8 content_type, gsize plain_len, guint8 aad[13])
{
  aad[0] = (guint8) (seq >> 56); aad[1] = (guint8) (seq >> 48);
  aad[2] = (guint8) (seq >> 40); aad[3] = (guint8) (seq >> 32);
  aad[4] = (guint8) (seq >> 24); aad[5] = (guint8) (seq >> 16);
  aad[6] = (guint8) (seq >>  8); aad[7] = (guint8) (seq);
  aad[8]  = content_type;
  aad[9]  = 0x03; aad[10] = 0x03;                        /* version 0x0303 */
  aad[11] = (guint8) ((plain_len >> 8) & 0xff);
  aad[12] = (guint8) (plain_len & 0xff);
}

gboolean
verimark_tls_gcm_wrap (const guint8 key[32], const guint8 fixed_iv[4],
                       guint64 seq, guint8 content_type,
                       const guint8 nonce[8],
                       const guint8 *plain, gsize plain_len,
                       guint8 **out, gsize *out_len, GError **error)
{
  guint8 iv[12], aad[13];
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  guint8 *buf = g_malloc (8 + plain_len + 16);
  int len = 0, clen = 0;
  gboolean ok = FALSE;

  memcpy (iv, fixed_iv, 4);
  memcpy (iv + 4, nonce, 8);
  gcm_build_aad (seq, content_type, plain_len, aad);
  memcpy (buf, nonce, 8);

  if (!ctx) goto out;
  if (EVP_EncryptInit_ex (ctx, EVP_aes_256_gcm (), NULL, NULL, NULL) != 1) goto out;
  if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto out;
  if (EVP_EncryptInit_ex (ctx, NULL, NULL, key, iv) != 1) goto out;
  if (EVP_EncryptUpdate (ctx, NULL, &len, aad, (int) sizeof aad) != 1) goto out;
  if (EVP_EncryptUpdate (ctx, buf + 8, &len, plain, (int) plain_len) != 1) goto out;
  clen = len;
  if (EVP_EncryptFinal_ex (ctx, buf + 8 + clen, &len) != 1) goto out;
  clen += len;
  if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, 16, buf + 8 + clen) != 1) goto out;

  *out = buf; *out_len = 8 + (gsize) clen + 16; buf = NULL; ok = TRUE;

out:
  EVP_CIPHER_CTX_free (ctx);
  g_free (buf);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "GCM wrap failed");
  return ok;
}

gboolean
verimark_tls_gcm_unwrap (const guint8 key[32], const guint8 fixed_iv[4],
                         guint64 seq, guint8 content_type,
                         const guint8 *frag, gsize frag_len,
                         guint8 **out, gsize *out_len, GError **error)
{
  if (frag_len < 8 + 16)
    {
      g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA, "short GCM record");
      return FALSE;
    }
  gsize plain_len = frag_len - 8 - 16;
  const guint8 *nonce = frag;
  const guint8 *ct    = frag + 8;
  const guint8 *tag   = frag + frag_len - 16;

  guint8 iv[12], aad[13];
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  guint8 *buf = g_malloc (plain_len ? plain_len : 1);
  int len = 0;
  gboolean ok = FALSE;

  memcpy (iv, fixed_iv, 4);
  memcpy (iv + 4, nonce, 8);
  gcm_build_aad (seq, content_type, plain_len, aad);

  if (!ctx) goto out;
  if (EVP_DecryptInit_ex (ctx, EVP_aes_256_gcm (), NULL, NULL, NULL) != 1) goto out;
  if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto out;
  if (EVP_DecryptInit_ex (ctx, NULL, NULL, key, iv) != 1) goto out;
  if (EVP_DecryptUpdate (ctx, NULL, &len, aad, (int) sizeof aad) != 1) goto out;
  if (EVP_DecryptUpdate (ctx, buf, &len, ct, (int) plain_len) != 1) goto out;
  if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *) tag) != 1) goto out;
  if (EVP_DecryptFinal_ex (ctx, buf + len, &len) != 1) goto out;   /* tag mismatch → fail */

  *out = buf; *out_len = plain_len; buf = NULL; ok = TRUE;

out:
  EVP_CIPHER_CTX_free (ctx);
  g_free (buf);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "GCM unwrap/auth failed");
  return ok;
}

gboolean
verimark_load_tsk_pubkey (const guint8 buf[256],
                          guint8 pub_x[32], guint8 pub_y[32], GError **error)
{
  return le_field_to_be32 (buf + 0x00, 0x44, pub_x, error) &&
         le_field_to_be32 (buf + 0x44, 0x44, pub_y, error);
}

gboolean
verimark_ecdh_premaster (const guint8 eph_priv[32],
                         const guint8 peer_x[32], const guint8 peer_y[32],
                         guint8 premaster[32], GError **error)
{
  gboolean ok = FALSE;
  EC_KEY *priv = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  EC_KEY *peer = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *d = BN_bin2bn (eph_priv, 32, NULL);
  BIGNUM *x = BN_bin2bn (peer_x, 32, NULL);
  BIGNUM *y = BN_bin2bn (peer_y, 32, NULL);

  if (!priv || !peer || !d || !x || !y) goto out;
  if (!EC_KEY_set_private_key (priv, d)) goto out;
  if (!EC_KEY_set_public_key_affine_coordinates (peer, x, y)) goto out;
  if (ECDH_compute_key (premaster, 32, EC_KEY_get0_public_key (peer), priv, NULL) != 32)
    goto out;
  ok = TRUE;

out:
  BN_free (d); BN_free (x); BN_free (y);
  EC_KEY_free (priv); EC_KEY_free (peer);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "ECDH failed");
  return ok;
}

gboolean
verimark_pub_from_priv (const guint8 priv[32],
                        guint8 pub_x[32], guint8 pub_y[32], GError **error)
{
  gboolean ok = FALSE;
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *d = BN_bin2bn (priv, 32, NULL);
  BIGNUM *x = BN_new (), *y = BN_new ();
  EC_POINT *pub = NULL;
  const EC_GROUP *grp = ec ? EC_KEY_get0_group (ec) : NULL;

  if (!ec || !d || !x || !y || !grp) goto out;
  pub = EC_POINT_new (grp);
  if (!pub) goto out;
  if (!EC_POINT_mul (grp, pub, d, NULL, NULL, NULL)) goto out;
  if (!EC_POINT_get_affine_coordinates (grp, pub, x, y, NULL)) goto out;
  if (BN_bn2binpad (x, pub_x, 32) != 32) goto out;
  if (BN_bn2binpad (y, pub_y, 32) != 32) goto out;
  ok = TRUE;

out:
  BN_free (d); BN_free (x); BN_free (y);
  EC_POINT_free (pub);
  EC_KEY_free (ec);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "pub-from-priv failed");
  return ok;
}

gboolean
verimark_ecdsa_verify (const guint8 pub_x[32], const guint8 pub_y[32],
                       const guint8 *msg, gsize msg_len,
                       const guint8 *sig_der, gsize sig_len, GError **error)
{
  gboolean ok = FALSE;
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *x = BN_bin2bn (pub_x, 32, NULL);
  BIGNUM *y = BN_bin2bn (pub_y, 32, NULL);
  EVP_PKEY *pkey = EVP_PKEY_new ();
  EVP_MD_CTX *md = EVP_MD_CTX_new ();

  if (!ec || !x || !y || !pkey || !md) goto out;
  if (!EC_KEY_set_public_key_affine_coordinates (ec, x, y)) goto out;
  if (!EVP_PKEY_assign_EC_KEY (pkey, ec)) goto out;   /* pkey now owns ec */
  ec = NULL;
  if (EVP_DigestVerifyInit (md, NULL, EVP_sha256 (), NULL, pkey) != 1) goto out;
  if (EVP_DigestVerify (md, sig_der, sig_len, msg, msg_len) == 1) ok = TRUE;

out:
  BN_free (x); BN_free (y);
  if (ec) EC_KEY_free (ec);
  EVP_PKEY_free (pkey);
  EVP_MD_CTX_free (md);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "ECDSA verify failed");
  return ok;
}

gboolean
verimark_ecdsa_sign (const guint8 priv[32],
                     const guint8 *msg, gsize msg_len,
                     guint8 **sig_der, gsize *sig_len, GError **error)
{
  gboolean ok = FALSE;
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *d = BN_bin2bn (priv, 32, NULL);
  EVP_PKEY *pkey = EVP_PKEY_new ();
  EVP_MD_CTX *md = EVP_MD_CTX_new ();
  EC_POINT *pub = NULL;
  guint8 *buf = NULL;
  size_t n = 0;

  if (!ec || !d || !pkey || !md) goto out;
  if (!EC_KEY_set_private_key (ec, d)) goto out;
  pub = EC_POINT_new (EC_KEY_get0_group (ec));
  if (!pub) goto out;
  if (!EC_POINT_mul (EC_KEY_get0_group (ec), pub, d, NULL, NULL, NULL)) goto out;
  if (!EC_KEY_set_public_key (ec, pub)) goto out;
  if (!EVP_PKEY_assign_EC_KEY (pkey, ec)) goto out;   /* pkey now owns ec */
  ec = NULL;
  if (EVP_DigestSignInit (md, NULL, EVP_sha256 (), NULL, pkey) != 1) goto out;
  if (EVP_DigestSign (md, NULL, &n, msg, msg_len) != 1) goto out;
  buf = g_malloc (n);
  if (EVP_DigestSign (md, buf, &n, msg, msg_len) != 1) goto out;
  *sig_der = buf; *sig_len = n; buf = NULL; ok = TRUE;

out:
  BN_free (d);
  EC_POINT_free (pub);
  if (ec) EC_KEY_free (ec);
  EVP_PKEY_free (pkey);
  EVP_MD_CTX_free (md);
  g_free (buf);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "ECDSA sign failed");
  return ok;
}

gboolean
verimark_ecdsa_sign_prehashed (const guint8 priv[32],
                               const guint8 digest[32],
                               guint8 **sig_der, gsize *sig_len, GError **error)
{
  gboolean ok = FALSE;
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *d = BN_bin2bn (priv, 32, NULL);
  guint8 *buf = NULL;
  unsigned int n = 0;

  if (!ec || !d) goto out;
  if (!EC_KEY_set_private_key (ec, d)) goto out;
  buf = g_malloc (ECDSA_size (ec));
  /* type=0 (unused), no internal hashing -- digest is signed as-is. */
  if (ECDSA_sign (0, digest, 32, buf, &n, ec) != 1) goto out;
  *sig_der = buf; *sig_len = n; buf = NULL; ok = TRUE;

out:
  BN_free (d);
  EC_KEY_free (ec);
  g_free (buf);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "ECDSA prehashed sign failed");
  return ok;
}
