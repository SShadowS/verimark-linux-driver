/*
 * verimark-pairing.c — see verimark-pairing.h. SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Oracle: re/synaTudor-rev/pydrv/tudor/sensor/sensor.py::pair (187-206) +
 * sensor/pair.py::SensorCertificate.create_host_cert/SensorPairingData +
 * sensor/sensor_keys/genhskey.py (HS-key derivation) + findings/46 (verified the
 * derivation and its little-endian-scalar quirk against the shipping DLL).
 */
#define FP_COMPONENT "verimark"
#include "verimark-pairing.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib/gstdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#define VERIMARK_PDATA_DEFAULT_DIR "/var/lib/fprint/verimark"

/* -------------------------------------------------------------------------
 * HS-key derivation (findings/46): a fixed, globally-shared Synaptics signing
 * key, NOT device- or install-specific. hs_priv_scalar =
 * PRF-SHA256(secret, "HS_KEY_PAIR_GEN", seed, 32), interpreted little-endian
 * (findings/46 "Endianness closed") -> reversed here to the big-endian form the
 * crypto core expects.
 * ---------------------------------------------------------------------- */
static gboolean
hs_key_scalar (guint8 out_be[32], GError **error)
{
  static const guint8 secret[16] = {
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
    0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19
  };
  static const guint8 seed[18] = {
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46,
    0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33, 0xaa, 0xaa
  };
  guint8 prf[32];

  if (!verimark_tls_prf (EVP_sha256 (), secret, sizeof secret, "HS_KEY_PAIR_GEN",
                         seed, sizeof seed, prf, sizeof prf))
    {
      g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "HS-key PRF failed");
      return FALSE;
    }
  for (int i = 0; i < 32; i++)
    out_be[i] = prf[31 - i];
  return TRUE;
}

/* -------------------------------------------------------------------------
 * Local EC keypair generation (SECP256R1). Not added to the shared crypto core
 * per docs/superpowers/plans/2026-07-10-verimark-tls-channel.md's reconciliation
 * note ("...or generate locally in verimark-pairing.c") -- this is the only
 * caller.
 * ---------------------------------------------------------------------- */
static gboolean
ec_keygen (guint8 priv[32], guint8 pub_x[32], guint8 pub_y[32], GError **error)
{
  gboolean ok = FALSE;
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *x = NULL, *y = NULL;

  if (!ec) goto out;
  if (EC_KEY_generate_key (ec) != 1) goto out;
  if (BN_bn2binpad (EC_KEY_get0_private_key (ec), priv, 32) != 32) goto out;

  x = BN_new (); y = BN_new ();
  if (!x || !y) goto out;
  if (!EC_POINT_get_affine_coordinates (EC_KEY_get0_group (ec), EC_KEY_get0_public_key (ec), x, y, NULL)) goto out;
  if (BN_bn2binpad (x, pub_x, 32) != 32) goto out;
  if (BN_bn2binpad (y, pub_y, 32) != 32) goto out;
  ok = TRUE;

out:
  BN_free (x); BN_free (y);
  EC_KEY_free (ec);
  if (!ok) g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_FAILED, "EC keygen failed");
  return ok;
}

/* -------------------------------------------------------------------------
 * Host cert build + HS-sign (pair.py:26-35, SensorCertificate.create_host_cert).
 * ---------------------------------------------------------------------- */
static gboolean
build_host_cert (const guint8 priv[32], VerimarkCert *cert, guint8 buf400[400], GError **error)
{
  guint8 pub_x[32], pub_y[32];
  if (!verimark_pub_from_priv (priv, pub_x, pub_y, error)) return FALSE;

  memset (cert, 0, sizeof *cert);
  cert->cert_type = 0;
  memcpy (cert->pub_x, pub_x, 32);
  memcpy (cert->pub_y, pub_y, 32);

  guint8 signbytes[142];
  if (!verimark_cert_signbytes (cert, signbytes, error)) return FALSE;

  guint8 hs[32];
  if (!hs_key_scalar (hs, error)) return FALSE;

  guint8 *sig_der = NULL; gsize sig_len = 0;
  /* NOT prehashed: signs the SHA-256 hash of signbytes internally (pair.py:33). */
  if (!verimark_ecdsa_sign (hs, signbytes, sizeof signbytes, &sig_der, &sig_len, error))
    return FALSE;
  if (sig_len > sizeof cert->signature)
    {
      g_free (sig_der);
      g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA, "HS signature too long");
      return FALSE;
    }
  memcpy (cert->signature, sig_der, sig_len);
  cert->sign_size = (guint16) sig_len;
  g_free (sig_der);

  return verimark_cert_serialize (cert, buf400, error);
}

#ifdef VERIMARK_TESTING
gboolean
verimark_pairing__test_build_host_cert (const guint8 priv[32], VerimarkCert *cert, guint8 buf400[400], GError **error)
{
  return build_host_cert (priv, cert, buf400, error);
}

gboolean
verimark_pairing__test_hs_key_scalar (guint8 out_be[32], GError **error)
{
  return hs_key_scalar (out_be, error);
}
#endif

/* -------------------------------------------------------------------------
 * 0x93 TOFU pairing exchange (sensor.py:187-206).
 * ---------------------------------------------------------------------- */
gboolean
verimark_pairing_do (VerimarkPairIo io, gpointer io_ctx, VerimarkPairing *pd, GError **error)
{
  g_return_val_if_fail (io != NULL, FALSE);
  g_return_val_if_fail (pd != NULL, FALSE);

  guint8 host_priv[32], pub_x[32], pub_y[32];
  if (!ec_keygen (host_priv, pub_x, pub_y, error)) return FALSE;

  VerimarkCert host_cert;
  guint8 host_cert_400[400];
  if (!build_host_cert (host_priv, &host_cert, host_cert_400, error)) return FALSE;

  guint8 out[401];
  out[0] = 0x93;
  memcpy (out + 1, host_cert_400, 400);

  guint8 *resp = NULL; gsize resp_len = 0;
  if (!io (io_ctx, out, sizeof out, &resp, &resp_len, error)) return FALSE;

  if (resp_len != 802 || resp[0] != 0x00 || resp[1] != 0x00)
    {
      g_set_error (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA,
                   "PAIR: unexpected reply (len=%" G_GSIZE_FORMAT ")", resp_len);
      g_free (resp);
      return FALSE;
    }

  gboolean ok = verimark_cert_parse (resp + 2, &pd->host_cert, error) &&
                verimark_cert_parse (resp + 402, &pd->sensor_cert, error);
  g_free (resp);
  if (!ok) return FALSE;

  memcpy (pd->priv_scalar, host_priv, 32);   /* persisted scalar is OUR generated priv */
  return TRUE;
}

/* -------------------------------------------------------------------------
 * pdata file persistence.
 * ---------------------------------------------------------------------- */
static const gchar *
pairing_base_dir (void)
{
  const gchar *override = g_getenv ("VERIMARK_PDATA_DIR");
  return override ? override : VERIMARK_PDATA_DEFAULT_DIR;
}

gchar *
verimark_pairing_path (const gchar *sid)
{
  gchar *fname = g_strconcat (sid, ".pdata", NULL);
  gchar *path = g_build_filename (pairing_base_dir (), fname, NULL);
  g_free (fname);
  return path;
}

gboolean
verimark_pairing_save_file (const VerimarkPairing *pd, const gchar *sid, GError **error)
{
  g_return_val_if_fail (pd != NULL, FALSE);
  g_return_val_if_fail (sid != NULL, FALSE);

  if (g_mkdir_with_parents (pairing_base_dir (), 0700) != 0)
    {
      int e = errno;
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e),
                   "mkdir %s failed: %s", pairing_base_dir (), g_strerror (e));
      return FALSE;
    }

  guint8 buf[868];
  if (!verimark_pairing_save (pd, buf, error)) return FALSE;

  gchar *path = verimark_pairing_path (sid);
  int fd = g_open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    {
      int e = errno;
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e), "open %s failed: %s", path, g_strerror (e));
      g_free (path);
      return FALSE;
    }
  g_free (path);

  gboolean ok = (write (fd, buf, sizeof buf) == (ssize_t) sizeof buf);
  if (!ok)
    {
      int e = errno;
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e), "write pdata failed: %s", g_strerror (e));
    }
  g_close (fd, NULL);
  return ok;
}

gboolean
verimark_pairing_load_file (const gchar *sid, VerimarkPairing *pd, GError **error)
{
  g_return_val_if_fail (sid != NULL, FALSE);
  g_return_val_if_fail (pd != NULL, FALSE);

  gchar *path = verimark_pairing_path (sid);
  gchar *data = NULL; gsize len = 0;
  gboolean ok = g_file_get_contents (path, &data, &len, error);
  g_free (path);
  if (!ok) return FALSE;

  if (len != 868)
    {
      g_set_error_literal (error, VERIMARK_TLS_CRYPTO_ERROR, VERIMARK_TLS_CRYPTO_ERROR_INVALID_DATA, "pdata file is not 868 bytes");
      g_free (data);
      return FALSE;
    }

  ok = verimark_pairing_load ((const guint8 *) data, pd, error);
  g_free (data);
  return ok;
}
