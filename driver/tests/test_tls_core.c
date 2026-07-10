#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "../verimark-tls-crypto.h"
#include "vectors.h"

static void test_prf_sha256 (void)
{
  guint8 out[40];
  g_assert_true (verimark_tls_prf (EVP_sha256 (),
                                   prf_sha256_secret, sizeof prf_sha256_secret,
                                   prf_sha256_label,
                                   prf_sha256_seed, sizeof prf_sha256_seed,
                                   out, sizeof out));
  g_assert_cmpmem (out, sizeof out, prf_sha256_out, sizeof prf_sha256_out);
}

static void test_prf_sha384 (void)
{
  guint8 out[40];
  g_assert_true (verimark_tls_prf (EVP_sha384 (),
                                   prf_sha384_secret, sizeof prf_sha384_secret,
                                   prf_sha384_label,
                                   prf_sha384_seed, sizeof prf_sha384_seed,
                                   out, sizeof out));
  g_assert_cmpmem (out, sizeof out, prf_sha384_out, sizeof prf_sha384_out);
}

static void test_derive_master (void)
{
  guint8 master[48];
  g_assert_true (verimark_tls_derive_master_secret (
      deriv_premaster, sizeof deriv_premaster,
      deriv_client_random, deriv_server_random, master));
  g_assert_cmpmem (master, sizeof master,
                   deriv_master_secret, sizeof deriv_master_secret);
}

static void test_derive_keys (void)
{
  VerimarkTlsKeys k;
  g_assert_true (verimark_tls_derive_keys (
      deriv_master_secret, deriv_client_random, deriv_server_random, &k));
  g_assert_cmpmem (k.encr_key, 32, deriv_encr_key, 32);
  g_assert_cmpmem (k.decr_key, 32, deriv_decr_key, 32);
  g_assert_cmpmem (k.encr_iv,  4,  deriv_encr_iv,  4);
  g_assert_cmpmem (k.decr_iv,  4,  deriv_decr_iv,  4);
}

static void test_cert_roundtrip (void)
{
  VerimarkCert c;
  guint8 buf[400];
  g_assert_true (verimark_cert_parse (sensor_cert_400, &c, NULL));
  g_assert_cmpuint (c.cert_type, ==, SENSOR_CERT_TYPE);
  g_assert_cmpuint (c.sign_size, ==, SENSOR_CERT_SIGN_SIZE);
  g_assert_cmpmem (c.pub_x, 32, sensor_cert_pub_x, 32);
  g_assert_cmpmem (c.pub_y, 32, sensor_cert_pub_y, 32);
  g_assert_true (verimark_cert_serialize (&c, buf, NULL));
  g_assert_cmpmem (buf, 400, sensor_cert_400, 400);   /* byte-for-byte */
}

static void test_cert_signbytes (void)
{
  VerimarkCert c;
  guint8 sb[142];
  g_assert_true (verimark_cert_parse (sensor_cert_400, &c, NULL));
  g_assert_true (verimark_cert_signbytes (&c, sb, NULL));
  g_assert_cmpmem (sb, 142, sensor_cert_400, 142);    /* signbytes == cert[0:142] */
}

static void test_pairing_roundtrip (void)
{
  const char *path = getenv ("VERIMARK_PDATA");
  if (!path)
    { g_test_skip ("set VERIMARK_PDATA to a 868-byte pdata to run"); return; }
  gchar *data = NULL; gsize len = 0;
  if (!g_file_get_contents (path, &data, &len, NULL) || len != 868)
    { g_free (data); g_test_skip ("VERIMARK_PDATA missing or not 868 bytes"); return; }
  VerimarkPairing pd; guint8 out[868];
  g_assert_true (verimark_pairing_load ((const guint8 *) data, &pd, NULL));
  g_assert_true (verimark_pairing_save (&pd, out, NULL));
  g_assert_cmpmem (out, 868, data, 868);
  g_free (data);
}

static void test_gcm_wrap (void)
{
  guint8 *out = NULL; gsize out_len = 0;
  g_assert_true (verimark_tls_gcm_wrap (gcm_key, gcm_fixed_iv, GCM_SEQ,
                                        VERIMARK_TLS_CT_APPDATA, gcm_nonce,
                                        gcm_plain, gcm_plain_len,
                                        &out, &out_len, NULL));
  g_assert_cmpuint (out_len, ==, gcm_fragment_len);
  g_assert_cmpmem (out, out_len, gcm_fragment, gcm_fragment_len);
  g_free (out);
}

static void test_gcm_unwrap (void)
{
  guint8 *out = NULL; gsize out_len = 0;
  g_assert_true (verimark_tls_gcm_unwrap (gcm_key, gcm_fixed_iv, GCM_SEQ,
                                          VERIMARK_TLS_CT_APPDATA,
                                          gcm_fragment, gcm_fragment_len,
                                          &out, &out_len, NULL));
  g_assert_cmpuint (out_len, ==, gcm_plain_len);
  g_assert_cmpmem (out, out_len, gcm_plain, gcm_plain_len);
  g_free (out);
}

static void test_gcm_unwrap_tamper (void)
{
  guint8 bad[64];
  g_assert_cmpuint (gcm_fragment_len, <=, sizeof bad);
  memcpy (bad, gcm_fragment, gcm_fragment_len);
  bad[gcm_fragment_len - 1] ^= 0x01;   /* flip a tag byte */
  guint8 *out = NULL; gsize out_len = 0;
  g_assert_false (verimark_tls_gcm_unwrap (gcm_key, gcm_fixed_iv, GCM_SEQ,
                                           VERIMARK_TLS_CT_APPDATA,
                                           bad, gcm_fragment_len,
                                           &out, &out_len, NULL));
  g_assert_null (out);
}

static void test_tsk_load (void)
{
  guint8 x[32], y[32];
  g_assert_true (verimark_load_tsk_pubkey (tsk_256, x, y, NULL));
  g_assert_cmpmem (x, 32, tsk_pub_x, 32);
  g_assert_cmpmem (y, 32, tsk_pub_y, 32);
}

static void test_ecdh_premaster (void)
{
  VerimarkCert c;
  guint8 pm[32];
  g_assert_true (verimark_cert_parse (sensor_cert_400, &c, NULL));
  g_assert_true (verimark_ecdh_premaster (ecdh_eph_priv, c.pub_x, c.pub_y, pm, NULL));
  g_assert_cmpmem (pm, 32, ecdh_premaster, 32);
}

static void test_ecdsa_verify_sensor_cert (void)
{
  VerimarkCert c;
  guint8 sb[142];
  g_assert_true (verimark_cert_parse (sensor_cert_400, &c, NULL));
  g_assert_true (verimark_cert_signbytes (&c, sb, NULL));
  /* sensor cert is signed by the 10.1-kf sensor key */
  guint8 kx[32], ky[32];
  g_assert_true (verimark_load_tsk_pubkey (tsk_256, kx, ky, NULL));
  g_assert_true (verimark_ecdsa_verify (kx, ky, sb, sizeof sb,
                                        c.signature, c.sign_size, NULL));
  /* tamper: flip a signbytes byte -> must fail */
  sb[0] ^= 0x01;
  g_assert_false (verimark_ecdsa_verify (kx, ky, sb, sizeof sb,
                                         c.signature, c.sign_size, NULL));
}

static void test_ecdsa_sign_roundtrip (void)
{
  const guint8 msg[] = "verimark sign roundtrip";
  guint8 *sig = NULL; gsize sig_len = 0;
  g_assert_true (verimark_ecdsa_sign (ecdh_eph_priv, msg, sizeof msg, &sig, &sig_len, NULL));
  g_assert_cmpuint (sig_len, >, 0);
  /* verify against the public key derived from the same private scalar */
  guint8 px[32], py[32];
  g_assert_true (verimark_pub_from_priv (ecdh_eph_priv, px, py, NULL));
  g_assert_true (verimark_ecdsa_verify (px, py, msg, sizeof msg, sig, sig_len, NULL));
  g_free (sig);
}

static void test_ecdsa_sign_prehashed_roundtrip (void)
{
  const guint8 msg[] = "verimark prehashed sign roundtrip";
  guint8 digest[32];
  g_assert_true (EVP_Digest (msg, sizeof msg, digest, NULL, EVP_sha256 (), NULL));

  guint8 *sig = NULL; gsize sig_len = 0;
  g_assert_true (verimark_ecdsa_sign_prehashed (ecdh_eph_priv, digest, &sig, &sig_len, NULL));
  g_assert_cmpuint (sig_len, >, 0);

  /* verimark_ecdsa_verify() hashes msg with SHA-256 internally -- since we signed
   * digest = SHA256(msg) directly (no re-hash), the two must agree. */
  guint8 px[32], py[32];
  g_assert_true (verimark_pub_from_priv (ecdh_eph_priv, px, py, NULL));
  g_assert_true (verimark_ecdsa_verify (px, py, msg, sizeof msg, sig, sig_len, NULL));

  /* tamper with the digest -> must fail */
  guint8 *sig2 = NULL; gsize sig2_len = 0;
  digest[0] ^= 0x01;
  g_assert_true (verimark_ecdsa_sign_prehashed (ecdh_eph_priv, digest, &sig2, &sig2_len, NULL));
  g_assert_false (verimark_ecdsa_verify (px, py, msg, sizeof msg, sig2, sig2_len, NULL));

  g_free (sig);
  g_free (sig2);
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/verimark/prf/sha256", test_prf_sha256);
  g_test_add_func ("/verimark/prf/sha384", test_prf_sha384);
  g_test_add_func ("/verimark/derive/master", test_derive_master);
  g_test_add_func ("/verimark/derive/keys",   test_derive_keys);
  g_test_add_func ("/verimark/cert/roundtrip", test_cert_roundtrip);
  g_test_add_func ("/verimark/cert/signbytes", test_cert_signbytes);
  g_test_add_func ("/verimark/cert/pairing",   test_pairing_roundtrip);
  g_test_add_func ("/verimark/gcm/wrap",         test_gcm_wrap);
  g_test_add_func ("/verimark/gcm/unwrap",       test_gcm_unwrap);
  g_test_add_func ("/verimark/gcm/unwrap_tamper", test_gcm_unwrap_tamper);
  g_test_add_func ("/verimark/ecc/tsk",         test_tsk_load);
  g_test_add_func ("/verimark/ecc/ecdh",        test_ecdh_premaster);
  g_test_add_func ("/verimark/ecc/verify_cert", test_ecdsa_verify_sensor_cert);
  g_test_add_func ("/verimark/ecc/sign_roundtrip", test_ecdsa_sign_roundtrip);
  g_test_add_func ("/verimark/ecc/sign_prehashed_roundtrip", test_ecdsa_sign_prehashed_roundtrip);
  return g_test_run ();
}
