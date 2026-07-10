/* GLib-GTest runner for verimark-tls.c + verimark-pairing.c.
 * Golden vectors are generated offline by gen_handshake_vectors.py (drives rev's
 * own client against a self-consistent synthesized server); see
 * docs/superpowers/plans/2026-07-10-verimark-tls-channel.md for the design.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <stdlib.h>
#include "../verimark-tls.h"
#include "../verimark-pairing.h"
#include "handshake_vectors.h"

/* ---------------------------------------------------------------------
 * Mock VerimarkTlsIo: asserts the client's outbound bytes match the golden
 * capture, then hands back the scripted server response. Proves the C client
 * is byte-identical to rev's.
 * ------------------------------------------------------------------- */
typedef struct {
  struct { const guint8 *resp; gsize resp_len;
           const guint8 *expect_out; gsize expect_out_len; } script[2];
  int idx;
} MockServer;

static gboolean
mock_io (gpointer ctx, const guint8 *out, gsize out_len,
         guint8 **in, gsize *in_len, GError **error)
{
  MockServer *m = ctx;
  (void) error;
  if (m->idx >= 2)
    {
      /* Beyond the 2-round-trip handshake script -- e.g. verimark_tls_close()'s
       * best-effort close_notify. Not under test here; swallow it. */
      *in = g_malloc0 (1);
      *in_len = 0;
      m->idx++;
      return TRUE;
    }
  g_assert_cmpmem (out, out_len, m->script[m->idx].expect_out, m->script[m->idx].expect_out_len);
  *in = g_memdup2 (m->script[m->idx].resp, m->script[m->idx].resp_len);
  *in_len = m->script[m->idx].resp_len;
  m->idx++;
  return TRUE;
}

static gboolean
load_test_pdata (VerimarkPairing *pd)
{
  const char *path = getenv ("VERIMARK_PDATA");
  if (!path) return FALSE;
  gchar *data = NULL; gsize len = 0;
  if (!g_file_get_contents (path, &data, &len, NULL) || len != 868) { g_free (data); return FALSE; }
  gboolean ok = verimark_pairing_load ((const guint8 *) data, pd, NULL);
  g_free (data);
  return ok;
}

/* Establishes a real channel against the mock server using the generated
 * handshake vectors. Returns NULL (and g_test_skip()s) if VERIMARK_PDATA isn't
 * set. `m_out` receives the heap-allocated MockServer (io_ctx) so the caller
 * can free it after freeing the returned VerimarkTls. */
static VerimarkTls *
establish_test_channel (MockServer **m_out)
{
  VerimarkPairing pd;
  if (!load_test_pdata (&pd))
    { g_test_skip ("set VERIMARK_PDATA to a 868-byte pdata to run"); return NULL; }

  MockServer *m = g_new0 (MockServer, 1);
  m->script[0].resp = server_rt1; m->script[0].resp_len = sizeof server_rt1;
  m->script[0].expect_out = golden_client_rt1; m->script[0].expect_out_len = sizeof golden_client_rt1;
  m->script[1].resp = server_rt2; m->script[1].resp_len = sizeof server_rt2;
  m->script[1].expect_out = golden_client_rt2; m->script[1].expect_out_len = sizeof golden_client_rt2;

  VerimarkTls *t = verimark_tls_new (mock_io, m);
  verimark_tls_set_pairing (t, &pd);
  verimark_tls__test_pin (t, hv_client_random, hv_eph_priv, hv_gcm_nonce);
  /* ECDSA CertificateVerify is randomized (fresh nonce every signing call) --
   * pin it to rev's captured signature so the transcript digest (and hence the
   * Finished messages) is reproducible. See verimark-tls.h for the rationale. */
  verimark_tls__test_pin_cert_verify_sig (t, golden_cert_verify + 4, sizeof golden_cert_verify - 4);

  GError *err = NULL;
  gboolean ok = verimark_tls_handshake (t, &err);
  g_assert_no_error (err);
  g_assert_true (ok);
  g_assert_true (verimark_tls_is_established (t));
  g_assert_cmpint (m->idx, ==, 2);

  *m_out = m;
  return t;
}

/* ---------------------------------------------------------------------
 * Task 2: ClientHello build + record framing
 * ------------------------------------------------------------------- */
static void
test_client_hello (void)
{
  VerimarkTls *t = verimark_tls_new (NULL, NULL);
  verimark_tls__test_pin (t, hv_client_random, NULL, NULL);

  guint8 *out = NULL; gsize out_len = 0;
  verimark_tls__test_build_client_hello (t, &out, &out_len);

  g_assert_cmpmem (out, out_len, golden_client_rt1, sizeof golden_client_rt1);

  g_free (out);
  verimark_tls_free (t);
}

/* ---------------------------------------------------------------------
 * Task 3: parse ServerHello/Certificate/CertReq/ServerHelloDone (RT1 response)
 * ------------------------------------------------------------------- */
static void
test_process_rt1 (void)
{
  VerimarkTls *t = verimark_tls_new (NULL, NULL);

  guint8 server_random[32];
  GError *err = NULL;
  gboolean ok = verimark_tls__test_process_rt1 (t, server_rt1, sizeof server_rt1, server_random, &err);
  g_assert_no_error (err);
  g_assert_true (ok);
  g_assert_cmpmem (server_random, 32, hv_server_random, 32);

  verimark_tls_free (t);
}

static void
test_process_rt1_rejects_bad_suite (void)
{
  guint8 bad[sizeof server_rt1];
  memcpy (bad, server_rt1, sizeof bad);
  /* cipher_suite field sits right after proto_ver(2)+rand(32)+ses_id(1+7) inside
   * the ServerHello body, which starts at record offset 5 (header) + 4 (hs hdr). */
  gsize suite_off = 5 + 4 + 2 + 32 + 1 + 7;
  bad[suite_off] = 0xc0; bad[suite_off + 1] = 0x05;   /* flip to the unimplemented CBC suite */

  VerimarkTls *t = verimark_tls_new (NULL, NULL);
  guint8 server_random[32];
  GError *err = NULL;
  gboolean ok = verimark_tls__test_process_rt1 (t, bad, sizeof bad, server_random, &err);
  g_assert_false (ok);
  g_assert_nonnull (err);
  g_clear_error (&err);
  verimark_tls_free (t);
}

/* ---------------------------------------------------------------------
 * Task 4: build client Certificate/CKE/CertVerify/CCS/Finished (RT2 request)
 * ------------------------------------------------------------------- */
static void
test_build_rt2 (void)
{
  VerimarkPairing pd;
  if (!load_test_pdata (&pd))
    { g_test_skip ("set VERIMARK_PDATA to a 868-byte pdata to run"); return; }

  VerimarkTls *t = verimark_tls_new (NULL, NULL);
  verimark_tls_set_pairing (t, &pd);
  verimark_tls__test_pin (t, hv_client_random, hv_eph_priv, hv_gcm_nonce);
  /* ECDSA CertificateVerify is randomized (fresh nonce every signing call) --
   * pin it to rev's captured signature so the transcript digest (and hence the
   * Finished messages) is reproducible. See verimark-tls.h for the rationale. */
  verimark_tls__test_pin_cert_verify_sig (t, golden_cert_verify + 4, sizeof golden_cert_verify - 4);

  /* Seed the transcript with RT1 exactly as the real handshake would. */
  guint8 *ch = NULL; gsize ch_len = 0;
  verimark_tls__test_build_client_hello (t, &ch, &ch_len);
  g_assert_cmpmem (ch, ch_len, golden_client_rt1, sizeof golden_client_rt1);
  g_free (ch);

  guint8 server_random[32];
  GError *err = NULL;
  g_assert_true (verimark_tls__test_process_rt1 (t, server_rt1, sizeof server_rt1, server_random, &err));
  g_assert_no_error (err);

  guint8 *rt2 = NULL; gsize rt2_len = 0;
  guint8 master_secret[48];
  gboolean ok = verimark_tls__test_build_rt2 (t, &rt2, &rt2_len, master_secret, &err);
  g_assert_no_error (err);
  g_assert_true (ok);

  g_assert_cmpmem (rt2, rt2_len, golden_client_rt2, sizeof golden_client_rt2);
  g_assert_cmpmem (master_secret, 48, hv_master_secret, 48);

  g_free (rt2);
  verimark_tls_free (t);
}

/* ---------------------------------------------------------------------
 * Task 5: verify server Finished + establish; full handshake through the mock
 * ------------------------------------------------------------------- */
static void
test_handshake_end_to_end (void)
{
  MockServer *m = NULL;
  VerimarkTls *t = establish_test_channel (&m);
  if (!t) return;   /* skipped */

  verimark_tls_free (t);
  g_free (m);
}

/* ---------------------------------------------------------------------
 * Task 6: steady-state wrap/unwrap + close
 * ------------------------------------------------------------------- */
static void
test_wrap_unwrap_roundtrip (void)
{
  MockServer *m = NULL;
  VerimarkTls *t = establish_test_channel (&m);
  if (!t) return;   /* skipped */

  /* Independently re-derive the session keys from the (public, pinned) golden
   * randoms + master secret -- this is the "swapped-key mirror" validation: we
   * don't have access to the opaque VerimarkTls's internal keys, so we recompute
   * them via the same crypto-core primitive and use them to independently
   * decrypt what verimark_tls_wrap() produced (using encr_key, since that's what
   * wrap() used) and to independently encrypt a record for verimark_tls_unwrap()
   * to consume (using decr_key, since that's what unwrap() expects). */
  VerimarkTlsKeys keys;
  g_assert_true (verimark_tls_derive_keys (hv_master_secret, hv_client_random, hv_server_random, &keys));

  /* Handshake consumed encr_seq=0 (client Finished) and decr_seq=0 (server
   * Finished); the first steady-state wrap/unwrap therefore uses seq=1. */
  const guint64 SEQ = 1;

  /* --- wrap() then independently decrypt --- */
  const guint8 plain[] = "GET_START_INFO probe";
  guint8 *record = NULL; gsize record_len = 0;
  GError *err = NULL;
  g_assert_true (verimark_tls_wrap (t, plain, sizeof plain, &record, &record_len, &err));
  g_assert_no_error (err);
  g_assert_cmpuint (record_len, >, 5);
  g_assert_cmpuint (record[0], ==, VERIMARK_TLS_CT_APPDATA);

  guint16 rlen = (guint16) ((record[3] << 8) | record[4]);
  g_assert_cmpuint (record_len, ==, 5 + rlen);

  guint8 *dec = NULL; gsize dec_len = 0;
  g_assert_true (verimark_tls_gcm_unwrap (keys.encr_key, keys.encr_iv, SEQ, VERIMARK_TLS_CT_APPDATA,
                                          record + 5, rlen, &dec, &dec_len, &err));
  g_assert_no_error (err);
  g_assert_cmpmem (dec, dec_len, plain, sizeof plain);
  g_free (dec);
  g_free (record);

  /* --- independently encrypt then unwrap() --- */
  const guint8 plain2[] = "STORAGE_PART_READ reply payload";
  guint8 nonce[8] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
  guint8 *frag = NULL; gsize frag_len = 0;
  g_assert_true (verimark_tls_gcm_wrap (keys.decr_key, keys.decr_iv, SEQ, VERIMARK_TLS_CT_APPDATA,
                                        nonce, plain2, sizeof plain2, &frag, &frag_len, &err));
  g_assert_no_error (err);

  GByteArray *record2 = g_byte_array_new ();
  guint8 hdr[5] = { VERIMARK_TLS_CT_APPDATA, 0x03, 0x03, (guint8) (frag_len >> 8), (guint8) (frag_len & 0xff) };
  g_byte_array_append (record2, hdr, 5);
  g_byte_array_append (record2, frag, frag_len);
  g_free (frag);

  guint8 *out2 = NULL; gsize out2_len = 0;
  g_assert_true (verimark_tls_unwrap (t, record2->data, record2->len, &out2, &out2_len, &err));
  g_assert_no_error (err);
  g_assert_cmpmem (out2, out2_len, plain2, sizeof plain2);
  g_free (out2);
  g_byte_array_free (record2, TRUE);

  verimark_tls_close (t);
  g_assert_false (verimark_tls_is_established (t));

  verimark_tls_free (t);
  g_free (m);
}

static void
test_wrap_unwrap_passthrough_before_established (void)
{
  VerimarkTls *t = verimark_tls_new (NULL, NULL);
  const guint8 plain[] = "not yet established";

  guint8 *record = NULL; gsize record_len = 0;
  g_assert_true (verimark_tls_wrap (t, plain, sizeof plain, &record, &record_len, NULL));
  g_assert_cmpmem (record, record_len, plain, sizeof plain);
  g_free (record);

  guint8 *out = NULL; gsize out_len = 0;
  g_assert_true (verimark_tls_unwrap (t, plain, sizeof plain, &out, &out_len, NULL));
  g_assert_cmpmem (out, out_len, plain, sizeof plain);
  g_free (out);

  verimark_tls_free (t);
}

/* ---------------------------------------------------------------------
 * Task 7: pairing (0x93) + pdata persistence
 * ------------------------------------------------------------------- */
static void
test_hs_key (void)
{
  guint8 scalar[32];
  GError *err = NULL;
  g_assert_true (verimark_pairing__test_hs_key_scalar (scalar, &err));
  g_assert_no_error (err);
  g_assert_cmpmem (scalar, 32, golden_hs_priv_scalar, 32);
}

static void
test_host_cert_build (void)
{
  VerimarkCert cert;
  guint8 buf400[400];
  GError *err = NULL;
  g_assert_true (verimark_pairing__test_build_host_cert (golden_pair_host_priv, &cert, buf400, &err));
  g_assert_no_error (err);

  /* The HS signature (verimark_ecdsa_sign, plain ECDSA) draws a fresh random
   * nonce every call, so it can never byte-match a previously-captured golden
   * signature (same reasoning as CertificateVerify) -- compare everything
   * deterministic byte-for-byte (magic/curve/pub key/cert_type, i.e. cert[0:142],
   * matching verimark_cert_signbytes()) and verify the signature cryptographically
   * instead of byte-for-byte. */
  g_assert_cmpmem (buf400, 142, golden_host_cert_400, 142);   /* magic|curve|pub_x|pub_y|pad|cert_type */
  g_assert_cmpuint (cert.cert_type, ==, 0);

  guint8 hs_scalar[32], hs_pub_x[32], hs_pub_y[32];
  g_assert_true (verimark_pairing__test_hs_key_scalar (hs_scalar, NULL));
  g_assert_true (verimark_pub_from_priv (hs_scalar, hs_pub_x, hs_pub_y, NULL));

  guint8 signbytes[142];
  g_assert_true (verimark_cert_signbytes (&cert, signbytes, NULL));
  g_assert_true (verimark_ecdsa_verify (hs_pub_x, hs_pub_y, signbytes, sizeof signbytes,
                                        cert.signature, cert.sign_size, NULL));
}

typedef struct { const guint8 *resp; gsize resp_len; guint8 sent_opcode; } MockPair;

static gboolean
mock_pair_io (gpointer ctx, const guint8 *out, gsize out_len, guint8 **in, gsize *in_len, GError **error)
{
  MockPair *m = ctx;
  (void) error;
  g_assert_cmpuint (out_len, ==, 401);
  g_assert_cmpuint (out[0], ==, 0x93);
  m->sent_opcode = out[0];
  *in = g_memdup2 (m->resp, m->resp_len);
  *in_len = m->resp_len;
  return TRUE;
}

static void
test_pairing_do (void)
{
  MockPair m = { golden_pair_resp_802, sizeof golden_pair_resp_802, 0 };
  VerimarkPairing pd;
  GError *err = NULL;
  gboolean ok = verimark_pairing_do (mock_pair_io, &m, &pd, &err);
  g_assert_no_error (err);
  g_assert_true (ok);
  g_assert_cmpuint (m.sent_opcode, ==, 0x93);

  /* golden_pair_resp_802 = status(0000) ++ host_cert_400 ++ sensor_cert_400 --
   * verify verimark_pairing_do() parsed both certs from the right offsets. */
  VerimarkCert expect_host, expect_sensor;
  g_assert_true (verimark_cert_parse (host_cert_400, &expect_host, NULL));
  g_assert_true (verimark_cert_parse (sensor_cert_400, &expect_sensor, NULL));
  g_assert_cmpmem (pd.host_cert.pub_x, 32, expect_host.pub_x, 32);
  g_assert_cmpmem (pd.host_cert.pub_y, 32, expect_host.pub_y, 32);
  g_assert_cmpmem (pd.sensor_cert.pub_x, 32, expect_sensor.pub_x, 32);
  g_assert_cmpmem (pd.sensor_cert.pub_y, 32, expect_sensor.pub_y, 32);
}

static void
test_pairing_file_roundtrip (void)
{
  VerimarkPairing pd;
  if (!load_test_pdata (&pd))
    { g_test_skip ("set VERIMARK_PDATA to a 868-byte pdata to run"); return; }

  gchar *tmpdir = g_dir_make_tmp ("verimark-pairing-test-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_setenv ("VERIMARK_PDATA_DIR", tmpdir, TRUE);

  GError *err = NULL;
  g_assert_true (verimark_pairing_save_file (&pd, "testsid", &err));
  g_assert_no_error (err);

  gchar *path = verimark_pairing_path ("testsid");
  GStatBuf st;
  g_assert_cmpint (g_stat (path, &st), ==, 0);
  g_assert_cmpuint (st.st_mode & 0777, ==, 0600);

  VerimarkPairing pd2;
  g_assert_true (verimark_pairing_load_file ("testsid", &pd2, &err));
  g_assert_no_error (err);

  guint8 buf1[868], buf2[868];
  g_assert_true (verimark_pairing_save (&pd, buf1, NULL));
  g_assert_true (verimark_pairing_save (&pd2, buf2, NULL));
  g_assert_cmpmem (buf1, 868, buf2, 868);

  g_unlink (path);
  g_free (path);
  g_rmdir (tmpdir);
  g_free (tmpdir);
  g_unsetenv ("VERIMARK_PDATA_DIR");
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/verimark/channel/client_hello", test_client_hello);
  g_test_add_func ("/verimark/channel/process_rt1", test_process_rt1);
  g_test_add_func ("/verimark/channel/process_rt1_rejects_bad_suite", test_process_rt1_rejects_bad_suite);
  g_test_add_func ("/verimark/channel/build_rt2", test_build_rt2);
  g_test_add_func ("/verimark/channel/handshake_end_to_end", test_handshake_end_to_end);
  g_test_add_func ("/verimark/channel/wrap_unwrap_roundtrip", test_wrap_unwrap_roundtrip);
  g_test_add_func ("/verimark/channel/wrap_unwrap_passthrough", test_wrap_unwrap_passthrough_before_established);

  g_test_add_func ("/verimark/pairing/hs_key", test_hs_key);
  g_test_add_func ("/verimark/pairing/host_cert_build", test_host_cert_build);
  g_test_add_func ("/verimark/pairing/pairing_do", test_pairing_do);
  g_test_add_func ("/verimark/pairing/file_roundtrip", test_pairing_file_roundtrip);

  return g_test_run ();
}
