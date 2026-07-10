/*
 * test_moc.c — offline GTest suite for driver/verimark-moc.c's pure framing
 * helpers (Tasks 1-3 of docs/superpowers/plans/2026-07-10-verimark-moc.md).
 *
 * Every vector is taken verbatim from prototype/p2_moc.py (the working
 * ground-truth prototype, findings/49/51) — see the comment above each test
 * for the exact source line(s). No GLib main loop, no USB, no device, no
 * libfprint: this links only verimark-moc.c built with
 * -DVERIMARK_MOC_PURE_ONLY (see meson.build).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <glib.h>
#include <string.h>
#include <stdio.h>
#include "../verimark-moc.h"

static void
hexchk (const guint8 *got, gsize got_len, const char *hex)
{
  gsize want_len = strlen (hex) / 2;
  gsize i;

  g_assert_cmpuint (got_len, ==, want_len);
  for (i = 0; i < want_len; i++)
    {
      guint b;

      sscanf (hex + 2 * i, "%02x", &b);
      g_assert_cmpuint (got[i], ==, b);
    }
}

static void
hex_to_bytes (const char *hex, guint8 *out, gsize out_len)
{
  gsize i;

  g_assert_cmpuint (strlen (hex), ==, out_len * 2);
  for (i = 0; i < out_len; i++)
    {
      guint b;

      sscanf (hex + 2 * i, "%02x", &b);
      out[i] = (guint8) b;
    }
}

/* ============================================================================
 * Task 1 — command-literal builders. p2_moc.py:37-42, 289.
 * ========================================================================= */

static void
test_build_begin_id (void)
{
  guint8 b[13];
  gsize n = verimark_moc_build_begin_id (b);

  g_assert_cmpuint (n, ==, 13);   /* findings/49: 13 B is load-bearing */
  hexchk (b, n, "99010000000000000000000000");
}

static void
test_build_enroll_create (void)
{
  guint8 b[13];
  gsize n = verimark_moc_build_enroll_create (b);

  g_assert_cmpuint (n, ==, 13);
  hexchk (b, n, "96010000000000000000000000");
}

static void
test_build_enroll_sample (void)
{
  guint8 b[5];

  hexchk (b, verimark_moc_build_enroll_sample (b), "9602000000");
}

static void
test_build_enroll_commit (void)
{
  guint8 b[5];

  hexchk (b, verimark_moc_build_enroll_commit (b), "9604000000");
}

static void
test_build_frame_acq_enroll (void)
{
  guint8 b[17];

  hexchk (b, verimark_moc_build_frame_acq (b, VERIMARK_ACQ_ENROLL),
         "800c000000010000000100000801010100");
}

static void
test_build_frame_acq_verify (void)
{
  guint8 b[17];

  hexchk (b, verimark_moc_build_frame_acq (b, VERIMARK_ACQ_VERIFY),
         "8014000000010000000100000801010100");
}

static void
test_build_frame_finish (void)
{
  guint8 b[1];

  hexchk (b, verimark_moc_build_frame_finish (b), "81");
}

/* ============================================================================
 * Task 2 — response parsers. Offsets from findings/51 + p2_moc.py
 * _run_enroll (l.204,212), mode_verify (l.256-260), _list (l.849-853),
 * mode_delete (l.865-866).
 * ========================================================================= */

/* status=0000, id at [2:18]=0102...0f10, coverage[22]=7f, counter[24]=05,
 * quality[42]=63 (43-byte vector). */
#define SAMPLE_HEX \
  "00000102030405060708090a0b0c0d0e0f10000000007f000500000000000000" \
  "0000000000000000000063"

static void
test_parse_sample_ok (void)
{
  guint8 resp[43];
  VerimarkMocSample s;
  GError *error = NULL;

  hex_to_bytes (SAMPLE_HEX, resp, sizeof (resp));
  g_assert_true (verimark_moc_parse_sample (resp, sizeof (resp), &s, &error));
  g_assert_no_error (error);

  g_assert_cmpuint (s.status, ==, 0x0000);
  g_assert_cmpuint (s.coverage, ==, 0x7f);
  g_assert_cmpuint (s.counter, ==, 0x05);
  g_assert_cmpuint (s.quality, ==, 0x63);   /* findings/51: 42, not 41 */

  {
    guint8 want_id[16];

    hex_to_bytes ("0102030405060708090a0b0c0d0e0f10", want_id, 16);
    g_assert_cmpmem (s.template_id, 16, want_id, 16);
  }
}

static void
test_parse_sample_too_short (void)
{
  guint8 resp[10] = { 0 };
  VerimarkMocSample s;
  GError *error = NULL;

  g_assert_false (verimark_moc_parse_sample (resp, sizeof (resp), &s, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
}

static void
test_parse_verify_match (void)
{
  guint8 resp[177] = { 0 };
  VerimarkMocMatch m;
  GError *error = NULL;
  guint8 want_id[16];

  /* status 0x0000 at [0:2], id at [2:18] — rest of the 177-B record is
   * don't-care for this parser (findings/51: only status+id are consumed). */
  hex_to_bytes ("0102030405060708090a0b0c0d0e0f10", want_id, 16);
  memcpy (resp + 2, want_id, 16);

  g_assert_true (verimark_moc_parse_verify (resp, sizeof (resp), &m, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (m.status, ==, 0x0000);
  g_assert_true (m.matched);
  g_assert_cmpmem (m.template_id, 16, want_id, 16);
}

static void
test_parse_verify_no_match (void)
{
  guint8 resp[177] = { 0 };
  VerimarkMocMatch m;
  GError *error = NULL;

  resp[0] = 0x09;   /* 0x0509 LE */
  resp[1] = 0x05;

  g_assert_true (verimark_moc_parse_verify (resp, sizeof (resp), &m, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (m.status, ==, 0x0509);
  g_assert_false (m.matched);
}

static void
test_parse_verify_too_short (void)
{
  VerimarkMocMatch m;
  GError *error = NULL;

  g_assert_false (verimark_moc_parse_verify (NULL, 0, &m, &error));
  g_clear_error (&error);

  {
    guint8 resp[1] = { 0 };

    g_assert_false (verimark_moc_parse_verify (resp, sizeof (resp), &m, &error));
    g_assert_nonnull (error);
    g_clear_error (&error);
  }
}

/* status=0000, count=2, two 16-B GUIDs of 0x11.. and 0x22.. (36-byte vector). */
#define OBJLIST_HEX \
  "0000020011111111111111111111111111111111222222222222222222222222" \
  "22222222"

static void
test_parse_obj_list_ok (void)
{
  guint8 resp[36];
  guint16 status = 0xffff;
  GArray *ids = NULL;
  GError *error = NULL;

  hex_to_bytes (OBJLIST_HEX, resp, sizeof (resp));
  g_assert_true (verimark_moc_parse_obj_list (resp, sizeof (resp), &status, &ids, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (status, ==, 0x0000);
  g_assert_nonnull (ids);
  g_assert_cmpuint (ids->len, ==, 2);

  {
    guint8 want_g1[16], want_g2[16];

    memset (want_g1, 0x11, 16);
    memset (want_g2, 0x22, 16);
    g_assert_cmpmem (&g_array_index (ids, guint8, 0), 16, want_g1, 16);
    g_assert_cmpmem (&g_array_index (ids, guint8, 16), 16, want_g2, 16);
  }

  g_array_unref (ids);
}

static void
test_parse_obj_list_truncated (void)
{
  guint8 resp[4] = { 0x00, 0x00, 0x05, 0x00 };   /* status=0, count=5, no GUIDs follow */
  guint16 status = 0;
  GArray *ids = NULL;
  GError *error = NULL;

  g_assert_false (verimark_moc_parse_obj_list (resp, sizeof (resp), &status, &ids, &error));
  g_assert_nonnull (error);
  g_assert_null (ids);
  g_clear_error (&error);
}

/* child id at [20:36] (52-byte vector), mode_delete l.866. */
#define OBJINFO_HEX \
  "0000000000000000000000000000000000000000aabbccddeeff001122334455" \
  "6677889900000000000000000000000000000000"

static void
test_parse_obj_info_ok (void)
{
  guint8 resp[52];
  guint8 child[16];
  guint8 want[16];
  GError *error = NULL;

  hex_to_bytes (OBJINFO_HEX, resp, sizeof (resp));
  hex_to_bytes ("aabbccddeeff00112233445566778899", want, 16);

  g_assert_true (verimark_moc_parse_obj_info (resp, sizeof (resp), child, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (child, 16, want, 16);
}

static void
test_parse_obj_info_too_short (void)
{
  guint8 resp[10] = { 0 };
  guint8 child[16];
  GError *error = NULL;

  g_assert_false (verimark_moc_parse_obj_info (resp, sizeof (resp), child, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
}

/* ============================================================================
 * Task 3 — finalize splicer + SID synthesis. p2_moc.py:52-53 WIN_FINALIZE,
 * build_finalize l.56-60.
 * ========================================================================= */

#define WIN_FINALIZE_HEX \
  "9603000000000000006f000000000010000000452dec91881390e414eb6a5" \
  "8128e412101004c000000030000001c000000010500000000000515000000" \
  "000000000000000000000000e90300000000000000000000000000000000" \
  "0000000000000000000000000000000000000000000000000000020001000000f5"

static void
test_finalize_splice (void)
{
  guint8 tid[16], sid[28], out[124];
  guint8 win_finalize[124];
  GError *error = NULL;
  gsize i;

  hex_to_bytes (WIN_FINALIZE_HEX, win_finalize, 124);

  for (i = 0; i < 16; i++)
    tid[i] = (guint8) (0xa0 + i);
  for (i = 0; i < 28; i++)
    sid[i] = (guint8) (0xb0 + i);

  g_assert_true (verimark_moc_build_finalize (tid, sid, out, &error));
  g_assert_no_error (error);

  g_assert_cmpuint (out[0], ==, 0x96);
  g_assert_cmpuint (out[1], ==, 0x03);
  g_assert_cmpmem (out + 19, 16, tid, 16);
  g_assert_cmpmem (out + 49, 28, sid, 28);

  /* Only the two spliced windows changed vs. the WIN_FINALIZE template —
   * everything else is byte-identical. */
  g_assert_cmpmem (out, 19, win_finalize, 19);
  g_assert_cmpmem (out + 35, 14, win_finalize + 35, 14);
  g_assert_cmpmem (out + 77, 47, win_finalize + 77, 47);
}

static void
test_finalize_matches_python (void)
{
  guint8 win_finalize[124];
  guint8 tid[16], sid[28], out[124];
  GError *error = NULL;

  hex_to_bytes (WIN_FINALIZE_HEX, win_finalize, 124);
  memcpy (tid, win_finalize + 19, 16);
  memcpy (sid, win_finalize + 49, 28);

  g_assert_true (verimark_moc_build_finalize (tid, sid, out, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (out, 124, win_finalize, 124);
}

static void
test_synth_sid_layout (void)
{
  guint8 seed_a[16], seed_b[16], sid_a[28], sid_b[28];
  GError *error = NULL;
  gsize i;

  for (i = 0; i < 16; i++)
    seed_a[i] = (guint8) i;
  for (i = 0; i < 16; i++)
    seed_b[i] = (guint8) (0x40 + i);

  g_assert_true (verimark_moc_synth_sid (1001, seed_a, sid_a, &error));
  g_assert_no_error (error);

  g_assert_cmpuint (sid_a[0], ==, 0x01);   /* revision */
  g_assert_cmpuint (sid_a[1], ==, 0x05);   /* subauthority count */
  g_assert_cmpuint (sid_a[2], ==, 0); g_assert_cmpuint (sid_a[3], ==, 0);
  g_assert_cmpuint (sid_a[4], ==, 0); g_assert_cmpuint (sid_a[5], ==, 0);
  g_assert_cmpuint (sid_a[6], ==, 0); g_assert_cmpuint (sid_a[7], ==, 0x05);

  {
    guint32 first_sub = (guint32) sid_a[8] | ((guint32) sid_a[9] << 8)
      | ((guint32) sid_a[10] << 16) | ((guint32) sid_a[11] << 24);
    guint32 rid = (guint32) sid_a[24] | ((guint32) sid_a[25] << 8)
      | ((guint32) sid_a[26] << 16) | ((guint32) sid_a[27] << 24);

    g_assert_cmpuint (first_sub, ==, 21);
    g_assert_cmpuint (rid, ==, 1001);
  }

  /* Same uid, different seed -> same header/rid, different a/b/c
   * subauthorities (determinism + seed-sensitivity). */
  g_assert_true (verimark_moc_synth_sid (1001, seed_b, sid_b, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (sid_a, 8, sid_b, 8);          /* header identical */
  g_assert_cmpmem (sid_a + 24, 4, sid_b + 24, 4); /* rid identical */
  g_assert_false (memcmp (sid_a + 8, sid_b + 8, 16) == 0);   /* a/b/c differ */

  /* Same seed called twice -> byte-identical (pure function). */
  {
    guint8 sid_again[28];

    g_assert_true (verimark_moc_synth_sid (1001, seed_a, sid_again, &error));
    g_assert_no_error (error);
    g_assert_cmpmem (sid_a, 28, sid_again, 28);
  }
}

/* ============================================================================
 * Task 4 (offline fallback) — capture SSM state-order contract. A full
 * mock-transport FpiSsm smoke test needs a real libfprint checkout to link
 * against (fpi-device.h/fpi-ssm.h are not available in this environment —
 * see verimark-moc.h's VERIMARK_MOC_PURE_ONLY banner), so per the plan's
 * Task 4 Step 3 fallback this instead pins the capture SSM's state
 * ordering: p2_moc.py::moc_capture (l.305-331) is
 *   arm[1,2] -> wait press -> arm[24] -> FRAME_ACQ -> poll for 0x18 ->
 *   clear mask -> FRAME_FINISH
 * i.e. exactly 7 states in this order. verimark-moc.c's actual FpiSsm
 * #defines its CAP_* state numbers FROM this enum (not the reverse), so a
 * reorder here would be a real (compile-visible) driver behavior change,
 * not just a stale comment. [DEFERRED: device] covers exercising the SSM
 * itself against real interrupt/EVENT_READ traffic.
 * ========================================================================= */

static void
test_capture_state_order (void)
{
  g_assert_cmpint (VERIMARK_CAP_ARM_PRESS, ==, 0);
  g_assert_cmpint (VERIMARK_CAP_WAIT_PRESS, ==, 1);
  g_assert_cmpint (VERIMARK_CAP_ARM_FRAME, ==, 2);
  g_assert_cmpint (VERIMARK_CAP_FRAME_ACQ, ==, 3);
  g_assert_cmpint (VERIMARK_CAP_WAIT_FRAME, ==, 4);
  g_assert_cmpint (VERIMARK_CAP_EVENT_CLEAR, ==, 5);
  g_assert_cmpint (VERIMARK_CAP_FRAME_FINISH, ==, 6);
  g_assert_cmpint (VERIMARK_CAP_N_STATES, ==, 7);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/verimark/moc/build/begin_id", test_build_begin_id);
  g_test_add_func ("/verimark/moc/build/enroll_create", test_build_enroll_create);
  g_test_add_func ("/verimark/moc/build/enroll_sample", test_build_enroll_sample);
  g_test_add_func ("/verimark/moc/build/enroll_commit", test_build_enroll_commit);
  g_test_add_func ("/verimark/moc/build/acq_enroll", test_build_frame_acq_enroll);
  g_test_add_func ("/verimark/moc/build/acq_verify", test_build_frame_acq_verify);
  g_test_add_func ("/verimark/moc/build/frame_finish", test_build_frame_finish);

  g_test_add_func ("/verimark/moc/parse/sample_ok", test_parse_sample_ok);
  g_test_add_func ("/verimark/moc/parse/sample_too_short", test_parse_sample_too_short);
  g_test_add_func ("/verimark/moc/parse/verify_match", test_parse_verify_match);
  g_test_add_func ("/verimark/moc/parse/verify_no_match", test_parse_verify_no_match);
  g_test_add_func ("/verimark/moc/parse/verify_too_short", test_parse_verify_too_short);
  g_test_add_func ("/verimark/moc/parse/obj_list_ok", test_parse_obj_list_ok);
  g_test_add_func ("/verimark/moc/parse/obj_list_truncated", test_parse_obj_list_truncated);
  g_test_add_func ("/verimark/moc/parse/obj_info_ok", test_parse_obj_info_ok);
  g_test_add_func ("/verimark/moc/parse/obj_info_too_short", test_parse_obj_info_too_short);

  g_test_add_func ("/verimark/moc/finalize/splice", test_finalize_splice);
  g_test_add_func ("/verimark/moc/finalize/matches_python", test_finalize_matches_python);
  g_test_add_func ("/verimark/moc/finalize/synth_sid_layout", test_synth_sid_layout);

  g_test_add_func ("/verimark/moc/capture/state_order", test_capture_state_order);

  return g_test_run ();
}
