# VeriMark TLS Channel + Pairing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the async-driven Synaptics "Tudor" custom TLS 1.2 **secure channel** (handshake state machine + record layer) and the **TOFU pairing** (`0x93`) + pdata persistence on top of two concurrently-developed modules: the pure crypto core `driver/verimark-tls-crypto.{h,c}` (PRF, key schedule, cert/pairing codec, AES-GCM wrap/unwrap, ECDH, ECDSA) and the raw EP0 async transport primitive in `driver/verimark.c`. This plan reproduces `rev`'s `TlsSession.establish()` round-trips 1:1 and is validated **offline** against generated golden vectors + a scripted mock server, with the on-device `p1_pair.py` reproduction deferred as the final proof.

**Architecture:** Two new files. `driver/verimark-pairing.{c,h}` owns the one-time provisioning concern: derive the global HS signing key (findings/46), generate a fresh host EC keypair, build+sign the 400-byte host cert, run command `0x93`, parse the 802-byte reply, and persist/load the 868-byte pdata blob (filesystem side-effects, 0600). `driver/verimark-tls.{c,h}` owns the per-session channel: an opaque `VerimarkTls` running the hand-rolled handshake (ClientHello → parse ServerHello/Certificate/CertificateRequest/ServerHelloDone → Certificate + ClientKeyExchange + CertificateVerify + ChangeCipherSpec + Finished → verify server Finished) via a `VerimarkTlsIo` callback that performs one control WRITE+READ per round-trip, plus the record layer (`verimark_tls_wrap`/`unwrap` for steady-state application_data, seq-num counters). Both `#include "verimark-tls-crypto.h"` and call its pure functions for every primitive — this plan writes **zero** new crypto. SOLID split rationale: pairing = provisioning + disk (changes when persistence/ownership changes); channel = session crypto (changes when the handshake changes) — different reasons to change → different files.

**Tech Stack:** C11, OpenSSL libcrypto (SHA-256 transcript ctx + the crypto-core primitives), GLib-2.0 (types + GTest + `g_file_*`), meson/ninja, Python 3 via the repo `.venv` (`PYTHONPATH=re/synaTudor-rev/pydrv`) importing `rev`'s `tudor.tls`/`tudor.sensor` as the differential oracle and offline handshake-transcript generator.

## Global Constraints

- **Reproduce `rev`'s `establish()` exactly** (`re/synaTudor-rev/pydrv/tudor/tls/session.py:47-71`): the handshake is a `start_handshake()` then a `while record_layer.has_data(): send+receive` loop — for this device that is **exactly two round-trips** (RT1: ClientHello → ServerHello‖Certificate‖CertificateRequest‖ServerHelloDone; RT2: client Certificate‖CKE‖CertVerify‖CCS‖Finished → server CCS‖Finished). The C `VerimarkTlsIo` is called exactly twice.
- **Mixed hash split** (PORTING-PLAN §3 #1): the transcript hash is **SHA-256** (`handshake.py:23` `hashlib.sha256()`), but the PRF for master-secret / key-expansion / Finished verify_data is **SHA-384** (suite `0xC02E`, `ecc.py:104`). The crypto core's `verimark_tls_prf` is MD-parameterized; pass `EVP_sha384()` for all PRF calls here and keep an `EVP_sha256()` `EVP_MD_CTX` for the transcript.
- **`#BROKEN` quirks that MUST be replicated or the server Finished check fails** (all cited in-task): Finished messages are **excluded** from the transcript (`handshake.py:67-68,80-81`); **no compression method** is advertised (empty 1-byte vector, `hello.py:45`); ClientHello advertises **both** `0xC005` and `0xC02E` but only the GCM path is implemented (`ecc.py:118`, `cipher/ecc.py`); the client Certificate message writes a **doubled/garbage length** structure (`cert.py:28-30` + `crypto.py:56-59`); the negotiated key exchange is **not** ECDHE — premaster = `ECDH(client_ephemeral_priv, sensor_cert.pub_key)` against the **static** sensor cert from pdata (`ecc.py:84`).
- **Two distinct transcript snapshots** (subtle, see T4): CertificateVerify signs the digest **before** CertVerify is appended (`ecc.py:79-81` evaluates `msg_digest.digest()` as the sign argument, then `send()` appends); both Finisheds use the digest **after** CertVerify is appended (`handshake.py:129,141`). Get this ordering wrong and either CertVerify or Finished is invalid.
- **All TLS integers are big-endian** (`stream.py:14,30` `int.from_bytes(...,"big")`). Handshake message framing = `msg_id(1) ‖ length(3 BE) ‖ body` (`handshake.py:48-58`). Record framing = `content_type(1) ‖ 0x03 0x03 ‖ length(2 BE) ‖ fragment` (`record.py:103-107`). Content types: handshake=`0x16`(22), change_cipher_spec=`0x14`(20, `crypto.py:123`), alert=`0x15`(21), application_data=`0x17`(23).
- **Seq counters:** the AEAD algo keeps independent `encr_seq_num`/`decr_seq_num`, each starting at 0 when the cipher is switched and incremented per record (`encr.py:109-110,136,155`). The client Finished is the first encrypted record (encr_seq 0); the server Finished is decr_seq 0; steady-state wrapped commands continue from there.
- **pdata is a secret** (contains the host private scalar): persist at `/var/lib/fprint/verimark/<sid>.pdata`, file mode **0600**, dir mode 0700; never commit it, never world-read it. This is the resolution proposed for PORTING-PLAN §5/§9's open question.
- **Never drive this with OpenSSL's/GnuTLS's TLS stack** — hand-rolled records only, primitives from the crypto core.
- Each task ends with a green `meson test` and one commit. Offline tests only; on-device is deferred (Testing strategy).

---

## File structure

| File | Responsibility |
|---|---|
| `driver/verimark-tls.h` | **Finalized** public API of the channel: opaque `VerimarkTls`, `VerimarkTlsIo` callback contract, new/free, `handshake`, `wrap`/`unwrap`, `is_established`, `close`. Replaces the current placeholder header (which explicitly says "signatures may change once the handshake is actually implemented"). |
| `driver/verimark-tls.c` | The handshake state machine (mirrors `session.py::establish` + `handshake.py`), the record layer (plaintext + AEAD framing, seq counters), and steady-state `wrap`/`unwrap`. Calls crypto core for every primitive. |
| `driver/verimark-pairing.h` | Public API of pairing/persistence: `verimark_pairing_do` (`0x93` TOFU), `verimark_pairing_load`/`_save_file`, `verimark_pairing_path`. |
| `driver/verimark-pairing.c` | HS-key derivation (findings/46 constants), host-cert build+sign, `0x93` exchange via the raw transport, 868-byte pdata load/save at 0600. |
| `driver/tests/gen_handshake_vectors.py` | Offline generator: drives `rev`'s client with **pinned** RNG (fixed client_random + fixed ephemeral) against a **synthesized** server side (it can be built fully offline because this broken handshake requires no server proof-of-possession — see T1), emitting `handshake_vectors.h`: golden client outbound bytes per message, the two scripted server responses, and the expected established state. |
| `driver/tests/handshake_vectors.h` | Generated golden vectors (committed; public + synthetic — the pinned ephemeral priv and pinned randoms are test-only, the host private scalar from pdata is **not** emitted). |
| `driver/tests/test_tls_channel.c` | GLib-GTest runner: per-message builder/parser assertions vs golden vectors, the mock-server end-to-end handshake reaching `is_established`, wrap/unwrap round-trips, and pairing codec round-trips. |
| `driver/tests/meson.build` | Extended with `test_tls_channel` linking `../verimark-tls.c`, `../verimark-pairing.c`, `../verimark-tls-crypto.c`. |

**Note on the current `driver/verimark-tls.h`:** it is a placeholder whose `VerimarkTls`, `VerimarkTlsIo`, `verimark_tls_handshake/wrap/unwrap/is_established/close` names this plan **finalizes** (the signatures below supersede it). The `pairing`/`pairing_len` args of the placeholder `verimark_tls_handshake` move into `verimark_pairing_*` + a `verimark_tls_set_pairing` setter (SOLID: the channel receives an already-loaded pairing, it does not do disk I/O).

---

## Finalized public API

### `driver/verimark-tls.h`

```c
/*
 * verimark-tls.h — Synaptics "Tudor" custom TLS 1.2 secure channel (handshake SM +
 * record layer). Non-standard TLS 1.2; primitives from verimark-tls-crypto.h.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Oracle: re/synaTudor-rev/pydrv/tudor/tls/{session,handshake,record}.py + cipher/{ecc,encr}.py
 */
#pragma once
#include <glib.h>
#include "verimark-tls-crypto.h"   /* VerimarkPairing, VerimarkTlsKeys, PRF/ECDH/ECDSA/GCM */

typedef struct _VerimarkTls VerimarkTls;   /* opaque; defined in verimark-tls.c */

/* One handshake round-trip: send `out_len` TLS record bytes to the sensor as a raw
 * TLS_DATA (0x93-adjacent 0x44) command and return the response record bytes.
 * The implementation (verimark.c) frames `out` as command 0x44 and calls the async
 * EP0 primitive; `in` is g_malloc'd by the callee, freed by the channel. Returns
 * FALSE + sets `error` on transport failure. Called exactly twice per handshake. */
typedef gboolean (*VerimarkTlsIo) (gpointer io_ctx,
                                   const guint8 *out, gsize out_len,
                                   guint8 **in, gsize *in_len,
                                   GError **error);

VerimarkTls *verimark_tls_new  (VerimarkTlsIo io, gpointer io_ctx);
void         verimark_tls_free (VerimarkTls *tls);

/* Install the loaded 868-byte pairing (from verimark_pairing_load). Copies it in;
 * the channel uses pd->priv_scalar (CertVerify), pd->host_cert (client Certificate),
 * pd->sensor_cert (ECDH peer + verified against the bundled 10.1-kf .tsk). */
void verimark_tls_set_pairing (VerimarkTls *tls, const VerimarkPairing *pd);

/* Run the custom 2-round-trip handshake (session.py::establish). Requires a pairing
 * set. On success the channel is established and wrap/unwrap are usable. */
gboolean verimark_tls_handshake (VerimarkTls *tls, GError **error);

/* Steady-state application_data record wrap (encr_seq++) — full TLS record bytes
 * (5-byte header ‖ nonce ‖ ct ‖ tag). The MOC layer sends this via the raw transport. */
gboolean verimark_tls_wrap (VerimarkTls *tls,
                            const guint8 *plain, gsize plain_len,
                            guint8 **record, gsize *record_len, GError **error);

/* Steady-state unwrap of the raw transport reply (one or more records; decr_seq++).
 * Concatenates application_data fragments; raises on an alert record. */
gboolean verimark_tls_unwrap (VerimarkTls *tls,
                              const guint8 *record, gsize record_len,
                              guint8 **plain, gsize *plain_len, GError **error);

gboolean verimark_tls_is_established (VerimarkTls *tls);
void     verimark_tls_close (VerimarkTls *tls);   /* build+send close_notify via io */
```

### `driver/verimark-pairing.h`

```c
/*
 * verimark-pairing.h — TOFU pairing (0x93) + 868-byte pdata persistence.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Oracle: re/synaTudor-rev/pydrv/tudor/sensor/{sensor.py::pair,pair.py} + findings/46.
 */
#pragma once
#include <glib.h>
#include "verimark-tls-crypto.h"   /* VerimarkPairing, VerimarkCert */

/* Same VerimarkTlsIo shape as the channel, but the command opcode is 0x93 (not 0x44):
 * send `out` (0x93 ‖ host_cert) as a command, return the 802-byte response. */
typedef gboolean (*VerimarkPairIo) (gpointer io_ctx,
                                    const guint8 *out, gsize out_len,
                                    guint8 **in, gsize *in_len, GError **error);

/* Perform first-pairer-wins pairing: gen host keypair, HS-sign host cert, send 0x93,
 * parse the 802-byte reply (status ‖ new host cert(400) ‖ sensor cert(400)), fill `pd`. */
gboolean verimark_pairing_do (VerimarkPairIo io, gpointer io_ctx,
                              VerimarkPairing *pd, GError **error);

/* Filesystem persistence. path = /var/lib/fprint/verimark/<sid>.pdata (0600). */
gchar   *verimark_pairing_path (const gchar *sid);
gboolean verimark_pairing_save_file (const VerimarkPairing *pd, const gchar *sid, GError **error);
gboolean verimark_pairing_load      (const gchar *sid, VerimarkPairing *pd, GError **error);
```

> **API reconciliation note (flag at implementation):** CertVerify signs a **prehashed** 32-byte transcript digest (`ecc.py:80` uses `ECDSA(Prehashed(SHA256()))`), so it must NOT be re-hashed. The crypto core's `verimark_ecdsa_sign` hashes its input with SHA-256 (correct for the host-cert/HS signature, `pair.py:33`, and for sensor-cert verify), but is **wrong** for CertVerify. This plan requires a prehashed signer `verimark_ecdsa_sign_prehashed(priv, hash32, 32, &der, &len, err)` (raw ECDSA over the given hash, no re-hash). Since the crypto core owns libcrypto EC, **add it there** (the TLS-core plan is still settling); if unavailable at implementation time, implement it locally in verimark-tls.c via `EVP_DigestSignInit(md, NULL, NULL, ...)` (NULL MD = no hashing) over the 32-byte digest. Named consistently with the core's `verimark_ecdsa_sign`. Likewise pairing needs an EC keypair generator; add `verimark_ec_keygen(priv[32], pub_x[32], pub_y[32], err)` to the crypto core (it already owns EC keygen surface) or generate locally in verimark-pairing.c.

---

## Task 1: `VerimarkTlsIo` contract + offline mock-server harness

**Files:**
- Create: `driver/tests/gen_handshake_vectors.py`
- Create (generated, committed): `driver/tests/handshake_vectors.h`
- Create: `driver/tests/test_tls_channel.c` (skeleton: mock struct + `main`)
- Modify: `driver/tests/meson.build`

**Why offline is possible (design rationale):** the broken handshake requires **no server proof-of-possession** — there is no ServerKeyExchange and the client ignores the server Certificate's contents (`ecc.py:50-54` only reacts to `CertificateRequest`; the ECDH peer is the pdata `sensor_cert`, `ecc.py:84`). The only server value the client validates is the server **Finished** verify_data, which is `PRF-SHA384(master, "server finished", transcript_digest)` — and `master` is derivable by us from the pinned premaster (pinned ephemeral × pdata sensor-cert pubkey) and pinned randoms. Therefore the generator can synthesize a **fully self-consistent** server transcript offline; **no hardware is needed for the unit tests.** (Fidelity caveat + on-device proof: Testing strategy / Risks.)

- [ ] **Step 1: Extract the record/message framing the generator must emit** from `re/synaTudor-rev/pydrv/tudor/tls/data/handshake/hello.py:73-79` (ClientHello), `data/handshake/extensions.py:70-112` + the `TlsHandshakeExtension`/`TlsVector` wrappers (SupportedGroups[23] + ECPointFormats[uncompressed] exact bytes), and `data/record.py:103-107` (record header). The generator uses `rev` directly so these are auto-correct; this step is to document the expected `ClientHello` layout as a comment for the C implementer: `0x16 03 03 <rec_len> | 0x01 <msg_len(3)> | 03 03 | rand(32) | 07 <7×00> | <2-byte suites_len=4> 00 05 00 05?`— confirm the exact suite-id bytes and extension framing from the generated `golden_client_hello[]` (the arbiter), not by hand.

- [ ] **Step 2: Write the generator** `driver/tests/gen_handshake_vectors.py`

Structure (run under the venv, `PYTHONPATH=re/synaTudor-rev/pydrv`):
```
1. Load pdata prototype/pdata/f7007ad929c60000.pdata -> SensorPairingData (priv, host_cert, sensor_cert).
2. Pin RNG for determinism:
   - monkeypatch tudor.tls.data.crypto.TlsRandom.create to return TlsRandom(FIXED_TIME, FIXED_28) -> client_random.
   - monkeypatch cipher.ecc.ecc.generate_private_key to return a FIXED SECP256R1 key (derive_private_key(FIXED_EPH_INT)).
   - monkeypatch tudor.tls.cipher.encr.secrets.token_bytes to a fixed 8-byte GCM nonce.
3. Build a CommunicationInterface stub whose remote_tls_status()==False and whose
   send_command captures each client flush_send_buffer() and returns the synthesized
   server response for that round-trip (see Step 3).
4. Construct TlsSession(stub, TlsEccRemoteKey(priv, host_cert, sensor_cert)); call establish().
5. Emit handshake_vectors.h:
   - golden_client_rt1[]  = captured client bytes for round-trip 1 (ClientHello record).
   - server_rt1[]         = synthesized ServerHello‖Certificate‖CertReq‖ServerHelloDone (plaintext records).
   - golden_client_rt2[]  = captured client bytes for round-trip 2 (Cert‖CKE‖CertVerify record ‖ CCS ‖ enc Finished).
   - server_rt2[]         = synthesized server CCS ‖ encrypted server Finished.
   - Plus per-message goldens for T2-T4 fine-grained tests: golden_client_hello[], golden_client_cert[], golden_cke[], golden_cert_verify[], golden_client_finished_plain[12].
   - pinned inputs: hv_client_random[32], hv_eph_priv[32], hv_gcm_nonce[8], the pdata-derived
     sensor_cert_400[] + host_cert_400[] (public), and the derived hv_master_secret[48] (for cross-checks).
```

- [ ] **Step 3: Synthesize the server side inside the generator** (the only intricate part). Using `rev`'s own primitives with the pinned values:
  - **RT1 response** = three/four plaintext handshake records (or one coalesced record — match what the sensor sends; for the offline test, emit them as `rev` would parse them): `ServerHello(0x0303, server_random=FIXED, ses_id=7×00, cipher_suite=0xC02E, compr=0x00, no extensions)` ‖ `Certificate(sensor_cert.tobytes())` (use `TlsHandshakeCertificate` so the 3+2 garbage framing matches `crypto.py:56-59`) ‖ `CertificateRequest([ECDSA_SIGN=64])` (`cert.py:51-53`, includes the 2 garbage bytes) ‖ `ServerHelloDone()`. Wrap each in a plaintext record (`content_type=0x16`).
  - **RT2 response** = `ChangeCipherSpec` plaintext record (`content_type=0x14`, body `0x01`) ‖ the **encrypted** server `Finished`. Compute `verify_data = tls_prf(master, "server finished", transcript_digest, 12, SHA384())` where `master` and `transcript_digest` come from replaying the client (the generator has them post-`establish` via the stub, or recompute). GCM-encrypt the Finished handshake message using the **server-write** key material = the client's `decr_key`/`decr_iv` at server seq 0 — **extract the exact encrypt steps from `encr.py:119-137`** (nonce ‖ GCM(iv=decr_iv‖nonce, aad=seq0(8 BE)‖0x16‖0x0303‖len) ‖ tag). Emit as `server_rt2[]`.

- [ ] **Step 4: Run the generator, expect `handshake_vectors.h` written**

Run: `cd /home/sshadows/nogit/LocalChanges/verimark-driver && PYTHONPATH=re/synaTudor-rev/pydrv ./.venv/bin/python driver/tests/gen_handshake_vectors.py`
Expected: prints `wrote .../handshake_vectors.h` and the internal `establish()` completed (`phase == FINISHED`) proving the synthesized server side is self-consistent. Exit 0.

- [ ] **Step 5: Define the mock-server harness + `VerimarkTlsIo` in the test skeleton** `driver/tests/test_tls_channel.c`

```c
#include <glib.h>
#include <string.h>
#include "../verimark-tls.h"
#include "handshake_vectors.h"

typedef struct {
  struct { const guint8 *resp; gsize resp_len;
           const guint8 *expect_out; gsize expect_out_len; } script[2];
  int idx;
} MockServer;

/* VerimarkTlsIo: assert the client's outbound bytes match the golden capture, then
 * hand back the scripted server response. Proves the C client is byte-identical to rev. */
static gboolean
mock_io (gpointer ctx, const guint8 *out, gsize out_len,
         guint8 **in, gsize *in_len, GError **error)
{
  MockServer *m = ctx;
  g_assert_cmpint (m->idx, <, 2);
  g_assert_cmpmem (out, out_len, m->script[m->idx].expect_out, m->script[m->idx].expect_out_len);
  *in = g_memdup2 (m->script[m->idx].resp, m->script[m->idx].resp_len);
  *in_len = m->script[m->idx].resp_len;
  m->idx++;
  return TRUE;
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  /* T2-T7 register their funcs here. */
  return g_test_run ();
}
```

- [ ] **Step 6: Add the test to meson + build the (empty) skeleton green**

Add to `driver/tests/meson.build`:
```meson
tls_channel_test = executable('test_tls_channel',
  ['test_tls_channel.c', '../verimark-tls.c', '../verimark-pairing.c', '../verimark-tls-crypto.c'],
  dependencies : [glib_dep, crypto_dep])
test('tls_channel', tls_channel_test, args : ['-p', '/verimark/channel'],
  env : ['VERIMARK_PDATA=' + meson.current_source_dir() + '/../../prototype/pdata/f7007ad929c60000.pdata'])
```
Run: `meson setup driver/tests/build driver/tests --reconfigure && meson test -C driver/tests/build tls_channel -v`
Expected: builds (with empty `verimark-tls.c`/`verimark-pairing.c` stubs providing the declared symbols) and reports `tls_channel` `OK` with 0 registered subtests. This confirms link wiring before any behavior. (If the crypto-core `.c` is not yet present, `git stash`-guard: this test project's `meson.build` is the same one from the TLS-core plan; the core `.c` must exist to link.)

- [ ] **Step 7: Commit**
```bash
git add driver/tests/gen_handshake_vectors.py driver/tests/handshake_vectors.h driver/tests/test_tls_channel.c driver/tests/meson.build
git commit -m "verimark-tls: offline handshake-vector generator + mock-server harness skeleton"
```

---

## Task 2: ClientHello build + outbound plaintext record framing

**Files:** Create `driver/verimark-tls.h` (finalized, above) + `driver/verimark-tls.c`; modify `test_tls_channel.c`.

**Interfaces:** internal `verimark_tls_new/free`, the `VerimarkTls` struct, an internal `hs_build_client_hello(VerimarkTls*, GByteArray *out)` and record helper `rec_write_plain(GByteArray *out, guint8 ct, const guint8 *body, gsize n)`. Consumes `handshake_vectors.h` `golden_client_rt1`, `hv_client_random`.

- [ ] **Step 1: Define the `VerimarkTls` struct + new/free in `verimark-tls.c`**
```c
#define FP_COMPONENT "verimark"
#include "verimark-tls.h"
#include <string.h>
#include <openssl/sha.h>

struct _VerimarkTls {
  VerimarkTlsIo io; gpointer io_ctx;
  gboolean have_pairing, established;
  VerimarkPairing pd;                 /* set via verimark_tls_set_pairing */
  guint8  client_random[32];
  guint8  server_random[32];
  guint8  eph_priv[32];               /* client ephemeral (T4) */
  guint8  master_secret[48];
  VerimarkTlsKeys keys;               /* crypto-core key block (T4) */
  guint64 encr_seq, decr_seq;
  EVP_MD_CTX *transcript;             /* SHA-256, excludes Finished */
};
VerimarkTls *verimark_tls_new (VerimarkTlsIo io, gpointer io_ctx) {
  VerimarkTls *t = g_new0 (VerimarkTls, 1);
  t->io = io; t->io_ctx = io_ctx;
  t->transcript = EVP_MD_CTX_new (); EVP_DigestInit_ex (t->transcript, EVP_sha256 (), NULL);
  return t;
}
void verimark_tls_free (VerimarkTls *t) { if (!t) return; EVP_MD_CTX_free (t->transcript); g_free (t); }
void verimark_tls_set_pairing (VerimarkTls *t, const VerimarkPairing *pd) { t->pd = *pd; t->have_pairing = TRUE; }
gboolean verimark_tls_is_established (VerimarkTls *t) { return t && t->established; }
```

- [ ] **Step 2: Implement record + transcript helpers**
```c
/* plaintext record: content_type ‖ 0x03 0x03 ‖ len(2 BE) ‖ body  (record.py:103-107) */
static void rec_write_plain (GByteArray *out, guint8 ct, const guint8 *body, gsize n) {
  guint8 hdr[5] = { ct, 0x03, 0x03, (guint8)(n >> 8), (guint8)(n & 0xff) };
  g_byte_array_append (out, hdr, 5); g_byte_array_append (out, body, n);
}
/* handshake message: id ‖ len(3 BE) ‖ body ; also feed raw bytes to transcript
 * unless it is Finished (0x14) — handshake.py:67-68. */
static void hs_msg (VerimarkTls *t, GByteArray *dst, guint8 id, const guint8 *body, gsize n) {
  guint8 h[4] = { id, (guint8)(n>>16), (guint8)(n>>8), (guint8)(n&0xff) };
  gsize start = dst->len;
  g_byte_array_append (dst, h, 4); g_byte_array_append (dst, body, n);
  if (id != 0x14) EVP_DigestUpdate (t->transcript, dst->data + start, 4 + n);
}
```

- [ ] **Step 3: Extract the exact ClientHello extension bytes** from `data/handshake/extensions.py:70-112` + the `TlsHandshakeExtension` wrapper (`ext_type(2) ‖ ext_len(2) ‖ ext_body`) and `TlsVector` prefix sizes (`data.py`). Encode SupportedGroups(id=10, curves=[23]) and ECPointFormats(id=11, formats=[0]) as constant byte arrays. The generated `golden_client_hello[]` is the arbiter — match it byte-for-byte.

- [ ] **Step 4: Implement `hs_build_client_hello`** (proto 0x0303 ‖ client_random(32) ‖ ses_id `07`+7×00 ‖ suites vector `00 04` + `C0 05` + `C0 2E` ‖ compr vector `00` (empty, #BROKEN `hello.py:45`) ‖ the two extensions from Step 3), wrap via `hs_msg(id=0x01)` then `rec_write_plain(ct=0x16)`. Generate `client_random` = 4-byte BE time ‖ 28 random (`crypto.py:20-22`); in tests inject `hv_client_random`.

- [ ] **Step 5: Failing test then implement.** Add `test_client_hello` asserting the built record `== golden_client_rt1`. Register under `/verimark/channel/client_hello`. Run `meson test -C driver/tests/build tls_channel -v` — expect FAIL (mismatch/undefined), then implement to green.

- [ ] **Step 6: Commit** `verimark-tls: ClientHello build + plaintext record framing`.

---

## Task 3: Parse ServerHello + Certificate + CertificateRequest + ServerHelloDone (RT1 response)

**Files:** modify `verimark-tls.c`, `test_tls_channel.c`. **Interfaces:** internal `hs_process_rt1(VerimarkTls*, const guint8 *resp, gsize)`. Consumes `handshake_vectors.h` `server_rt1`.

- [ ] **Step 1: Implement a record splitter + handshake-message splitter.** A response buffer is a sequence of records (`ct ‖ 0303 ‖ len(2 BE) ‖ frag`); RT1 records are all plaintext handshake (`ct==0x16`). Concatenate their fragments, then iterate handshake messages purely by their self-delimiting header (`id ‖ len(3 BE) ‖ body`) — **no need to understand Certificate internals**; split by length only. Feed each message's raw bytes (`id‖len‖body`) to the transcript via `EVP_DigestUpdate` (all RT1 messages precede Finished).

- [ ] **Step 2: Dispatch by message id** (`handshake/*` ids): `0x02` ServerHello → parse `proto_ver(2) ‖ server_random(32) ‖ ses_id(len+data) ‖ cipher_suite(2) ‖ compr(1)`; **assert cipher_suite == 0xC02E** (`ecc.py:99-103` negotiation) else `HANDSHAKE_FAILURE`; store `server_random`. `0x0b` Certificate → ignore body (transcript only). `0x0d` CertificateRequest → parse the 1-byte-count cert-type vector (`cert.py:47`) and **assert ECDSA_SIGN (64) present** (`ecc.py:61`) else `HANDSHAKE_FAILURE`. `0x0e` ServerHelloDone → mark RT1 complete. Any other id in RT1 → `UNEXPECTED_MESSAGE`.

- [ ] **Step 3: Failing test then implement.** `test_process_rt1` feeds `server_rt1`, asserts `server_random == hv_server_random` and that RT1 completed without error. Run, FAIL→implement→green.

- [ ] **Step 4: Commit** `verimark-tls: parse ServerHello/Certificate/CertReq/ServerHelloDone`.

---

## Task 4: Build client Certificate + ClientKeyExchange + CertificateVerify + CCS + Finished (RT2 request)

**Files:** modify `verimark-tls.c`, `test_tls_channel.c`. **Interfaces:** internal `hs_build_rt2(VerimarkTls*, GByteArray *out)`; calls crypto core `verimark_ecdh_premaster`, `verimark_tls_derive_master_secret`, `verimark_tls_derive_keys`, `verimark_ecdsa_sign_prehashed`, `verimark_tls_prf`, `verimark_tls_gcm_wrap`, `verimark_pub_from_priv`. Consumes `golden_client_rt2`, `hv_eph_priv`, `hv_gcm_nonce`, `hv_master_secret`.

- [ ] **Step 1: Extract the client Certificate wire quirk** from `cert.py:28-30` + `crypto.py:56-59`: Certificate message body = `outer_len(3 BE = len(host_cert)=400) ‖ inner_len(3 BE = 400) ‖ 0x00 0x00 (garbage) ‖ host_cert(400)` (total body = 3+3+2+400 = 408; the **outer 400 ≠ following 405** is the intended `#BROKEN` bug — replicate it). The generated `golden_client_cert[]` cross-checks this.

- [ ] **Step 2: Build the three client messages into one coalesced handshake record** (rev buffers same content-type then flushes one record, `record.py:98-103,114-122`):
  - **Certificate** (id `0x0b`): body from Step 1 using `t->pd.host_cert` serialized via `verimark_cert_serialize`.
  - **ClientKeyExchange** (id `0x10`): body = raw EC point `0x04 ‖ eph_pub_x(32) ‖ eph_pub_y(32)` (`cipher/ecc.py:25-28`, no length prefix — `kex.py:18` writes content raw). Generate the ephemeral key (`verimark_ec_keygen` → `eph_priv`,`eph_pub`); in tests inject `hv_eph_priv` and derive its pub via `verimark_pub_from_priv`.
  - **CertificateVerify** (id `0x0f`): sign the transcript digest **as it stands after CKE, before CertVerify is appended** (`ecc.py:79-81`): snapshot `EVP_MD_CTX_copy` → `EVP_DigestFinal` → 32-byte digest `dA`; `verimark_ecdsa_sign_prehashed(t->pd.priv_scalar, dA, 32, &der, &len)`; body = `der` (raw, no length prefix — `cert.py:67` writes raw, #BROKEN).
  - Each appended via `hs_msg` so the transcript now covers …‖CKE‖CertVerify. Wrap the coalesced body in one `rec_write_plain(ct=0x16)`.
- [ ] **Step 3: Compute premaster + keys.** `verimark_ecdh_premaster(eph_priv, t->pd.sensor_cert.pub_x, .pub_y, premaster)` (`ecc.py:84`); `verimark_tls_derive_master_secret(premaster, 32, client_random, server_random, master_secret)`; `verimark_tls_derive_keys(master_secret, client_random, server_random, &t->keys)`; `t->encr_seq = t->decr_seq = 0`.
- [ ] **Step 4: Append the ChangeCipherSpec record** (`ct=0x14`, body single byte `0x01`, `crypto.py:124`; separate content type ⇒ its own record).
- [ ] **Step 5: Build the client Finished (first encrypted record).** Snapshot the transcript **now** (after CertVerify appended) → digest `dB`; `verimark_tls_prf(EVP_sha384(), master_secret, 48, "client finished", dB, 32, verify_data, 12)` (`handshake.py:129`). Frame as a handshake message `hs_msg(id=0x14 …)` **but Finished is excluded from the transcript** (the `id!=0x14` guard in `hs_msg` handles this); GCM-encrypt the 16-byte Finished handshake-message bytes with `verimark_tls_gcm_wrap(t->keys.encr_key, t->keys.encr_iv, t->encr_seq++, /*ct*/0x16, nonce, msgbytes, 16, &frag, &fraglen)` (in tests nonce=`hv_gcm_nonce`); wrap `frag` in `rec_write_plain(ct=0x16)`. Note: the AEAD content_type in the AAD is `0x16` (handshake), not app-data — pass it explicitly.
- [ ] **Step 6: Failing test then implement.** `test_build_rt2` runs T3 on `server_rt1` first (to load `server_random`), then asserts `hs_build_rt2` output `== golden_client_rt2` and `master_secret == hv_master_secret`. FAIL→implement→green.
- [ ] **Step 7: Commit** `verimark-tls: build client Certificate/CKE/CertVerify/CCS/Finished (RT2)`.

---

## Task 5: Verify server Finished + establish; full handshake through the mock

**Files:** modify `verimark-tls.c`, `test_tls_channel.c`. **Interfaces:** `verimark_tls_handshake` (public), internal `hs_process_rt2`. Consumes `server_rt2`, and the full `golden_client_rt1/rt2` + `server_rt1/rt2` mock script.

- [ ] **Step 1: Implement `hs_process_rt2`.** Split the response into records: first record `ct==0x14` ChangeCipherSpec (switch remote→encrypted); second record `ct==0x16` = encrypted server Finished → `verimark_tls_gcm_unwrap(t->keys.decr_key, t->keys.decr_iv, t->decr_seq++, 0x16, frag, fraglen, &msg, &n)`; parse handshake message id `0x14`, body = 12-byte `verify_data`. Compute `expected = PRF-SHA384(master, "server finished", dB, 12)` using the **same `dB`** snapshot from T4 Step 5 (server Finished is also excluded from the transcript, so the digest is unchanged — `handshake.py:141`). `g_assert`/error if `memcmp` differs (`DECRYPT_ERROR`). On match set `t->established = TRUE`.
- [ ] **Step 2: Implement the public `verimark_tls_handshake`** mirroring `establish()`:
```c
gboolean verimark_tls_handshake (VerimarkTls *t, GError **error) {
  g_return_val_if_fail (t->have_pairing, FALSE);
  /* (optional) verify sensor_cert vs bundled 10.1-kf .tsk here — sensor.py:184 / p1_pair.py:89 */
  g_autoptr(GByteArray) out = g_byte_array_new ();
  hs_build_client_hello (t, out);                     /* RT1 request  */
  g_autofree guint8 *in = NULL; gsize in_len = 0;
  if (!t->io (t->io_ctx, out->data, out->len, &in, &in_len, error)) return FALSE;
  if (!hs_process_rt1 (t, in, in_len, error)) return FALSE;
  g_byte_array_set_size (out, 0); g_clear_pointer (&in, g_free);
  if (!hs_build_rt2 (t, out, error)) return FALSE;    /* RT2 request  */
  if (!t->io (t->io_ctx, out->data, out->len, &in, &in_len, error)) return FALSE;
  if (!hs_process_rt2 (t, in, in_len, error)) return FALSE;
  g_assert (t->established);
  return TRUE;
}
```
- [ ] **Step 3: Failing test then implement** — the flagship offline test. `test_handshake_end_to_end`: build `MockServer` from `{server_rt1, golden_client_rt1}` + `{server_rt2, golden_client_rt2}`, `verimark_tls_new(mock_io, &m)`, load pdata via `verimark_pairing_load`/env `VERIMARK_PDATA` (or a `handshake_vectors.h` embedded copy), `verimark_tls_set_pairing`, inject pinned `client_random`/`eph_priv`/`nonce` (test-only setters `verimark_tls__test_pin(...)` behind `#ifdef VERIMARK_TESTING`), `g_assert_true (verimark_tls_handshake(...))`, `g_assert_true (verimark_tls_is_established(...))`, and `g_assert_cmpint (m.idx, ==, 2)`. FAIL→implement→green. This proves the C client is byte-identical to `rev`'s (mock asserts every outbound blob) AND completes a real handshake.
- [ ] **Step 4: Commit** `verimark-tls: verify server Finished + full handshake vs mock server`.

---

## Task 6: Steady-state record wrap / unwrap (application_data) + close

**Files:** modify `verimark-tls.c`, `test_tls_channel.c`. **Interfaces:** public `verimark_tls_wrap`, `verimark_tls_unwrap`, `verimark_tls_close`. Consumes crypto-core GCM + `hv_master_secret`-derived keys (reuses the established channel from T5).

- [ ] **Step 1: Implement `verimark_tls_wrap`** — content_type application_data (`0x17`): generate an 8-byte random nonce; `verimark_tls_gcm_wrap(keys.encr_key, keys.encr_iv, encr_seq++, 0x17, nonce, plain, plain_len, &frag, &fraglen)`; prepend the 5-byte record header via `rec_write_plain` semantics; return the full record (`encr.py:119-137`). If `!established`, pass through (`session.py:91`).
- [ ] **Step 2: Implement `verimark_tls_unwrap`** — iterate records in the reply (`record.py:44-92`): for `ct==0x17` app-data, `verimark_tls_gcm_unwrap(keys.decr_key, keys.decr_iv, decr_seq++, 0x17, frag, fraglen, &p, &n)` and append `p` to a `GByteArray`; for `ct==0x15` alert, decrypt+raise (`BAD_RECORD_MAC`/`close_notify`); return the concatenated plaintext. If `!established`, pass through.
- [ ] **Step 3: Implement `verimark_tls_close`** — build a `close_notify` alert (`level=WARNING(1)`, `descr=CLOSE_NOTIFY(0)`, `record.py:125-127`) as an encrypted app-alert record (`ct=0x15`), send via `io`; set `established=FALSE`. (`record.py:29-34` / `session.py:73-87`.)
- [ ] **Step 4: Failing test then implement.** `test_wrap_unwrap_roundtrip`: after T5's established channel, `verimark_tls_wrap(plain)` → feed the record back through `verimark_tls_unwrap` **using a swapped-key mirror** (or assert against a `rev`-generated `golden_wrapped_0x19[]` for the `GET_START_INFO` command from the generator, reproducing `p1_pair.py:106`). Prefer the golden-vector assertion (deterministic, exercises the real decr path against `rev`'s encr output). FAIL→implement→green.
- [ ] **Step 5: Commit** `verimark-tls: application_data wrap/unwrap + close_notify`.

---

## Task 7: Pairing (`0x93`) — HS-key host cert build/sign + pdata persistence

**Files:** Create `driver/verimark-pairing.h` (finalized, above) + `driver/verimark-pairing.c`; modify `test_tls_channel.c`, `gen_handshake_vectors.py` (emit `golden_host_cert[]`).

**Interfaces:** `verimark_pairing_do`, `verimark_pairing_path`, `verimark_pairing_save_file`, `verimark_pairing_load`; calls crypto-core `verimark_ec_keygen`, `verimark_cert_signbytes`, `verimark_ecdsa_sign` (SHA-256, NOT prehashed — `pair.py:33`), `verimark_cert_serialize`, `verimark_cert_parse`, `verimark_pairing_load`/`_save` (the 868-byte codec from the crypto core Task 4). Note the crypto core already owns `verimark_pairing_load(buf868,...)`/`verimark_pairing_save(pd,buf868,...)` (in-memory codec); this file adds the **file** layer + the `0x93` exchange.

- [ ] **Step 1: Extract the HS-key derivation constants** from findings/46 (and `re/synaTudor-rev/pydrv/tudor/sensor/sensor_keys/genhskey.py`): `secret = 717cd72d0962bc4a2846138dbb2c2419` (16 B), `seed = 2512a76407065f383846139d4bec2033 ‖ aaaa` (18 B), `label = "HS_KEY_PAIR_GEN"`; `hs_priv_scalar = PRF-SHA256(secret, label, seed, 32)` interpreted **little-endian** (findings/46 "Endianness closed"). Implement:
```c
static gboolean hs_key_scalar (guint8 out_be[32], GError **error) {
  static const guint8 secret[16] = {0x71,0x7c,0xd7,0x2d,0x09,0x62,0xbc,0x4a,0x28,0x46,0x13,0x8d,0xbb,0x2c,0x24,0x19};
  static const guint8 seed[18]   = {0x25,0x12,0xa7,0x64,0x07,0x06,0x5f,0x38,0x38,0x46,0x13,0x9d,0x4b,0xec,0x20,0x33,0xaa,0xaa};
  guint8 prf[32];
  if (!verimark_tls_prf (EVP_sha256 (), secret, 16, "HS_KEY_PAIR_GEN", seed, 18, prf, 32)) {
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "HS PRF failed"); return FALSE; }
  for (int i = 0; i < 32; i++) out_be[i] = prf[31 - i];   /* LE scalar -> BE for crypto-core */
  return TRUE;
}
```
Cross-check against findings/46: `hs_priv_scalar = 0xe8a2a2b6656254d6acb0ef479cae4140c7e8e260db3f642e35d4099c01b36a86`.

- [ ] **Step 2: Implement `verimark_pairing_do`** (mirrors `sensor.py:187-206` + `pair.py:26-35`):
  1. `verimark_ec_keygen(host_priv, host_pub_x, host_pub_y)`.
  2. Build `VerimarkCert host = { cert_type=0, pub_x=host_pub_x, pub_y=host_pub_y }`; `verimark_cert_signbytes(&host, sb142)`; `hs_key_scalar(hs)`; `verimark_ecdsa_sign(hs, sb142, 142, &der, &len)` (SHA-256 over signbytes — `pair.py:33`); set `host.signature=der`, `host.sign_size=len`; `verimark_cert_serialize(&host, buf400)`.
  3. `out = 0x93 ‖ buf400` (401 B); `io(ctx, out, 401, &resp, &resp_len)`; assert `resp_len == 802`, status `resp[0..1] == 0x0000`.
  4. `verimark_cert_parse(resp+2, &pd->host_cert)` (the sensor's re-minted host cert), `verimark_cert_parse(resp+402, &pd->sensor_cert)` (`sensor.py:203`); `memcpy(pd->priv_scalar, host_priv, 32)` — the persisted scalar is **our generated** priv, not the returned cert's.

- [ ] **Step 3: Implement the file layer.**
```c
gchar *verimark_pairing_path (const gchar *sid) {
  return g_build_filename ("/var/lib/fprint/verimark", g_strconcat (sid, ".pdata", NULL), NULL); /* leak-free variant at impl */
}
gboolean verimark_pairing_save_file (const VerimarkPairing *pd, const gchar *sid, GError **error) {
  g_autofree gchar *dir = g_build_filename ("/var/lib/fprint/verimark", NULL);
  if (g_mkdir_with_parents (dir, 0700) != 0) { /* set error */ return FALSE; }
  guint8 buf[868];
  if (!verimark_pairing_save (pd, buf, error)) return FALSE;   /* crypto-core 868 codec */
  g_autofree gchar *path = verimark_pairing_path (sid);
  int fd = g_open (path, O_WRONLY|O_CREAT|O_TRUNC, 0600);      /* 0600 — host priv scalar */
  if (fd < 0) { /* set error */ return FALSE; }
  gboolean ok = (write (fd, buf, 868) == 868); g_close (fd, NULL);
  return ok;
}
gboolean verimark_pairing_load (const gchar *sid, VerimarkPairing *pd, GError **error) {
  g_autofree gchar *path = verimark_pairing_path (sid);
  g_autofree gchar *data = NULL; gsize len = 0;
  if (!g_file_get_contents (path, &data, &len, error)) return FALSE;   /* NOT_FOUND ⇒ caller pairs */
  if (len != 868) { /* INVALID_DATA */ return FALSE; }
  return verimark_pairing_load ((const guint8 *) data, pd, error);     /* crypto-core 868 codec */
}
```
> Naming collision to reconcile at implementation: the crypto core already exports `verimark_pairing_load(const guint8 buf[868], ...)`. Rename the **file** loader to `verimark_pairing_load_file(sid, ...)` (parallel to `_save_file`) to avoid the clash; update `verimark-pairing.h` accordingly.

- [ ] **Step 4: Failing test then implement.**
  - `test_hs_key` asserts `hs_key_scalar` == findings/46 constant (reverse to LE and compare, or compare the BE form directly).
  - `test_host_cert_build` (deterministic via a pinned `verimark_ec_keygen` seam in tests) asserts the serialized host cert `== golden_host_cert[]` from the generator (which builds it via `SensorCertificate.create_host_cert` with the same pinned pub).
  - `test_pairing_do` uses a mock `VerimarkPairIo` returning a canned 802-byte reply (from the generator: `status(0) ‖ pdata.host_cert ‖ pdata.sensor_cert`); asserts `pd.sensor_cert.pub_x == sensor_cert_pub_x`.
  - `test_pairing_file_roundtrip`: `verimark_pairing_load(buf868)` (from `VERIMARK_PDATA`) → `verimark_pairing_save_file` to a `g_dir_make_tmp` path (override the base dir via a test-only env `VERIMARK_PDATA_DIR`) → reload → `g_assert_cmpmem` 868 bytes; assert mode is 0600 via `g_stat`.
  FAIL→implement→green.
- [ ] **Step 5: Commit** `verimark-pairing: 0x93 TOFU + HS-key host cert + 868-byte pdata (0600)`.

---

## Testing strategy

- **Offline is the primary proof (no hardware).** Every task asserts C output against `rev`-generated golden vectors (`gen_handshake_vectors.py`, differential oracle), exactly like the crypto-core plan. The crypto core already covers the primitives (PRF/derive/GCM/ECDH/ECDSA/cert codec); this plan tests the **glue**: message framing, transcript hashing with the Finished-exclusion + mixed-hash quirks, the 2-round-trip state machine, seq-num handling, and the pairing codec.
- **The mock-server harness (T1/T5)** replays a **synthesized, self-consistent** handshake generated offline. This is sound because the broken handshake needs no server proof-of-possession; the generator internally runs `rev`'s `establish()` to `phase==FINISHED`, guaranteeing the script is valid. The mock also asserts the client's outbound bytes match `rev` byte-for-byte (`mock_io`'s `g_assert_cmpmem`).
- **Fidelity gap + on-device proof (deferred).** The synthesized server messages are what `rev` would *accept*, which may differ in incidental bytes (extension echoes, ses_id, CertificateRequest garbage) from what the physical sensor emits. The **final** proof is on-device: wire `verimark_tls_new` into `verimark.c`'s OPEN SSM with a real `VerimarkTlsIo` over the EP0 transport, run against the sensor, and confirm it reproduces `p1_pair.py` (`remote_tls_status()` established + a wrapped `0x19 GET_START_INFO` returns status `0x0000`). This is out of scope here (belongs to the verimark.c OPEN-SSM plan) and requires the device + a live pairing; flag it as the acceptance gate for P2.
- **Optional higher-fidelity augmentation:** if a real usbmon handshake capture (paired, pinned or not) is available, feed its two server responses into the mock as an additional test variant — but the server Finished will only validate if the client RNG is pinned to the captured values, so a *captured* transcript still needs a matching *captured* client_random+ephemeral. The offline-generated vectors avoid this and are the default.

---

## Risks / open questions

- **Mock-server transcript source (T1).** Resolved: generated **offline** by `gen_handshake_vectors.py` (no device). Residual risk = incidental byte differences vs the real sensor (see fidelity gap) — closed by the deferred on-device reproduction, not by the unit tests. If offline synthesis of the encrypted server Finished (T1 Step 3) proves fiddly, fall back to a one-time instrumented `p1_pair.py` run with pinned RNG that dumps the two server responses; flag this as the only scenario that needs hardware before the unit tests can go green.
- **Sync handshake behind an async SSM (PORTING-PLAN §3 #2).** Recommended design: `verimark_tls_handshake` stays **synchronous** and calls `VerimarkTlsIo` twice; the OPEN SSM provides an `io` that performs a **synchronous** `g_usb_device_control_transfer` WRITE+READ (framing `out` as command `0x44`). This is acceptable because it runs only during `dev_open`'s bounded 2-round-trip handshake — **not** steady-state — so it cannot stall an in-progress enroll/verify, and it needs **no nested main loop** (the open question in §3 #2). Steady-state MOC commands use the async `FpiSsm` path with `verimark_tls_wrap`/`unwrap` (pure, non-blocking). If a fully-async open is later required, switch to option (a) (SSM state per round-trip) — the record/handshake helpers here are already pure and reusable; only `verimark_tls_handshake`'s driver loop changes.
- **pdata location/permissions (PORTING-PLAN §5/§9).** Proposed: `/var/lib/fprint/verimark/<sid>.pdata`, mode 0600, dir 0700, created by fprintd (root). Open sub-question: multi-user/multi-sensor keying (the `<sid>` filename handles multiple sensors; per-user is N/A — pairing is device-global TOFU). Confirm fprintd's effective uid can create `/var/lib/fprint` on the target distro.
- **API reconciliation with the still-settling crypto core** (surfaced above): needs `verimark_ecdsa_sign_prehashed` (CertVerify, `ecc.py:80`) and `verimark_ec_keygen` (pairing) — both belong in the crypto core (owns libcrypto EC). If they are not present when this plan is implemented, add them there (preferred) or implement locally; either way keep the `verimark_ecdsa_*` / `verimark_*` naming consistent with the crypto-core plan.
- **`verimark_pairing_load` name clash** between the crypto-core in-memory codec and this file's disk loader — rename the disk loader `verimark_pairing_load_file` (noted in T7 Step 3).
- **Content-type in the AEAD AAD for the Finished** is `0x16` (handshake), not `0x17` (app-data); the crypto-core `verimark_tls_gcm_wrap` takes `content_type` as a parameter, so pass `0x16` for the Finished and `0x17` for steady-state — a per-call value, not a constant. Easy to get wrong; called out in T4/T6.

---

## Self-review

**Spec coverage (PORTING-PLAN §3 #1/#2 + P2 checklist):**
- Custom TLS 1.2 channel in C, primitives-only, hand-rolled records — T2-T6. ✔
- No ServerKeyExchange / premaster = ECDH(ephemeral, sensor-cert static pubkey) — T4 Step 3 (`ecc.py:84`). ✔
- Client auth: Certificate + CertificateVerify via pairing keypair — T4 Steps 2 (`ecc.py:65-81`). ✔
- SHA-256 transcript / SHA-384 PRF split — Global Constraints + T2 (transcript ctx) + T4/T5 (PRF-SHA384 Finished). ✔
- Finished excluded from transcript; no compression advertised; advertise `0xC005`+`0xC02E`, implement GCM only — Global Constraints + `hs_msg` guard (T2) + T2 Step 4 + T3 Step 2. ✔
- AES-256-GCM record: nonce/AAD/tag, seq counters — T4 Step 5, T6 (via crypto-core `gcm_wrap`/`unwrap`). ✔
- Pairing `0x93`, 800-byte (802 w/ status) reply parse, 868-byte pdata, sensor-cert ECDSA verify — T7 + T5 Step 2 note. ✔
- HS-key derivation (findings/46 constants + LE scalar) — T7 Step 1. ✔
- Reproduces `establish()` 1:1 (2 round-trips) — T5 Step 2. ✔
- Sync-vs-async decision (option b, no nested loop) — Risks. ✔
- pdata path/perms decided — Global Constraints + T7 + Risks. ✔
- Offline unit-testable channel before USB (PORTING-PLAN §6/§7) — T1 mock harness, all tasks TDD vs golden vectors. ✔

**API-name consistency:** `VerimarkTls`, `VerimarkTlsIo`, `verimark_tls_new/free/handshake/wrap/unwrap/is_established/close` match (and finalize) the existing `driver/verimark-tls.h` placeholder; `verimark_tls_set_pairing` replaces its `pairing`/`pairing_len` handshake args. Crypto-core calls use the exact signatures from `2026-07-10-verimark-tls-core.md`: `verimark_tls_prf`, `verimark_tls_derive_master_secret`, `verimark_tls_derive_keys` (+`VerimarkTlsKeys`), `verimark_cert_parse/serialize/signbytes`, `verimark_pairing_load/save` (868 codec), `verimark_tls_gcm_wrap/unwrap` (+`VERIMARK_TLS_CT_APPDATA`), `verimark_ecdh_premaster`, `verimark_ecdsa_verify/sign`, `verimark_pub_from_priv`, `verimark_load_tsk_pubkey`. Two additions are flagged for reconciliation (`verimark_ecdsa_sign_prehashed`, `verimark_ec_keygen`) with rationale, not silently assumed.

**Placeholder scan:** no TBD/"similar to". Every determinable byte layout is concrete (record header, handshake framing, ClientHello suites/compr, client Certificate double-length, CKE EC point, CCS body, Finished, HS-key constants). Four details are **explicit in-task extractions** with cited sources because the exact wire bytes must be read at implementation and are cross-checked by a generated golden vector: (T1S1/T2S3) the ClientHello **extension** framing (`extensions.py:70-112` + `TlsHandshakeExtension`/`TlsVector` wrappers — nested vector length-prefix sizes are the one thing not fully derivable from the files already read); (T3S1) confirming the RT1 record grouping the sensor uses; (T4S1) the client Certificate garbage-length quirk (derived, but arbitered by `golden_client_cert[]`); (T1S3) the offline server-Finished GCM encryption steps (`encr.py:119-137`). Each is a first step of its task with a file:line, exactly per the requested format.
