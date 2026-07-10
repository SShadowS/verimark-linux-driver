# VeriMark TLS Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the offline, unit-testable TLS 1.2 crypto core of the VeriMark driver's secure channel as a standalone C module (`driver/verimark-tls-crypto.{h,c}`), validated byte-for-byte against the `rev` Python prototype used as a differential oracle.

**Architecture:** A single self-contained C module exposes pure functions for the crypto primitives the Synaptics "Tudor" non-standard TLS 1.2 channel needs — the TLS PRF (P_hash), master-secret + key-block derivation, `SensorCertificate`/`SensorPairingData` (de)serialization, the AES-256-GCM record wrap/unwrap, and thin ECDH/ECDSA wrappers over OpenSSL **libcrypto** (EVP + EC, primitives only — never a TLS stack). A Python generator (`gen_vectors.py`) imports the real `rev` code + a real pairing blob and emits golden vectors into a committed C header; a GLib-GTest runner asserts the C output equals the Python output bit-for-bit. No USB, no libfprint SSMs, no device, no handshake state machine — those are later plans.

**Tech Stack:** C11, OpenSSL libcrypto (>=3.0, EVP/EC/ECDSA/SHA/HMAC/GCM), GLib-2.0 (types + GTest), meson/ninja, Python 3 via the repo `.venv` (`cryptography` 49.0.0) importing `re/synaTudor-rev/pydrv/tudor`.

## Global Constraints

- Output MUST match `rev` Python (`re/synaTudor-rev/pydrv/tudor/tls/*`, `.../sensor/pair.py`) byte-for-byte — the Python prototype is the ground-truth oracle.
- Use libcrypto for **primitives only** (ECDH, ECDSA, AES-256-GCM, SHA-256/384, HMAC). NEVER use OpenSSL/GnuTLS TLS-stack APIs — this is a non-standard TLS 1.2.
- Mixed hashing: the handshake transcript hash is **SHA-256**, but the PRF / key-expansion / Finished hash for suite `0xC02E` is **SHA-384**. This module implements the PRF for both; callers pick the MD.
- PRF seed order for BOTH master-secret and key-expansion is `client_random ‖ server_random` (this deviates from RFC 5246, which uses `server ‖ client` for the key block — the sensor uses client‖server for both; source: `cipher/encr.py:13-17,34`). Follow the source, not the RFC.
- Little-endian on the wire for EC scalars/coords inside cert blobs (68-byte LE fields, low 32 bytes significant, rest zero); big-endian inside the C structs (canonical EC representation).
- AEAD record format is exact: explicit nonce = 8 bytes; GCM IV(12) = `fixed_iv(4) ‖ nonce(8)`; AAD = `seq_num(8, big-endian) ‖ content_type(1) ‖ version(0x0303) ‖ plaintext_len(2, big-endian)`; output fragment = `nonce(8) ‖ ciphertext ‖ tag(16)`.
- C11; link `libcrypto` + `glib-2.0`. Compile the test project with `-DOPENSSL_API_COMPAT=0x10100000L` so the legacy EC_KEY/ECDH APIs used here build warning-clean on OpenSSL 3.x.
- Unit tests run via `meson test`; each task ends with a green test and a commit. Commit frequently — one commit per task.
- Never commit the 868-byte pairing blob or the host private key. Public artifacts (sensor cert, `.tsk` sensor pubkey, synthetic-input vectors) may be committed in the generated `vectors.h`.

---

## File structure

| File | Responsibility |
|---|---|
| `driver/verimark-tls-crypto.h` | Public API surface of the standalone crypto core: PRF, master/key derivation, `VerimarkCert`/`VerimarkPairing` (de)serialization, GCM wrap/unwrap, ECDH/ECDSA/tsk wrappers. All signatures the later async `verimark-tls.c` will consume. |
| `driver/verimark-tls-crypto.c` | Implementation over libcrypto (EVP/EC/HMAC). Pure functions, no USB, no GLib main loop. |
| `driver/tests/meson.build` | Standalone meson `project()` that builds `../verimark-tls-crypto.c` + the test runner and registers one `test()` per subsystem. Not yet wired into libfprint. |
| `driver/tests/gen_vectors.py` | Golden-vector generator. Runs under the repo `.venv` with `PYTHONPATH=re/synaTudor-rev/pydrv`; imports `rev`'s `tudor.tls`, reads a real pdata + `.tsk`, forces a FIXED GCM nonce via monkeypatch, and emits `tests/vectors.h`. |
| `driver/tests/vectors.h` | Generated C header of golden inputs+outputs (byte arrays). Committed (contains only public / synthetic-input data — never the host private key). |
| `driver/tests/test_tls_core.c` | GLib-GTest runner: one test function per subsystem, feeding `vectors.h` inputs to the C API and asserting equality with the golden outputs, plus negative (tamper) cases. |

Note on naming: the existing `driver/verimark-tls.h` is the *async channel* placeholder (handshake driver + I/O callback) and is **out of scope** for this plan — leave it untouched. This plan creates a separate `verimark-tls-crypto.{h,c}`; the async `verimark-tls.c` (a later plan) will `#include "verimark-tls-crypto.h"` and call these pure functions.

---

## Task 1: Golden-vector generator + committed `vectors.h`

**Files:**
- Create: `driver/tests/gen_vectors.py`
- Create (generated, committed): `driver/tests/vectors.h`

**Interfaces:**
- Consumes: `re/synaTudor-rev/pydrv/tudor/tls/*` (`tls_prf`, `TlsAEADEncryptionAlgorithm`, `TlsRandom`, `TlsCompressed`, `TlsContentType`, `TlsProtocolVersion`), `re/synaTudor-rev/pydrv/tudor/sensor/pair.py` (`SensorCertificate`, `SensorPairingData`), the real pdata `prototype/pdata/f7007ad929c60000.pdata`, and `re/synaTudor-rev/pydrv/tudor/sensor/sensor_keys/10.1-kf.tsk`.
- Produces: `driver/tests/vectors.h` with these committed symbols (all `static const guint8 …[]` unless noted; `_len` companions where variable):
  - PRF: `prf_sha256_secret[]`, `prf_sha256_label[]` (ascii, NUL-terminated `char[]`), `prf_sha256_seed[]`, `prf_sha256_out[]` (40 B); same set `prf_sha384_*`.
  - Derivation: `deriv_premaster[32]`, `deriv_client_random[32]`, `deriv_server_random[32]`, `deriv_master_secret[48]`, `deriv_encr_key[32]`, `deriv_decr_key[32]`, `deriv_encr_iv[4]`, `deriv_decr_iv[4]`.
  - GCM: `gcm_key[32]`, `gcm_fixed_iv[4]`, `gcm_nonce[8]`, `#define GCM_SEQ 0`, `gcm_plain[]`, `gcm_plain_len`, `gcm_fragment[]`, `gcm_fragment_len`.
  - Cert: `sensor_cert_400[400]` (public), `sensor_cert_pub_x[32]`, `sensor_cert_pub_y[32]` (big-endian), `#define SENSOR_CERT_TYPE …`, `#define SENSOR_CERT_SIGN_SIZE …`.
  - ECC: `tsk_256[256]` (public sensor pubkey file), `tsk_pub_x[32]`, `tsk_pub_y[32]` (big-endian), `ecdh_eph_priv[32]`, `ecdh_premaster[32]` (= ECDH(eph_priv, sensor_cert pubkey)).

- [ ] **Step 1: Write the generator**

Create `driver/tests/gen_vectors.py`:

```python
#!/usr/bin/env python3
# Golden-vector generator for the VeriMark TLS crypto core.
# Run under the repo venv:  PYTHONPATH=re/synaTudor-rev/pydrv ./.venv/bin/python driver/tests/gen_vectors.py
# Emits driver/tests/vectors.h. rev's tudor.tls is the differential oracle.
import os, sys, importlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

from tudor.tls.data.crypto import tls_prf, TlsRandom
from tudor.tls.data.record import TlsCompressed, TlsContentType, TlsProtocolVersion
from tudor.sensor.pair import SensorCertificate, SensorPairingData
import cryptography.hazmat.primitives.ciphers as cipher
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.ec as ecc
encr = importlib.import_module("tudor.tls.cipher.encr")  # importlib avoids a relative-import shadow

OUT = []
def emit_bytes(name, b):
    body = ", ".join("0x%02x" % x for x in b)
    OUT.append("static const guint8 %s[%d] = { %s };" % (name, len(b), body))
def emit_str(name, s):
    OUT.append('static const char %s[] = "%s";' % (name, s))
def emit_define(name, val):
    OUT.append("#define %s %d" % (name, val))
def be32(i):  # big-endian 32-byte encoding of an int
    return i.to_bytes(32, "big")

# ---- PRF (crypto.py::tls_prf) ----
prf_secret = bytes(range(48))
prf_seed   = bytes(range(64))
emit_bytes("prf_sha256_secret", prf_secret); emit_str("prf_sha256_label", "test label")
emit_bytes("prf_sha256_seed", prf_seed)
emit_bytes("prf_sha256_out", tls_prf(prf_secret, "test label", prf_seed, 40, hashes.SHA256()))
emit_bytes("prf_sha384_secret", prf_secret); emit_str("prf_sha384_label", "test label")
emit_bytes("prf_sha384_seed", prf_seed)
emit_bytes("prf_sha384_out", tls_prf(prf_secret, "test label", prf_seed, 40, hashes.SHA384()))

# ---- master secret + key block (cipher/encr.py::TlsAEADEncryptionAlgorithm) ----
premaster = bytes(range(32))
cr_raw = bytes(range(32)); sr_raw = bytes(range(32, 64))
cr = TlsRandom(int.from_bytes(cr_raw[0:4], "big"), cr_raw[4:32])   # .write() == cr_raw
sr = TlsRandom(int.from_bytes(sr_raw[0:4], "big"), sr_raw[4:32])   # .write() == sr_raw
algo = encr.TlsAEADEncryptionAlgorithm(premaster, cr, sr,
        cipher.algorithms.AES, cipher.modes.GCM, hashes.SHA384, 32, 4, 16)
emit_bytes("deriv_premaster", premaster)
emit_bytes("deriv_client_random", cr_raw); emit_bytes("deriv_server_random", sr_raw)
emit_bytes("deriv_master_secret", algo.master_secret)
emit_bytes("deriv_encr_key", algo.encr_key); emit_bytes("deriv_decr_key", algo.decr_key)
emit_bytes("deriv_encr_iv", algo.encr_iv);   emit_bytes("deriv_decr_iv", algo.decr_iv)

# ---- AES-256-GCM record wrap (force a FIXED nonce so the vector is reproducible) ----
FIXED_NONCE = bytes([0xAB] * 8)
encr.secrets.token_bytes = lambda n: FIXED_NONCE[:n]     # seam: rev uses secrets.token_bytes(8)
plain = b"hello verimark!!"
ct = algo.encrypt(TlsCompressed(TlsContentType.types[23], TlsProtocolVersion.current, plain))
emit_bytes("gcm_key", algo.encr_key); emit_bytes("gcm_fixed_iv", algo.encr_iv)
emit_bytes("gcm_nonce", FIXED_NONCE); emit_define("GCM_SEQ", 0)
emit_bytes("gcm_plain", plain); emit_define("gcm_plain_len", len(plain))
emit_bytes("gcm_fragment", ct.fragment); emit_define("gcm_fragment_len", len(ct.fragment))

# ---- SensorCertificate (sensor/pair.py) from a real pdata (sensor cert is public) ----
with open(os.path.join(REPO, "prototype", "pdata", "f7007ad929c60000.pdata"), "rb") as f:
    import io
    pd = SensorPairingData.load(io.BytesIO(f.read()))
sc = pd.sensor_cert
emit_bytes("sensor_cert_400", sc.tobytes())
emit_bytes("sensor_cert_pub_x", be32(sc.pub_key.public_numbers().x))
emit_bytes("sensor_cert_pub_y", be32(sc.pub_key.public_numbers().y))
emit_define("SENSOR_CERT_TYPE", sc.cert_type)
emit_define("SENSOR_CERT_SIGN_SIZE", len(sc.signature))

# ---- .tsk sensor public key (public) + ECDH premaster against sensor cert pubkey ----
with open(os.path.join(REPO, "re", "synaTudor-rev", "pydrv", "tudor", "sensor",
                       "sensor_keys", "10.1-kf.tsk"), "rb") as f:
    tsk = f.read()
tsk_x = int.from_bytes(tsk[0x00:0x44], "little"); tsk_y = int.from_bytes(tsk[0x44:0x88], "little")
emit_bytes("tsk_256", tsk); emit_bytes("tsk_pub_x", be32(tsk_x)); emit_bytes("tsk_pub_y", be32(tsk_y))
eph_priv_int = int.from_bytes(bytes(range(1, 33)), "big")
eph = ecc.derive_private_key(eph_priv_int, ecc.SECP256R1())
premaster_ecdh = eph.exchange(ecc.ECDH(), sc.pub_key)      # exactly ecc.py::end_handshake line 84
emit_bytes("ecdh_eph_priv", be32(eph_priv_int)); emit_bytes("ecdh_premaster", premaster_ecdh)

hdr = "/* GENERATED by driver/tests/gen_vectors.py — do not edit. */\n#pragma once\n#include <glib.h>\n\n"
with open(os.path.join(HERE, "vectors.h"), "w") as f:
    f.write(hdr + "\n".join(OUT) + "\n")
print("wrote", os.path.join(HERE, "vectors.h"), "with", len(OUT), "symbols")
```

- [ ] **Step 2: Run the generator, expect it to write vectors.h**

Run: `cd /home/sshadows/nogit/LocalChanges/verimark-driver && PYTHONPATH=re/synaTudor-rev/pydrv ./.venv/bin/python driver/tests/gen_vectors.py`
Expected: prints `wrote .../driver/tests/vectors.h with 34 symbols` (exact count may differ ±; must be >0). Command exits 0.

- [ ] **Step 3: Assert the file exists and is non-empty**

Run: `test -s driver/tests/vectors.h && grep -c '^static const' driver/tests/vectors.h`
Expected: prints a number `>= 25` (the byte-array symbols). Exit 0.

- [ ] **Step 4: Sanity-check the GCM fragment length is nonce+plain+tag**

Run: `grep -E 'gcm_(plain|fragment)_len' driver/tests/vectors.h`
Expected: `gcm_plain_len 16` and `gcm_fragment_len 40` (16 plaintext + 8 nonce + 16 tag = 40).

- [ ] **Step 5: Commit**

```bash
git add driver/tests/gen_vectors.py driver/tests/vectors.h
git commit -m "verimark-tls-core: golden-vector generator + committed vectors.h (rev oracle)"
```

---

## Task 2: TLS 1.2 PRF (P_hash, SHA-256 & SHA-384)

**Files:**
- Create: `driver/verimark-tls-crypto.h`
- Create: `driver/verimark-tls-crypto.c`
- Create: `driver/tests/meson.build`
- Create: `driver/tests/test_tls_core.c`

**Interfaces:**
- Consumes: `vectors.h` symbols `prf_sha256_*`, `prf_sha384_*`.
- Produces:
  ```c
  gboolean verimark_tls_prf (const EVP_MD *md,
                             const guint8 *secret, gsize secret_len,
                             const char *label,
                             const guint8 *seed, gsize seed_len,
                             guint8 *out, gsize out_len);
  ```

- [ ] **Step 1: Write the header skeleton with the PRF declaration**

Create `driver/verimark-tls-crypto.h`:

```c
/*
 * verimark-tls-crypto.h — offline crypto core of the Synaptics "Tudor" custom
 * TLS 1.2 secure channel. Primitives only (libcrypto EVP/EC); NOT a TLS stack.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Oracle: re/synaTudor-rev/pydrv/tudor/tls/* + tudor/sensor/pair.py.
 */
#pragma once
#include <glib.h>
#include <openssl/evp.h>

/* TLS 1.2 PRF (P_hash), rev crypto.py::tls_prf. `md` = EVP_sha256() or EVP_sha384().
 * inp = ascii(label) || seed; A(1)=HMAC(secret,inp); A(i+1)=HMAC(secret,A(i));
 * out += HMAC(secret, A(i) || inp); truncated to out_len. Returns TRUE on success. */
gboolean verimark_tls_prf (const EVP_MD *md,
                           const guint8 *secret, gsize secret_len,
                           const char *label,
                           const guint8 *seed, gsize seed_len,
                           guint8 *out, gsize out_len);
```

- [ ] **Step 2: Write the failing test**

Create `driver/tests/test_tls_core.c`:

```c
#include <glib.h>
#include <string.h>
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

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/verimark/prf/sha256", test_prf_sha256);
  g_test_add_func ("/verimark/prf/sha384", test_prf_sha384);
  return g_test_run ();
}
```

- [ ] **Step 3: Write the standalone test meson project**

Create `driver/tests/meson.build`:

```meson
project('verimark-tls-core-tests', 'c',
  default_options : ['c_std=c11', 'warning_level=2'])

glib_dep   = dependency('glib-2.0')
crypto_dep = dependency('libcrypto', version : '>=3.0.0')

# Legacy EC_KEY/ECDH_compute_key path used by the module builds warning-clean here.
add_project_arguments('-DOPENSSL_API_COMPAT=0x10100000L', language : 'c')

tls_core_test = executable('test_tls_core',
  ['test_tls_core.c', '../verimark-tls-crypto.c'],
  dependencies : [glib_dep, crypto_dep])

test('tls_prf', tls_core_test, args : ['-p', '/verimark/prf'])
```

- [ ] **Step 4: Run the test, expect a BUILD/LINK failure (function undefined)**

Run: `cd /home/sshadows/nogit/LocalChanges/verimark-driver && meson setup driver/tests/build driver/tests && meson test -C driver/tests/build tls_prf -v`
Expected: build fails at link with `undefined reference to 'verimark_tls_prf'` (the .c has no implementation yet).

- [ ] **Step 5: Implement the PRF**

Create `driver/verimark-tls-crypto.c`:

```c
/* verimark-tls-crypto.c — see verimark-tls-crypto.h. SPDX-License-Identifier: LGPL-2.1-or-later */
#include "verimark-tls-crypto.h"
#include <string.h>
#include <openssl/hmac.h>

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
```

- [ ] **Step 6: Run the test, expect PASS**

Run: `meson test -C driver/tests/build tls_prf -v`
Expected: `/verimark/prf/sha256` and `/verimark/prf/sha384` both `OK`; meson reports `tls_prf` `OK`, `1/1 passed`.

- [ ] **Step 7: Commit**

```bash
git add driver/verimark-tls-crypto.h driver/verimark-tls-crypto.c driver/tests/meson.build driver/tests/test_tls_core.c
git commit -m "verimark-tls-core: TLS 1.2 PRF (P_hash, SHA-256 & SHA-384) vs rev oracle"
```

---

## Task 3: Master secret + key-block derivation

**Files:**
- Modify: `driver/verimark-tls-crypto.h`
- Modify: `driver/verimark-tls-crypto.c`
- Modify: `driver/tests/test_tls_core.c`
- Modify: `driver/tests/meson.build`

**Interfaces:**
- Consumes: `verimark_tls_prf(...)` (Task 2); `vectors.h` `deriv_*`.
- Produces:
  ```c
  typedef struct {
    guint8 encr_key[32];
    guint8 decr_key[32];
    guint8 encr_iv[4];
    guint8 decr_iv[4];
  } VerimarkTlsKeys;

  gboolean verimark_tls_derive_master_secret (const guint8 *premaster, gsize premaster_len,
                                              const guint8 client_random[32],
                                              const guint8 server_random[32],
                                              guint8 master_secret[48]);

  gboolean verimark_tls_derive_keys (const guint8 master_secret[48],
                                     const guint8 client_random[32],
                                     const guint8 server_random[32],
                                     VerimarkTlsKeys *keys);
  ```

- [ ] **Step 1: Add declarations to the header**

Append to `driver/verimark-tls-crypto.h` (before the final newline):

```c
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
```

- [ ] **Step 2: Write the failing test**

Add to `driver/tests/test_tls_core.c` (new functions + registrations in `main`):

```c
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
```

Add to `main`, before `return g_test_run ();`:

```c
  g_test_add_func ("/verimark/derive/master", test_derive_master);
  g_test_add_func ("/verimark/derive/keys",   test_derive_keys);
```

Add to `driver/tests/meson.build`, after the `test('tls_prf', ...)` line:

```meson
test('tls_keys', tls_core_test, args : ['-p', '/verimark/derive'])
```

- [ ] **Step 3: Run the test, expect FAIL (link error)**

Run: `meson test -C driver/tests/build tls_keys -v`
Expected: build fails, `undefined reference to 'verimark_tls_derive_master_secret'`.

- [ ] **Step 4: Implement the derivation functions**

Append to `driver/verimark-tls-crypto.c`:

```c
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
```

- [ ] **Step 5: Run the test, expect PASS**

Run: `meson test -C driver/tests/build tls_keys -v`
Expected: `/verimark/derive/master` and `/verimark/derive/keys` `OK`; `tls_keys` `OK`.

- [ ] **Step 6: Commit**

```bash
git add driver/verimark-tls-crypto.h driver/verimark-tls-crypto.c driver/tests/test_tls_core.c driver/tests/meson.build
git commit -m "verimark-tls-core: master-secret + key-block derivation (PRF-SHA384, client||server seed)"
```

---

## Task 4: SensorCertificate (400 B) + SensorPairingData (868 B) (de)serialization

**Files:**
- Modify: `driver/verimark-tls-crypto.h`
- Modify: `driver/verimark-tls-crypto.c`
- Modify: `driver/tests/test_tls_core.c`
- Modify: `driver/tests/meson.build`

**Interfaces:**
- Consumes: `vectors.h` `sensor_cert_400`, `sensor_cert_pub_x/y`, `SENSOR_CERT_TYPE`, `SENSOR_CERT_SIGN_SIZE`. Optionally the real 868-byte pdata file at runtime via env `VERIMARK_PDATA`.
- Produces:
  ```c
  typedef struct {
    guint8  cert_type;
    guint8  pub_x[32];      /* P-256 X, big-endian */
    guint8  pub_y[32];      /* P-256 Y, big-endian */
    guint16 sign_size;
    guint8  signature[256]; /* DER ECDSA sig, sign_size bytes significant */
  } VerimarkCert;

  typedef struct {
    guint8       priv_scalar[32];  /* P-256 private scalar, big-endian */
    VerimarkCert host_cert;
    VerimarkCert sensor_cert;
  } VerimarkPairing;

  gboolean verimark_cert_parse     (const guint8 buf[400], VerimarkCert *cert, GError **error);
  gboolean verimark_cert_serialize (const VerimarkCert *cert, guint8 buf[400], GError **error);
  gboolean verimark_cert_signbytes (const VerimarkCert *cert, guint8 out[142], GError **error);
  gboolean verimark_pairing_load   (const guint8 buf[868], VerimarkPairing *pd, GError **error);
  gboolean verimark_pairing_save   (const VerimarkPairing *pd, guint8 buf[868], GError **error);
  ```

> Layout facts (from `sensor/pair.py`, struct `<HH68s68sxBH256s`): offset 0 magic `0x5f3f` (2 LE), 2 curve `23` (2 LE), 4 pub_x (68 LE), 72 pub_y (68 LE), 140 pad(1), 141 cert_type(1), 142 sign_size(2 LE), 144 signature(256). `signbytes` = first 142 bytes of the serialized cert (`HH68s68sxB`). Pairing = priv_scalar (0x44=68 LE) ‖ host_cert(400) ‖ sensor_cert(400) = 868.

- [ ] **Step 1: Add declarations + endian helpers to the header**

Append to `driver/verimark-tls-crypto.h`:

```c
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
```

- [ ] **Step 2: Write the failing test**

Add to `driver/tests/test_tls_core.c` (include `<stdlib.h>` at top for `getenv`):

```c
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
```

Add to `main`:

```c
  g_test_add_func ("/verimark/cert/roundtrip", test_cert_roundtrip);
  g_test_add_func ("/verimark/cert/signbytes", test_cert_signbytes);
  g_test_add_func ("/verimark/cert/pairing",   test_pairing_roundtrip);
```

Add to `driver/tests/meson.build`:

```meson
test('tls_cert', tls_core_test,
  args : ['-p', '/verimark/cert'],
  env  : ['VERIMARK_PDATA=' + meson.current_source_dir() + '/../../prototype/pdata/f7007ad929c60000.pdata'])
```

- [ ] **Step 3: Run the test, expect FAIL (link error)**

Run: `meson test -C driver/tests/build tls_cert -v`
Expected: build fails, `undefined reference to 'verimark_cert_parse'`.

- [ ] **Step 4: Implement parse/serialize/signbytes/pairing**

Append to `driver/verimark-tls-crypto.c` (near the top, after the existing includes, add static endian helpers; then the functions):

```c
/* ---- little-endian wire field <-> big-endian 32-byte scalar ---- */
static gboolean
le_field_to_be32 (const guint8 *le, gsize field_len, guint8 out_be[32], GError **error)
{
  for (gsize i = 32; i < field_len; i++)
    if (le[i] != 0)
      {
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
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
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "bad cert magic/curve (0x%04x/%u)", magic, curve);
      return FALSE;
    }
  if (!le_field_to_be32 (buf + 4,  68, cert->pub_x, error)) return FALSE;
  if (!le_field_to_be32 (buf + 72, 68, cert->pub_y, error)) return FALSE;
  cert->cert_type = buf[141];
  cert->sign_size = (guint16) buf[142] | ((guint16) buf[143] << 8);   /* LE */
  if (cert->sign_size > 256)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "sign_size > 256");
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
```

- [ ] **Step 5: Run the test, expect PASS**

Run: `meson test -C driver/tests/build tls_cert -v`
Expected: `/verimark/cert/roundtrip` and `/verimark/cert/signbytes` `OK`; `/verimark/cert/pairing` `OK` (the meson `env` points `VERIMARK_PDATA` at the real 868-byte blob). `tls_cert` `OK`.

> If `prototype/pdata/f7007ad929c60000.pdata` is absent (it is git-ignored), the pairing subtest reports `SKIP` instead of failing; the cert roundtrip + signbytes still run from committed `vectors.h`. **Flag for the human:** the pairing round-trip needs a local 868-byte pdata (present now, owned by the user, readable); CI without a device/pdata would only run the cert subtests.

- [ ] **Step 6: Commit**

```bash
git add driver/verimark-tls-crypto.h driver/verimark-tls-crypto.c driver/tests/test_tls_core.c driver/tests/meson.build
git commit -m "verimark-tls-core: SensorCertificate (400B) + SensorPairingData (868B) (de)serialization"
```

---

## Task 5: AES-256-GCM record wrap / unwrap

**Files:**
- Modify: `driver/verimark-tls-crypto.h`
- Modify: `driver/verimark-tls-crypto.c`
- Modify: `driver/tests/test_tls_core.c`
- Modify: `driver/tests/meson.build`

**Interfaces:**
- Consumes: `vectors.h` `gcm_key`, `gcm_fixed_iv`, `gcm_nonce`, `GCM_SEQ`, `gcm_plain`, `gcm_plain_len`, `gcm_fragment`, `gcm_fragment_len`.
- Produces:
  ```c
  #define VERIMARK_TLS_CT_APPDATA 0x17   /* content type 23 */

  gboolean verimark_tls_gcm_wrap (const guint8 key[32], const guint8 fixed_iv[4],
                                  guint64 seq, guint8 content_type,
                                  const guint8 nonce[8],
                                  const guint8 *plain, gsize plain_len,
                                  guint8 **out, gsize *out_len, GError **error);

  gboolean verimark_tls_gcm_unwrap (const guint8 key[32], const guint8 fixed_iv[4],
                                    guint64 seq, guint8 content_type,
                                    const guint8 *frag, gsize frag_len,
                                    guint8 **out, gsize *out_len, GError **error);
  ```

> Record format (encr.py::TlsAEADEncryptionAlgorithm): IV(12)=fixed_iv(4)‖nonce(8); AAD(13)=seq(8 BE)‖content_type(1)‖`0x03 0x03`‖plaintext_len(2 BE); out=nonce(8)‖ciphertext‖tag(16). Caller supplies the 8-byte nonce (in the driver it is random per record; here it is a parameter so the vector is deterministic).

- [ ] **Step 1: Add declarations to the header**

Append to `driver/verimark-tls-crypto.h`:

```c
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
```

- [ ] **Step 2: Write the failing test**

Add to `driver/tests/test_tls_core.c`:

```c
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
```

Add to `main`:

```c
  g_test_add_func ("/verimark/gcm/wrap",         test_gcm_wrap);
  g_test_add_func ("/verimark/gcm/unwrap",       test_gcm_unwrap);
  g_test_add_func ("/verimark/gcm/unwrap_tamper", test_gcm_unwrap_tamper);
```

Add to `driver/tests/meson.build`:

```meson
test('tls_gcm', tls_core_test, args : ['-p', '/verimark/gcm'])
```

- [ ] **Step 3: Run the test, expect FAIL (link error)**

Run: `meson test -C driver/tests/build tls_gcm -v`
Expected: build fails, `undefined reference to 'verimark_tls_gcm_wrap'`.

- [ ] **Step 4: Implement wrap/unwrap**

Append to `driver/verimark-tls-crypto.c` (add `#include <openssl/aes.h>` is not needed; EVP is already included via the header):

```c
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
  if (!ok) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "GCM wrap failed");
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
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "short GCM record");
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
  if (!ok) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "GCM unwrap/auth failed");
  return ok;
}
```

- [ ] **Step 5: Run the test, expect PASS**

Run: `meson test -C driver/tests/build tls_gcm -v`
Expected: `/verimark/gcm/wrap`, `/verimark/gcm/unwrap`, `/verimark/gcm/unwrap_tamper` all `OK`; `tls_gcm` `OK`.

- [ ] **Step 6: Commit**

```bash
git add driver/verimark-tls-crypto.h driver/verimark-tls-crypto.c driver/tests/test_tls_core.c driver/tests/meson.build
git commit -m "verimark-tls-core: AES-256-GCM record wrap/unwrap (exact nonce/IV/AAD/tag) vs rev oracle"
```

---

## Task 6: ECDH premaster + ECDSA sign/verify + .tsk pubkey loader

**Files:**
- Modify: `driver/verimark-tls-crypto.h`
- Modify: `driver/verimark-tls-crypto.c`
- Modify: `driver/tests/test_tls_core.c`
- Modify: `driver/tests/meson.build`

**Interfaces:**
- Consumes: `vectors.h` `tsk_256`, `tsk_pub_x/y`, `sensor_cert_400`, `ecdh_eph_priv`, `ecdh_premaster`, `SENSOR_CERT_SIGN_SIZE`; `verimark_cert_parse`, `verimark_cert_signbytes` (Task 4).
- Produces:
  ```c
  gboolean verimark_load_tsk_pubkey (const guint8 buf[256],
                                     guint8 pub_x[32], guint8 pub_y[32], GError **error);

  gboolean verimark_ecdh_premaster (const guint8 eph_priv[32],
                                    const guint8 peer_x[32], const guint8 peer_y[32],
                                    guint8 premaster[32], GError **error);

  gboolean verimark_ecdsa_verify (const guint8 pub_x[32], const guint8 pub_y[32],
                                  const guint8 *msg, gsize msg_len,
                                  const guint8 *sig_der, gsize sig_len, GError **error);

  gboolean verimark_ecdsa_sign (const guint8 priv[32],
                                const guint8 *msg, gsize msg_len,
                                guint8 **sig_der, gsize *sig_len, GError **error);
  ```

> ECDH (ecc.py:84): `eph_priv.exchange(ECDH(), sensor_cert.pub_key)` → the 32-byte X coordinate of the shared point (this is exactly `ECDH_compute_key` with a NULL KDF). ECDSA verify (sensor.py:144): `sensor_pubkey.verify(sensor_cert.signature, sensor_cert.signbytes(), ECDSA(SHA256))` — DER signature over SHA-256 of the 142-byte signbytes. `.tsk` (sensor.py:34-35): X = LE(buf[0x00:0x44]), Y = LE(buf[0x44:0x88]), SECP256R1.

- [ ] **Step 1: Add declarations to the header**

Append to `driver/verimark-tls-crypto.h`:

```c
/* Load a 256-byte .tsk sensor public key: X=LE(buf[0:0x44]), Y=LE(buf[0x44:0x88]). */
gboolean verimark_load_tsk_pubkey (const guint8 buf[256],
                                   guint8 pub_x[32], guint8 pub_y[32], GError **error);

/* ECDH premaster (SECP256R1) = X coord of eph_priv * peer, 32 bytes big-endian. */
gboolean verimark_ecdh_premaster (const guint8 eph_priv[32],
                                  const guint8 peer_x[32], const guint8 peer_y[32],
                                  guint8 premaster[32], GError **error);

/* Verify ECDSA-SHA256 (DER sig) over msg with pub (x,y). TRUE iff signature valid. */
gboolean verimark_ecdsa_verify (const guint8 pub_x[32], const guint8 pub_y[32],
                                const guint8 *msg, gsize msg_len,
                                const guint8 *sig_der, gsize sig_len, GError **error);

/* Sign msg with ECDSA-SHA256 using priv scalar; *sig_der = g_malloc'd DER, caller g_free. */
gboolean verimark_ecdsa_sign (const guint8 priv[32],
                              const guint8 *msg, gsize msg_len,
                              guint8 **sig_der, gsize *sig_len, GError **error);
```

- [ ] **Step 2: Write the failing test**

Add to `driver/tests/test_tls_core.c`:

```c
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
  /* tamper: flip a signbytes byte → must fail */
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
  /* derive pub from the same priv via a throwaway ECDH? No — verify with the public
   * key that matches ecdh_eph_priv. We recover it by signing then verifying with the
   * public point that libcrypto derives internally; expose it by verifying against a
   * public key computed from priv using verimark_ecdh path is not applicable, so verify
   * using the known-good self-consistency: sign+verify with a freshly loaded pub. */
  /* Compute the public key for ecdh_eph_priv by ECDH with the generator is overkill;
   * instead verify using OpenSSL through a second sign/verify with the SAME priv:
   * verify requires (x,y). We obtain them by parsing a cert we don't have, so this
   * subtest verifies via verimark_ecdsa_verify using pub derived in the impl helper. */
  guint8 px[32], py[32];
  g_assert_true (verimark_pub_from_priv (ecdh_eph_priv, px, py, NULL));
  g_assert_true (verimark_ecdsa_verify (px, py, msg, sizeof msg, sig, sig_len, NULL));
  g_free (sig);
}
```

> The sign round-trip needs the public key for a private scalar. Add a small public helper `verimark_pub_from_priv` (declared in Step 1's block is omitted — add it now).

Add this declaration to `driver/verimark-tls-crypto.h` (with the Task-6 block):

```c
/* Derive the SECP256R1 public point (x,y big-endian) from a private scalar. */
gboolean verimark_pub_from_priv (const guint8 priv[32],
                                 guint8 pub_x[32], guint8 pub_y[32], GError **error);
```

Add to `main`:

```c
  g_test_add_func ("/verimark/ecc/tsk",         test_tsk_load);
  g_test_add_func ("/verimark/ecc/ecdh",        test_ecdh_premaster);
  g_test_add_func ("/verimark/ecc/verify_cert", test_ecdsa_verify_sensor_cert);
  g_test_add_func ("/verimark/ecc/sign_roundtrip", test_ecdsa_sign_roundtrip);
```

Add to `driver/tests/meson.build`:

```meson
test('tls_ecc', tls_core_test, args : ['-p', '/verimark/ecc'])
```

- [ ] **Step 3: Run the test, expect FAIL (link error)**

Run: `meson test -C driver/tests/build tls_ecc -v`
Expected: build fails, `undefined reference to 'verimark_load_tsk_pubkey'` (and the other ecc symbols).

- [ ] **Step 4: Implement the ECC wrappers**

Append to `driver/verimark-tls-crypto.c` (add these includes near the top: `#include <openssl/ec.h>`, `#include <openssl/ecdh.h>`, `#include <openssl/bn.h>`, `#include <openssl/obj_mac.h>`):

```c
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
  if (!ok) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "ECDH failed");
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
  if (!ok) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "pub-from-priv failed");
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
  if (!ok) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "ECDSA verify failed");
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
  if (!ok) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "ECDSA sign failed");
  return ok;
}
```

- [ ] **Step 5: Run the test, expect PASS**

Run: `meson test -C driver/tests/build tls_ecc -v`
Expected: `/verimark/ecc/tsk`, `/verimark/ecc/ecdh`, `/verimark/ecc/verify_cert`, `/verimark/ecc/sign_roundtrip` all `OK`; `tls_ecc` `OK`.

- [ ] **Step 6: Run the full suite (all five meson tests)**

Run: `meson test -C driver/tests/build -v`
Expected: `tls_prf`, `tls_keys`, `tls_cert`, `tls_gcm`, `tls_ecc` — `Ok: 5, Fail: 0` (the pairing subtest may `SKIP` if pdata is absent, but its meson `env` points at the real file so it should run `OK`).

- [ ] **Step 7: Commit**

```bash
git add driver/verimark-tls-crypto.h driver/verimark-tls-crypto.c driver/tests/test_tls_core.c driver/tests/meson.build
git commit -m "verimark-tls-core: ECDH premaster + ECDSA sign/verify + .tsk pubkey loader vs rev oracle"
```

---

## Self-review

**Spec coverage (PORTING-PLAN §3 #1 + §6):**
- TLS 1.2 PRF (SHA-256 & SHA-384) — Task 2. ✔
- master secret via PRF-SHA384 — Task 3. ✔
- key expansion `encr_key(32) decr_key(32) encr_iv(4) decr_iv(4)` — Task 3. ✔
- Premaster = ECDH(client ephemeral, sensor cert pubkey) — Task 6. ✔
- CertificateVerify / client-auth ECDSA sign, sensor-cert ECDSA verify — Task 6 (sign + verify wrappers). ✔
- AES-256-GCM record: explicit nonce, IV=fixed(4)‖nonce(8), AAD=seq(8 BE)‖type‖version(2)‖len(2), out=nonce‖ct‖tag(16) — Task 5. ✔
- SensorCertificate 400 B (magic/curve/pub/cert_type/sign) + SensorPairingData 868 B — Task 4. ✔
- Differential oracle vs `rev` Python — Task 1 generator + every task's `g_assert_cmpmem`. ✔
- Mixed SHA-256-transcript / SHA-384-PRF split — documented in Global Constraints; the PRF is MD-parameterized so the later handshake plan passes SHA-256 for the transcript-Finished and SHA-384 for key schedule. The transcript hashing itself and the ClientHello/Finished message flow are **out of scope** (later handshake plan) — noted. ✔
- HS-key derivation (findings/46) — **out of scope**, consumed by the later pairing plan (Global Constraints + File-structure note). The `verimark_ecdsa_sign` wrapper here is what that plan will use to sign the host cert. ✔

**Placeholder scan:** No TBD / "add error handling" / "similar to Task N". Every code step shows complete C or Python. Error paths are concrete `goto out` + `g_set_error`. (The one long comment in the sign round-trip test is explanatory, not a placeholder — the actual assertion uses the concrete `verimark_pub_from_priv` helper, which is declared and implemented.)

**Type consistency:** `verimark_tls_prf` signature identical in Task 2 header, Task 3 caller, and impl. `VerimarkTlsKeys` fields (`encr_key/decr_key/encr_iv/decr_iv`) consistent across Task 3 header/impl/test. `VerimarkCert` fields (`cert_type/pub_x/pub_y/sign_size/signature`) consistent Task 4→6. `verimark_ecdh_premaster`/`verimark_ecdsa_verify`/`verimark_ecdsa_sign`/`verimark_pub_from_priv`/`verimark_load_tsk_pubkey` signatures identical in header, tests, and impl. `VERIMARK_TLS_CT_APPDATA` = 0x17 used in Task 5 test + AAD. Meson test names (`tls_prf/tls_keys/tls_cert/tls_gcm/tls_ecc`) unique and match `-p` paths.

**Deferred exact values:** None. Every byte-level constant (magic `0x5f3f`, curve `23`, offsets 4/72/140/141/142/144, priv field `0x44`, tag 16, IV 4, version `0x0303`, content type `0x17`, seed order client‖server) was extracted from a read source file and cited inline. The golden outputs (PRF results, master/keys, GCM fragment, ECDH premaster) are computed by the Task-1 generator from the live `rev` code, so no output byte is hand-invented.
