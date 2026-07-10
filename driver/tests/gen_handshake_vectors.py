#!/usr/bin/env python3
# Offline handshake-vector generator for the VeriMark custom TLS 1.2 channel.
#
# Drives rev's REAL client (tudor.tls.TlsSession.establish()) against a stub
# CommunicationInterface whose synthesized server responses are built with
# pinned randomness, so the whole handshake is reproducible without hardware.
# The stub reaches into the *live* rev session objects (msg_digest, the
# negotiated AEAD algo's derived keys) to build a self-consistent server
# Finished — see driver/PORTING-PLAN.md and
# docs/superpowers/plans/2026-07-10-verimark-tls-channel.md Task 1 Step 3 for
# the rationale (no server proof-of-possession is required by this broken
# handshake, so this is sound).
#
# Run under the repo venv:
#   PYTHONPATH=re/synaTudor-rev/pydrv ./.venv/bin/python driver/tests/gen_handshake_vectors.py
import os, sys, io, struct

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

import tudor
import tudor.tls as tls
from tudor.tls.data.crypto import TlsRandom, TlsCertificate, TlsCipherSuiteId, TlsCompressionMethodId, TlsCertificateType, tls_prf
from tudor.tls.data.stream import TlsDataWriteStream
from tudor.tls.data.handshake.handshake import TlsHandshakeMessage
from tudor.tls.data.handshake.hello import TlsHandshakeServerHello, TlsHandshakeServerHelloDone, TlsSessionId
from tudor.tls.data.handshake.cert import TlsHandshakeCertificate, TlsHandshakeCertificateRequest
from tudor.tls.cipher.ecc import TlsEccRemoteKey
from tudor.sensor.pair import SensorPairingData, SensorCertificate
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.ec as ecc_mod
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import importlib
encr_mod = importlib.import_module("tudor.tls.cipher.encr")  # for the secrets.token_bytes seam

OUT = []
def emit_bytes(name, b):
    body = ", ".join("0x%02x" % x for x in b)
    OUT.append("static const guint8 %s[%d] = { %s };" % (name, len(b), body))
def emit_define(name, val):
    OUT.append("#define %s %d" % (name, val))
def be(n, size):  # big-endian bytes
    return n.to_bytes(size, "big")

# ---------------------------------------------------------------------------
# Pin all randomness for full determinism.
# ---------------------------------------------------------------------------
FIXED_CLIENT_TIME  = 0x11111111
FIXED_CLIENT_RAND28 = bytes([0xAA] * 28)
FIXED_CLIENT_RANDOM = be(FIXED_CLIENT_TIME, 4) + FIXED_CLIENT_RAND28

FIXED_SERVER_TIME  = 0x22222222
FIXED_SERVER_RAND28 = bytes([0xBB] * 28)
FIXED_SERVER_RANDOM = be(FIXED_SERVER_TIME, 4) + FIXED_SERVER_RAND28

FIXED_EPH_INT = int.from_bytes(bytes(range(1, 33)), "big")  # reuse the crypto-core's ecdh_eph_priv value
FIXED_EPH_KEY = ecc_mod.derive_private_key(FIXED_EPH_INT, ecc_mod.SECP256R1())

FIXED_CLIENT_FIN_NONCE = bytes([0xC1] * 8)   # client Finished GCM nonce
FIXED_SERVER_FIN_NONCE = bytes([0xC2] * 8)   # server Finished GCM nonce (synthesized)

TlsRandom.create = staticmethod(lambda: TlsRandom(FIXED_CLIENT_TIME, FIXED_CLIENT_RAND28))
ecc_mod.generate_private_key = lambda curve: FIXED_EPH_KEY
encr_mod.secrets.token_bytes = lambda n: FIXED_CLIENT_FIN_NONCE[:n]

# ---------------------------------------------------------------------------
# Load pdata (real sensor + host certs; the private scalar is test-only, not
# emitted).
# ---------------------------------------------------------------------------
PDATA_PATH = os.path.join(REPO, "prototype", "pdata", "f7007ad929c60000.pdata")
with open(PDATA_PATH, "rb") as f:
    pd = SensorPairingData.load(io.BytesIO(f.read()))

sensor_cert_bytes = pd.sensor_cert.tobytes()
host_cert_bytes = pd.host_cert.tobytes()

# ---------------------------------------------------------------------------
# Prebuild the synthesized RT1 server response (ServerHello .. ServerHelloDone
# coalesced into one plaintext handshake record) -- doesn't depend on any live
# client state, only on our own pinned server_random + the pdata sensor cert.
# ---------------------------------------------------------------------------
server_random_obj = TlsRandom(FIXED_SERVER_TIME, FIXED_SERVER_RAND28)
sh = TlsHandshakeServerHello(
    tls.data.TlsProtocolVersion.current, server_random_obj, TlsSessionId(bytes(7)),
    TlsCipherSuiteId.suites[0xc02e], TlsCompressionMethodId(0), [])
cert_msg = TlsHandshakeCertificate(TlsCertificate(sensor_cert_bytes))
certreq = TlsHandshakeCertificateRequest([TlsCertificateType.ECDSA_SIGN])
shd = TlsHandshakeServerHelloDone()

rt1_content = TlsDataWriteStream()
for m in (sh, cert_msg, certreq, shd):
    TlsHandshakeMessage(m).write(rt1_content)
server_rt1_bytes = bytes([0x16, 0x03, 0x03]) + be(len(rt1_content.data), 2) + rt1_content.data

# ---------------------------------------------------------------------------
# Stub CommunicationInterface: captures the client's outbound record bytes and
# hands back the (pre-built or, for RT2, live-derived) synthesized server
# response. remote_tls_status() is False on the first call (pre-handshake),
# True afterwards (post-handshake final assert in establish()).
# ---------------------------------------------------------------------------
class StubComm(tudor.CommunicationInterface):
    def __init__(self):
        self.session = None
        self.send_count = 0
        self.status_calls = 0
        self.golden_client_rt1 = None
        self.golden_client_rt2 = None
        self.server_rt2_bytes = None
        self.hv_master_secret = None
        self.hv_verify_digest = None

    def close(self): pass
    def reset(self): pass

    def remote_tls_status(self):
        self.status_calls += 1
        return self.status_calls > 1

    def send_command(self, cmd, resp_size, timeout=2000, raw=False):
        assert raw
        assert cmd[0] == tudor.Command.TLS_DATA
        assert cmd[1:4] == b"\x00\x00\x00"
        tdata = cmd[4:]
        self.send_count += 1

        if self.send_count == 1:
            self.golden_client_rt1 = tdata
            return server_rt1_bytes

        if self.send_count == 2:
            self.golden_client_rt2 = tdata

            algo = self.session.record_layer.encryption_algo
            master_secret = algo.master_secret
            decr_key, decr_iv = algo.decr_key, algo.decr_iv
            dB = self.session.handshake_proto.msg_digest.copy().digest()
            self.hv_master_secret = master_secret
            self.hv_verify_digest = dB

            verify_data = tls_prf(master_secret, "server finished", dB, 12, hashes.SHA384())
            fin_msg = bytes([0x14]) + be(12, 3) + verify_data  # Finished handshake message (id=20=0x14)

            aad = be(0, 8) + bytes([0x16, 0x03, 0x03]) + be(len(fin_msg), 2)  # seq=0, ct=handshake
            iv = decr_iv + FIXED_SERVER_FIN_NONCE
            ct_and_tag = AESGCM(decr_key).encrypt(iv, fin_msg, aad)
            fin_frag = FIXED_SERVER_FIN_NONCE + ct_and_tag

            ccs_record = bytes([0x14, 0x03, 0x03]) + be(1, 2) + bytes([0x01])
            fin_record = bytes([0x16, 0x03, 0x03]) + be(len(fin_frag), 2) + fin_frag
            self.server_rt2_bytes = ccs_record + fin_record
            return self.server_rt2_bytes

        raise Exception("unexpected extra send_command call (%d)" % self.send_count)

stub = StubComm()
remote_key = TlsEccRemoteKey(pd.priv_key, pd.host_cert, pd.sensor_cert)
session = tls.TlsSession(stub, remote_key)
stub.session = session
session.establish()
assert session.established
assert session.handshake_proto.phase == tls.handshake.TlsHandshakePhase.FINISHED
print("rev establish() reached FINISHED -- synthesized server side is self-consistent")

# ---------------------------------------------------------------------------
# Emit the golden vectors.
# ---------------------------------------------------------------------------
emit_bytes("golden_client_rt1", stub.golden_client_rt1)
emit_bytes("server_rt1", server_rt1_bytes)
emit_bytes("golden_client_rt2", stub.golden_client_rt2)
emit_bytes("server_rt2", stub.server_rt2_bytes)

emit_bytes("hv_client_random", FIXED_CLIENT_RANDOM)
emit_bytes("hv_server_random", FIXED_SERVER_RANDOM)
emit_bytes("hv_eph_priv", be(FIXED_EPH_INT, 32))
emit_bytes("hv_gcm_nonce", FIXED_CLIENT_FIN_NONCE)
emit_bytes("hv_master_secret", stub.hv_master_secret)
emit_bytes("hv_verify_digest", stub.hv_verify_digest)

emit_bytes("sensor_cert_400", sensor_cert_bytes)
emit_bytes("host_cert_400", host_cert_bytes)

# per-message goldens (fine-grained tests) -- sliced out of the RT1/RT2 records
def record_frag(rec):
    assert rec[0] == 0x16
    ln = (rec[3] << 8) | rec[4]
    assert len(rec) == 5 + ln
    return rec[5:]
def hs_msg_at(buf, off):
    mid, ln = buf[off], (buf[off+1] << 16) | (buf[off+2] << 8) | buf[off+3]
    return buf[off:off+4+ln], off + 4 + ln

rt1_frag = record_frag(server_rt1_bytes)
off = 0
sh_msg, off = hs_msg_at(rt1_frag, off)
certmsg, off = hs_msg_at(rt1_frag, off)
certreqmsg, off = hs_msg_at(rt1_frag, off)
shdmsg, off = hs_msg_at(rt1_frag, off)
assert off == len(rt1_frag)
emit_bytes("golden_server_hello", sh_msg)

rt2_client_frag = record_frag(stub.golden_client_rt2[:5 + ((stub.golden_client_rt2[3] << 8) | stub.golden_client_rt2[4])])
off = 0
certclientmsg, off = hs_msg_at(rt2_client_frag, off)
ckemsg, off = hs_msg_at(rt2_client_frag, off)
certverifymsg, off = hs_msg_at(rt2_client_frag, off)
assert off == len(rt2_client_frag)
emit_bytes("golden_client_cert", certclientmsg)
emit_bytes("golden_cke", ckemsg)
emit_bytes("golden_cert_verify", certverifymsg)

# ---- T7: HS-key scalar + a deterministic host-cert build vector ----
hs_secret = bytes.fromhex("717cd72d0962bc4a2846138dbb2c2419")
hs_seed = bytes.fromhex("2512a76407065f383846139d4bec2033aaaa")
hs_prf = tls_prf(hs_secret, "HS_KEY_PAIR_GEN", hs_seed, 32, hashes.SHA256())
hs_priv_scalar_be = hs_prf[::-1]  # rev interprets the PRF bytes little-endian as the scalar
emit_bytes("golden_hs_priv_scalar", hs_priv_scalar_be)

PAIR_HOST_INT = int.from_bytes(bytes(range(64, 96)), "big")  # distinct pinned key, unrelated to the eph key
pair_host_key = ecc_mod.derive_private_key(PAIR_HOST_INT, ecc_mod.SECP256R1())
golden_host_cert = SensorCertificate.create_host_cert(pair_host_key.public_key())
emit_bytes("golden_pair_host_priv", be(PAIR_HOST_INT, 32))
emit_bytes("golden_host_cert_400", golden_host_cert.tobytes())

# Canned 802-byte 0x93 PAIR reply (status=0 ++ host_cert ++ sensor_cert), reusing
# the real pdata's certs -- format-valid, doesn't need to be a fresh pairing.
golden_pair_resp_802 = bytes(2) + host_cert_bytes + sensor_cert_bytes
emit_bytes("golden_pair_resp_802", golden_pair_resp_802)

hdr = "/* GENERATED by driver/tests/gen_handshake_vectors.py -- do not edit. */\n#pragma once\n#include <glib.h>\n\n"
OUTPATH = os.path.join(HERE, "handshake_vectors.h")
with open(OUTPATH, "w") as f:
    f.write(hdr + "\n".join(OUT) + "\n")
print("wrote", OUTPATH, "with", len(OUT), "symbols")
