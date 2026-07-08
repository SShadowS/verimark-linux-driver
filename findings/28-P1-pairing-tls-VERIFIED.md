# findings/28 — P1: Linux host pairing + live TLS session (VERIFIED)

**Date:** 2026-07-08 · **Device:** `047d:00f2`, sensor id `f7007ad929c60000`, FW `10.1.3235317`,
prov=3, key_flag set. **Status: DONE.** First write to the sensor succeeded; a TLS 1.2
session is established from Linux and a wrapped command round-trips.

Runner: `prototype/p1_pair.py` (mirrors `p0b_bringup.py`, adds the pairing write + persist +
TLS bring-up). Reuses `synaTudor rev` `tudor.sensor`/`tudor.tls` unchanged over the
`control_comm.ControlComm` EP0 transport (findings/27).

## What happened (single clean run)
1. **Construct `Sensor`** — read-only reset: GET_VERSION + 4 IOTAs + `load_sensor_key(10.1-kf)`.
   Guards asserted: `prov==3`, `key_flag`, `advanced_security`.
2. **`sensor.pair()` — SENSOR WRITE `0x93`.** Sent `0x93 ‖ host_cert(400 B)`; got the
   802-byte response (`0x322`): `resp[2:402]`=new host cert, `resp[402:802]`=device cert.
3. **Persisted immediately** → `prototype/pdata/f7007ad929c60000.pdata` (868 B =
   0x44 priv + 400 host_cert + 400 sensor_cert). **git-ignored** (holds the host EC private key).
4. **Device cert verifies** against this sensor's `10.1-kf` pubkey (ECDSA-P256/SHA-256) ✓ —
   independent interop proof of the key material *and* cert framing for THIS sensor.
5. **`sensor.initialize(pdata)`** — TLS 1.2 handshake completed:
   - ClientHello suites `c005 c02e` (advertised), server chose **`0xC02E`**
     (ECDH-ECDSA-AES256-GCM-SHA384) — matches the captured Windows handshake (findings/22).
   - Cert exchange carried the `3f5f` Synaptics cert magic; server Finished verified;
     ChangeCipherSpec both ways.
   - `remote_tls_status()` → **established**.
6. **Wrapped `GET_START_INFO` (0x19)** through the encrypted channel → **status `0x0000`**,
   68 B, payload matches the plaintext shape (`0000020021000110…`, per-boot nvinfo differs).
7. Clean `uninitialize()` → TLS close alert (`15 03 03`).

## Observed cert fields (this sensor)
- `host_cert`: `cert_type=2`, ECDSA signature 32 B (host-side, our HS key).
- `sensor_cert` (device): `cert_type=0`, ECDSA signature **71 B** (DER, rooted at the sensor key).

## Rollback / coexistence
- Host partitions are multi-slot; the Windows enrollment was expected to survive. `unpair()`
  is only a soft reset. The pairing slot for Linux is now persisted locally in the `.pdata`.
- To re-establish later: `SensorPairingData.load()` the file → `sensor.initialize(pdata)`.
  **Losing the `.pdata` means re-pairing** (mints a new slot); keep it.

## Next (P2 — MOC, the real RE gap)
Enroll `0x96` (coverage bitmask `01→7f`) + verify `0x99` (177-B match record / `0x0509`
no-match). Oracle: the git-ignored `captures/win` Frida plaintexts already contain decrypted
`0x96`/`0x99` traffic (incl. two 177-B `PLAINTEXT-IN`) and `re/ghidra-out/moc/`. `rev` lacks
these opcodes (it does host-side matching, not on-chip MOC).
