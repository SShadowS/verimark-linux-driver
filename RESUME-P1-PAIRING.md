# Resume prompt — VeriMark Linux driver, P1 (pairing + TLS)

Paste the block below into a fresh Claude Code session on the Linux box to continue.
Self-contained: names the verified state, the transport, what's done, and the P1 plan.

---

You are resuming a reverse-engineering → driver project: a **libfprint driver for the
Kensington VeriMark Desktop** (USB **`047d:00f2`**, Synaptics "Tudor" silicon). The
Windows RE is done (verdict GO); the **transport is solved and the reuse stack runs
read-only against the real device**. Your job now is **P1: pair a Linux host identity and
bring up the TLS session** — this is the **first write to the sensor**.

## Environment (running as root this session)
- You're likely running Claude Code **as root** (so `sudo`/device access needs no
  fingerprint taps). **Keep the tree owned by `sshadows`:** run `umask 022`, and before you
  finish (or after creating files) run
  `chown -R sshadows:sshadows /home/sshadows/nogit/LocalChanges/verimark-driver`.
- The Python deps (`pyusb`, `cryptography`) are installed under **sshadows'** user site,
  not root's. Run device scripts with
  `PYTHONPATH=/home/sshadows/.local/lib/python3.14/site-packages python3 …` (or
  `pip install --break-system-packages pyusb cryptography` for root). No `sudo` needed now.

## Hard facts already VERIFIED (do NOT re-derive)
- **Device:** `047d:00f2`, **FW 10.1**, `key_flag` set ⇒ sensor pubkey =
  `sensor_keys/10.1-kf.tsk` (loads + verifies fine). Sensor is **provisioned (prov=3)**,
  currently paired to the **Windows** host (we don't have that host key ⇒ must pair fresh).
- **Transport = bulk-over-EP0-control (`findings/27`, verified 3 ways).** iface0 is FIDO
  U2F (ignore it); the biometric channel is **iface1** (vendor; only endpoint is `0x83`
  interrupt-IN = async **events**). Commands ride **EP0 vendor control**:
  - WRITE `bmRequestType=0x40, bRequest=0x16, wValue=(len&7), wIndex=0`, data **padded to
    /8**, chunked at 4096 (continuation flags `0x4000`/`0x8000`).
  - READ `bmRequestType=0xc0, bRequest=0x17, wValue=0`, chunked 4096, **retry-on-timeout**.
  - Responses come on **control-IN**, NOT `0x83`. Aux: `0xc0/0x14` status, `0x40/0x15` DFT.
- **The transport shim works.** `prototype/control_comm.py` = `ControlComm(
  CommunicationInterface)` implementing the above. `prototype/p0b_bringup.py` runs the full
  `synaTudor rev` stack over it read-only: GET_VERSION + READ_IOTA×4 (incl. a 3580-B
  chunked read) + `load_sensor_key`(10.1-kf) + GET_START_INFO, all status OK, then stops at
  `initialize(None)` → `Exception('No pairing data given')`. Re-run it to re-confirm state.

## Reuse (the leverage)
- **`synaTudor` `rev`** worktree at `re/synaTudor-rev/pydrv/` (git-ignored). Everything
  above `CommunicationInterface` is reused unchanged: `tudor.tls` (TLS-1.2
  ECDH-ECDSA-AES256-GCM), `tudor.sensor.Sensor`, DB2, and **pairing**.
- **Pairing flow** (`tudor/sensor/sensor.py::pair()`): reset → assert prov==3 → generate
  host P-256 keypair → `SensorCertificate.create_host_cert(pub)` → send
  **`0x93 PAIR ‖ host_cert`** (resp 0x322=802 B) → parse `host_cert=resp[2:402]`,
  `dev_cert=resp[402:802]` → returns `SensorPairingData(priv, host_cert, dev_cert)`.
  `SensorPairingData.save(f)/load(f)` persist it. `unpair()` is just a soft reset.

## Read first (ground truth, committed)
`findings/27-ep0-transport-VERIFIED.md` (transport), `findings/24` (reuse map + GO),
`findings/23`+`25` (command byte-map + response struct offsets), `findings/22` (captured
TLS handshake). Then `rev`'s `tudor/sensor/{sensor,pair}.py` + `tudor/tls/`.

## P1 goal & first actions
1. **Re-confirm state:** `lsusb -d 047d:00f2`; run `prototype/p0b_bringup.py` (read-only) —
   expect it to reach the pairing gate.
2. **(Optional, zero-risk de-risk):** parse the captured handshake in
   `captures/win/win-usb-20260708-*-hub2.pcap` and confirm `rev`'s `SensorCertificate`
   parses **this** sensor's 400-B cert and the `10.1-kf` key verifies it — proving TLS
   interop before any write. (Captures are a git-ignored oracle: hub2 pcaps + the two
   `win-cng-*.log` Frida session-key/plaintext logs with every command's bytes.)
3. **⚠ FIRST SENSOR WRITE — pairing.** Build a runner (mirror `p0b_bringup.py`) that does
   `pdata = sensor.pair()` then **immediately** `pdata.save(...)` to a file (e.g.
   `/home/sshadows/nogit/LocalChanges/verimark-driver/prototype/pdata/<sensorid>.pdata`,
   chown to sshadows). Watch `LOG_COMM`; the `0x93` write returns host+device certs.
   Rollback: `unpair()` is a soft reset; host partitions are multi-slot so the Windows
   enrollment should survive — but stop immediately if anything looks off.
4. **Bring up TLS:** `sensor.initialize(pdata)` → establishes the TLS session, then confirm
   `comm.remote_tls_status()` is True and a **wrapped** `GET_START_INFO` (`0x19`) round-trips
   (status 0x0000 through the encrypted channel). That is P1 done: a live secure session
   from Linux.

## After P1
- **P2 — MOC:** enroll via `0x96` (coverage bitmask `01→7f` → `fpi_device_enroll_progress`)
  and verify via `0x99` (177-B match record or `0x0509` no-match). Semantics in
  `findings/23`+`25`; the git-ignored `re/ghidra-out/moc/` + the `captures/win` plaintexts
  are the sources. These two opcodes are the only genuine RE gap (`rev` lacks them — it does
  host-side matching, not on-chip MOC).
- **P3 — libfprint glue:** enroll/verify/delete/list callbacks → opcodes (the `driver/` C
  skeleton is the target). Port `control_comm.py`'s transport to the C driver.

## Notes
- Clean-room: implement behaviour only (opcodes/sizes/framing); `rev` is an independent
  reimplementation you may study, not copy.
- `prototype/p0_probe*.py` were the iface0/FIDO dead-end (how iface0 was ruled out) — safe
  to ignore or delete; `p0_ctrl.py` + `control_comm.py` are the transport references.

---
