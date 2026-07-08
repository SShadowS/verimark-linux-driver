# Resume prompt — P2 via owner-key impersonation (Fedora/Linux box)

Paste the block below into a fresh Claude Code session on the Linux box. Prereq: copy
`C:\ProgramData\verimark-extract\pairing-fields.json` (from the Windows box) to the Fedora box first
— it holds the extracted **owner private key**, so move it securely and keep it out of git.

---

You are resuming a libfprint driver project for the Kensington VeriMark Desktop (USB `047d:00f2`,
Synaptics "Tudor"). P1 pairing + TLS work (findings/28); MOC enroll/verify is decoded (findings/38)
but gated: our Linux host paired *second*, so the sensor granted it a non-owner slot (`cert_type=2`)
and `0x96`/`0x99` return `0x0405`. `git pull` first — findings/39/41/42 and this file are pushed.

**The plan (findings/42): present Windows' OWNER key from Linux.** There is only one sensor and it's
Windows-owned; reset is owner-gated and un-obtainable (findings/36/39). But owner identity = the host
EC keypair (no TPM — findings/DECISION). We DPAPI-decrypted Windows' owner pairing data on the
Windows box and exported it. Loading it into `rev` makes Linux present the owner keypair → the sensor
should give an authorized (`cert_type=0`) session → MOC works. Non-destructive; Windows Hello keeps
working (both hosts use the same owner key).

**Input file:** `pairing-fields.json` (copied from Windows). It is the decrypted Synaptics TagVal
container, parsed to entries `{tag, len, hex}` (little-endian TLV). Contents:
- `tag=0x0002 len=32`  → **owner EC private key** (raw P-256 scalar `d`, 32 bytes).
- `tag=0x0001 len=400` → a Synaptics cert (magic `3f5f`).
- `tag=0x0003 len=400` → a Synaptics cert (magic `3f5f`).
- `tag=0x0004 len=420` → an extra field (unknown — likely a fuller/host container; ignore for the
  first attempt, revisit if enroll still fails).
- `tag=0x0000 len=2`   → trailer.

**Task:**
1. Load `pairing-fields.json`. Extract the 32-byte private scalar (tag `0x0002`) and the two 400-B
   certs (tags `0x0001`, `0x0003`).
2. **Identify which 400-B cert is the SENSOR cert vs the HOST(owner) cert:** the sensor cert's ECDSA
   signature verifies against THIS sensor's `10.1-kf` pubkey (findings/28 — `rev`'s
   `sensor.pub_key`, `Cert.signbytes()` + `ECDSA(SHA256)`). The one that verifies = sensor cert; the
   other = the owner **host** cert.
3. Build a `rev` `SensorPairingData` from: the owner private key (construct a P-256
   `EllipticCurvePrivateKey` from the 32-byte scalar `d`; derive the pubkey), the owner **host** cert
   (400 B), and the **sensor** cert (400 B). Note `rev`'s persisted `.pdata` is `0x44`(68)-byte priv
   + 400 host + 400 sensor (findings/28) — inspect `re/synaTudor-rev/pydrv/tudor/sensor/pair.py`
   (`SensorPairingData` (de)serialize + `SensorCertificate`) to see the exact 68-byte private-key
   encoding and emit it from our 32-byte scalar. Do NOT re-pair (`0x93`) — that would mint a new
   non-owner slot; we want to LOAD the owner identity, not create a new one.
4. `sensor.initialize(pdata)` to bring up TLS presenting the owner cert, confirm
   `remote_tls_status()` established, then run `prototype/p2_moc.py` enroll/identify.

**Verdict:**
- `0x99` dedup returns `0x0509` and `0x96 01` returns OK (not `0x0405`) → **owner impersonation
  works, MOC unblocked.** Implement the full enroll/verify per findings/38.
- Still `0x0405` → the owner key alone isn't sufficient. Next: try including the `tag=0x0004` 420-B
  field / re-check the host-partition (`0x3e/0x3f/0x41`, findings/30) content; if nothing lifts it,
  the MOC-owner binding is not purely the keypair and the non-destructive MOC path is exhausted
  (host-readout `0x7f` looked dead on this firmware, findings/31).

**Safety:** `pairing-fields.json` and any `.pdata` built from it hold the OWNER private key — keep
out of git (`prototype/pdata/` is already git-ignored; put it there). This is non-destructive: you're
loading an existing owner identity, not resetting or re-provisioning the sensor. This repo uses the
superpowers workflow — brainstorm + a short plan before editing `rev`.

---
