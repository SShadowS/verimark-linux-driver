# 24 — VCSFW opcode names + libfprint/synaTudor reuse map (go/no-go)

**Date:** 2026-07-08. Cross-references the live opcodes (`23-command-bytemap.md`)
against public reimplementations to answer `prior-art.md` §4: *is the VeriMark's inner
protocol the Synaptics command set already implemented in open source, just wrapped in
TLS?* **Answer: yes — the command set is identical Synaptics Tudor "VCSFW"; the secure
layer already exists in open source; only two MOC opcodes + the USB transport shim
remain to RE.**

Method: authoritative names from the **`synaTudor` `rev` branch** (a from-scratch
reimplementation, not the DLL-relinker default branch) — `pydrv/tudor/comm.py`
(the `VCSFW_CMD_*` enum) and `rev/proto.txt` (protocol RE doc) — plus libfprint
upstream. 8 of our 10 opcodes match **byte-for-byte** (command sizes + arg bytes),
verified against our own capture.

## Verdict

**CONFIRMED: 047d:00f2 and 06cb:00be share one VCSFW opcode space.** Byte-exact on
`0x19/0x80/0x81/0x86/0x87` and `0xa0/0xa3`; enum/RE-doc match on `0x9e`. The captured
TLS-1.2 **AES-256-GCM** channel is the same one synaTudor already implements.

## Opcode → VCSFW name

| opcode | our role (23) | VCSFW name | confidence | evidence |
|---|---|---|---|---|
| `0x19` | startinfo | **GET_START_INFO** | confirmed | `comm.py` 0x19; `resp_size=0x44`=**68 B** = our resp |
| `0x80` | capture config | **FRAME_ACQ** | confirmed | `<BIIHxBBBBB>` = **17 B** = our cmd |
| `0x81` | capture step | **FRAME_FINISH** | confirmed | `<B>` = **1 B** |
| `0x86` | ~~frame data~~ | **EVENT_CONFIG** | confirmed | `<B8II>` = 1+32+4 = **37 B**; event-mask, re-armed per cycle (our "frame data" guess was wrong) |
| `0x87` | frame poll | **EVENT_READ** | **byte-exact** | `<BHHI>(0x87,seq,32,1)` = `87 0000 2000 01000000` = our cmd verbatim |
| `0x96` | capture step | **UNMAPPED (MOC)** | gap | 0x94–0x9d gap; not in any public RE — on-chip enroll/identify |
| `0x99` | begin op | **UNMAPPED (MOC)** | gap | same gap; "begin identity/enroll session" — the matcher path synaTudor left as TODO |
| `0x9e` | ~~finalize~~ | **DB2_GET_DB_INFO** | med-high | `comm.py` 0x9e; opcodes are unique, so not a separate "end" cmd — driver reads DB state after each op |
| `0xa0` | DB2 query | **DB2_GET_OBJ_INFO** | confirmed | `comm.py` 0xa0; 1+u32+id[16]=**21 B** |
| `0xa3` | DB2 delete | **DB2_DELETE_OBJ** | confirmed | `comm.py` 0xa3; carries the 16-B object id |

**DB2 object-store range** (on-sensor secure template DB, ~126 slots, survives BIOS
reset): `0x9e` GET_DB_INFO · `0x9f` GET_OBJ_LIST · `0xa0` GET_OBJ_INFO · `0xa1`
GET_OBJ_DATA · `0xa2` (inferred write) · `0xa3` DELETE_OBJ · `0xa4` (inferred cleanup)
· `0xa5` FORMAT. Our two-step delete = `GET_OBJ_INFO`→`DELETE_OBJ` per template.

## Reuse map

**Upstream libfprint `synaptics` — NOT usable (~zero reuse).**
- Speaks **bmkt** (`BMKT_CMD_*`, CRC-framed), a different protocol; no opcode overlap.
- **No TLS / ECDH / AES-GCM / cert handling anywhere** — cleartext bulk only.
- `id_table` is `06cb` only; the bmkt path times out against SDCP/Windows-Hello-secured
  firmware — the same `0x0`-not-ready failure as our device in synaTudor issue #51.

**synaTudor `rev` branch — the real reference (reusable today).** `pydrv/tudor/` is a
complete pure-Python Tudor driver + a native `libfprint/.../drivers/tudor.c` shim:
- **TLS 1.2 stack** (`tls/`): advertises `TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384`
  (the negotiated suite) — exactly our `findings/22`. Server-auth, ECDSA-P256 cert,
  no client cert. Handshake carried inside VCSFW **cmd `0x44` TLS_DATA** (`44 00 00 00 ‖
  record`); app-data as `17 03 03`; record overhead `0x45` (69 B).
- **Pairing** (`0x93` PAIR): host-keypair provisioning + host-cert exchange.
- **Capture/events** (`0x80/0x81/0x86/0x87`) and **DB2 storage** (incl. our delete flow).

**Caveats before treating `rev` as drop-in:**
1. **It's image-capture, not MOC.** `rev` establishes TLS then does raw frame capture +
   host-side NBIS matching; it does **not** implement on-chip enroll/verify/delete —
   which is exactly what our VeriMark session does (`0x96`/`0x99`). Our own
   `synaFpAdapter132.dll` decompiles (`21`, `re/ghidra-out/moc/`) are currently the
   **better** source for those than anything public.
2. **Transport differs.** `rev`'s `USBCommunication` assumes **bulk** endpoints on
   iface0; 047d:00f2 has **no bulk pipe** — commands ride EP0 control transfers,
   responses/events on interrupt-IN `0x83` (`20`, `device-facts.md`). VCSFW/TLS layer
   is identical; the USB plumbing underneath must be swapped.
3. `rev` loads a per-firmware sensor pubkey (`sensor_keys/<major>.<minor>.tsk`); the
   VeriMark's FW-version key may not ship with it.

## Go / no-go

- **Reusable today** (from `synaTudor@rev`): the entire secure layer — TLS-1.2
  ECDHE-ECDSA-AES256-GCM handshake, record framing (`0x44` TLS_DATA), pairing (`0x93`),
  start-info (`0x19`), event/frame capture (`0x80/0x81/0x86/0x87`), DB2 storage incl.
  delete (`0x9e/0x9f/0xa0/0xa1/0xa3/0xa5`).
- **`0x96` + `0x99` now functionally mapped** (`23`, by phase-diffing the live capture):
  `0x96` = guided-enroll capture/update (coverage-bitmask progress), `0x99` = identify/
  match. Only their exact response-struct field offsets remain partial.
- **Must still capture/RE:**
  1. **A fresh handshake + pairing** — our capture reused a cached TLS session (0
     `16 03 03` records on hub2), so ClientHello/cert/`0x93` PAIR/`0x44` TLS_DATA are
     unseen live. This is the one piece needed to *establish* the channel from scratch;
     `synaTudor@rev` implements it, but our device's actual bytes are uncaptured.
  2. A **control-transfer transport shim** (no bulk pipe on `047d`).
- **Not reusable:** upstream libfprint `synaptics` (wrong protocol).

→ Net: this is **GO**. The crypto/transport is solved and open-source, and every
command opcode is now identified. Remaining: one cold-start capture (handshake/pair) +
a USB transport adapter + exact MOC struct offsets.

## Sources
- synaTudor `rev` (reference impl + RE docs): https://github.com/Popax21/synaTudor/tree/rev — `pydrv/tudor/comm.py`, `rev/proto.txt`, `pydrv/tudor/{sensor,tls}/`
- synaTudor issue #51 (our exact device 047d:00f2): https://github.com/Popax21/synaTudor/issues/51
- libfprint upstream (bmkt `synaptics`, no VCSFW/TLS): https://gitlab.freedesktop.org/libfprint/libfprint/-/tree/master/libfprint/drivers/synaptics
- MarcelineVPQ/elitebook840-fingerprint (relink port: pairing+TLS+DB2 read on sibling FS7605): https://github.com/MarcelineVPQ/elitebook840-fingerprint
