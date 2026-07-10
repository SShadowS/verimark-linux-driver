# libfprint driver — Kensington VeriMark Desktop (047d:00f2)

**Status (2026-07-10): integration pass complete, on-device proof deferred.**
`verimark.c` now wires every layer together (P0-P6 of `driver/PORTING-PLAN.md`):
USB open/claim, the P1/P2 bring-up (sensor-id resolution, TOFU pairing, TLS
handshake), and thin enroll/verify/identify/list/delete/clear_storage vfuncs
that hand off to `verimark-moc.c`. All wire protocol and crypto were already
solved and prototyped in Python (`prototype/p2_moc.py`, findings/49, 51) before
this port; nothing here is new RE. The earlier IOCTL-shaped skeleton (fictional
opcode enum, wrong TLS record format) described in older history was removed —
every module below is written and cited against the real Tudor wire protocol.

No libfprint headers or the physical device are available in this environment,
so `verimark.c`/`.h` are **written-correct-but-uncompiled** against the API
surface confirmed in `re/synaTudor-rev/libfprint/` (see file-level citations in
`verimark.c`) — see "Build & status" below for exactly what is/isn't verified.

## Files

| File | Role |
|---|---|
| `verimark.h` | USB/transport constants, real Tudor wire opcodes, the `FpiDeviceVerimark` object (open session state: iface, `tls`, `pairing`, `sid`, enroll/event bookkeeping). |
| `verimark.c` | **Integration layer** (this pass). `FpDeviceClass` + `dev_open`/`dev_close` (sync P1/P2 bring-up: sid resolution, load-or-pair, TLS handshake) + thin enroll/verify/identify/list/delete/clear_storage/cancel wiring onto `verimark-moc.c`. |
| `verimark-transport-framing.h/.c` | Pure EP0 control-transfer chunk/pad/wValue math (no I/O). Shared by the async transport and `verimark.c`'s synchronous open-time helpers. |
| `verimark-transport.h/.c` | Async EP0 bulk-over-control transport (`verimark_cmd`) + interrupt-IN wait, built on the framing helpers, driven by `FpiSsm`. Used post-open by `verimark-moc.c`. |
| `verimark-tls-crypto.h/.c` | Offline crypto core: PRF, key derivation, cert (de)serialize, AES-256-GCM record wrap/unwrap, ECDH/ECDSA (libcrypto). |
| `verimark-tls.h/.c` | Hand-rolled Synaptics "Tudor" TLS 1.2 handshake state machine + record layer, built on the crypto core. |
| `verimark-pairing.h/.c` | `0x93` TOFU pairing exchange + 868-byte pdata file persistence (`/var/lib/fprint/verimark/<sid>.pdata`). |
| `verimark-moc.h/.c` | Match-on-chip operations layer: command builders/parsers (pure, offline-tested) + the `FpiSsm` capture/enroll/verify/identify/list/delete/clear state machines. |
| `60-verimark.rules` | udev rule granting seat/plugdev access to `047d:00f2`; install into `/usr/lib/udev/rules.d/` alongside libfprint's own generated rules. |
| `PORTING-PLAN.md` | The phased (P0-P7) port plan this driver follows; cites the exact prototype function each phase mirrors. |

## How it maps to the protocol

- **Transport**: commands go OUT/IN over **EP0 vendor control transfers**
  (`0x40/0x16` write, `0xc0/0x17` read, chunked/padded); the interrupt-IN EP
  `0x83` carries finger-press/frame-ready events only. No bulk pipe. Claim
  iface 1. (findings/27)
- **Secure channel**: a non-standard TLS 1.2 (suite `0xC02E`,
  ECDH-ECDSA-AES256-GCM-SHA384), server(sensor)-auth, TOFU pairing — no TPM, no
  client cert chain. (findings/28, `verimark-tls.c` header banner)
- **Pairing**: `0x93` first-pairer-wins TOFU; the 868-byte pdata blob (host
  privkey + host cert + sensor cert) is generated once per sensor id and
  persisted to disk — re-pairing on every open would be both wrong (breaks
  TOFU) and wasteful.
- **MOC** (match-on-chip): `0x99`/`0x96` sub-command dispatched
  enroll/identify; add-sample coverage completes at `resp[22]==0x7f`; the
  sensor mints the 16-byte template id. (findings/49, findings/51)

## Build & status

The driver is designed to build inside a real libfprint checkout, as
`libfprint/drivers/verimark/` (see `meson.build` here for the per-driver
snippet: source list, the `libcrypto` dependency for the TLS/pairing crypto,
and the standalone-test notes). It cannot be compiled in *this* environment —
no libfprint checkout/headers are installed here — so `verimark.c`/`.h` are
correct-by-inspection against the API surface in `re/synaTudor-rev/libfprint/`
(every non-obvious call is cited to a `file:line` in that clone) rather than
compiler-verified; **on-device build and enroll/verify/identify/list/delete
are DEFERRED** until this lands in an actual libfprint tree with the physical
sensor attached.

What *is* verified in this repo, offline, without a device:

- **`driver/tests/`** — glib+libcrypto-only unit tests for the crypto core,
  the TLS channel/handshake (against golden vectors from `rev` itself), the
  EP0 transport framing math, and the MOC command builders/parsers/finalize
  splicer/SID synthesis. All green as of this pass (`meson test -C
  driver/tests/build`: 11/11 OK).
- **The wire protocol itself** — proven end-to-end from Linux against the real
  sensor by the Python prototype (`prototype/p2_moc.py`): pairing, TLS
  handshake, encrypted DB reads, and a full guided enroll + verify all
  succeeded (findings/49, findings/51). `verimark.c`'s `dev_open` and the
  `verimark_moc_*` entry points are a byte-for-byte port of that already-
  working choreography, not new protocol work.

## Prerequisites already satisfied (from RE + prototyping)

Wire opcodes, TLS handshake/record format, pairing exchange, MOC enroll/verify
choreography, EP0 transport framing — all reverse-engineered and prototyped
working in Python. This pass turns that into async/sync C wired onto libfprint
`FpDeviceClass`. What remains is exercising the compiled driver against real
hardware (P3's on-device capture-SSM manual test, P4's guided enroll, P5's
match/no-match, P6's list/delete/clear) and P7's fprintd/PAM integration.
