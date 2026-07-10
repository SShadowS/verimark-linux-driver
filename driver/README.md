# libfprint driver for the Kensington VeriMark Desktop (047d:00f2)

Works on real hardware. The driver builds and links into upstream libfprint
1.94.10 and enrolls, verifies, and unlocks the VeriMark Desktop (`047d:00f2`)
through `fprintd`, confirmed on Fedora 44. `verimark.c` wires every layer
together (P0-P6 of `driver/PORTING-PLAN.md`): USB open/claim, the P1/P2
bring-up (sensor-id resolution, TOFU pairing, TLS handshake), and the
enroll/verify/identify/list/delete/clear_storage vfuncs that hand off to
`verimark-moc.c`. All wire protocol and crypto were solved and prototyped in
Python (`prototype/p2_moc.py`, findings/49, 51) before this port; nothing here
is new RE.

This file is the driver-internals reference (file roles, protocol mapping, what's
tested). For install steps, overall status, and caveats see the top-level
[`README.md`](../README.md).

## Files

| File | Role |
|---|---|
| `verimark.h` | USB/transport constants, real Tudor wire opcodes, the `FpiDeviceVerimark` object (open session state: iface, `tls`, `pairing`, `sid`, enroll/event bookkeeping). |
| `verimark.c` | Integration layer. `FpDeviceClass` + `dev_open`/`dev_close` (sync P1/P2 bring-up: sid resolution, load-or-pair, TLS handshake) + thin enroll/verify/identify/list/delete/clear_storage/cancel wiring onto `verimark-moc.c`. |
| `verimark-transport-framing.h/.c` | Pure EP0 control-transfer chunk/pad/wValue math (no I/O). Shared by the async transport and `verimark.c`'s synchronous open-time helpers. |
| `verimark-transport.h/.c` | Async EP0 bulk-over-control transport (`verimark_cmd`) + interrupt-IN wait, built on the framing helpers, driven by `FpiSsm`. Used post-open by `verimark-moc.c`. |
| `verimark-tls-crypto.h/.c` | Offline crypto core: PRF, key derivation, cert (de)serialize, AES-256-GCM record wrap/unwrap, ECDH/ECDSA (libcrypto). |
| `verimark-tls.h/.c` | Hand-rolled Synaptics "Tudor" TLS 1.2 handshake state machine + record layer, built on the crypto core. |
| `verimark-pairing.h/.c` | `0x93` TOFU pairing exchange + 868-byte pdata file persistence (`/var/lib/fprint/verimark/<sid>.pdata`). |
| `verimark-moc.h/.c` | Match-on-chip operations layer: command builders/parsers (pure, offline-tested) + the `FpiSsm` capture/enroll/verify/identify/list/delete/clear state machines. |
| `60-verimark.rules` | udev rule granting seat/plugdev access to `047d:00f2`; install into `/usr/lib/udev/rules.d/` alongside libfprint's own generated rules. |
| `PORTING-PLAN.md` | The phased (P0-P7) port plan this driver follows; cites the exact prototype function each phase mirrors. |
| `setup-libfprint-build.sh` | One-shot Fedora setup: installs build deps, wires `driver/*.c/.h` into a real libfprint tree (default: the `re/synaTudor-rev` reference clone) by editing its `meson.build` (`default_drivers` + per-driver source list + `libcrypto` dep, following the exact pattern libfprint uses for `goodixmoc`), compiles it, installs the udev rule, and prints `fprintd` test steps. `--help` for flags; safe to re-run. |
| `install-verimark.sh` | Points the system `fprintd` at the build produced above for on-device testing, non-destructively and reversibly: udev rule + a systemd `LD_LIBRARY_PATH` drop-in on `fprintd.service` (never overwrites `/usr/lib*/libfprint-2.so*`, never `meson install`s). Also relocates the built `.so` to `/usr/local/lib64/verimark-libfprint` (relabeled `lib_t`) since SELinux's `fprintd_t` cannot load a library out of `/home` under Enforcing; the drop-in points there, not at the build dir. `--uninstall` reverts fully (including the relocated copy); safe to re-run either direction. |

## How it maps to the protocol

Commands go OUT/IN over EP0 vendor control transfers (`0x40/0x16` write,
`0xc0/0x17` read, chunked/padded); the interrupt-IN EP `0x83` carries
finger-press/frame-ready events only. There is no bulk pipe. Claim iface 1.
(findings/27)

The secure channel is a non-standard TLS 1.2 (suite `0xC02E`,
ECDH-ECDSA-AES256-GCM-SHA384), server(sensor)-auth, with TOFU pairing: no TPM,
no client cert chain. (findings/28, `verimark-tls.c` header banner)

Pairing is a `0x93` first-pairer-wins TOFU exchange. The 868-byte pdata blob
(host privkey + host cert + sensor cert) is generated once per sensor id and
persisted to disk, since re-pairing on every open would be both wrong (breaks
TOFU) and wasteful.

Match-on-chip operations dispatch enroll/identify through `0x99`/`0x96`
sub-commands; add-sample coverage completes at `resp[22]==0x7f`, and the
sensor mints the 16-byte template id. (findings/49, findings/51)

## Build & status

The driver builds inside a real libfprint checkout as `libfprint/drivers/verimark/`
(see `meson.build` here for the per-driver snippet: source list, the `libcrypto`
dependency for the TLS/pairing crypto, and the standalone-test notes).
`setup-libfprint-build.sh` does the whole thing (deps + checkout + register +
compile); `install-verimark.sh` then points the system `fprintd` at it, reversibly.

Verified:

- On hardware: enroll (coverage `0x01`→`0x7f`), verify/identify (single tap),
  and lock-screen / `sudo` unlock, all via `fprintd` on `047d:00f2` (Fedora 44,
  libfprint 1.94.10).
- In `driver/tests/`: glib+libcrypto-only unit tests for the crypto core, the TLS
  channel/handshake (against golden vectors from `rev` itself), the EP0 transport
  framing math, and the MOC command builders/parsers/finalize splicer/SID synthesis
  (`meson test -C driver/tests/build`: 12/12 OK).
- On the wire: independently proven end-to-end from Linux by the Python
  prototype (`prototype/p2_moc.py`): pairing, TLS handshake, encrypted DB reads, and
  a full guided enroll + verify (findings/49, findings/51). `verimark.c`'s `dev_open`
  and the `verimark_moc_*` entry points mirror that already-working choreography.

Still deferred: `fprintd`-side device print listing (needs the `0xa0` minted↔list
GUID bridge; `STORAGE_LIST` is currently off), on-device exercise of
`delete`/`clear_storage`, and an `EC_KEY` to EVP crypto-core migration. See
"Limitations" in the top-level [`README.md`](../README.md).
