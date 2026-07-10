# findings/52 — C libfprint driver port: OFFLINE-COMPLETE (uncompiled against real libfprint, on-device deferred)

**Date:** 2026-07-10. Documentation/status checkpoint, no device, no new RE. Records that the
clean-room C port of the VeriMark (`047d:00f2`) driver — begun in the 2026-07-07 skeleton, taken
through the TLS core/channel and MOC plans, then integrated this session — now has **every layer of
`driver/` written**, with the pure-logic parts offline-tested green. This does **not** claim the
driver runs on hardware: it has never been compiled against a real `libfprint` checkout, and the
on-device SSM/USB paths are unverified by construction (no libfprint headers, no compiler pass, on
this machine).

Source of truth for the wire protocol/crypto this port mirrors: **findings/49** (the truncated-command
breakthrough that unblocked MOC `0x96 01`) and **findings/51** (enroll+verify working end-to-end from
the Python prototype `prototype/p2_moc.py`) — this is a 1:1 port of already-proven choreography, not
new protocol work. Implementation plans executed: `docs/superpowers/plans/2026-07-10-verimark-tls-core.md`,
`docs/superpowers/plans/2026-07-10-verimark-tls-channel.md`, `docs/superpowers/plans/2026-07-10-verimark-moc.md`.

## Module inventory (all under `driver/`)

| Module | Responsibility (one line) | Test status |
|---|---|---|
| `verimark-transport-framing.{c,h}` | Pure EP0 chunk/pad/`wValue` framing math (from `control_comm.py`), no I/O. | Written, TDD (`driver/tests/test_transport_framing.c`, 5 GTest cases, red→green per its own header). **Not currently wired into the `meson test` run** (`driver/tests/meson.build` builds only `test_tls_core`/`test_tls_channel`/`test_moc`) — it's scaffolded for the real libfprint tree's own test harness (see the commented block in `driver/meson.build`). Manually compiled+run standalone this session to confirm it still passes (5/5 OK) — not part of the "11/11" figure below. |
| `verimark-transport.{c,h}` | Async EP0 control transport (`verimark_cmd`) + interrupt-EP `0x83` waiter (`verimark_intr_wait_async`), built on the framing helpers. | Written; needs `fpi-usb-transfer.h`/`FpiSsm` (libfprint) to compile — **uncompiled**. |
| `verimark-tls-crypto.{c,h}` | Offline TLS1.2 crypto core: PRF, master/key-block derivation, 400 B cert + 868 B pairing-data codec, AES-256-GCM record wrap/unwrap, ECDH premaster, ECDSA sign/verify (+ prehashed). Pure `libcrypto`, no TLS stack, no device. | **UNIT-TESTED** against golden vectors generated from `rev` itself (`gen_vectors.py`) — `tls_prf`, `tls_keys`, `tls_cert`, `tls_gcm`, `tls_ecc` all green. |
| `verimark-tls.{c,h}` | Hand-rolled Synaptics "Tudor" TLS 1.2 channel: handshake (SHA-256 transcript / SHA-384 PRF split, Finished-excluded per findings/28, premaster = ECDH vs. the sensor's static cert, mutual auth) + record wrap/unwrap. | **UNIT-TESTED** offline via a synthesized mock server (`tls_channel` GTest) — no real device needed since the handshake is deterministic given a captured pdata blob. |
| `verimark-pairing.{c,h}` | `0x93` TOFU pairing (HS-key-signed host cert per findings/46) + 868 B pdata persist/load (`/var/lib/fprint/verimark/<sid>.pdata`, mode 0600). | **UNIT-TESTED** (`tls_pairing` GTest, same binary as `tls_channel`). |
| `verimark-moc.{c,h}` | Match-on-chip operations: `FpiSsm` capture/enroll/verify/identify/list/delete/clear state machines, plus their pure halves — command builders, response parsers, the `0x96 03` finalize splicer, SID synthesis (offsets: coverage @22, quality @42, id @2:18, per findings/49/51). | Pure halves **UNIT-TESTED** (`moc_build`, `moc_parse`, `moc_finalize`, `moc_capture_state_order` GTests, compiled standalone with `-DVERIMARK_MOC_PURE_ONLY`). The `FpiSsm` state-machine half needs `fpi-device.h`/`fpi-ssm.h` — **uncompiled**, device-deferred by design (see the plan's own Task 4 fallback). |
| `verimark.c`/`.h` | `FpDeviceClass` integration: `dev_open` runs sid resolution → load-or-pair → synchronous TLS handshake, then thin enroll/verify/identify/list/delete/clear_storage/cancel vfuncs handing off to `verimark-moc.c`; `dev_close`. | Written and inspected against the API surface in `re/synaTudor-rev/libfprint/` (every non-obvious call cited `file:line` in-source) — **uncompiled**, no libfprint checkout on this machine to link against. |
| `60-verimark.rules` | udev rule granting seat/plugdev access to `047d:00f2`. | N/A (static config, not code). |
| `driver/tests/` | Offline GTest suite (glib + libcrypto only, no libfprint/gusb/device) covering every pure module above. | See result below. |

## Offline test result (verified this session)

```
$ meson test -C driver/tests/build
 1/11 verimark-tls-core-tests:tls_prf                 OK
 2/11 verimark-tls-core-tests:tls_keys                OK
 3/11 verimark-tls-core-tests:tls_cert                OK
 4/11 verimark-tls-core-tests:tls_gcm                 OK
 5/11 verimark-tls-core-tests:tls_ecc                 OK
 6/11 verimark-tls-core-tests:tls_channel             OK
 7/11 verimark-tls-core-tests:tls_pairing             OK
 8/11 verimark-tls-core-tests:moc_build               OK
 9/11 verimark-tls-core-tests:moc_parse               OK
10/11 verimark-tls-core-tests:moc_finalize            OK
11/11 verimark-tls-core-tests:moc_capture_state_order OK

Ok:    11
Fail:  0
```

This is the full registered `driver/tests/meson.build` suite — **11/11 OK, zero regressions**. It
covers every pure/offline-testable module: TLS crypto core, the hand-rolled handshake/record layer
(against a synthesized mock server), pairing, and the MOC command builders/parsers/finalize
splicer/SID synthesis. It does **not** cover: `verimark-transport-framing.c`'s own test file (written,
passes standalone, but not wired into this `meson.build` — see the inventory row above), the `FpiSsm`
state machines in `verimark-moc.c`, or any of `verimark.c` — none of those compile without a real
libfprint checkout.

## Build status (2026-07-10): COMPILES against libfprint 1.94.10

Later the same day, the driver was actually built (no device attached — this is a compile/link-only
checkpoint, hardware exercise is still deferred, see below). Target: a **fresh upstream clone** of
`https://gitlab.freedesktop.org/libfprint/libfprint.git`, tag/HEAD **1.94.10** — not the bundled
`re/synaTudor-rev/libfprint` RE reference clone (that tree is 1.90.7 and was RE study material, never
intended as the real build target). Result: **compiles and links cleanly** —

- **76 `verimark` symbols** present in the built `libfprint.so`.
- The driver is **registered in `fpi-drivers.c`** (generated from the `drivers_info` dict — confirms
  `fpi_device_verimark_get_type` resolves and the meson registration took effect end to end, not just
  a partial compile).

Build config that worked:

```
meson setup build -Ddrivers=verimark -Dgtk-examples=false -Ddoc=false -Dintrospection=false
meson compile -C build
```

**Reconciliation needed to get there** (small — the port's own architecture/protocol logic needed zero
changes, everything here is build-plumbing):

1. **`fpi_ssm_jump_to_state_delayed()` is a 3-arg call** in this libfprint version (`verimark-transport.c`,
   `verimark-moc.c`) — already correct in the committed driver source, no fix needed at build time.
2. **`OPENSSL_API_COMPAT` defines** (`0x10100000L`, silencing OpenSSL 3.0 deprecation warnings for the
   legacy EC_KEY API) — already present in `verimark-pairing.c`, `verimark-tls.c`,
   `verimark-tls-crypto.c`. Both (1) and (2) are **already committed in `driver/*.c` itself** as of this
   session — nothing left to patch for them, and `driver/setup-libfprint-build.sh` does not (and must
   not) patch them.
3. **Upstream's driver-registration format is a DICT, not the flat list `driver/setup-libfprint-build.sh`
   originally assumed.** Upstream 1.94.10's top-level `meson.build` has a `drivers_info` dict
   (`'goodixmoc': {},` etc. — a driver needing extra deps declares `{ 'helper': ['openssl'] }`, which
   alone pulls in libcrypto) and `libfprint/meson.build` has a matching `driver_sources` dict of
   `files()` calls, not the older `default_drivers = [...]` list / `if driver == 'x' drivers_sources +=
   [...] endif` per-driver blocks the script's registration step was written against (that pattern was
   accurate for the 1.90.7 RE reference tree, not for real upstream). `setup-libfprint-build.sh` now
   **auto-detects which format the target tree uses** and applies the matching idempotent insertion —
   see its updated header comment and Section 2c.
4. **`tests/meson.build`'s `foreach driver_test: drivers_tests`** (a 1-var foreach over a dict) is
   rejected by the meson version on this machine — needed a compat patch to the 2-var form
   `foreach driver_test, _vmk_unused : drivers_tests`. This could **not** be worked around by disabling
   the `tests/`/`examples/` subdirs instead: core `fpi-device.c` `#include`s a `tests/`-generated header
   (`fpi-test-emulation.h`), so disabling them breaks the *core* libfprint build, not just the test
   suite. `setup-libfprint-build.sh` now applies this patch automatically (idempotent — only touches the
   exact incompatible line, only if present).

None of this touched the driver's actual protocol/crypto logic (findings/49/51's choreography) — it was
purely getting a hand-written driver's build plumbing to match a real, current upstream tree instead of
the older RE reference tree it was written by reading headers against.

## How to build/test on-device (next session)

1. **Offline suite only, no libfprint needed** (what was verified 2026-07-10 morning):
   `meson setup driver/tests/build driver/tests && meson test -C driver/tests/build`
   — requires only `glib-2.0` and `libcrypto >=3.0` dev packages, already satisfied here.
2. **Full driver build against real libfprint — now automated and verified** (see Build status above):
   `driver/setup-libfprint-build.sh --libfprint-src /path/to/upstream/libfprint/libfprint` (or let it
   clone the recommended upstream tree per its own `--help`/error-path guidance). This wires the driver
   into the target tree (dict- or list-format meson registration, auto-detected), installs deps
   (including `cmake`, needed by upstream's `meson setup` and previously missing from the script's dnf
   list), applies the `tests/meson.build` compat patch, and runs `meson setup`/`meson compile` with the
   verified flags above. Install `60-verimark.rules` alongside libfprint's generated udev rules (the
   script does this too, `--skip-udev` to opt out).
3. **Then exercise on-device** (the part still actually deferred — no VeriMark hardware on this
   machine): open/pair, enroll, verify/identify, list/delete/clear_storage. See the script's own
   printed "next steps" for the `fprintd` `LD_LIBRARY_PATH` drop-in test procedure.

## Deferred / open (state honestly)

1. **On-device test** — the driver now **builds and links cleanly** against upstream libfprint 1.94.10
   (see Build status above; no longer uncompiled). What remains deferred is purely **hardware exercise**
   — open/pair, enroll, verify/identify, list/delete/clear_storage against the real sensor — since there
   is no VeriMark attached to this machine this session.
2. **Minted-vs-`0x9f`-list template-id mapping** (findings/51 §5, still open) — the driver stores both
   ids (`fpi-data`: finger, minted_tid, list_gid, user_id); resolving which one `0xa0` actually wants
   is on-device-only.
3. **Driver-synthesized SID vs. the captured Windows SID** — whether `0x96 03`'s embedded SID field
   can be a driver-synthesized value (vs. the captured Windows SID `WIN_FINALIZE[49:77]` used verbatim
   by the prototype) is **untested**; `verimark-moc.c` synthesizes one from the local uid per the plan,
   but this has never round-tripped against the real sensor.
4. **`0xa5` DB2_FORMAT clear payload** is a best-effort guess (`[0xa5, 0x01]`, shaped like the other
   DB2_* commands) — never captured live in any prototype run or `rev` trace.

(`FpDeviceClass.clear_storage` / `fpi_device_clear_storage_complete` — previously listed here as a risk
against the older RE reference tree's `fpi-device.h` — is now **resolved**: both exist in upstream
1.94.10 and `verimark.c`'s use of them compiled cleanly. See Build status above.)

## Artifacts

`driver/` (all modules above), `driver/tests/` (offline suite), `driver/PORTING-PLAN.md` (P0–P7 phase
plan this port follows), `driver/README.md` (file-by-file map + protocol summary, kept in sync with
this finding), `docs/superpowers/plans/2026-07-10-verimark-{tls-core,tls-channel,moc}.md` (the three
plans executed to build this). Prior findings this is grounded in: **findings/49** (truncated-command
breakthrough), **findings/51** (enroll+verify working live), findings/28/29/38/46 (TLS/MOC/pairing
protocol detail cited throughout the C source).
