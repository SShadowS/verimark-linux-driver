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

## How to build/test on-device (next session)

1. **Offline suite only, no libfprint needed** (what was verified this session):
   `meson setup driver/tests/build driver/tests && meson test -C driver/tests/build`
   — requires only `glib-2.0` and `libcrypto >=3.0` dev packages, already satisfied here.
2. **Full driver, needs a real libfprint checkout:**
   - Clone/checkout `libfprint` (not the RE reference clone at `re/synaTudor-rev/libfprint`, which is
     read-only RE material — a real buildable tree).
   - Drop this repo's `driver/*.c`/`*.h` into `libfprint/libfprint/drivers/verimark/`.
   - Add `'verimark'` to the `drivers` list in libfprint's own `meson.build`; wire in the per-driver
     snippet already staged in `driver/meson.build` (source list + `libcrypto` dependency, modeled on
     `egismoc-sdcp`'s pattern).
   - Install `libgusb`, `libcrypto` (>=3.0), `json-glib` dev packages (libfprint's own deps) — not
     installed on this machine.
   - `meson setup build && ninja -C build` — this is the **first compiler pass** `verimark.c` and the
     `FpiSsm` half of `verimark-moc.c` will ever see; expect to fix compile errors (API surface was
     confirmed by reading headers, not by compiling against them).
   - Install `60-verimark.rules` alongside libfprint's generated udev rules.
   - Then exercise on-device: open/pair, enroll, verify/identify, list/delete/clear_storage.

## Deferred / open (state honestly)

1. **On-device build+test** — needs a real libfprint checkout (`drivers/verimark/`) + `libgusb`/
   `libcrypto`/`json-glib` dev packages; none installed here, so the libfprint-integrated `.c` files
   (`verimark.c`, the `FpiSsm` half of `verimark-moc.c`, all of `verimark-transport.c`) are
   **uncompiled**.
2. **`FpDeviceClass.clear_storage` / `fpi_device_clear_storage_complete`** don't exist in the RE
   reference clone's older `fpi-device.h` — must be verified against whatever libfprint version is
   actually targeted for the real build.
3. **Minted-vs-`0x9f`-list template-id mapping** (findings/51 §5, still open) — the driver stores both
   ids (`fpi-data`: finger, minted_tid, list_gid, user_id); resolving which one `0xa0` actually wants
   is on-device-only.
4. **Driver-synthesized SID vs. the captured Windows SID** — whether `0x96 03`'s embedded SID field
   can be a driver-synthesized value (vs. the captured Windows SID `WIN_FINALIZE[49:77]` used verbatim
   by the prototype) is **untested**; `verimark-moc.c` synthesizes one from the local uid per the plan,
   but this has never round-tripped against the real sensor.
5. **`0xa5` DB2_FORMAT clear payload** is a best-effort guess (`[0xa5, 0x01]`, shaped like the other
   DB2_* commands) — never captured live in any prototype run or `rev` trace.

## Artifacts

`driver/` (all modules above), `driver/tests/` (offline suite), `driver/PORTING-PLAN.md` (P0–P7 phase
plan this port follows), `driver/README.md` (file-by-file map + protocol summary, kept in sync with
this finding), `docs/superpowers/plans/2026-07-10-verimark-{tls-core,tls-channel,moc}.md` (the three
plans executed to build this). Prior findings this is grounded in: **findings/49** (truncated-command
breakthrough), **findings/51** (enroll+verify working live), findings/28/29/38/46 (TLS/MOC/pairing
protocol detail cited throughout the C source).
