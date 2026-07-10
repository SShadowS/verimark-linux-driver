# Linux driver for the Kensington VeriMark Desktop

![status](https://img.shields.io/badge/status-working%20%C2%B7%20enroll%20%2B%20verify%20%2B%20unlock-brightgreen)
![license](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue)
![device](https://img.shields.io/badge/USB-047d%3A00f2-orange)
![libfprint](https://img.shields.io/badge/libfprint-1.94.10-informational)

A clean-room `libfprint` driver for the Kensington VeriMark Desktop
(`047d:00f2`), a Synaptics "Tudor" match-on-chip fingerprint reader. It plugs
into `fprintd`, so enroll, verify, and fingerprint unlock all work through the
standard Linux stack. As far as we know this is the first working Linux support
for the device; upstream libfprint, the vendor, and earlier reverse-engineering
attempts all stopped at the sensor's encrypted channel.

## Status

Confirmed on real hardware (Fedora 44, libfprint 1.94.10):

| Operation | State |
|---|---|
| Enroll | Works (`fprintd-enroll`) |
| Verify / identify | Works, single tap (`fprintd-verify`, PAM login/unlock) |
| Fingerprint unlock (lock screen, `sudo`) | Works |
| Delete / clear storage | Implemented, not yet exercised on-device |

Two caveats before you rely on it. It has been tested on a single unit and a
single distro, so treat it as "works for me" rather than battle-hardened. And
the driver deliberately does not advertise `FP_DEVICE_FEATURE_STORAGE_LIST`:
a failed match can never delete your enrollment, but `fprintd` also can't
enumerate or garbage-collect prints on the device. Details in
[Limitations](#limitations).

## Install

Two steps: build the driver into a real `libfprint`, then point the system
`fprintd` at it. Both scripts are idempotent and the install is fully
reversible.

```sh
# 1. Build: install deps, clone/register the driver into upstream libfprint, compile.
./driver/setup-libfprint-build.sh

# 2. Install: relocate the built .so to a system path, add a fprintd drop-in + udev rule.
sudo ./driver/install-verimark.sh
```

Then enroll:

```sh
fprintd-enroll        # press-and-hold each prompt (~8 taps to full coverage)
fprintd-verify        # single tap
```

To uninstall (removes the drop-in, udev rule, and relocated library, restoring
the stock `libfprint` and the built-in Synaptics reader):

```sh
sudo ./driver/install-verimark.sh --uninstall
```

### SELinux note

`install-verimark.sh` copies the built `.so` into `/usr/local/lib64/verimark-libfprint`,
relabels it `lib_t`, and drops a systemd `LD_LIBRARY_PATH` override on
`fprintd.service`. The relocation is required because under SELinux Enforcing,
`fprintd` runs confined (`fprintd_t`) and is denied `dlopen()` of a library
under `/home`. The script never touches `/usr/lib*/libfprint-2.so*` and never
runs `meson install`. Run `./driver/install-verimark.sh --help` for flags
(`--build-dir`, etc.).

Full build/install detail lives in [`driver/README.md`](driver/README.md).

## The hardware

The dongle combines a FIDO U2F security key and a Windows Hello fingerprint
reader, exposed as two separate USB interfaces:

| Iface | Class | What it is | Linux status |
|---|---|---|---|
| 0 | HID, usage page `0xF1D0` | FIDO / U2F authenticator (CTAPHID) | Already works as a U2F key (`pam-u2f`). CTAP1/U2F only, no CTAP2, so the fingerprint is not reachable here. |
| 1 | Vendor `0xFF` | Synaptics "Tudor" match-on-chip sensor | The interface this driver speaks. Wrapped in server-auth TLS 1.2 (`17 03 03 …`). |

## How it works

The biometric channel (interface 1) has no bulk endpoints. Commands ride EP0
vendor control transfers (a bulk-over-control framing), and an interrupt-IN
endpoint (`0x83`) carries finger and frame events. On top of that the driver
speaks the Synaptics "Tudor" stack, split across these files:

| File | Responsibility |
|---|---|
| `verimark.c` / `.h` | `FpDeviceClass` glue: open/close plus the enroll/verify/identify/list/delete/clear/cancel vfuncs |
| `verimark-transport*.c` | async EP0 bulk-over-control transport and interrupt-event waits |
| `verimark-tls*.c` | hand-rolled TLS 1.2 handshake and record layer (server-auth, host-anonymous ECDH, no TPM binding, which is why a stock Linux host can pair) |
| `verimark-pairing.c` | `0x93` trust-on-first-use pairing; persists per-host key material |
| `verimark-moc.c` | match-on-chip operations: `FpiSsm` state machines for capture / enroll / verify / identify / delete / clear |

Offline unit tests (TLS PRF/keys/GCM/ECC, the TLS channel and pairing against a
mock sensor, and the MOC builders/parsers/state order) live in `driver/tests/`
(`meson test -C driver/tests/build`). Design notes:
[`driver/PORTING-PLAN.md`](driver/PORTING-PLAN.md).

## Limitations

- No device-side print listing in `fprintd`. Enroll and the `0x9f` device list
  identify a template under two different 16-byte ids (a minted id vs. the DB
  GUID), so their `fpi-data` can't be reconciled for `fp_print_equal`. Proper
  support needs the `0xa0 GET_OBJ_INFO` bridge between the two ids verified
  on-device; until then `STORAGE_LIST` stays off.
- `fprintd-delete` and clear-storage are implemented but untested on hardware.
- The crypto core still uses the legacy OpenSSL `EC_KEY` API
  (`OPENSSL_API_COMPAT 0x10100000L`); migrating to EVP is pending.
- Not yet submitted upstream to `libfprint`.

## Reverse-engineering history

The driver came out of a multi-week clean-room reverse-engineering effort:
characterizing the two USB interfaces, mapping the roughly 31-command Tudor
protocol, proving the TLS channel can be impersonated from a stock host, and
building a Python reference that was debugged on hardware before the C port.
The protocol map, the GO/NO-GO analysis, and the command-surface notes are in
[`findings/`](findings/); the working Python reference the C driver mirrors is
`p2_moc.py` under [`prototype/`](prototype/). Proprietary vendor binaries,
Ghidra decompiles, USB captures, and key material are git-ignored and kept
local only.

## Credits and license

This is clean-room work, but it leans heavily on
[Popax21/synaTudor](https://github.com/Popax21/synaTudor) (the `rev` branch),
the reference for the Tudor protocol and TLS stack, and on the synaTudor
community's issue trail for `047d:00f2`.

Licensed LGPL-2.1-or-later, matching `libfprint`.
