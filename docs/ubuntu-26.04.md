# Ubuntu / Kubuntu 26.04: build notes and test report

Second-unit, second-distro report for the `driver/` (clean-room) libfprint driver, plus the
Debian-family translation of the dependency list and the KDE/PAM pitfalls we hit. Everything
below was done on real hardware; where something was *not* tested it says so.

## Environment

| | |
|---|---|
| Distro | Kubuntu 26.04.1 LTS ("Resolute Raccoon") |
| Kernel | 7.0.0-34 / 7.0.0-38 generic |
| Desktop | Plasma 6.6.6, SDDM 0.21 |
| `fprintd` / system `libfprint` | 1.94.5-4 / 1.95.1+tod1-0ubuntu2 (left untouched) |
| libfprint built against | upstream `main`, commit `6f9479c3d55f` (2026-09-02), reports `1.94.100` |
| This repo | `1239ab8` |
| Device | Kensington VeriMark Desktop K62330WW, `047d:00f2`, factory-fresh, product string "VeriMark DT Fingerprint Key" |

## Result

| Operation | State |
|---|---|
| Build against libfprint `main` (1.94.100) | Works, no source changes needed |
| First enroll on a factory-fresh unit (this is the pairing step) | Works, 8 stages, two fingers enrolled |
| `fprintd-verify` | Works, single tap |
| Plasma lock-screen unlock | Works |
| SDDM login | Works, with the caveat below |
| `sudo` | Not tested (passwordless sudo on this machine) |
| "Touch now" LED (white, front of the key) | Works (lights while waiting for a touch) |
| Delete / clear storage | Not tested |

`fprintd-list` showed "No devices available" before the driver was installed, and
`fido2-token -I` on the key's HID interface reports `caps: nocbor, msg` (U2F only), so the
fingerprint sensor really is only reachable through the vendor interface this driver uses.

## Dependencies (apt)

```
sudo apt install meson ninja-build cmake gcc g++ pkgconf git rsync \
  libglib2.0-dev libgusb-dev libssl-dev libjson-glib-dev libpixman-1-dev \
  libnss3-dev libgirepository1.0-dev libsystemd-dev libcairo2-dev \
  libudev-dev libgudev-1.0-dev systemd-dev fprintd libpam-fprintd
```

`systemd-dev` is the non-obvious one. libfprint's `meson.build` asks for the `udev`
pkg-config module, and on Debian/Ubuntu `udev.pc` ships in `systemd-dev`, not in
`libudev-dev`. Without it `meson setup` stops with
`Dependency "udev" not found, tried pkgconfig and cmake`.

## Build and install

`setup-libfprint-build.sh` installs the dependencies above itself when it finds `apt-get`
(and no `dnf`). There is no `v1.95.1` tag upstream (Ubuntu's 1.95.1 is a development
snapshot), so use the default clone of `main`:

```sh
./driver/setup-libfprint-build.sh --drivers=default
./driver/install-verimark.sh   # defaults to ~/verimark-build/libfprint/build
```

`--drivers=default` builds every stock driver plus `verimark`, so other readers keep
working. (What was actually run here: `--skip-udev --work-dir ~/verimark-build --libfprint-src
~/verimark-build/upstream-libfprint` on a manual clone of `main`, with the dependencies
installed by hand; the apt branch of the script was then exercised separately, as a no-op
because the packages were already present. The bare invocation above is the same thing
with defaults and was not run end to end.) The SELinux relabel step is skipped automatically (Ubuntu uses AppArmor; no
AppArmor changes were needed). Offline tests (`meson test`) pass.

Check it took effect:

```sh
systemctl show fprintd -p Environment   # LD_LIBRARY_PATH=/usr/local/lib64/verimark-libfprint
fprintd-list "$USER"                    # should now list the Kensington device
```

## Pitfalls

**Other `fprintd` drop-ins can silently win.** systemd merges
`/etc/systemd/system/fprintd.service.d/*.conf` alphabetically and a later file's
`Environment=LD_LIBRARY_PATH=` replaces an earlier one. A leftover `override.conf` from
another experimental driver sorted after `10-verimark-libfprint.conf`, so `fprintd` kept
loading the wrong library and reported "No devices available" with no error. If
`systemctl show fprintd -p Environment` does not show the verimark path, look for other
drop-ins.

## KDE / PAM

The lock screen needed no PAM changes; SDDM needs a two-line stack and has an inherent
limit, and the distro's global fprintd PAM profile should stay disabled. KWallet also needs a
decision. All of that is written up distro-neutrally in [kde-pam.md](kde-pam.md).

## Notes

- The reader's white LED lights while the driver waits for a touch and turns off once the
  frame wait ends (or the press wait times out). It uses the `0x39` LED_EX2 command (frames
  from the Windows capture, findings/25), is purely cosmetic, and any LED error is ignored so
  it can never fail a login. Set `VERIMARK_LED=0` in `fprintd`'s environment to disable all
  LED traffic. It is switched on at `CAP_ARM_PRESS`, before the press wait. On this unit
  `CAP_WAIT_PRESS` returned immediately even with no touch, so the real wait is the frame wait
  (`CAP_FRAME_ACQ`/`CAP_WAIT_FRAME`) and the LED stays lit through it until `CAP_EVENT_CLEAR`.
  A first attempt that turned it off again right after the press wait was invisible
  (milliseconds). The press-timeout path (`no finger detected`) turns the LED off too, but
  that path could not be reached on this unit and is untested on hardware.
- Pairing was a non-event on a factory-fresh unit, but it is one-way, as the READMEs say. We
  did not test what happens when a unit that was previously paired elsewhere is used.
