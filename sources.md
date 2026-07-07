# Sources (annotated)

Everything gathered 2026-07-07. Grouped by usefulness.

## ⭐ Directly about this device
- **RE writeup of the exact scanner** — https://blog.inexplicity.de/reverse-engineering-the-kensington-verimark-fingerprint-scanner.html
  The one prior attempt on `047d:00f2`. pyusb replay of init, then blocked by
  TLS. Confirms Synaptics silicon + `17 03 03` TLS records. Start here.
- **Community driver hub — status of 047d:00f2** — https://github.com/jedbillyb/linux-fingerprint-drivers
  · README: https://github.com/jedbillyb/linux-fingerprint-drivers/blob/master/README.md
  Lists the device as "no known fix." Where to publish/collaborate.
- **linux-hardware.org probe DB** — https://www.linux-hardware.org/?id=usb:047d-00f2
  Confirms VID:PID, kernel binding, "unsupported" field data.

## Secure-channel / crypto background
- **Synaptics/MS SDCP spec** — https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/sdcp
  What the TLS-like sensor channel is and why it exists (the go/no-go context).
- **TenSeventy7/libfprint-egismoc-sdcp** — https://github.com/TenSeventy7/libfprint-egismoc-sdcp
  SDCP secure channel implemented inside a libfprint driver. **Different device
  (EgisTec 1c7a), but the best code template for the crypto plumbing.**
- **antoskuu/libfprint-egismoc-sdcp-fix** — https://github.com/antoskuu/libfprint-egismoc-sdcp-fix
  Build/OpenSSL-linking fixes for the above; Fedora/Arch/Ubuntu build notes.
- **AUR libfprint-egismoc-sdcp-git** — https://aur.archlinux.org/packages/libfprint-egismoc-sdcp-git

## libfprint itself
- **Upstream repo** — https://gitlab.freedesktop.org/libfprint/libfprint
  Study `libfprint/drivers/synaptics/` (likely-related command set) and
  `libfprint/drivers/egismoc/` (secure channel). Driver-writing patterns.
- **Supported-devices list** — https://fprint.freedesktop.org/supported-devices.html
  Confirms no `047d`/Kensington entry exists anywhere upstream.

## Community discussion (context, low signal)
- Linux Mint — "kensington VeriMark DT: No devices available" — https://forums.linuxmint.com/viewtopic.php?t=436343
- Zorin — "Kensington VeriMark Fingerprint not working" — https://forum.zorin.com/t/device-kensington-verimark-fingerprint-not-working/31298
- EgisTec ETU905 update notes (unrelated device, shows the general MOC/PID-add workflow) — https://hackmd.io/@wilson920430/rkgYsUpKWe

## Vendor
- **Kensington VeriMark Desktop setup (Windows-only)** — https://www.kensington.com/software/verimark-setup/verimark-desktop-setup-guide/
- Product page — https://www.kensington.com/p/products/data-protection/fingerprint-security-keys/verimark-desktop-fingerprint-key/

## FIDO tooling (for the §0 no-driver route)
- `libfido2` / `fido2-tools` (installed) — `fido2-token -L`, `fido2-token -I`.
- `pam-u2f` / `pamu2fcfg` — local auth via the U2F interface.
