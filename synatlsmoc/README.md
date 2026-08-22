# VeriMark on Linux via the upstream-track `synatlsmoc` driver

This directory installs the **`vojtapl/synaTudorMiS` `synatlsmoc` driver** with the
**`Uriziel01` Kensington Match-in-Sensor patch**, replacing our earlier
clean-room driver in `../driver/`. It is the more feature-complete, more
compatible, upstream-track path (see the 2026-08-18 changelog entry).

One build supports **both** of this machine's readers:

| USB ID | Reader | libfprint driver |
|---|---|---|
| `047d:00f2` | Kensington VeriMark Desktop | `synatlsmoc` (+ Kensington EP0 transport) |
| `06cb:0126` | built-in Synaptics | `synaptics` |

## Why this over `../driver/`

- **Storage list works safely** (no verify-purges-enrollment bug — the driver
  persists the fprintd `user_id` on-device and reuses it at list time).
- **Proper `delete`** removes template *and* user objects, plus device-side GC.
- **Modern OpenSSL 3 EVP** crypto (no deprecated `EC_KEY`).
- **LED feedback**, warm-open fast path, secret-redacted logs.
- **Whole Synaptics Tudor family**, tests, and heading for upstream libfprint.

## Use

Two steps. Build as your normal user, install with sudo.

```bash
./build.sh                 # reproducible: clone pinned source + verified patch + native build
sudo ./install.sh          # point fprintd at it (SELinux-safe, reversible)

# then, with the VeriMark plugged in:
fprintd-enroll             # first open AUTO-PAIRS from Linux (replaces Windows pairing)
fprintd-verify
```

A prebuilt `dist/libfprint-2.so.2.0.0` is already staged, so `sudo ./install.sh`
works without running `./build.sh` first. Re-run `./build.sh` any time to
rebuild from pinned source.

### Pairing

The driver **auto-pairs on the first open** (first `fprintd-enroll`): it sends
one `PAIR` (`0x93`), which **replaces any existing Windows pairing**, then
writes the new host key + sensor certs to
`/var/lib/fprint/verimark/047d-00f2/libfprint-persistent.bin` (root-owned,
`0600`). No separate pairing step. Re-pairing is expected and safe.

> **Note:** upstream fails closed here and requires an out-of-band, capture-
> audited pairing tool. Our local patch `0002-verimark-self-pairing.patch`
> re-enables automatic first-pairing and makes the driver self-persist to the
> file above, so `fprintd-enroll` is a single step. If auto-pairing ever fails
> on your unit, the upstream guarded tool
> (`Uriziel01/kensington-verimark-desktop-linux` `tools/verimark_pair.py`) is
> the fallback.

### Reverting

```bash
sudo ./install.sh --status      # show what's installed / paired
sudo ./install.sh --uninstall   # back to stock libfprint (keeps pairing file)
sudo ./install.sh --purge       # back to stock AND wipe pairing state
```

Uninstall restores the packaged libfprint; the built-in Synaptics reader keeps
working (the VeriMark is unsupported by stock libfprint).

## Files

| File | What |
|---|---|
| `build.sh` | No-sudo reproducible build → `dist/libfprint-2.so.2.0.0` |
| `install.sh` | Sudo install / `--status` / `--uninstall` / `--purge` |
| `versions.env` | Pinned upstream commit + patch checksum (reproducibility) |
| `0001-Add-Kensington-...patch` | The upstream Kensington Match-in-Sensor patch (checksummed) |
| `0002-verimark-self-pairing.patch` | Local patch: auto-pair on first open + self-persist to the env file |
| `60-verimark.rules` | udev `uaccess` rule for `047d:00f2` |
| `dist/` | Staged prebuilt library |
| `src/` | Build working tree (git clone; remove with `./build.sh --clean`) |

## Provenance

- Base: `vojtapl/synaTudorMiS` @ `5452637` (pinned in `versions.env`).
- Patch: `Uriziel01/kensington-verimark-desktop-linux`
  `0001-Add-Kensington-VeriMark-Match-in-Sensor-support.patch`
  (sha256 `dddce7ea…aaab1`), patched tree `f7161290…befdd`.
- Independently reported working on Ubuntu 26.04 and Bazzite/Fedora
  (synaTudor issue #51, comment 2026-08-17).
