# RE roadmap — VeriMark Desktop libfprint driver

Ordered so the **cheapest question that can kill the project comes first**. Don't
skip to writing a driver; do §1 and §2 before committing real time.

---

## §0. If you just want auth, not a driver (read this first)

Your original goal was *fingerprint login*. Two lower-effort routes exist that
may satisfy it without any RE:

- **Built-in Synaptics reader `06cb:0126`** already works with fprintd. For the
  laptop itself, this is done today (`fprintd-enroll`).
- **The VeriMark as a U2F/WebAuthn key.** Interface 0 is a working U2F
  authenticator (confirmed). You can use it for 2FA on websites and for local
  auth via `pam-u2f`:
  ```
  sudo dnf install pam-u2f pamu2fcfg
  pamu2fcfg > ~/.config/Yubico/u2f_keys      # touch the VeriMark when it flashes
  # then add: auth sufficient pam_u2f.so   to a PAM stack
  ```
  Caveat: it's **U2F/CTAP1 only** (no FIDO2 resident keys, no PIN/UV surfaced),
  and the *fingerprint* is not individually exposed — the touch/finger just
  provides user presence. If "tap the dongle to authenticate" is good enough,
  this avoids the entire driver problem.

If you specifically need the fingerprint driving `fprintd` from the external
dongle, continue.

---

## §1. GO/NO-GO: is the TLS endpoint impersonable? (do this first)

The project lives or dies here. You must find out whether the host side holds (or
can derive) everything needed to complete the secure-channel handshake, or
whether the sensor authenticates a secret the host never sees.

1. Get a Windows box/VM with the sensor and Kensington's driver installed and
   working (enroll a finger there).
2. Capture a full session with **Wireshark + USBPcap** (Windows) covering:
   device plug-in → driver init → **enroll** → **verify** → delete.
   Also capture on Linux with `usbmon` for cross-reference (see §3).
3. Locate the **handshake before** the first `17 03 03` app-data record — i.e.
   the TLS `ClientHello`/`ServerHello`/cert/key-exchange (`16 03 03 …`
   handshake records) or a vendor pre-amble.
4. Decide the variant:
   - **(a) Host-anonymous channel** (server-auth only, like normal TLS to a web
     server): the host just needs to *verify* the sensor and derive a session
     key. **Impersonable → project is feasible.**
   - **(b) Mutually-authenticated / TPM-bound** (host presents a cert, or keys
     are sealed to Windows/TPM): **likely infeasible** on stock Linux without
     extracting a host key — and that key may not exist off-Windows.

**If (b), stop** (or pivot to §0). Document the finding in the community hub so
the next person doesn't repeat it.

---

## §2. Is the inner protocol just Synaptics-MOC-in-TLS?

Cheap high-value test. libfprint's `synaptics` driver already speaks Synaptics
match-on-chip. If the VeriMark's decrypted commands match that command set, you
inherit most of the state machine.

- Study `libfprint/drivers/synaptics/` (command opcodes, enroll/identify flow).
- Once you can decrypt (needs §1 success) or if any framing leaks pre-encryption,
  compare opcodes/response codes.
- Outcome shapes the driver: *thin secure-channel shim over existing synaptics
  logic* (best case) vs *brand-new protocol* (worst case).

---

## §3. Reverse the Windows driver (the expensive core, only if §1 = feasible)

Passive sniffing is already known to fail (see `prior-art.md`). To get keys /
handshake logic you reverse the driver binary.

- Find the WBDI/usermode driver DLL + sensor firmware in the Kensington install
  (`C:\Windows\System32\drivers\` + the Synaptics WBF DLLs). Identify the crypto:
  look for imports from `bcrypt.dll`/`ncrypt.dll` (CNG), ECDH (`BCRYPT_ECDH_P256`),
  cert parsing.
- Tools: **Ghidra** (free) or IDA; **API Monitor** / **Frida** to hook CNG calls
  at runtime and dump the negotiated session key / pre-master secret live (often
  far easier than static crypto RE — grab the key, then decrypt your pcap).
- With a session key you can decrypt the captured `17 03 03` records and finally
  read the plaintext command protocol (feeds §2).

## §4. Prototype in Python (`prototype/`)

- Use `pyusb`/`hidapi` to talk to the raw interfaces (detach `hid-generic` from
  interface 1 first, or use the hidraw/usbfs path).
- Reimplement: secure-channel handshake → open → enroll (loop) → identify →
  list/delete. Prove enroll+verify end to end from Linux **before** touching C.
- Keep every capture in `captures/` and every experiment reproducible.

## §5. Write the libfprint driver (`libfprint/drivers/verimark/` or extend `synaptics`)

Anatomy of a libfprint MOC driver (mirror an existing one — `egismoc` for the
secure-channel plumbing, `synaptics` for the command set):

- Register VID:PID `047d:00f2` in the driver's `id_table` + the udev rules.
- Implement the `FpDeviceClass` vfuncs: `open`, `close`, `enroll`, `verify`,
  `identify`, `list`, `delete`, `cancel`.
- Do the ECDH/TLS handshake in `open`; wrap/unwrap every command in the session.
- Emit `fpi_device_enroll_progress` / report `FPI_MATCH_SUCCESS|FAIL`.
- Build against a libfprint checkout (`meson`/`ninja`); test with `fprintd` or the
  libfprint example tools before enrolling for real.
- Upstream target: https://gitlab.freedesktop.org/libfprint/libfprint (an MR, or
  publish via the community hub first).

## Realistic effort & odds

- **§1 feasible + §2 = synaptics-compatible:** weeks of focused work. Best case.
- **§1 feasible + new protocol:** months.
- **§1 = mutually-authenticated/TPM-bound:** effectively a no. This is the
  single most likely outcome for an enterprise "security key," so treat §1 as
  the real gate, not a formality.

## Tooling checklist

- Linux: `usbutils` (lsusb), `usbhid-dump`, `python3-pyusb`/`hidapi`, `wireshark`
  (usbmon), `libfprint`+`meson`/`ninja` build deps, `fido2-tools` (already
  installed).
- Windows (RE box/VM): Kensington VeriMark driver, Wireshark+USBPcap, Ghidra,
  Frida/API Monitor.
- `modprobe usbmon` on Linux to capture; `sudo setfacl` or run captures as root.
