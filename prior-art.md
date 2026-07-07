# Prior art & protocol background

## 1. The existing RE attempt on THIS device ⭐ most relevant

**"Reverse Engineering the Kensington Verimark Fingerprint Scanner"** —
https://blog.inexplicity.de/reverse-engineering-the-kensington-verimark-fingerprint-scanner.html

- Same device: `047d:00f2`, "VeriMark DT Fingerprint Key".
- Approach: captured Windows↔device USB traffic (Wireshark + usbmon), then
  rebuilt the early init in a **Python / pyusb** prototype — replayed the
  vendor-specific control messages and endpoint setup; got the device to start
  its exchange.
- **Wall hit:** the payloads are **TLS-encrypted**. Author flagged records
  beginning `17 03 03 …` (that byte string is a **TLS 1.2 Application Data**
  record: `0x17` content-type = application_data, `0x03 0x03` = TLS 1.2). Their
  conclusion, verbatim in spirit: *"Due to the encryption, it's going to be
  virtually impossible to do this just by observing traffic over USB."*
- Identifies the underlying sensor as **Synaptics**.
- Status: left as a milestone / open for future work. No driver produced.

**Takeaway:** the cheap path (passive sniff → replay) is already known to fail.
Don't repeat it expecting a different result; start from `plan.md` §1 (decide
whether the TLS endpoint is impersonable at all).

## 2. Community driver hub — device is catalogued as unsupported

**jedbillyb/linux-fingerprint-drivers** —
https://github.com/jedbillyb/linux-fingerprint-drivers
(README: https://github.com/jedbillyb/linux-fingerprint-drivers/blob/master/README.md)

- Lists `047d:00f2` as `External (USB)` under **"No known fix yet"** — one of
  ~116 unsupported sensors, no WIP driver, no partial code. Explicitly invites
  owners to contribute a driver or hardware dump. **This is where your work
  should eventually land / where to look for collaborators.**

## 3. Why the EgisTec `egismoc-sdcp` forks do NOT apply

These come up in every VeriMark search — rule them out early:

- **TenSeventy7/libfprint-egismoc-sdcp** — https://github.com/TenSeventy7/libfprint-egismoc-sdcp
- **antoskuu/libfprint-egismoc-sdcp-fix** — https://github.com/antoskuu/libfprint-egismoc-sdcp-fix

They add **SDCP** (Secure Device Connection Protocol) support to libfprint's
`egismoc` driver, but only for **EgisTec** devices (VID `1c7a:…`). Our device is
**Synaptics silicon behind Kensington VID `047d`**, and its transport differs
(`egismoc` uses **bulk**; ours declares HID/interrupt + control). Different
vendor, different chip, different protocol. *However* — they are the **best
worked example of implementing a TLS/ECDH secure channel inside a libfprint
driver.** Read them as a template for the crypto plumbing, not as a device match.

## 4. The relevant upstream driver family: `synaptics`

- libfprint already has a **`synaptics`** driver (Prometheus/Triton MOC sensors,
  the `06cb:00xx` ThinkPad readers — including the built-in `06cb:0126` on this
  laptop). It speaks Synaptics' MOC command set.
- Open question worth checking early: **is the VeriMark's inner protocol a
  variant of the same Synaptics MOC command set, just wrapped in TLS?** If yes,
  most of the state machine may already exist in the `synaptics` driver and the
  real work collapses to "establish the secure channel, then reuse known
  commands." If no, it's a from-scratch protocol. `plan.md` §2 covers how to
  test this.
- Source to study: libfprint `libfprint/drivers/synaptics/` (upstream:
  https://gitlab.freedesktop.org/libfprint/libfprint).

## 5. Secure-channel background (what `17 03 03` implies)

- Synaptics **SDCP** and Microsoft's **Enhanced Sign-in Security (ESS)** both put
  a cryptographically authenticated channel between host and fingerprint sensor
  precisely so a host-side attacker can't sniff or inject. Reference:
  Microsoft SDCP spec — https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/sdcp
- Typical shape: sensor holds a **device certificate + private key** (endorsed by
  the vendor); host and sensor do an **ECDH**-based handshake; the host verifies
  the sensor's cert, and a session key protects all subsequent commands. If the
  channel also *authenticates the host* (or binds to a TPM), an unmodified Linux
  host may be unable to complete the handshake **even with full protocol
  knowledge**. Establish which variant this is — it's the project's go/no-go.
- Blaud/analysis of blackbox capture confirming TLS-1.2 record framing is the
  strongest evidence we already have that this is a real cryptographic channel,
  not light obfuscation.

## 6. Kensington's own Linux position

Kensington ships **Windows-only** software for the VeriMark line
(https://www.kensington.com/software/verimark-setup/verimark-desktop-setup-guide/).
No Linux driver, no published protocol. Don't expect vendor help; a support
request asking for the protocol spec under interop terms is a long shot but
costs nothing.
