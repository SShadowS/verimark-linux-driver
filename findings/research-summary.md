# Research summary — VeriMark Desktop secure channel (cited)

Deep-research fan-out: 5 angles → 14 sources fetched → 56 claims → 25 adversarially
verified (22 confirmed, 3 refuted). Run 2026-07-07. Feeds `DECISION.md`.

## Question

Is the Kensington VeriMark Desktop (047d:00f2) secure channel impersonable from a
stock Linux host (server-auth-only = GO), or is host auth bound to a
Windows/TPM/firmware secret (= NO-GO)? Sub-questions: (1) SDCP vs proprietary TLS;
(2) libfprint state for secure Synaptics MOC; (3) has anyone RE'd this device;
(4) mutual auth / TPM binding vs server-auth-only.

## Confirmed findings

1. **047d:00f2 unsupported.** Absent from libfprint supported-devices; on the
   official Unsupported-Devices wiki (issue #575, "likely Synaptics FS7600"). Real
   users: enumerates in `lsusb`, `fprintd` says "No devices available."
   Sources: fprint.freedesktop.org/supported-devices.html; libfprint wiki #575;
   forums.linuxmint.com/viewtopic.php?t=436343; forum.zorin.com/t/...31298;
   github.com/jedbillyb/linux-fingerprint-drivers

2. **Exact device already RE'd, dead-ended.** inexplicity.de (2025-04-11): replayed
   USB control msgs, hit encrypted `17 03 03` channel, "virtually impossible …
   observing traffic over USB", "We'll have to reverse engineer the driver … leave
   that for another time." No driver produced.
   Source: blog.inexplicity.de/reverse-engineering-the-kensington-verimark-fingerprint-scanner.html

3. **Synaptics secure sensors run proprietary TLS in practice, SDCP shipped
   disabled.** Blackwing HQ: "SDCP wasn't even enabled on two out of three of the
   devices we targeted." Validity90 confirms TLS-after-key-exchange framing.
   Sources: blackwinghq.com/blog/posts/a-touch-of-pwn-part-i/; github.com/nmikhailov/Validity90

4. **SDCP is device-auth-only, no TPM/host secret → GO *for SDCP devices*.**
   Ephemeral P-256 ECDH + AES256-CBC + HMAC-SHA256 + SP800-108 KDF; host key
   regenerated per connection; "the host does not authenticate to the device."
   Implemented host-side in TenSeventy7 EgisTec fork (`fpi-sdcp-device.c`). Does
   NOT establish 047d:00f2 uses SDCP.
   Sources: github.com/microsoft/SecureDeviceConnectionProtocol (+ wiki);
   github.com/TenSeventy7/libfprint-egismoc-sdcp; github.com/antoskuu/libfprint-egismoc-sdcp-fix

5. **Open path dead-ends; only relinked Windows driver gets close, still fails.**
   Benjamin Berg started SDCP in libfprint (2020-05, #257). Open synaptics.c fails
   secure enroll: `Enrollment failed (104) = BMKT_OUT_OF_MEMORY`. `Popax21/synaTudor`
   relinks the Synaptics WBDI Windows driver → ~90% (pairs, TLS up, reads secure DB)
   but blocked at secure enroll. Built for Synaptics **06cb**, not Kensington **047d**.
   Sources: mail-archive.com/fprint@lists.freedesktop.org/msg01128.html;
   github.com/MarcelineVPQ/elitebook840-fingerprint; github.com/Popax21/synaTudor

## Refuted during verification (do NOT rely on these)

- ✗ "Synaptics custom TLS uses mutual auth; host client key is a readable encrypted
  flash blob." — **0-3**.
- ✗ "Host key derived from BIOS product-name+serial (recoverable) → host side
  impersonable." — **1-2**. (This was the tempting GO shortcut; it did not survive.)
- ✗ "SDCP channel has no TPM binding / per-device host keys, so implementable in
  open software" (as stated for the egismoc-sdcp-fix repo) — **0-3** as phrased.

## Net

Practical **NO-GO** for an open driver. The strict crypto question for 047d:00f2
(SDCP vs proprietary; host-credential-bound or not) is **unresolved by open
sources** — only first-hand RE of this device's Windows driver + live handshake
could settle it, and precedent (synaTudor) shows even that may hit a firmware-side
secure-enroll wall.

## Primary sources

- Microsoft SDCP spec: github.com/microsoft/SecureDeviceConnectionProtocol (+ wiki)
- Blackwing HQ, A Touch of Pwn Part I: blackwinghq.com/blog/posts/a-touch-of-pwn-part-i/
- libfprint supported devices: fprint.freedesktop.org/supported-devices.html
- Benjamin Berg SDCP announce: mail-archive.com/fprint@lists.freedesktop.org/msg01128.html
- Validity90 RE: github.com/nmikhailov/Validity90
- This-device RE: blog.inexplicity.de/reverse-engineering-the-kensington-verimark-fingerprint-scanner.html
- synaTudor (relink Windows driver): github.com/Popax21/synaTudor
- elitebook840 (error 104 dead-end): github.com/MarcelineVPQ/elitebook840-fingerprint
- Community hub / #575: github.com/jedbillyb/linux-fingerprint-drivers
