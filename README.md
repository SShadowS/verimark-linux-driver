# VeriMark Desktop — Linux fingerprint driver project

Goal: make the **Kensington VeriMark Desktop (`047d:00f2`)** usable as a normal
Linux fingerprint reader (enroll/verify through `fprintd` + PAM), by writing a
`libfprint` driver for it. This folder is the starting point: every fact, dump,
and source gathered so far, plus an honest RE plan.

> **Read `plan.md` before spending money on time.** The device gates its
> biometric channel behind a **TLS-encrypted secure channel**, and one prior
> effort on this exact device stalled there. This is a hard RE project with a
> real chance of being infeasible without extracting a key from the Windows
> driver or firmware. This folder is written so you go in with eyes open.

## The device, precisely characterized (2026-07-07)

It's a **FIDO U2F security key + Windows-Hello fingerprint** in one dongle. Two
USB interfaces, two totally different worlds:

| Iface | Class | What it is | Linux status |
|---|---|---|---|
| **0** | HID, usage page `0xF1D0` | **FIDO / U2F** authenticator (CTAPHID: 64B in/out reports) | **Works today** as a U2F key. But `caps=nocbor` → CTAP1/U2F **only**, no FIDO2/CTAP2, so **no** standard `authenticatorBioEnrollment`. The fingerprint is *not* reachable here. |
| **1** | Vendor-specific `0xFF` | **Synaptics match-on-chip biometric** channel (Windows Hello / WBF) | **The target.** Opaque, and wrapped in **TLS** (`17 03 03 …` app-data records). This is what a `libfprint` driver must speak. |

So the driver problem = **reverse-engineer interface 1's encrypted vendor
protocol** and reimplement it. Interface 0 is a red herring for the fingerprint
goal (though it means the dongle is already useful as a WebAuthn 2FA key via
`libfido2`/`pam-u2f` — see `plan.md` §"If you just want auth, not a driver").

## Why it's hard (the one-paragraph version)

The fingerprint sensor is a Synaptics **match-on-chip** unit: templates never
leave the chip, and host↔sensor traffic runs inside a **TLS session** (this is
what modern secure fingerprint stacks — Synaptics SDCP, Windows "Enhanced Sign-in
Security" — do on purpose). You cannot learn the plaintext protocol by sniffing
USB, because that's exactly the threat TLS defends against. Progress requires
reversing the **Windows driver binary** to recover the handshake / key material —
and if the sensor authenticates the host with a key held in tamper-resistant
firmware, there may be nothing extractable at all.

## Folder map

```
README.md            ← you are here: goal, device model, honest framing
device-facts.md      ← every hardware fact, both interfaces decoded
prior-art.md         ← the existing RE attempt + community status + protocol background
plan.md              ← concrete RE roadmap, tools, go/no-go gates, libfprint driver anatomy
sources.md           ← annotated links (everything found)
dump-device-info.sh  ← regenerate the reference/ snapshots on demand
reference/           ← live dumps from THIS machine (lsusb -v, HID rdesc, fido probe, sysfs)
captures/            ← (empty) put USB traffic captures here (usbmon .pcapng, etc.)
prototype/           ← (empty) Python/pyusb scratch code goes here before a C driver
```

## Fastest way to learn if this is even possible

The whole project hinges on one question — *can the TLS endpoint be
impersonated from the host, or is the key in firmware?* `plan.md` §1 is a
cheap-ish recon step to answer it before committing to a full driver. Do that
first.
