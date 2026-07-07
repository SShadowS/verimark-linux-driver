# VeriMark Desktop — Linux fingerprint driver project

![license](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue)
![platform](https://img.shields.io/badge/platform-Linux%20%C2%B7%20libfprint-informational)
![device](https://img.shields.io/badge/USB-047d%3A00f2-orange)
![status](https://img.shields.io/badge/status-GO%20%E2%80%94%20RE%20mapped%2C%20skeleton%20drafted-brightgreen)
![next](https://img.shields.io/badge/next-Windows%20capture%20phase-yellow)

Making the **Kensington VeriMark Desktop (`047d:00f2`)** — a Synaptics match-on-chip
fingerprint reader — usable on Linux via a clean-room **`libfprint`** driver.

## Status

The reverse-engineering is **done to the static ceiling**, and the project's
go/no-go gate is **GO** (proven from decompiled code): the sensor's secure channel
is **server-authenticated TLS 1.2 with no client cert and no TPM binding**, so it's
impersonable from a stock Linux host. See **[`findings/DECISION.md`](findings/DECISION.md)**.

| Area | State |
|---|---|
| GO/NO-GO verdict | ✅ **GO** — server-auth TLS, host-anonymous ECDH pairing, no TPM |
| Protocol map | ✅ transport, TLS framing, pairing, full ~31-command surface, operation state machines — **[`findings/21-command-reference.md`](findings/21-command-reference.md)** |
| Driver | 🟨 **skeleton** drafted (`FpDeviceClass` + operation SSMs) — **[`driver/`](driver/)** |
| Remaining | ⏳ encrypted command bodies + exact handshake bytes — need a **Windows working-session capture** (USBPcap + Frida), then fill the `driver/`'s `TODO(capture)` gaps |

## Clone

```sh
git clone https://github.com/SShadowS/verimark-linux-driver.git
cd verimark-linux-driver
```

Cross-machine (dual-boot) workflow: reverse-engineering and the driver are edited on
**Linux**; the capture phase runs on **Windows** (the dongle enrolls under the
vendor driver there). Clone on both, `git pull`/`push` to sync. Note: the
proprietary vendor binaries, Ghidra decompiles, and captures are **git-ignored**
(kept local only) — see `.gitignore`.

## The device, precisely characterized

A **FIDO U2F security key + Windows-Hello fingerprint** in one dongle — two USB
interfaces, two different worlds:

| Iface | Class | What it is | Linux status |
|---|---|---|---|
| **0** | HID, usage page `0xF1D0` | **FIDO / U2F** authenticator (CTAPHID) | **Works today** as a U2F key (`pam-u2f`). CTAP1/U2F only — no CTAP2, so the fingerprint is *not* reachable here. |
| **1** | Vendor `0xFF` | **Synaptics "Tudor" match-on-chip** biometric channel | **The target.** Wrapped in server-auth TLS 1.2 (`17 03 03 …`). What the `libfprint` driver speaks. |

## Folder map

```
README.md            ← this file
findings/            ← the reverse-engineering output:
   DECISION.md          GO/NO-GO verdict + evidence
   10-crypto-map.md     secure channel (TLS/ECDH/AES, no TPM)
   20-protocol.md       Tudor protocol (transport, handshake, command stack)
   21-command-reference.md   ⭐ driver-facing reference: full command surface + state machines
   00/30/40/50, research-summary.md   inventory, synaTudor, UMDF1-host scope, ghidra scope
driver/              ← clean-room libfprint driver SKELETON (verimark.c/.h, verimark-tls.h)
tools/               ← RE toolbox: device probe, usbmon parser, TLS decoder,
                       Frida hook (Windows), Ghidra headless + scripts
device-facts.md · prior-art.md · plan.md · sources.md · RESEARCH-PROMPT.md   ← docs
reference/           ← live device dumps (lsusb -v, HID rdesc, fido probe, sysfs)
dump-device-info.sh  ← regenerate reference/ snapshots
```

## Next step (the Windows capture phase)

The only thing between the skeleton and a working driver is a capture of a real
session to fill the encrypted gaps. Per `plan.md` §3: on Windows, run
**USBPcap + `tools/frida-hook-cng.js`** during enroll/verify to dump the session
key + wire bytes, then decrypt and fill the `driver/`'s `TODO(capture)` markers
(`driver/README.md` lists exactly which capture closes which gap). No further static
RE is needed — see `findings/21` "Static-research ceiling".

## Don't need a driver, just auth?

Interface 0 already works as a **U2F/WebAuthn** key (`pamu2fcfg` + `pam-u2f`), and
the laptop's built-in Synaptics reader (`06cb:0126`) works with `fprintd` today.
See `plan.md` §0.
