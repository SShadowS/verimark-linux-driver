# 26 — Transport, settled empirically: iface0 is FIDO; biometric = iface1 EP0-control

> **UPDATE 2026-07-08: the blocker below is RESOLVED — see `findings/27`.** The exact
> EP0 command/response encoding (`0x40/0x16` write, `0xc0/0x17` read, 8-byte pad,
> `wValue=len&7`) was recovered from the decompiles and **verified live** (GET_VERSION →
> FW 10.1 PROVISIONED; GET_START_INFO 68 B matching `findings/25`). This file remains the
> record of *how iface0 was ruled out*; `27` is the authoritative transport spec.

**Date:** 2026-07-08. This file **supersedes its own first draft** (which claimed the
command channel was iface0 EP `0x01`/`0x81`). That draft was **WRONG** — caught by a
live probe. The corrected, live-verified transport is below. It matches the original
`RESUME-LINUX.md` brief and `findings/20`. Clean-room: endpoint/behaviour facts only.

## What was tested

`prototype/p0_probe*.py` claimed iface0, wrote a bare command opcode to EP `0x01`, and
read EP `0x81`. It got a 60-byte reply with a `0x0000`-looking prefix — which *looked*
like a Tudor OK, so the first draft concluded "transport = iface0 `0x01`/`0x81`." Decoding
the reply properly refuted that:

```
00 00 00 00 | bf | 00 01 | 0b
  CID = 0     CMD   BCNT     data
```
`0xbf = 0x80|0x3f` = **CTAPHID_ERROR**; data `0x0b` = **ERR_INVALID_CHANNEL** (a message
was sent on channel 0, which isn't allocated). **That is a FIDO/CTAPHID error frame, not
a Tudor response.** iface0 speaks FIDO, and the probe was talking to the U2F stack.

## The corrected, verified transport map

| iface | class | role | endpoints |
|---|---|---|---|
| **0** | HID | **FIDO U2F only** (NOT biometric) | `0x01` int-OUT 60B / `0x81` int-IN 60B |
| **1** | Vendor 255 | **Synaptics biometric / Tudor** | **`0x83` int-IN, 8B — the only endpoint** |

- **iface0 = FIDO, confirmed two ways:** (a) its HID report descriptor is a *single*
  `FIDOAlliance.U2FAuthenticatorDevice` application collection — no Report IDs, no
  Synaptics/vendor collection, no `0xFF00` usage (`reference/hid-report-descriptor.txt`);
  (b) the live CTAPHID error above. `reference/fido2-probe.txt` already flagged this
  (U2F/CTAP1-only; fingerprint "lives only behind vendor interface 1").
- **iface1 = biometric, and it has NO OUT or bulk endpoint** — single config, no alternate
  settings (full `lsusb -v` checked). Its only endpoint is the 8-byte interrupt-IN `0x83`.

## How commands actually move (from the 132 DLL decompiles)

With no OUT endpoint on iface1, the **only** way to send bytes to the sensor is **EP0
vendor control transfers**. The driver confirms this:

- `usbio/palUsbDriverIoControl.c` issues `palUsbDriverCtrlRequest(handle, bmRequestType,
  bRequest, wValue, buf, wLen)` — e.g. device-mgmt `(0x40,0x19,…)` vendor-OUT and
  `(0xc0,0x1a,…)` vendor-IN, and `(0x40,0x1b,…)`. (`0x40` = host→device vendor/device;
  `0xc0` = device→host vendor/device.)
- `FUN_18004ada0.c` resolves **`WinUsb_ControlTransfer`** via `GetProcAddress` — the EP0
  primitive underneath `palUsbDriverCtrlRequest`.
- The `palWinUsbBulkWrite`/`BulkRead` + `palWinHidOpen` functions live in a
  **`transport-select`** module: the driver *chooses* a transport per device. Bulk/HID
  are for **bulk-capable sibling sensors** (e.g. 06cb, which synaTudor targets); the
  047d/FS7600 path with no bulk pipe uses the **control** transport. The first draft
  over-weighted the `WinUsb_WritePipe` code without checking it applies to 047d — it does
  not.

## Still UNKNOWN — and this is what blocks P0 bring-up

The **command-carrying** control request is not yet pinned. Known: the mgmt requests
(`0x19/0x1a/0x1b`). Unknown:
1. The **bRequest (+ wValue/wIndex) that carries a Tudor command buffer** out (and how a
   TLS record / multi-hundred-byte command is chunked across control transfers).
2. Whether **command responses** come back via a **control-IN** read (`0xc0, bRequest=?`)
   or via the **`0x83` interrupt-IN** (8-byte chunks). `0x83` is almost certainly the
   async **event** pipe (2-byte finger/keepalive); responses are more likely control-IN
   (the 8-byte pipe is tiny). Both were *inferences* in `findings/20`, never observed.

`palUsbDriverCtrlRequest`'s body and the niseCore→USB send path were **not** in the dumped
decompile set — pinning them is either a focused Ghidra pass or (faster) reading the USB
**transport layer** of the Windows working-session USBPcap (`win-usb-…hub2.pcap` on the
Windows box), which recorded the real biometric control transfers. The local
`captures/verimark-047d-00f2.pcap` (issue #51) has **no** biometric traffic (`findings/20`),
so it cannot answer this.

## Net

- **Retract** the "iface0 `0x01`/`0x81`" claim. Biometric transport = **iface1, EP0
  vendor control-OUT, responses via control-IN and/or `0x83` events** (original brief).
- FIDO/U2F (iface0) and the biometric channel (iface1) are **independent interfaces** —
  no interface-sharing constraint after all.
- **P0 first-light is blocked** on the exact command-carrying control-request encoding.
  Fastest unblock: re-analyze the Windows `hub2.pcap` at the USB-transport layer (SETUP
  packets — no PII there), or a targeted Ghidra dump of `palUsbDriverCtrlRequest` + the
  send path. `prototype/p0_probe*.py` (iface0/FIDO) are **not** the bring-up path — keep
  only as the record of how iface0 was ruled out.
