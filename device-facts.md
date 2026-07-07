# Device facts — Kensington VeriMark Desktop

All values captured live from this machine on 2026-07-07. Raw dumps in
`reference/`. Regenerate with `./dump-device-info.sh`.

## Identity

| Field | Value |
|---|---|
| USB VID:PID | `047d:00f2` |
| Vendor | Kensington (`047d`) |
| Product string | `VeriMark DT Fingerprint Key` |
| bcdDevice | `0.00` |
| Underlying sensor | **Synaptics** match-on-chip (per prior-art RE; not exposed in descriptors) |
| Kernel binding | `hid-generic` (iface 0 → `hidraw`, e.g. `/dev/hidraw7`) |
| Enumerated at (this box) | bus 3, path `3-3.4.1.1` (`00:14.0` integrated xHCI), USB 2.0 |

## Interfaces & endpoints

`bNumInterfaces = 2`.

### Interface 0 — FIDO / U2F (HID)
- `bInterfaceClass = 3` (HID)
- Endpoints: `0x01 OUT` + `0x81 IN`, both **Interrupt**, `wMaxPacketSize = 60`, `bInterval = 4`.
- HID report descriptor (47 bytes, decoded):
  ```
  06 D0 F1   Usage Page (0xF1D0 = FIDO Alliance)
  09 01      Usage (0x01, U2F Authenticator Device)
  A1 01      Collection (Application)
  09 20  15 00  26 FF 00  75 08  95 40  81 02   Input  (Data), 64 bytes
  09 21  15 00  26 FF 00  75 08  95 40  91 02   Output (Data), 64 bytes
  09 07  15 00  26 FF 00  75 08  95 08  B1 02   Feature(Data),  8 bytes
  C0         End Collection
  ```
  → This is the **standard CTAPHID** transport (FIDO). Confirmed via `fido2-token`:
  `caps: 0x00 (nowink, nocbor, msg)` = **U2F/CTAP1 only, no CBOR/CTAP2**.
  Consequence: **no CTAP 2.1 `authenticatorBioEnrollment`** — the fingerprint
  cannot be enrolled/managed through standard FIDO tooling. Dead end for the
  fingerprint goal (but fine as a plain U2F 2FA key).

### Interface 1 — Vendor-specific (THE TARGET)
- `bInterfaceClass = 255` (`0xFF`, vendor-specific), `bInterfaceSubClass = 0`, `bInterfaceProtocol = 0`.
- Endpoint: `0x83 IN` only, **Interrupt**, `wMaxPacketSize = 8`.
  - Note: only an 8-byte interrupt-IN is *declared*. The bulk of the biometric
    traffic in the prior-art capture appears to move via control transfers and/or
    the HID reports; confirm the real data path from your own usbmon capture.
- This is the **Windows Hello / Windows Biometric Framework** channel to the
  Synaptics MOC sensor. Payloads observed as **TLS records** (`17 03 03 LL LL …`
  = TLS 1.2 *Application Data*). Encrypted end to end.

## What "match-on-chip" means for the driver

- The host **never** receives raw images or templates. Enrollment and matching
  run on the sensor. The host driver only orchestrates a state machine:
  `open / init → enroll (N captures) → identify → list / delete templates → close`,
  shuttling opaque (here: TLS-encrypted) blobs.
- Good news: no image-reconstruction or matching math to write.
- Bad news: the orchestration is inside a TLS session you must first be able to
  establish *as an authenticated peer*.

## Reference files

| File | Contents |
|---|---|
| `reference/lsusb-verbose.txt` | Full `lsusb -v -d 047d:00f2` |
| `reference/hid-report-descriptor.txt` | Decoded HID rdesc (debugfs) |
| `reference/usbhid-dump.txt` | Raw HID rdesc bytes |
| `reference/fido2-probe.txt` | `fido2-token -L/-I` output + interpretation |
| `reference/sysfs-attrs.txt` | sysfs device attributes |
| `reference/usb-topology.txt` | `lsusb -t` (where it sits in the hub tree) |
