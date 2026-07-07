# libfprint driver skeleton — Kensington VeriMark Desktop (047d:00f2)

Clean-room libfprint driver **skeleton** for the Synaptics "Tudor" match-on-chip
sensor, built from the reverse-engineering in `../findings/` (chiefly
`21-command-reference.md`). It compiles *structurally* as a libfprint driver and
encodes the full operation flow; the parts that need a live working-session capture
to finalize are marked `TODO(capture)`.

## Files
| File | Role |
|---|---|
| `verimark.h` | USB/transport constants, the command opcode enum (from the IOCTL surface), status/region codes, the `FpiDeviceVerimark` object. |
| `verimark.c` | `FpDeviceClass` + the operation state machines: open / enroll / verify+identify / list / delete / clear. |
| `verimark-tls.h` | Secure-channel API (handshake + record wrap/unwrap). |
| `verimark-tls.c` | *(to add)* OpenSSL-backed impl of the server-auth TLS 1.2 channel. |

## How the skeleton maps to the RE

- **Transport** (`verimark.c` `verimark_cmd`): commands go OUT via EP0 vendor control
  transfers, responses arrive on the **interrupt-IN EP 0x83**; no bulk pipe. Claim
  iface 1. *(findings/21 "USB transport")*
- **Secure channel** (`verimark-tls.*`): 2-RTT server-auth TLS 1.2, record
  `17 03 03 | len | IV[16] | AES-CBC | HMAC-SHA256[32]`, 48-B master secret, no
  client cert / no TPM. *(findings/10, 20)*
- **Command set** (`VerimarkCmd` enum): the ~31 IOCTL→handler opcodes.
  *(findings/21 "MASTER IOCTL → handler table")*
- **State machines** (the `enum *_states`): open = RESET→CONNECT_SECURE→[pair]→
  GET_STATUS; enroll = DB_COUNT→CREATE→{CAPTURE→UPDATE while `0x80098008`}→CHECKDUP→
  COMMIT; verify = CAPTURE→IDENTIFY. *(findings/21 "Operation state machines")*
- **Enroll progress**: `ENROLL_UPDATE` parses the 72-B struct — status `+0x00`,
  finger-region bitmask `+0x2c` (`VMK_REGION_*`) → `fpi_device_enroll_progress`.

## Build (against a libfprint checkout)

Drop this dir in as `libfprint/drivers/verimark/`, add to `libfprint/meson.build`
`drivers` and the udev rule for `047d:00f2`, then:
```sh
meson setup build && ninja -C build
```
`meson.build` here is the per-driver snippet.

## TODO — before it runs (needs a live capture: `plan.md` §1–§3)

Everything below is blocked on a **Windows USBPcap + Frida session-key capture** —
the encrypted command bodies and exact handshake bytes are not statically recoverable
(see findings/21 "Static-research ceiling"):

1. `verimark_cmd`: exact control-transfer SETUP fields (`bRequest`/`wValue`/`wIndex`)
   and the pre-handshake framing.
2. `verimark-tls.c`: the ClientHello cipher-suite list + the handshake record bytes;
   the server-cert chain validation anchor.
3. Pairing (`OPEN_PAIR`): the `tudorSecurityDoPair` command bodies (P-256 host key +
   server-auth ECDH; the 420-B EC-param blob `DAT_180142130` is in the driver DLL).
4. Per-command payload structs: CAPTURE (32-B in), IDENTIFY (opaque 4232/6316),
   COMMIT/DELETE template-id encoding, STORAGE_QUERY record enumeration.
5. Persist/restore `pairing_data` via libfprint storage (host side of the pairing).

## Prerequisites already satisfied (from RE)
GO verdict (server-auth, no TPM); USB transport; command surface; operation
sequencing; enroll-progress semantics; status codes. This is enough scaffolding that
filling the `TODO(capture)` gaps against a real capture is the remaining work — not
more static RE.
