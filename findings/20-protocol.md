# 20 — Tudor protocol map (initial, from Ghidra static RE)

**Date:** 2026-07-07. Source: static decompilation of `synaWudfBioUsb132.dll`
(Ghidra 12.1.2). **Initial pass** — the state machine and transport are mapped;
exact wire byte-layouts of each command are the next layer (see "Next"). Raw
decompiled functions in git-ignored `re/ghidra-out/protocol/`. Method: headless
import → `AutoNameFromStrings` (recovered **319** function names from the driver's
own log strings) → `DumpFunctions` decompiled the pairing/TLS/enroll core.

Clean-room note: this documents *behavior* (opcodes, order, sizes) for an original
driver — no vendor code is copied.

## Transport layers (two command paths seen)

The driver object (`CBiometricDevice`, `this` = `param_1`) issues sensor commands
through two vfunc handles:

- **`this[0xe]`** — the pairing/partition IOCTL channel. Helpers:
  `FUN_18001df30(chan, &state, hdr, &size)` (transactional send/recv),
  `FUN_18001c7c0(chan, cmd, buf)` and `FUN_18001cc30(chan, cmd, buf)`.
  Return code **`0x74`** = "buffer too small, `size` now holds required length"
  → caller `operator_new(size)` and retries (a standard two-call size probe).
- **`this[0x70]`** — the secure/USB command target for large data commands.
  Helper `FUN_18001e650(target, out, hdr, len)`. Used by `OnConnectSecure`.

Both ultimately ride the **`ssiTls`** record layer (below) once a secure session
is up (payloads on the wire are `17 03 03 …`, per `10-crypto-map.md`).

## Command opcodes identified so far

| Opcode | Where | Meaning (inferred) |
|---|---|---|
| `0x6c` | `DoPairing` → `FUN_18001c7c0/cc30(this[0xe], 0x6c, …)` | Commit/set **pairing context** to the sensor |
| `0xb0` | `OnConnectSecure` → `FUN_18001e650(this[0x70], …, hdr{0xb0,len}, …)` | **Secure connect / attestation** — returns the sensor's ECC key material |
| `0x74` | return value, not an opcode | "need bigger buffer; retry with `size`" |

(Enroll/identify/delete opcodes live in `OnEnrollment*` / `OnIdentify*` /
`OnDeleteFinger` — decompiled, not yet byte-mapped. See "Next".)

## Pairing flow — `CBiometricDevice::DoPairing` (@ 0x180003170)

1. Query device props **`PairingInProcess`** / **`PairingContext`** (via the
   CFG-guarded property vfunc). If a context already exists → re-assert it with
   cmd `0x6c` and finish.
2. Otherwise run the pairing transaction loop on `this[0xe]` (`FUN_18001df30`),
   driven by a state byte (`state==3` → issue cmd `0x6c` with the returned
   context; `state==0` → done). Buffers grow via the `0x74` size-probe.
3. On success, store the resulting **pairing blob** (`this[0x9c]=len`,
   `this[0x9d]=ptr`) to the **registry** value at device-object offset `+0x394`
   (`FUN_18000188c` = the `_wrapPairingData`→registry write; matches the
   `SOFTWARE\Syna` host-partition mirror from `10-crypto-map.md`).
4. On failure, bump an **ownership-failure counter** (`this[0x16]`, capped at 5)
   and push `SetOwnershipFailureCount` up to the WBF adapter.

→ Confirms `10`: pairing is host-generated + stored (registry mirror + in-sensor
host partition), **no TPM/Windows sealing**.

## Secure connect / attestation — `CBiometricDevice::OnConnectSecure` (@ 0x1800069e0)

- Sends cmd **`0xb0`** (header `{0xb0, len=0xb0}`, body copied from a 0x90-byte
  struct) on `this[0x70]`; receives into a **`0x1372`-byte** response buffer.
- Parses the response into output records built from repeating blocks of:
  - **`0x41` (65) bytes** ×N → **uncompressed NIST P-256 points** (`04‖X‖Y`),
  - **`0x20` (32) bytes** → hashes / key components,
  - **`0x40` (64) bytes** → **ECDSA signatures**.
- Emits a `0x14`-tagged record set of this material to the WBF engine.

→ This is the **server(device)-authentication payload**: the sensor's ECC public
key(s) + signature(s) that the host verifies. Consistent with the "Microsoft ECC
Devices Root CA 2017" chain in `10`. Host stays anonymous (no host cert sent).

## `ssiTls*` secure-channel layer (decompiled, addresses noted)

`ssiTlsInit` / `ssiTlsEstablish` (@0x18006f670, 2789 B — the handshake) /
`ssiTlsWrap` / `ssiTlsUnwrap` / `ssiTlsDataSet` (send) / `ssiTlsDataGet` (recv) /
`ssiTlsIsInSecureSession` / `ssiTlsGetSessionKeyLength` / `ssiTlsGetSecurityType`
(ECC vs PSK) / `ssiTlsAlertNotify`. This is the TLS-1.2 record engine every
command is wrapped in after `Establish`.

## Enroll / delete (decompiled, byte-map pending)

`OnEnrollmentCreate` → `OnEnrollmentUpdate` (per-capture) →
`OnEnrollmentCheckForDuplicate` → `OnEnrollmentCommit` / `OnEnrollmentDiscard`;
`OnDeleteFinger`. These are the MOC enroll state machine; each builds a command
buffer for `this[0xe]`/`this[0x70]` then wraps via `ssiTlsDataSet`.

## UPDATE — wire transport + command layering (deeper pass)

### USB transport (verified live + from code) — **control-out, interrupt-in; NO bulk**

Live `lsusb -v` of 047d:00f2: interface 1 (vendor) declares **exactly one
endpoint — `0x83`, Interrupt-IN, 8 bytes.** No bulk pipe, no OUT pipe. The driver's
low-level layer references `WinUsb_ReadPipe`/`WinUsb_WritePipe` + an interrupt-EP
reader (`VCSDRV_IOCTL_INTERRUPT_DATA_GET`) — that core is generic across sensors,
but **for the VeriMark, with no bulk/OUT pipe, commands must go out as USB control
transfers (EP0 vendor requests) and responses arrive on the 8-byte interrupt-IN**
(+ control-IN reads for larger data). This confirms `device-facts.md` and the
prior-art's "vendor control messages," and tells a native driver exactly which USB
primitives to use (libusb control + interrupt transfers, TLS records chunked across
them).

### Command layering (mapped) — driver → VFM → niseCore → TLS → USB

The "opcodes" seen at the driver level are **not** raw wire bytes; they index a
layered VFM (nise-core) interface:

1. **Driver** (`CBiometricDevice::On*`) calls two VFM entry points:
   - `vfmGetParamBlob(hSensor, paramId, outBlob)` = `FUN_18001c7c0`. Dispatch by
     **paramId**: `0x67`→sub 1, **`0x69`→`palSecureWrap`**, `0x6b`→sub 9,
     **`0x6c`→sub 10 (pairing)**, `0xc9/0xca/0xcb`→sub 4/6/7. Two-call size probe
     via return `0x74`.
   - `vfmSecureBioConnect(hSensor, out, hdr16, len)` = `FUN_18001e650`. Copies a
     **16-byte header** (byte0 = command, e.g. `0xb0`) and invokes niseCore
     **action `0x1d`**.
2. **niseCore object** — obtained from the singleton `FUN_180055200()` (+0x20 =
   its vtable). `getParameterBlob` (`FUN_18001d850`) calls vtable **`+0x50`** (build
   blob → length), **`+0xa8`** (finalize), and secure-connect uses vtable **`+0xc0`**.
   **The actual Tudor command bytes are constructed inside these niseCore vtable
   methods.**
3. **niseCore → `ssiTls*`** wraps each command as a TLS-1.2 record, then hands it
   to the USB layer (control-out / interrupt-in).

### Strategic implication
The wire byte-layout lives **inside the niseCore's vtable-dispatched methods** —
many functions, resolved through C++ vtables/RTTI. Fully byte-mapping every command
is a **large** effort (this is precisely why `synaTudor` *relinks* the DLL rather
than reimplementing). A native driver is still feasible (transport + crypto are now
known), but the command-serialization is the deep part; the issue-#51 pcap is the
fastest way to get concrete packet bytes to anchor the niseCore RE.

### IDs/codes catalogued so far
`vfmGetParamBlob` paramIds `0x67 0x69 0x6b 0x6c 0xc9 0xca 0xcb`; `vfmSecureBioConnect`
action `0x1d`; command byte `0xb0` (attestation); return `0x74` = "buffer too small".

## UPDATE — issue-#51 pcap decoded → **contains no secure-channel traffic**

Pulled `captures/verimark-047d-00f2.pcap.gz` from synaTudor issue #51 and decoded
it with a new dependency-free `tools/parse-usbmon.py` (Linux usbmon/DLT 220 parser
— no tshark/pyshark needed). Result: **it does not contain the Tudor protocol.**

- The VeriMark is **dev23** (device descriptor `12 01 …7d 04 f2 00…` = 047d:00f2;
  config confirms iface0 HID EP `0x01/0x81`, iface1 vendor EP `0x83` 8-byte INT).
- dev23's captured traffic is **only enumeration + the FIDO/U2F HID interface**
  (interrupt EP `0x01/0x81`). **No traffic to vendor EP `0x83`, no vendor-class
  control transfers, no `16 03 03`/`17 03 03` records** → the secure biometric
  channel never established. Matches #51's "all transfers time out, sensor returns
  `0x0` not `WINBIO_SENSOR_READY`."
- The `17 03 03` records that *do* appear are on **dev15**, a Google/Android USB
  tethering adapter (`18d1:4eec`, NCM frames — the phone's HTTPS); dev19 is a
  Genesys card-reader (`05e3:0751`). Both unrelated to the sensor.

**Consequence:** this capture can't anchor the wire protocol. Real Tudor bytes need
a capture of a **working session** — i.e. Windows + the real driver (USBPcap), or a
working Linux driver (chicken-and-egg). So the niseCore static RE has no shortcut
from this pcap; a Windows-side capture (`plan.md` §1–§3) is the way to get ground
truth. (The Frida session-key dump would then also decrypt the `17 03 03` bodies.)

## UPDATE — TLS byte layout + full command-builder stack (niseCore grind)

### The secure channel is textbook server-auth TLS 1.2 (decompiled)

`ssiTlsEstablish` is a **2-round-trip** handshake state machine (state byte at
`hSsiTls+0xab`):

| State | Action | TLS message(s) |
|---|---|---|
| 0 | TlsPrepareValidate | (init) |
| 1 | emit | **ClientHello** (→ sensor) |
| 2 | consume | **ServerHello + Certificate + ServerKeyExchange + ServerHelloDone** |
| 3 | emit | **ClientKeyExchange + ChangeCipherSpec + Finished** |
| 4 | consume | server **ChangeCipherSpec + Finished** |
| 7 | done | "END TLS", finalize key contexts (`+0xac`, `+0xaf`) |
| 5/6 | Alert / Fail | — |

→ **Server(device)-authenticated, no client Certificate** — decompiled proof of the
GO. Cipher modes `tlsSecurityTypeEcc` (ECDHE + ECDSA server cert) or PSK.

### Session + record framing (concrete bytes)

- **Master secret = 48 bytes** (`ssiTlsDataSet` tag `0x3d` copies `0x30` bytes) —
  standard TLS; this is the session/PSK cache path.
- **App-data record** (`ssiTlsWrap`): overhead is exactly **`0x45` = 69 bytes** over
  the plaintext = TLS header(5) + **IV(16) + AES-CBC(payload) + HMAC-SHA256(32)** +
  padding(≤16). So the wire record is:
  `17 03 03 ‖ len16 ‖ IV[16] ‖ AES‑CBC(cmd) ‖ HMAC‑SHA256[32]`.
  Guarded by TLS-done state (`hSsiTls+0x558 == 7`).

### Full command stack (driver → wire), now resolved

```
CBiometricDevice::On*  (OnConnectSecure / DoPairing / OnEnrollment* / …)
  → vfmGetParamBlob(hSensor, paramId, out)          [FUN_18001c7c0]
       paramId 0x67→sub1  0x69→palSecureWrap  0x6b→sub9  0x6c→sub10(pairing)  0xc9-cb
  → getParameterBlob → niseCore dispatch slot +0x50 [FUN_18001d850]
  → tudorGetParameterBlob(hSensor, subId, out)       [@0x180057cb0]  ← builds the blob
       sub1 → FUN_180058910  → 0x12 (18)-byte blob   (per-subId fixed sizes)
       sub8 → cached blob at sensorObj+0x100/+0x108
       …sub2..0xd each = a dedicated builder
  → ssiTlsWrap  → 17 03 03 record (AES-CBC+HMAC-SHA256)
  → USB: control-transfer OUT (EP0) / interrupt-IN (EP 0x83)
```
(The secure-data path is the twin: `vfmSecureBioConnect` [FUN_18001e650], niseCore
action `0x1d`, 16-byte header with cmd byte `0xb0`.)

niseCore singleton = global `0x18013df40`; dispatch table at `+0x20`
(slot `+0x50 = tudorGetParameterBlob @0x180057cb0`, `+0xa8 = FUN_180055550`).

### What's byte-complete vs still opaque
- **Complete:** USB transport; TLS handshake shape + record framing + cipher
  (AES-CBC/SHA256, 69-B overhead); session master-secret size; the full call stack;
  paramId→subId map; one blob size (sub1 = 18 B).
- **Still opaque (needs per-builder decompile):** the exact byte layout of each
  sub-command blob (`FUN_180058910` & siblings for sub2..0xd, the pairing sub10,
  the `0xb0` attestation request/response structs) and the ClientHello cipher-suite
  list. Each is one more `DumpByAddress` + read — mechanical but many functions.
- **Unobtainable statically:** live session keys / a working-session capture (need
  Windows USBPcap + Frida, per the pcap UPDATE above).

## Next (to finish the wire protocol)

1. Decompile the transport builders `FUN_18001df30` / `FUN_18001c7c0` /
   `FUN_18001e650` → exact **command header layout** (opcode, length, seq, flags).
2. Byte-map each `OnEnrollment*` / `OnIdentify*` / `OnDeleteFinger` command +
   response.
3. Cross-check opcodes against libfprint's `synaptics` driver (`plan.md` §2) — how
   much of the MOC command set is already upstream.
4. Validate framing against the issue-#51 `verimark-047d-00f2.pcap.gz`.
5. (Parallel, for the UMDF1-host path) map the driver's `QueryInterface` IID sites
   → `findings/60-umdf1-interface-map.md`.
