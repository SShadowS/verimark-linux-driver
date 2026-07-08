# 21 — VeriMark/Tudor command reference (engineering map for the driver)

**Date:** 2026-07-07. Consolidated from Ghidra static RE of `synaWudfBioUsb132.dll`
(raw decompiles in git-ignored `re/ghidra-out/{protocol,transport,usbio}/`). This is
the working reference a driver author builds against; `20-protocol.md` has the
narrative. Clean-room: behavior only, no vendor code.

## Layer cake (call stack, top → wire)

```
CBiometricDevice::On*      (WBF adapter ops: connect/enroll/identify/delete)
  ├─ vfmGetParamBlob(hSensor, paramId, out)     FUN_18001c7c0   (READ  params)
  ├─ vfmSetParamBlob(hSensor, paramId, in)      FUN_18001cc30   (WRITE params)
  └─ vfmSecureBioConnect(hSensor, out, hdr16)   FUN_18001e650   (action 0x1d, cmd 0xb0)
        → niseCore singleton  @ global 0x18013df40 (dispatch table at +0x20)
             slot +0x50 = tudorGetParameterBlob  @ 0x180057cb0
             slot +0xa8 = FUN_180055550
        → ssiTls* TLS-1.2 record layer  (wrap/unwrap)
        → pal USB transport (multi-mode: WinUsb bulk / HID / IOCTL)
```

## Crypto / secure channel (byte-level; from `10` + `20`)

- **Handshake** (`ssiTlsEstablish`, state @ `hSsiTls+0xab`): 2-RTT, **server-auth
  TLS 1.2, no client cert**. ClientHello → ServerHello+Certificate+ServerKeyExchange
  → ClientKeyExchange+CCS+Finished → server Finished. Cipher: `tlsSecurityTypeEcc`
  (ECDHE + ECDSA server cert) or `tlsSecurityTypePsk`.
- **Server cert chain** roots in *Microsoft ECC Devices Root CA 2017* (host verifies).
- **Master secret = 48 B** (`ssiTlsDataSet` tag `0x3d`, session/PSK cache).
- **App-data record**: `17 03 03 ‖ len16 ‖ IV[16] ‖ AES-CBC(cmd) ‖ HMAC-SHA256[32]`
  — `ssiTlsWrap` overhead exactly `0x45` (69 B). Gated on TLS-done (`+0x558==7`).
  **⚠ CORRECTED by live capture (`22-live-secure-channel.md`): the channel is actually
  AES-256-GCM (AEAD, nonce+16-B tag), NOT AES-CBC+HMAC — no records are block-aligned
  and `pbIV` is null. Treat the CBC framing here as superseded.**
- Primitives: CNG `bcrypt` ECDH(P-256)/ECDSA/AES + `crypt32` (DPAPI at rest). **No
  ncrypt/TPM.** Host keypair ephemeral, self-generated (`tudorSecurityGenHostKeyPair`).

## USB transport (pal layer)

Device 047d:00f2 iface1 declares only **EP 0x83 interrupt-IN (8 B)**; iface0 = HID
(interrupt EP 0x01/0x81, 60 B). The pal layer is multi-mode (generic across Synaptics
sensors) — the runtime path for 047d is **not yet pinned** (needs init-trace):

| Function | Role |
|---|---|
| `palWinUsbDeviceHandleOpen` @0x180044930 | open WinUsb handle |
| `palWinUsbBulkWrite` @0x180045e00 | WinUsb WritePipe (vtable@`sensorObj+0xb0`: +0x20 QueryPipe, +0x38 WritePipe) |
| `palWinUsbBulkRead` @0x180045b40 | WinUsb ReadPipe |
| `palWinHidOpen` (via `palUsbDriverIoControl` case 1) | **HID-report** path |
| `palUsbDriverIoControl` @0x1800437c0 | IOCTL dispatch (case0→FUN_180047e80, case1→HID open, …) |

**Transport selection RESOLVED** (`palUsbDriverOpen` → `palWinUsbQueryInterface`):
the driver reads registry `SOFTWARE\Syna\useWbf` (mode `1` default / `3` if set),
then **opens a WinUsb interface on iface1** (`palWinUsbQueryInterfaceExternal` +
`palWinUsbDeviceHandleOpen`) and **spawns a device-event thread** (`FUN_180048f20`
running `FUN_180046f40`) that reads the **interrupt-IN EP 0x83**. The `useWbf` flag
just toggles a WinUsb mode variant — the HID path (`palWinHidOpen`) is for other
sensor models, **not** 047d. Since 047d has no bulk pipe, command OUT rides WinUsb
control transfers; responses/events arrive on the EP-0x83 interrupt reader.

→ **libfprint/libusb mapping:** claim iface1 (detach kernel driver), send commands
as USB control transfers, run an interrupt-IN transfer loop on EP `0x83` for
events/responses, wrap/unwrap the TLS records in between. This is the driver's USB
skeleton.

## Command dispatch tables

### `vfmGetParamBlob` paramId → handler  (FUN_18001c7c0)
| paramId | handler | note |
|---|---|---|
| `0x67` | tudorGetParameterBlob sub 1 → `FUN_180058910` | 18 B = 9×u16 **cached** sensor props (obj +0x6f..+0x7f) |
| `0x69` | `palSecureWrap` | secure-wrap a blob (PSK) |
| `0x6b` | sub 9 → `FUN_18005c1f0` | (decompile pending) |
| `0x6c` | sub 10 | **pairing data read** |
| `0xc9/0xca/0xcb` | `FUN_18001d9d0`(4/6/7) | matcher params |

`tudorGetParameterBlob` (GET) implements subs **1, 8, 9** (others → `0x71` not-impl);
sub 8 returns a cached blob from `sensorObj+0x100`(len)/`+0x108`(ptr). Most GETs are
**cached-property reads**, not live commands.

### `vfmSetParamBlob` paramId ranges → target  (FUN_18001cc30)
| range | target object | e.g. |
|---|---|---|
| `1..99` | sensor handle (`*plVar1`) | sensor config |
| `101..199` | **matcher/engine** (`plVar1[4]` / `plVar1[2]+0xc0`) | `0x6c` pairing-commit |
| `201..299` | third object | |

### `vfmSecureBioConnect` (FUN_18001e650)
16-byte header, byte0 = cmd (`0xb0` = attestation/secure-connect); niseCore action
`0x1d`. `OnConnectSecure` parses the `0x1372`-byte response into records of
**65 B (P-256 points), 32 B (hashes), 64 B (ECDSA sigs)**.

## Sensor-object field offsets discovered (for struct reconstruction)
`+0x6f..0x7f` 9×u16 sensor props · `+0x100/0x108` cached-blob len/ptr ·
`+0xab` TLS state · `+0xac/0xaf` ECDH key contexts · `+0xb0` WinUsb iface vtable ·
`+0x134` TLS out len · `+0x138`(=`+0x27` as longlong[]) TLS out buf · `+0x394`
registry pairing-blob path · `+0x540` TLS out ptr · `+0x550/0x558` TLS flags ·
`+0x55c` TLS status.

## MASTER IOCTL → handler table (complete command surface)

The driver's SSI IOCTL dispatch is `FUN_1800074c0` (synaWudfBioUsb132.dll) — it switches
the IOCTL code to a `CBiometricDevice::On*` handler (which then drives VFM/matcher →
TLS → USB). This is the **entire command surface** (~31 commands):

| IOCTL | Handler | Operation |
|---|---|---|
| `0x440004` | OnGetAttributes | sensor attributes/caps |
| `0x440008` | OnReset | reset sensor |
| `0x44000c` | OnCalibrate | calibrate |
| `0x440010` | OnGetSensorStatus | sensor status |
| `0x440014` | OnCaptureData | **capture image/sample** |
| `0x440018` | OnUpdateFirmware | firmware update |
| `0x44001c` | OnGetSupportedAlgorithms | algorithms |
| `0x440020` / `0x440024` | OnGetIndicator / OnSetIndicator | LED get/set |
| `0x44002c` | OnConnectSecure | **TLS secure connect** |
| `0x440034` | OnNotifyWake | **wake-on-finger** |
| `0x44200c` | OnEnrollmentCreate | **begin enroll** |
| `0x442010` | OnEnrollmentUpdate | **add enroll sample** |
| `0x442014` | OnEnrollmentCheckForDuplicate | dup check |
| `0x442018` | OnEnrollmentCommit | **commit/store template** |
| `0x44201c` | OnEnrollmentDiscard | discard enroll |
| `0x442020` | OnDiscardSMIData | discard SMI data |
| `0x442028` | OnEraseDatabase | **wipe all templates** |
| `0x44202c` | OnGetDatabaseAllRecordsCount | template count |
| `0x442030` | OnStorageQuery | query records |
| `0x442034` | OnDeleteFinger | **delete template** |
| `0x442038` / `0x44203c` | OnGetCommonData / OnSetCommonData | common data blob |
| `0x442040` | OnResetOwnership | **unpair / reset ownership** |
| `0x442044` | OnSetLEDState | LED state |
| `0x442048` | OnSapRequest | SAP (secure-app protocol) |
| `0x442050` / `0x442054` | OnGetTemplate / OnSetTemplateList | template get/set |
| `0x442058` | OnControlUnit | **identify / match** (IdentifyFeatureSet) |
| `0x442064` | OnGetIsNonEnrollCommmitProcess | commit-mode query |
| `0x442080` | OnSetBiotestRunningState | test mode |

Each `On*` handler is in `re/ghidra-out/{protocol,moc}/`; the translation to Tudor
USB/TLS commands is the layer-cake above. This closes the chain
**WBF op → IOCTL → On* handler → VFM/matcher → niseCore/tudorGetParameterBlob → ssiTls → WinUsb**.

## MOC IOCTL command set (adapter → driver boundary) — the operational protocol

From `synaFpAdapter132.dll` (WBF engine/sensor adapter; raw decompiles in
`re/ghidra-out/adapter/`). Each WBF operation drives the driver via `DeviceIoControl`
with an **SSI IOCTL code** (async, `OVERLAPPED`); the driver translates each into the
Tudor USB/TLS commands mapped above. IOCTL = `CTL_CODE(dev=0x44, func, METHOD_BUFFERED,
FILE_ANY_ACCESS)`; `0x440xxx` = **sensor** ops, `0x442xxx` = **engine/matcher** ops.

| IOCTL | Operation | in | out |
|---|---|---|---|
| `0x440008` | Sensor **Reset** | 0 | 8 |
| `0x440010` | Sensor **QueryStatus** | 0 | 0x14 (20) |
| `0x44002c` | Sensor **ConnectSecure** (TLS handshake ↔ `ssiTlsEstablish`) | var | var |
| `0x440014` | **StartCapture** | 0x20 (32) | var (`ctx+0x48`) |
| `0x440030` | **StartCaptureEx** | var | var |
| `0x440034` | **StartNotifyWake** (finger-on-wake arm) | 0 | 0xc (12) |
| `0x44200c` | **CreateEnrollment** (begin) | 8 | 0x28 (40) |
| `0x442010` | **UpdateEnrollment** (add sample) | 0 | 0x48 (72) |
| `0x442014` | **CheckForDuplicate** | 0 | 0x50 (80) |
| `0x44201c` | **DiscardEnrollment** | 0 | 0 |
| `0x44202c` | query **enrollment count** (>9 ⇒ DB full) | 0 | 8 |
| `0x442018` | Storage **AddRecord** (store template, on Commit) | var | — |
| `0x442028` | Storage **EraseDatabase** (wipe all) | 0 | — |
| `0x442034` | Storage **DeleteRecord** | var | — |
| `0x442064` | Storage DeleteRecord (secondary/confirm) | var | — |
| `0x442058` | **IdentifyFeatureSet** | 0x1088 (4232) | 0x18ac (6316) |
| `0x442080` | **Attach** (engine bind) | 1 | 0 |

Storage/template-DB layer (`StorageAdapter*`) also exposes: OpenDatabase, CreateDatabase,
EraseDatabase, AddRecord, DeleteRecord, First/Next/GetCurrentRecord, GetRecordCount,
GetDatabaseSize (`0x44202c`), QueryByContent/BySubject — the on-sensor template store.

**WINBIO status codes** (from `local[0] = 0x8009…`): `0x80098008` = enroll **needs more
samples / continue**; `0x80098018` = **DB full** (>9 templates); `0x8009800f` = enroll
error; `0x80070000|err` = wrapped Win32.

### Operation state machines (from the EngineAdapter/SensorAdapter flows)
- **Open:** `Attach(0x442080)` → `ConnectSecure(0x44002c)` (TLS) → `QueryStatus(0x440010)`.
- **Enroll:** `query count(0x44202c)` → `CreateEnrollment(0x44200c)` → loop{
  `StartCapture(0x440014)` → `UpdateEnrollment(0x442010)` while resp==`0x80098008` } →
  `CheckForDuplicate(0x442014)` → CommitEnrollment (commit IOCTL — decompile pending).
- **Verify/Identify:** `StartCapture` → `IdentifyFeatureSet(0x442058)` /
  `VerifyFeatureSet` (large in/out = the encrypted feature blob + match result).
- **Wake-on-finger:** `StartNotifyWake(0x440034)` → interrupt-IN event on EP 0x83.

→ **This is the driver's operation layer.** A libfprint driver implements the same
sequences; each IOCTL corresponds to a Tudor command the driver-DLL side (mapped
above) sends over the TLS channel. Remaining: the exact **in/out buffer struct
layouts** per IOCTL (each is a `DumpByAddress` + read in the driver's IOCTL dispatch),
CommitEnrollment/Identify/Delete IOCTLs, and matching to libfprint `synaptics`.

## Buffer struct layouts (static extraction — the meaningful ones)

From the adapter/handler parsing. Encrypted feature-set/template blobs are opaque
(ciphertext/on-chip; see ceiling note) — these are the *interpretable* structs:

**`UpdateEnrollment` (`0x442010`) output — 72 B (enroll progress):**
```
+0x00  u32  status        (0x80098008 = need more samples; 0 = sample accepted)
+0x04  u32  remaining/len  (high dword of the first qword; sample data length)
+0x08  …    (feature/sample data, ~32 B, opaque)
+0x28  u32  sub-status     (→ ctx+0x64)
+0x2c  u32  region code    (finger-coverage bitmask: 1/2/4/8/0x10)
+0x30  …    (remainder)
```
Driver keeps per-region remaining-sample counters at ctx `+0x70/+0x74/+0x78/+0x7c/
+0x80` and decrements by the returned region code → **guided-enroll progress**
(maps to libfprint `fpi_device_enroll_progress`). Loop continues while `0x80098008`.

**`CreateEnrollment` (`0x44200c`):** in = 8 B (`byte0` = a mode flag from a
feature check), out = 40 B (ack; driver sets ctx+0x60 = `0x90001` = enroll session id).
Preceded by `query count` (`0x44202c`, out 8 B; `>9` ⇒ DB full `0x80098018`).

**`GetSensorStatus` (`0x440010`):** out = 20 B sensor-status struct.
**`CaptureData`/StartCapture (`0x440014`):** in = 32 B capture-params struct.
**`IdentifyFeatureSet` (`0x442058`):** in 4232 B / out 6316 B — **opaque** (encrypted
feature set in, match result + template out).

## Static-research ceiling (what cannot be finished without a live capture)

The following are **encrypted / on-chip opaque blobs** — their internal byte layout is
not recoverable from the binary and needs a working-session capture (Windows USBPcap +
Frida key-dump, `plan.md` §1–§3):
- enrolled **template** payloads (stored on-sensor; `GetTemplate`/`SetTemplateList`),
- **feature-set** blobs (`IdentifyFeatureSet` in/out),
- the post-handshake **encrypted command bodies** on the wire (AES-CBC ciphertext),
- the exact `DAT_180142130` 420-B pairing EC struct interior (constant, dumpable from
  `re/` if needed, but semantics need the handshake trace).

Everything else — transport, handshake shape, record framing, command surface,
operation state machines, and the interpretable status/progress structs — is **done
statically**. The static research is closed here.

## Remaining decompile targets (prioritized, for full wire byte-map)
1. ~~**Transport selection**~~ ✅ DONE — WinUsb on iface1 + interrupt-IN(0x83) event
   thread, `useWbf` registry flag (see "USB transport" above).
2. **Pairing** — *structure mapped* (`tudorSecurityDoPair` @ see `re/ghidra-out/
   pairing/`): TagVal container → load **hardcoded 420-byte (`0x1a4`) EC-param blob
   `DAT_180142130`** → `palCryptEccEllipticCurveSet` (**P-256**) → gen host keypair →
   **basic**: `tudorSecurityGetSSPubKey` (sensor pubkey + ECDH, **host anonymous**)
   / **advanced**: `FUN_18006b710` (heavier — CHECK if it adds host attestation) →
   `palTagValGetContainerDataAsBlob` → pairing blob (host store + sensor write).
   *Still to byte-map:* the `DAT_180142130` 420-B struct layout, `GetSSPubKey`
   request/response, `FUN_18006b710` advanced path, `palSecureWrap` (PSK).
3. **`0xb0` attestation** request/response struct (`vfmSecureBioConnect` internals).
4. **MOC ops** — *architecture mapped* (`re/ghidra-out/moc/`). The driver's
   `OnEnrollmentCreate/Commit`, `OnIdentify*`, `OnDeleteFinger` are **WBF glue**:
   extract params (enroll = `identity[8]` + `param[0x28]`; delete magic `0x25066282`,
   resp codes `0x74/0x76/0x73`), manage power/session, then **delegate via C++ virtual
   dispatch to the engine object at `this+0x428`**. The sensor commands ride a
   **second vtable-dispatched engine, the "matcher"**, exactly paralleling the sensor
   niseCore:
   ```
   matcher accessor FUN_18001d290  → matcher core FUN_180078700 (global 0x180146240, vtable +0x20)
     build slot +0x28 = FUN_180078fb0(matcher, subId, out)   ← MOC command builder
        subId 3/4/5/6/7 …  (5 = 0x34-byte struct via FUN_180079f70)
        [matcher GET paramIds 0xc9/0xca/0xcb = subId 4/6/7; SET range 101-199]
   ```
   *Still to do:* byte-map each matcher subId builder (`FUN_180078fb0` cases + the SET
   builders) **and import `synaFpAdapter132.dll`** (the engine adapter) for the
   enroll/identify **operation state machine** (the sequence of matcher commands).
   Compare opcodes vs libfprint `synaptics` (`plan.md` §2).
5. **ClientHello** cipher-suite list (the niseTlsLib handshake builder).
6. **niseTlsLib** engine (name-collision in auto-namer — resolve the distinct funcs).

Each is a `DumpByAddress`/`DumpStringXref` run + read; mechanical but large. The one
gap static RE can't fill = a **working-session capture** (Windows USBPcap + Frida) to
validate framing and dump live keys.
