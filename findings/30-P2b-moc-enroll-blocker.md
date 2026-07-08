# findings/30 — P2b blocker: MOC enroll/verify gated by a host-authorization precondition

**Date:** 2026-07-08. Live on the Linux box over the P1 TLS session. Enroll (`0x96`) and
identify (`0x99`) are **rejected with status `0x0405`** even though every prerequisite we
can see works. Root cause is a **session/host-authorization precondition** the Windows
driver satisfies at *driver-load init* — which our capture never recorded (it starts at the
enroll action) and which `rev` never implements (rev does host-side matching, not on-chip
MOC). Tool: `prototype/p2_moc.py` (modes `events/probe1/probe2/probe3/diag/enroll/...`).

## What works (verified live)
- TLS session from Linux (loaded P1 `.pdata`), `remote_tls_status`=established.
- Wrapped reads: `0x19`, `0x9e` DB info, `0x9f` obj-list (3 Windows objects), `0x82`
  frame-state, `0x3e` STORAGE_INFO_GET (52 B, partition table readable).
- **Finger events + frame capture fully cracked** (this session's real progress):
  - Interrupt `0x83` delivers finger events directly: byte[0] type (`0x01`=PRESS,
    `0x02`=RELEASE), byte[6] = monotonic seq.
  - `0x86 EVENT_CONFIG` layout: **8 u32 slots (slots 0 & 4 carry the mask) + trailer u32**
    (`0` if mask≠0 else `4`) — NOT rev's "8 identical" assumption. Mask bit = `1<<event_type`.
  - MOC frame-capture choreography: arm `[1,2]`(0x06) → catch PRESS → arm `[24]`
    (`0x01000000`, frame-ready) → `0x80 FRAME_ACQ` (arg `0x14`) → read frame-ready event
    **`0x18`** → `0x81 FRAME_FINISH`. Confirmed: `frame-ready 0x18` fires reliably.

## The blocker (verified, not timing)
- `0x99` dedup/identify → **`0x0405`**, `0x96 01` create → **`0x0405`**, `0x96 02`
  add-sample → **`0x0404`** (2-byte error, not the 82-B progress record).
- **Not a frame/finger-timing issue:** `probe3` calls `0x99` with the finger *held down*,
  both before and after `FRAME_FINISH`, with `0x18` frame-ready confirmed — still `0x0405`.
- **`0x96 01` create needs no frame at all** yet still `0x0405` → pure state/auth gate.
- Windows sent the **byte-identical** create (`96 01000000 00000000 0000`) and got `0000`;
  its `0x99` dedup got `0x0509`. We never see `0x0509` — we get `0x0405`.
- **Smoking gun (`diag`, read-only):** `0x50 GET_CERTIFICATE_EX` → **`0x0401`**. So the
  whole `0x04xx` family (`0x0401` cert, `0x0404`/`0x0405` enroll/identify) is a
  **host-not-authorized** category. Generic reads (`0x3e/0x9e/0x82/0x9f`) are outside it and
  succeed. Ghidra corroborates the *concept*: `moc/FUN_180078fb0` (host synaLib matcher)
  guards ops with `"Invalid state: not in the enroll/authen"`.

## Working hypothesis
Our pairing used `rev`'s `sensor.pair()` = **TLS cert exchange only**. Windows' *original*
first-time provisioning additionally established the host as an **enrollment-authorized
identity** (host storage partition / credential the sensor checks for `0x96`/`0x99`/`0x50`).
That one-time provisioning is **not in any capture** (only the steady-state enroll is) and
**not in `rev`**. So we have a TLS-capable but **not enroll-authorized** host.

## To unblock (options, in rough order)
1. **Fresh Windows capture of driver-LOAD → first enroll of a NEW user** (plug dongle on the
   Windows box, Frida+USBPcap from t=0). This should reveal the init/authorize commands
   (likely around `0x50` GET_CERT_EX, host-partition `0x3e/0x3f/0x41`, or a host-verify) that
   precede the first `0x99`/`0x96`. Requires moving the dongle back to Windows temporarily.
2. **Reverse the provisioning path in Ghidra** — `protocol/CBiometricDevice__DoPairing.c`,
   `tudorHostPartitionFormat.c`, and the `0x50`/`0x3f`/`0x41` command builders — to derive the
   authorization step without a recapture.
3. **Re-pair as a "primary" host** if pairing has a mode flag we set wrong (cert_type: our
   host_cert came back `type=2`; the device cert was `type=0` — worth checking whether an
   enrollment-authorized host needs a different cert type / an extra provisioning cmd).

## Offline RE progress — the provisioning mechanism (Ghidra)
Traced the provisioning path in the dumped driver:
- **`tudorGetHostPartitionInfo`** (`18006db50`): `tudorCmdGetStorageInfo` (`0x3e`) → allocate host
  partition buffer → **read** it (`FUN_18006dad0`) → **`palCryptoDigest` validate** → read a
  **crypto "version tag"** (`FUN_18006e640`); if the tag is missing (returns `0x76`) it
  **creates** one via `palCryptoDigest`. So each host has a *cryptographically-validated host
  partition + version tag* stored in sensor flash.
- **`tudorHostPartitionFormat`** (`18006e8c0`): "update host partition in sensor" → format
  (`FUN_18006dab0`) + **write** (`FUN_18006db10`, "tudorHostPartitionWrite").
- **`CBiometricDevice__DoPairing`**: an **ownership** handshake (`PairingContext`,
  `SetOwnershipFailureCount`, IOCTL `0x6c`) — more than `rev`'s cert-only `pair()`.
- **`CBiometricDevice__OnConnectSecure`**: on secure connect, reads the host partition and
  builds matcher state.
⇒ Strong hypothesis: **MOC enroll is gated on a validated host partition + version tag that
our `rev`-based (cert-only) pairing never wrote.** The exact opcodes (expect STORAGE_PART
`0x3f`/`0x40`/`0x41`) and the version-tag crypto (`palCryptoDigest` — key/alg TBD) are being
dumped from Ghidra (`re/ghidra-out/HOST-PROVISION-TRACE.md`, in progress). **Crux:** whether
the version-tag digest uses only material we hold (host EC priv key + certs) or a secret we
can't derive — that determines if provisioning is reproducible from Linux.

## RESOLVED (diagnosis) — provisioning path fully decoded (Ghidra + live read)
`re/ghidra-out/HOST-PROVISION-TRACE.md` (background agent) + a live read-only partition dump
(`p2_moc.py partinfo`) settled it:
- **Gate:** the sensor treats a host as a *provisioned owner* only if its **host partition
  (STORAGE partition id 2)** in flash holds a valid **type-1 version-tag** entry
  (`data=01 00 00 00`) **and** a **type-2 pairing-data** entry. Missing ⇒ `0x04xx`
  (`0x0405` MOC, `0x0401` cert). Our `rev`-based pairing wrote the TLS certs but **never the
  host partition**.
- **STORAGE opcodes (byte-exact):** `0x3e` INFO (descriptors 12 B: type/flags/…/size); host
  partition = descriptor `type==2`. `0x3f` FORMAT = `[3f][pid]`. `0x40` READ / `0x41` WRITE =
  `[op][pid][flags=0][ffff][offset:u32][length:u32](+data)`. **pid = 2**.
- **Partition = TLV list:** `[type:u16][len:u16][sha256(data):32][data]`, stride `len+0x24`.
  Integrity is **plain unkeyed SHA-256** — no HMAC, no device secret ⇒ **reproducible** from
  what we already hold (pairing blob).
- **SAFETY (live-verified):** as the Linux host, reading pid 2 returns **all `0xff` (empty)** —
  it's **per-host**, so Windows' slot is separate and untouched. `0x3e` shows 3 descriptors
  (type 1/2/3); type-2 host partition capacity **4096**. Writing it can't harm Windows;
  reversible via `0x3f` format.

## Fix (implemented, pending execution): `p2_moc.py provision`
Writes pid-2 = `TLV[ type1=010000 00 , type2=<our pairing blob> ]` via `0x3f` format + `0x41`
write, with an **abort-if-not-empty** guard and read-back verify, then probes `0x50` to see if
the `0x04xx` gate lifted. **Residual uncertainty:** the exact type-2 blob the firmware expects
(Windows uses a Synaptics *TagVal* container; we feed our `rev` `SensorPairingData` bytes) — if
the firmware validates type-2 content (not just presence+SHA), we may need the TagVal format.
Empirical test: provision → `enroll`.

## EMPIRICAL RESULT: partition write did NOT unblock (2026-07-08)
Ran `p2_moc.py provision`: pid-2 was empty; `0x3f` format OK, `0x41` write OK (944 B:
type-1 `01000000` + type-2 = our 868-B `rev` pairing blob), **read-back verified**. But
post-write, `0x96 01`/`0x99 01` still `0x0405` and `0x50` still `0x0401` (`0x9e` still OK).
⇒ **The host partition alone (with our `rev`-format blob) is not sufficient.** The partition
image is left in place (valid TLV, per-host, harmless).

## DEEPER GATE FOUND: pairing is "basic" vs "advanced" — ours is basic
`tudorSecurityDoPair` (`re/ghidra-out/host-provision/tudorSecurityDoPair.c`) branches on the
sensor security flag (`param+0x1c`):
- **basic** → `tudorSecurityGetSSPubKey` (fetch sensor static pubkey). Log *"Pairing in basic
  security mode"*.
- **advanced** → `FUN_18006b710` (fuller handshake). Log *"Pairing in advanced security mode"*.
Then both build the TagVal pairing container (`palTagValGetContainerDataAsBlob`).
**Our device is `advanced_security=True`** ⇒ Windows pairs **advanced**; but `rev`'s `pair()`
(our P1) does the simpler cert exchange (≈basic). ⇒ **Strong new hypothesis: MOC enroll needs
the ADVANCED pairing handshake (`FUN_18006b710`) that our pairing never performed** — and the
type-2 blob must be the real **TagVal container**, not `rev`'s `priv+host_cert+sensor_cert`.

## Remaining work to unblock (deep)
1. Reverse `FUN_18006b710` (advanced pairing handshake) — the exact extra sensor commands.
2. Reverse the **TagVal container** format (`palTagValContainerInit` /
   `palTagValGetContainerDataAsBlob`) for the type-2 blob.
3. Likely re-pair in advanced mode (may need `RESET_OWNERSHIP 0x10` / `TAKE_OWNERSHIP_EX2 0x4f`
   first — more invasive), then write the correct partition.
Alternative: a **Windows driver-load recapture** (t=0 → first enroll of a NEW user) would show
the advanced-pair + provisioning command sequence directly (needs the dongle back on Windows).

## FINAL DIAGNOSIS (Ghidra `ADVANCED-PAIR-TRACE.md`) — corrects the "advanced pairing" guess
- **Our `0x93` pairing already matches Windows.** "advanced" mode (our sensor) is the *simpler*
  `0x93` cert exchange = exactly what `rev`/our P1 sends. `0x93` is **not** the gap. Pairing
  crypto is fully reproducible (ephemeral self-signed host cert, no TPM/fuse). The type-2 blob
  is a plain TagVal TLV, DPAPI-wrapped host-locally (sensor-opaque) — not the gate either.
- **The real enroll gate = the NiseCore matcher-driven OWNERSHIP transaction**
  (`CBiometricDevice::DoPairing` → `FUN_18001df30` loop over `0x6c` PairingContext blobs →
  ownership opcodes **`0x4f` TAKE_OWNERSHIP_EX2 / `0x10` RESET_OWNERSHIP / `0xe` PROVISION**).
  It is emitted **inside NiseCore, not in this DLL**, and **`rev` does not implement it**
  (confirmed: `rev` only sends `0x93`; grep shows no `0x4f/0x10/0xe/0x6c` usage). That is why
  we are TLS-paired but not enroll-authorized (`0x0405`), and why writing our own valid type-2
  partition entry did nothing.
- ⚠ **Ownership is single-owner; the sensor is owned by Windows.** Taking ownership from Linux
  (`0x4f`/`0x10`) will **most likely WIPE the user's Windows fingerprint enrollments**
  (findings/25). The exact ownership opcode layouts are in **neither** the dumped DLL **nor**
  `rev` — obtaining them needs reversing the separate NiseCore engine or a Windows
  *provisioning* capture (itself destructive on Windows).

## Strategic consequence
On-chip **MOC enroll requires a destructive, not-yet-obtainable ownership step**. The
**host-side-matching** architecture (`rev`'s actual design) **sidesteps ownership entirely**:
`FRAME_READ 0x7f` → native `process_frame` → image → match on host (NBIS/libfprint). `rev`
implements it; our device's `product_id=0x41 (PROD_ID5)` is supported by `rev`'s image
converter; and frame capture already works for us. This path needs no ownership and poses no
risk to Windows. ⇒ **Recommend pivoting P2 to host-side matching** (was declined earlier, but
that predated learning MOC needs destructive ownership).

## Not the blocker (ruled out)
Tap timing, finger presence, frame validity, command byte-layout, TLS health, DB access,
host-partition *presence* (written & verified — insufficient alone).
