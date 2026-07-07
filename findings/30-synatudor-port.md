# 30 — Adapting `Popax21/synaTudor` to 047d:00f2 (assessment)

**Date:** 2026-07-07. Clone in git-ignored `re/synaTudor/`. Goal: how far is a
working Linux bring-up of the VeriMark Desktop via synaTudor?

## What synaTudor actually is

Not an open reimplementation — it's a **Windows-driver relinking runtime**:
`libtudor` is a PE loader + WinAPI/WDF/BCrypt shims that load the *real* Synaptics
Windows driver DLL and run it on Linux over libusb. BCrypt ECDH/ECDSA/AES are
re-served via OpenSSL `libcrypto` (which is exactly why the "no TPM" finding in
`10-crypto-map.md` matters — the crypto is emulated host-side, nothing sealed).

Parts: `libtudor` (runtime), `cli` (debug wrapper, takes `-V`/`-P`), `tudor-host`
+ `tudor-host-launcher` (sandboxed host for the libfprint module), `libfprint-tod`
(the actual fprintd-facing driver; `id_table` hardcodes `06cb:00be`).

## Build status on this machine ✅

- Trimmed root `meson.build` to `libtudor` + `cli` (the other subdirs need
  `libfprint-2-tod-1`/`gusb`/`json-glib`/`libseccomp` we don't have). Backup at
  `meson.build.orig`.
- Installed `meson`, `ninja-build`, `innoextract`, `libusb1-devel`.
- **Builds cleanly** on Fedora 44 / gcc 16.1.1. Produces `build/cli/tudor_cli` +
  `build/libtudor/libtudor.so`.
- Stock build auto-downloads Lenovo `r19fp02w.exe` = **v6.0.33.1104, Synaptics
  FingerPrint "FM3463" driver**, and embeds `synaWudfBioUsb104.dll` +
  `synaFpAdapter104.dll` via `ld -r -b binary`. (The `shasum: command not found`
  line just skips the integrity check; extraction still works.)

## Device-matching is trivial; the DLL choice is the real question

- CLI takes `-V 0x047d -P 0x00f2` at runtime — **no recompile** needed to target
  our device. (The libfprint module would need one line added to `tudor_ids[]`.)
- **Which driver DLL to relink is the crux.** Two options:

### Option A — stock Lenovo `104` DLL, pointed at 047d
- Pro: libtudor's shims are written/tested against 104; **build already works**.
- Pro/con: 104 is the **FM3463** sensor driver, not the VeriMark's. The Tudor USB
  transport + secure-channel + MOC command set are *family-common*, so it may well
  drive the 047d sensor; but a version/model mismatch could cause a clean refusal
  (safe) or misbehaviour (risk).

### Option B — our exact `132` VeriMark DLL
- Pro: firmware-matched to 047d:00f2 (`synaWudfBioUsb132.dll` +
  `synaFpAdapter132.dll` are in `re/driver/`). Lowest protocol-mismatch risk.
- Con: **needs ~18 extra Windows shims** that 132 imports but 104 doesn't (static
  import diff): USER32 windowing (`CreateWindowExW`, `GetMessageW`, `DefWindowProcW`,
  `RegisterClassExW`, `TranslateMessage`, `DispatchMessageW`, paint, `*WindowLongPtrW`,
  `PostThreadMessageW`, `CallWindowProcW`, `Destroy/UnregisterClass`),
  WTS session notifications (`WTSRegister/UnRegisterSessionNotification`), power
  notifications (`Register/UnregisterPowerSettingNotification`), `TerminateThread`.
  None are on the enroll/verify path — they're session/power event plumbing — but
  the DLL likely touches them during init, so they'd need at least no-op stubs.
  Also `driver.c`/`meson` reference the `104` filenames+symbols, so swapping means
  renaming our DLLs to the `104` names (keeps the `_binary_..._104_dll` symbols) or
  editing `driver.c`.

## Risk (why this needs explicit user consent before any device run)

`tudor_open()` (called on CLI startup) initializes the driver against the live
sensor, and per the driver strings the host **auto-pairs when it has no pairing
data** — a **write to the sensor's host partition**. Upstream README warns in
capitals about *bricked sensors / corrupted firmware / host-security bypass*.
This is the owner's real hardware. First device contact must be deliberate:
fresh datastore, matched-ish driver, watching logs, ready to stop.

## Recommended sequence

1. **Try Option A first** (stock 104 → `-V 0x047d -P 0x00f2`, fresh datastore):
   cheapest probe. A refusal is a safe, informative outcome; success is a huge win.
2. If 104 refuses/misbehaves, **do Option B**: stub the ~18 shims, embed the 132
   DLLs, rebuild, retry.
3. On a working channel, move to the `libfprint-tod` module (add `047d:00f2` to
   `tudor_ids`, build the tod fork) for real fprintd integration.

## Open risks to confirm on first run
- Does the relinked driver enumerate 047d's endpoints? (iface 1 declares only an
  8-byte interrupt-IN; bulk of traffic is control transfers — the WDF/USB shim must
  handle whatever the DLL requests.)
- Is this specific unit already paired/provisioned (from any prior Windows use)?
- basic vs advanced pairing mode.

---

## UPDATE — Device run #1 result: **UMDF-version blocker** (the 132 path is a dead end via synaTudor)

Built the adapted binary (132 DLLs embedded, 20 shims added, all imports resolved,
DBGIMPORT on) and ran it against the live sensor (`-V0x047d -P0x00f2`, fresh
datastore). It got through PE-load + both DLLs' DllMain, then **aborted at**:

```
[ERR] Couldn't find DLL export 'FxDriverEntryUm'!
```

Root cause (confirmed): **the two drivers use different UMDF generations.**

| | Lenovo `104` (synaTudor's target) | Kensington `132` (VeriMark, exact match) |
|---|---|---|
| INF | — | **`UmdfLibraryVersion=1.11.0`** |
| Framework | **UMDF 2.x** (WDF) | **UMDF 1.x** (COM in-proc server) |
| Entry export | `FxDriverEntryUm` | `DllGetClassObject` (+ 1 more) |
| Model imports | WDF stub, WppRecorder | **`ole32`** (COM) |

synaTudor's runtime (`libtudor/src/winapi/wdf/*`, `FxDriverEntryUm`,
`DRIVER_OBJECT_UM`) is a **UMDF 2.x host**. The 132 driver is **UMDF 1.x** — it
would need a completely different host: `DllGetClassObject` → `IClassFactory` →
the WUDF 1.x COM interfaces (`IDriverEntry`, `IPnpCallback`, `IWDFDevice`, …).
libtudor implements none of that. **Implementing a UMDF 1.x COM host is a larger
project than synaTudor itself** → the exact-match-132-via-synaTudor route is not
viable as-is.

The 20 import shims + `CryptAcquireContextW` remain correct and harmless (kept for
any UMDF2 132-class driver); the blocker is purely the framework generation.

### Revised options
- **A. Lenovo `104` (UMDF2) → 047d sensor** — supported by synaTudor now; tests
  whether the FM3463 driver drives the VeriMark over the common Tudor USB
  protocol. Cheapest (revert the DLL swap, rebuild). Risk: model mismatch could
  refuse (safe) or misbehave. This is the route synaTudor was designed for.
- **B. Find a UMDF2 driver that supports 047d** — newer Synaptics/Kensington
  packages (Windows Update Catalog "Synaptics – Biometric", or a later VeriMark
  release) may have migrated to UMDF2 *and* list 047d. If one exists it slots into
  synaTudor cleanly (exact match **and** compatible framework). No device risk to
  search. Best outcome if it exists.
- **C. Implement UMDF 1.x COM hosting in libtudor** — largest effort; only if A and
  B fail and the goal justifies it.

**Recommendation: B (search, no device risk) → fall back to A (try 104 on the
sensor).**

---

## UPDATE 2 — search result: BOTH fallbacks are already-documented dead ends (synaTudor issue #51)

Searched before touching the sensor. **synaTudor issue #51** (opened 2026-03-18,
still open) is a prior worker doing exactly this on **047d:00f2** and independently
reaching the same wall — and, critically, it also rules out the 104 fallback:

- **DLL 104 (Lenovo FM3463, UMDF2) → 047d: loads/initializes but *all USB
  transfers time out*** — the sensor returns status `0x0` instead of
  `WINBIO_SENSOR_READY`. i.e. the UMDF2 host works, but the FM3463 driver's
  protocol is not what the VeriMark (FS7600) firmware answers. **Option A is a
  known dead end — not worth the brick risk to reproduce.**
- **DLL 132 = "the correct driver for this device", but exports only by ordinal;
  ordinal 1 = `DllGetClassObject` (COM), not `FxDriverEntryUm`** — verbatim
  confirmation of the UMDF1-vs-UMDF2 blocker above.
- Same `LIBUSB_ERROR_BUSY` on `set_configuration` (iface 0 = hid-generic) that we'd
  have hit; they patched it to ignore busy.
- A USB capture `verimark-047d-00f2.pcap.gz` is attached to the issue (useful raw
  protocol data for any future UMDF1 effort). Ref:
  https://github.com/Popax21/synaTudor/issues/51

**Option B result: negative.** No UMDF2 driver for the FS7600/047d sensor appears
to exist — the 132 UMDF1 driver is "the correct" (only) one, and the sole UMDF2
Tudor driver in play (Lenovo 104) times out against this sensor.

### Net conclusion
The only remaining route to a synaTudor-based 047d driver is **Option C: implement
a UMDF 1.x COM host in libtudor** (`DllGetClassObject`→`IClassFactory`→ the WUDF
1.x COM interface set) — a large, standalone piece of work that upstream has not
done. Absent that (or upstream adding it), 047d:00f2 stays unsupported via this
approach.

**What still stands as real progress:** the crypto-binding gate is *passed*
(`DECISION.md` — channel is impersonable, no TPM), synaTudor builds on this box,
and the 132 import surface is fully shimmed — so a UMDF1-host effort would start
from a working relinking runtime, not zero.
