# 50 — Scoping: the Ghidra pass on `synaWudfBioUsb132.dll`

**Date:** 2026-07-07. Plan + effort only — no analysis run yet. This is the shared
next step both remaining paths need (`40-umdf1-host-scope.md` §6): the UMDF1-host
path needs the driver's **COM interface usage**; the native-reimpl path needs the
**Tudor command/protocol builders**. One import + analysis serves both.

---

## 0. Why this binary is unusually tractable

`synaWudfBioUsb132.dll` — PE32+ x64, 1.4 MB, **`.text` ≈ 736 KB** (est. ~2–4k
functions), stripped of a PDB **but heavily self-logging**:

- **122** distinct `CClass::Method` name strings, **503** `tudor*/ssiTls*/pal*/nise*`
  function-name references, plus `funcName | …` log prefixes.
- Each such string is referenced from the function it names, so a **string-xref
  auto-naming** pass recovers symbolic names for a large fraction of `.text`
  essentially for free. This turns a blind RE into a mostly-labelled one.
- The method names already expose the state machine to target:
  `DoPairing` / `DoUnpairing` / `attemptUnpairAndPairSensor`,
  `OnConnectSecure`, `OnEnrollmentCreate/Commit/CheckForDuplicate`,
  `OnDeleteFinger`, `OnIdentify*`, `OnControlUnit`, `CaptureImage`,
  plus the `tudorSecurity*` / `ssiTls*` / `tudorHostPartition*` helpers from
  `10-crypto-map.md`.

## 1. Tooling setup (one-time)

- **Install Ghidra** (not present). Needs a JDK; **JDK 25 is installed but Ghidra
  11.x officially targets JDK 21** — verify launch, else install `java-21-openjdk`.
  *(This is the one real setup unknown; ~15–30 min.)*
- Headless import is ready: `GHIDRA_HOME=/opt/ghidra tools/ghidra-headless.sh
  "re/driver/…/synaWudfBioUsb132.dll" verimark` → project under `ghidra-projects/`
  (git-ignored). `-analysisTimeoutPerFile 900` already set; a 1.4 MB DLL analyzes in
  a few minutes.
- Optional but recommended: **GhidraMCP** (per `RESEARCH-PROMPT.md` appendix) so the
  analysis can be driven by an agent (`decompile_function`, `list_methods`,
  `rename`, `list_imports`, xrefs) instead of by hand in the GUI.
- First analysis action: run a **string-xref auto-name** script (Ghidra ships
  `LabelFromStringsScript`-style snippets; or a 20-line Python/Jython script:
  for each defined string matching `^[A-Za-z_][\w:]+$`, name its sole calling
  function). This applies the 122+503 anchors before any manual work.

## 2. Deliverables

### 2a. For the UMDF1-host path (`40` §3)
- **Coclass CLSID + `DllGetClassObject`/`IClassFactory`** flow → which object is
  created and what `IDriverEntry` it returns.
- **Interfaces the driver IMPLEMENTS** — enumerate the `QueryInterface`
  IID-comparison sites (the driver's `QI` switch on IID GUIDs). Map each accepted
  IID → known UMDF1 interface (`IDriverEntry`, `IPnpCallbackHardware`,
  `IQueueCallbackDeviceIoControl`, `IObjectCleanup`, …). **This pins exactly which
  host→driver callbacks must be dispatched** (so the host implements no more, no
  less).
- **Host interfaces the driver CONSUMES** — find calls through `IWDF*` vtables
  (`IWDFDevice`, `IWDFIoQueue`, `IWDFIoRequest`, `IWDFUsbTargetDevice/Pipe`,
  `IWDFMemory`) and record **which vtable slots/methods** are actually called. The
  host only needs to implement those methods for real; the rest can be safe stubs.
- The `OnDeviceAdd` → device/queue/USB-target creation sequence (object lifecycle).

Output: `findings/60-umdf1-interface-map.md` (IID table, per-interface method-usage,
lifecycle diagram) — the exact build list for `40`'s `umdf1/` host.

### 2b. For the native clean-room path (`40` §6)
- **WinBio IOCTL dispatch** → map each `OnXxx` (`OnConnectSecure`, `OnEnrollment*`,
  `OnDeleteFinger`, `OnControlUnit`, `OnIdentify*`) to the bytes it builds.
- **Pairing sequence**: `DoPairing` → `tudorSecurityGenHostKeyPair` →
  `_tudorSecurityPreparePairingParams` → `_tudorSecuritySendPairingCommand` →
  `_wrap/_unwrapPairingData` → `tudorHostPartitionWrite`. Byte layouts + order.
- **TLS handshake construction**: `ssiTlsEstablish` / `prfTLS12` / the ECC-vs-PSK
  cipher selection — enough to reproduce the handshake host-side (crypto primitives
  are the OpenSSL-equivalent BCrypt calls already mapped in `10`).
- **MOC command builders** (the plaintext *before* `ssiTlsDataSet` wraps it): the
  opcode + request/response layout for enroll/identify/list/delete. **Key point:
  the driver builds plaintext commands then hands them to the TLS layer — so static
  RE yields the plaintext protocol directly, without decrypting anything.** The
  issue-#51 pcap is then only a framing cross-check, and a Frida session-key dump
  (`plan.md` §3) becomes optional validation rather than a prerequisite.
- Cross-check opcodes against libfprint's `synaptics` driver (`plan.md` §2) to see
  how much of the state machine is already upstream.

Output: `findings/20-protocol.md` (the file `RESEARCH-PROMPT.md` asks for) — message
tables + sequence diagrams — feeding the pyusb prototype (`plan.md` §4).

## 3. Effort

- **Setup:** ~0.5–1 h (Ghidra + JDK21 check + headless import + auto-name pass).
- **UMDF1 interface map (2a):** ~1–2 days. The IID/`QueryInterface` sites and vtable
  call sites are localized; the auto-naming makes them findable fast.
- **Protocol extraction (2b):** ~3–7 days for a full enroll/verify/pair map; less
  for a first pairing+handshake slice. The state machine is large but well-labelled.
- **Confidence:** high that the pass *succeeds* (produces the maps) — the binary is
  labelled and standard MSVC/COM. It does not by itself prove either downstream
  path works; it removes the unknowns each path is currently blocked on.

## 4. Risks / limits
- **JDK 25 vs Ghidra** — the only setup gotcha; fall back to JDK 21.
- **No live keys** — static RE gives *structure* (layouts, opcodes, handshake shape),
  not the per-session ECDH/session keys. For the native path that's fine (plaintext
  builders are pre-encryption); to *decrypt an existing capture* you'd still want
  the Frida dump.
- **C++ vtables / object layout** — `CBiometricDevice` is a C++ object; Ghidra needs
  some manual struct recovery for the `this`-heavy methods (mitigated by the named
  anchors).
- **Scope creep** — 736 KB of code; stay target-driven (only the functions reachable
  from the deliverable lists above), don't boil the ocean.

## 5. Concrete first commands
```sh
# 1. install Ghidra (verify JDK 21 if launch complains), then:
GHIDRA_HOME=/opt/ghidra ./tools/ghidra-headless.sh \
  "re/driver/Kensington-132 _v6_0_9_1132_x64_inf_WHQL_pass/synaWudfBioUsb132.dll" verimark
# 2. open project in Ghidra (or attach GhidraMCP), run the string-xref auto-name pass
# 3. UMDF1 path: find QueryInterface IID sites  →  60-umdf1-interface-map.md
#    native path: start at CBiometricDevice::DoPairing + OnEnrollmentCommit  →  20-protocol.md
```
