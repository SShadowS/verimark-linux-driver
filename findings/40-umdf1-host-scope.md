# 40 — Scoping: a UMDF 1.x COM host for libtudor (to run the 132 VeriMark driver)

**Date:** 2026-07-07. Design + effort estimate only — no code. Follows from
`30-synatudor-port.md`: the exact-match driver `synaWudfBioUsb132.dll` is
**UMDF 1.11 (COM)**, but synaTudor only hosts **UMDF 2.x** (`FxDriverEntryUm`/WDF),
so it aborts at init. This scopes what it takes to close that gap.

---

## 1. Why this is the remaining path

- Crypto gate is **passed** (`DECISION.md`): the channel is impersonable host-side
  (no TPM, ephemeral host key, server-auth, pairing stored in-sensor). Not a blocker.
- Both cheaper routes are **closed** (`30`, synaTudor issue #51): the 104 UMDF2
  driver loads on 047d but times out every USB transfer (wrong sensor protocol);
  the 132 driver is the correct one but UMDF1/COM.
- ⇒ To reuse the vendor driver's protocol logic, libtudor must gain a **UMDF 1.x
  COM host**. (Alternative: skip hosting, do a native clean-room reimpl — see §6.)

## 2. How a UMDF 1.x driver is actually driven (the model to emulate)

On Windows, a UMDF1 driver is a COM in-proc server; `WUDFHost.exe` + `WUDFx.dll`
(the UMDF1 runtime) drive it. Sequence:

1. `DllGetClassObject(CLSID_driver, IID_IClassFactory, …)` → `IClassFactory`.
2. `IClassFactory::CreateInstance(IID_IDriverEntry)` → the driver's root object.
3. Host calls **`IDriverEntry::OnInitialize`**, then **`OnDeviceAdd(IWDFDriver*,
   IWDFDeviceInitialize*)`** per device.
4. Driver calls back into **host-provided framework objects** (`IWDFDriver`,
   `IWDFDeviceInitialize`, `IWDFDevice`, …) to create its device, IO queues, and
   USB targets, and registers its **callback interfaces** (`IPnpCallbackHardware`,
   `IQueueCallback*`, …) which the host then invokes on PnP/IO events.
5. IO flows as `IWDFIoRequest` objects through `IWDFIoQueue` → driver callbacks →
   driver issues USB via `IWDFUsbTargetPipe`/`IWDFUsbTargetDevice` → **host maps to
   libusb** → completes the request.

Key fact for scoping: the 132 DLL imports **no `WUDFx`** (only `ole32` for COM).
So **all** the `IWDF*` framework objects are things the *host* must implement and
hand to the driver — exactly what `WUDFx.dll` does on Windows. This is the bulk of
the work.

## 3. What must be built vs. reused

### Build new — a `libtudor/src/winapi/umdf1/` peer to the existing `wdf/`

COM plumbing:
- Minimal **COM runtime**: `IUnknown` vtable helpers (`QueryInterface`/`AddRef`/
  `Release`), an `IClassFactory`, GUID/IID tables, and the `DllGetClassObject`
  bootstrap. (~300–600 LOC; libtudor currently stubs only `ole32!PropVariantClear`.)

Host-side framework objects the driver consumes (implement the vtables from the
public WDK `wudfddi.h`), the UMDF1 analogues of what `wdf/*` already does for UMDF2:
- `IWDFDriver`, `IWDFDeviceInitialize`, `IWDFDevice`
- `IWDFIoQueue`, `IWDFIoRequest`, `IWDFIoTarget`
- `IWDFUsbTargetDevice`, `IWDFUsbInterface`, `IWDFUsbTargetPipe`
- `IWDFMemory`, `IWDFObject` (+ context store), completion-params interfaces

Host→driver dispatch (call the driver's registered callbacks):
- `IDriverEntry`, `IPnpCallbackHardware` (OnPrepare/ReleaseHardware),
  `IPnpCallback` (D0 entry/exit, remove), `IQueueCallbackDeviceIoControl` (+ Read/
  Write/Create as used), `IObjectCleanup`/`IFileCallback*` if referenced.

The **exact subset** the 132 driver uses is finite and **decompilable** from its
`QueryInterface`/`CreateInstance` call sites in Ghidra — do that first to pin the
interface list and avoid implementing unused ones.

### Reuse — already in libtudor, version-independent
- **WBF adapter layer** (`tudor/winbio.h` + `device.c`, ~1,064 LOC): the sensor/
  engine/storage adapter interfaces (`WbioQuery*`) are the same for 132 and 104 —
  the 132 adapter exports the same `WbioQuerySensorInterface`/`…Engine`/`…Storage`.
- **USB/libusb IO logic** in `wdf/usb.c` (594 LOC): control + interrupt/bulk
  transfer mechanics port directly under the UMDF1 USB-target objects.
- **Crypto** (`winapi/bcrypt/*`, `winapi/crypt/*` — BCrypt/CAPI over OpenSSL):
  unchanged; this is why "no TPM" matters.
- **WinAPI shims** (kernel32/advapi/reg/heap/sync/…) incl. the **20 we just added**
  (`user32.c` + `CryptAcquireContextW`): unchanged.
- **IO-request completion + async model** (`request.c`, `evtqueue.c`): the routing
  logic largely reuses; only the object surface (COM vs WDF) changes.

## 4. Effort estimate

- **New code:** ~2,000–3,500 LOC. (The UMDF2 host is 2,715 LOC; UMDF1 adds COM
  boilerplate — QI/AddRef/Release per interface — but reuses the USB/IO/crypto
  substrate, roughly a wash.)
- **Calendar (one experienced dev, comfortable with COM + UMDF):** ~2–4 weeks to
  first working enroll/verify, plus debugging tail. Higher if unfamiliar with COM
  vtable ABI or UMDF lifecycle.
- **Confidence:** medium. The interface definitions are *public* (WDK `wudfddi.h`),
  the driver is decompilable, and the crypto/USB substrate exists — so it's bounded
  and knowable, not open-ended. The main way it fails is subtle UMDF1
  lifecycle/threading or vtable-layout mismatches.

### Milestones + decision gates
1. **COM bootstrap** — load 132 via `DllGetClassObject`, instantiate coclass, get
   `IDriverEntry`. (days) — proves the COM plumbing.
2. **DriverEntry → device add** — `OnInitialize`/`OnDeviceAdd`, minimal
   `IWDFDriver`/`IWDFDeviceInitialize`/`IWDFDevice`, reach `OnPrepareHardware`.
3. **USB target over libusb** — `IWDFUsbTargetDevice`/`…Pipe`; get the driver
   issuing real transfers to the sensor. **★ KEY GATE:** if transfers succeed here
   (vs the 104 driver's timeouts), success through enroll is likely.
4. **IO queue + IOCTL routing** — `IWDFIoQueue`/`IWDFIoRequest` +
   `IQueueCallbackDeviceIoControl`; reach the Tudor **TLS pairing handshake**.
5. **Enroll/verify end-to-end**, then wire into the `libfprint-tod` module
   (`tudor_ids` += `047d:00f2`).

## 5. Risks
- **COM ABI exactness** — vtable method order/signatures must match `wudfddi.h`
  precisely; a mismatch is a silent crash. Mitigated by using the public headers.
- **Unmodeled interface** — the driver may QI for something we didn't implement;
  the DBGIMPORT-style stub logging + Ghidra pre-survey mitigate.
- **iface-0 `LIBUSB_ERROR_BUSY`** — hid-generic owns iface 0; need detach/ignore-
  busy on `set_configuration` (issue #51 hit this; one-line fix).
- **Pairing writes to the sensor** — same brick caveat as before; test with a
  fresh in-sensor partition, Linux-only unit.
- Output is a **relinking hack** (loads a proprietary DLL) — not upstreamable to
  libfprint; personal-use only. (Contrast §6.)

## 6. Alternative worth weighing: native clean-room driver (no hosting)

Because the crypto gate is passed, the other path is to **not host the DLL at all**:
decompile the 132 driver's Tudor protocol (pairing → TLS(ECC/PSK) → MOC enroll/
identify/list/delete) and write an **original** pyusb prototype → libfprint driver
(`plan.md` §4–§5), using the DLL only as a reference and the issue-#51 pcap as
ground truth.

- **Pros:** upstreamable (clean IP, no proprietary blob, no COM host), a *real*
  libfprint driver, no UMDF1 lifecycle to emulate.
- **Cons:** must fully reverse the plaintext protocol (needs the Frida session-key
  dump from Windows, `plan.md` §3, to decrypt captures) — more RE, less plumbing.
- **Effort:** comparable order (weeks–months); different risk profile (protocol RE
  vs COM hosting).

**Recommendation:** if the goal is a *usable* driver fastest, the UMDF1 host is the
more mechanical path and has an early go/no-go at **milestone 3**. If the goal is an
*upstreamable* driver, do §6 instead. Either way, **milestone 3 / a Frida key-dump**
is the next concrete, decisive step — and both benefit from first decompiling the
132 driver's `QueryInterface` sites (host) or command builders (native) in Ghidra.
```
Suggested first action for EITHER path: Ghidra headless import of
synaWudfBioUsb132.dll (tools/ghidra-headless.sh) → map QueryInterface/CreateInstance
(for the host) and the WinBio IOCTL command builders (for the native reimpl).
```
