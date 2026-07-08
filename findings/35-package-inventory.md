# findings/35 — Retail package inventory: is provisioning shipped, or factory-only?

**Date:** 2026-07-08. Fable's gate BEFORE the VM: the retail WUDF driver never provisions
(findings/34). So either (i) a provisioning component ships ELSEWHERE in the Kensington package
(→ a fresh Windows host re-provisions → VM captures it → GO), or (ii) provisioning is
factory-only and NO Windows host ever re-provisions (→ VM captures nothing → HOLD). Inventory
the ENTIRE package to decide.

## The full package (Kensington-132 v6.0.9.1132)
| file | role | talks to sensor? |
|---|---|---|
| `synaWudfBioUsb132.dll` | UMDF driver — **only** `WinUsb_Initialize`/`WinUsb_ControlTransfer` holder | **YES** (EP0). Proven: only `0x93`-pairs, never provisions (findings/34). |
| `synaFpAdapter132.dll` | WBF adapter, marshals IOCTLs to the driver | no (IOCTL only) |
| `SynaCP132.dll` | WinBio control-panel plugin (`winbio.dll`, `Secur32`) | no |
| `synaFpCoInstaller132.dll` | co-installer (SHELL32/ADVAPI/SHLWAPI) — install-time file/reg setup | no |
| `WBFResetService132.exe` | "SensRst" service — imports **only ADVAPI32/KERNEL32/SETUPAPI** | **no** (device-restart/enumeration reset, NOT a protocol/ownership reset) |
| `WudfUpdate_01011.dll` | UMDF runtime updater (MS) | no |
| `KensingtonFingerprintApplication.exe` | .NET UI (mscoree, WinBio via `GetCurrentUserWinbioIdentity`, enroll/delete via WinBio API) | no (WinBio only) |
| `synaWudfBioUsb.inf` / `synaumdf.cat` | install manifest | — |

## Findings
- **The ONLY component that opens the USB device / issues control transfers is
  `synaWudfBioUsb132.dll`** — and it is exactly the binary we proved never sends
  `0x4f/0x10/0x0e` (no builder, no selector; opcodes exist only as names). Everything else talks
  to the sensor **through** it via WinBio/IOCTL, so nothing else can provision either.
- **`WBFResetService132.exe` is NOT a provisioner.** Despite the name, its only imports are
  ADVAPI32/KERNEL32/SETUPAPI (service + SetupAPI device control). The INF installs it as the
  `SensRst-132` service = a **device restart** helper, not an ownership/protocol reset. No USB,
  no crypto, no VCSFW.
- **The INF has no provisioning custom action / RunOnce.** Co-installer + service installs are
  standard UMDF/WinUsb plumbing (`WUDFRd`, `WinUsb` filter, `SensRst`); `CoInstallers32` =
  `synaFpCoInstaller132.dll` + `WudfUpdate_01011.dll` (runtime), neither sensor-facing.
- **The setup SOP doc** describes only: download driver → plug in → Update Driver in Device
  Manager → restart → "you are all set." **No first-run provisioning step, no tool, no
  ceremony.** Ownership state is assumed already present.
- Ownership strings (`RESET_OWNERSHIP`, `PROVISION`, `TAKE_OWNERSHIP_EX2`, `OUT_OF_OTP`,
  `GET_CERTIFICATE_EX`) appear in **exactly one** binary — `synaWudfBioUsb132.dll` — as the
  opcode-name table only (no emitter). Zero occurrences in any other package file.

## Verdict: leans (ii) — provisioning is NOT in the retail package
No shipped component provisions the sensor; the only sensor-facing binary demonstrably only
`0x93`-pairs. ⇒ the user's 3 Windows templates were enrolled against a sensor whose owner state
was **established before/outside this package** — i.e. **factory-provisioned**, or provisioned by
a separate Synaptics manufacturing/RMA tool that does NOT ship to end users.

**Consequence for the VM plan (Fable's own logic):** a fresh Windows VM installing THIS package
would do exactly what our Linux host does — establish TLS, `0x93`-pair — and would hit the **same
owner gate**. It would **not** perform a take-ownership transaction, because no code in the
package performs one. ⇒ **The VM would capture nothing new. This is a HOLD signal.**

## Caveat (why it's "leans" not "certain")
- We did NOT decompile `SynaCP132.dll` or the .NET app opcode-by-opcode — but neither imports
  WinUsb/bcrypt-for-sensor nor references VCSFW, and both route through WinBio, so they
  physically cannot issue a raw ownership opcode to the sensor.
- It remains *conceivable* the sensor ships **unprovisioned** and Windows-Hello first-enroll
  triggers provisioning **inside** the WUDF driver via a path our static trace missed — but
  findings/34 enumerated the complete transport selector table and the raw-blob path's only two
  callers, none of which provision. Low probability.
- A genuinely separate **Synaptics provisioning/RMA utility** (not in this package) would live
  outside anything we can inventory.

## Recommendation
The free gate resolved toward **HOLD on the VM** — but see the REFRAME below; the reason is not
"factory-only" but "owner-slot already claimed on THIS unit."

## REFRAME (Fable, 2026-07-08) — first-pairer-wins TOFU, not factory-only
The "factory-only" story fails to explain the core delta: the retail driver on the user's Windows
box ALSO only `0x93`-pairs, yet Windows' `0x93` clears the enroll gate while our **byte-identical**
Linux `0x93` gets `0x0405`. Same driver, same TLS suite, same self-signed ephemeral host key, same
opcode. A separate factory transaction would make both hosts behave identically. They don't.

The model that fits EVERY fact (no provisioner binary; multi-host pairing; Windows-passes/
Linux-fails; ownership opcodes present-but-unemitted): **the owner slot ships empty, and the FIRST
host to `0x93`-pair against an empty slot claims ownership as a side effect of ordinary pairing**
(the driver writes the owner record when the slot is empty, no-ops when full).
- User's Windows paired first → owns slot → can enroll.
- Our Linux paired **second** → joined the multi-host pair set (why Windows' 3 templates survived)
  but slot already full → paired-but-not-owner → `0x0405`.
- `0x10 RESET_OWNERSHIP` clears the slot but is authorization-gated → a non-owner Linux host can't
  fire it, and it ships in no reachable artifact → wall **on this already-owned unit**.

⇒ The provisioning "transaction" may literally BE the `0x93` we already send live. What we lack is
not bytes but a **precondition: a sensor with an empty owner slot.**

## Refined verdict (supersedes the (ii) framing above)
The Linux driver is blocked **on this unit** not by crypto (ownership credential is forgeable —
host-generated self-signed P-256, proven) and not by user policy, but because **enroll-auth is
conferred by claiming an unowned owner-slot, and this unit's slot is already owned by Windows and
cannot be cleared** (`RESET_OWNERSHIP` is auth-gated + in no end-user artifact).

## Why the VM is dead (tighter than the static argument)
A VM — fresh host or not — can only present the sensor in its **current already-owned state**.
Take-ownership is only observable against an **unowned** slot, and we cannot make this unit
unowned. So the VM captures a guaranteed non-event. State-precondition unreachable ⇒ HOLD.

## The one untested, cheap, non-destructive GO path
**A factory-fresh SECOND unit, paired FIRST from Linux.** If first-pairer-TOFU holds, Linux becomes
the enroll-authorized owner with zero forging / zero reset / zero factory tool — because Linux is
the first host that virgin sensor ever meets. Keeps the user's current unit on Windows untouched.
Probes, in cost order:
1. **Free:** search `Popax21/synaTudor` + `rev` issues for anyone who enrolled a factory-fresh
   `047d` (or any Synaptics MOC unit) from Linux, or hit this exact `0x0405`/OTP-ownership gate.
   Virgin-unit-from-Linux works → TOFU confirmed; fresh units also gate → theory dead, close hard.
2. **~$50:** buy a 2nd VeriMark Desktop; BEFORE any Windows contact, pair first from Linux and try
   `0x96` enroll. Success → non-destructive working Linux driver, ship it. `0x0405` → factory-
   pre-owned, close hard.
**Do NOT** blind-fire `0x10` at the current unit (no payload format; malformed privileged opcode
against the user's only provisioned unit = reckless).

## Probe 1 (free community search) — RESULT: INCONCLUSIVE (not negative)
Ran 2026-07-08. No public data point confirms or refutes first-pairer-TOFU, because **we are the
furthest anyone has publicly gotten on this device:**
- **synaTudor issue #51 = our exact device (047d:00f2)** — dead-ended at the UMDF-hosting wall
  (DLL 132 is COM/`DllGetClassObject`, not UMDF `FxDriverEntryUm`; DLL 104 loads but all USB
  transfers time out). **Never reached pairing or enroll** → no ownership-gate data. Its attached
  pcap is the one already in our `captures/`.
- The only public RE blog on this scanner (inexplicity.de) **stopped at the TLS `1703` wall** —
  far behind us (we have live TLS + `0x93` pair + DB2 r/w + MOC byte-map).
- No synaTudor issue references MOC ownership / `OUT_OF_OTP` / `0x0405` — synaTudor targets
  integrated `06cb:` readers doing **host-side matching**, which never hit the MOC ownership gate.
- `rev` corroborates the state model (`is_paired()` ≡ `is_provisioned()`; provision states
  0/1=unprovisioned, 3=provisioned) but `rev` never provisions (host-side matching), so it can
  neither confirm nor refute first-pairer-wins.
⇒ Inconclusive → per Fable's decision tree, the trigger for **Probe 2 (~$50 second unit)** rather
than a hard close. This is a user spend/decision, not a technical unknown.
