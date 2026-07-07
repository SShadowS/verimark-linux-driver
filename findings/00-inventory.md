# 00 — Binary inventory (static triage, Phase 0–1)

**Driver package:** `kensington-132-_v6_0_9_1132_x64_inf_whql_pass.zip`
(Kensington VeriMark Desktop, driver **v6.0.9.1132**, WHQL, built 2021-02-19).
Source: kensington.com VeriMark Desktop setup page (direct .zip). Kept local under
`re/driver/` (git-ignored). SHA-256 of the zip:
`acc39a512de841611c3ebc4653e574df1ad186f6c11819c84887f249dd88ea3e`.

Build path leaked in symbols: `D:\Jenkins\workspace\Kensington-132\HDRFP-6678\...`.

| File | Type | Tool | Role |
|---|---|---|---|
| **`synaWudfBioUsb132.dll`** | PE32+ x64 (WUDF UMDF driver) | **Ghidra** | ⭐ The user-mode biometric driver. **All TLS/crypto/pairing/MOC logic is here.** Primary RE target. |
| `synaFpAdapter132.dll` | PE32+ x64 | Ghidra | WBF engine adapter (BioAPI shim). No crypto imports of its own. |
| `SynaCP132.dll` | PE32+ x64 | Ghidra | Control-panel / settings helper. |
| `synaFpCoInstaller132.dll` | PE32+ x64 | Ghidra | Driver co-installer (setup only). |
| `WBFResetService132.exe` | PE32+ x64 console | Ghidra | Windows service that resets WBF state. Symbols show only `TlsAlloc/…` (thread-local storage, *not* TLS crypto). |
| **`KensingtonFingerprintApplication.exe`** | PE32 **.NET (Mono/.NET)** | ILSpy | Companion UI = "SynapticsFingerprintManager". Pure orchestration/UI (enroll animations, "type your Windows password", remove-finger prompts). **No crypto** — confirms the channel lives entirely in the native DLL. |
| `WudfUpdate_01011.dll` | PE32+ x64 | — | Microsoft's WUDF framework redistributable. Not Synaptics. Ignore. |
| `synaWudfBioUsb.inf`, `synaumdf.cat` | INF + catalog | — | Install metadata (INF is Kensington-branded Synaptics WBF). |

## Triage conclusion

Only **one binary matters** for the go/no-go: `synaWudfBioUsb132.dll`. The .NET app
holds no protocol logic. Crypto map → `10-crypto-map.md`.

Note the sensor family: the driver's own symbols call it **"Tudor"**
(`tudorSecurity*`, `tudorTls*`, "Tudor family sensors"). This is the same family
targeted by **`Popax21/synaTudor`** — see `10-crypto-map.md` and `DECISION.md`.
