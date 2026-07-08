# findings/42 — Extract Windows' owner host-key via DPAPI (single-unit path)

**Date:** 2026-07-09. Static RE of `synaWudfBioUsb132.dll` (scratchpad copy, capstone/pefile).
**Goal:** with only ONE Windows-owned unit and no reset path, make Linux the **owner** by presenting
Windows' own host keypair. Windows persists that keypair DPAPI-wrapped in the registry; this documents
how to decrypt + reformat it. Non-destructive (both hosts present the same owner key; Hello keeps
working).

## Why this is the path (recap)
- Reset (`0x10`) is owner-gated (`0x0401`, findings/36) and has no builder (findings/39) — can't
  un-own the unit. cert_type is the sensor's grant, not a lever (findings/41).
- Owner identity = the host **keypair** (findings/DECISION: no TPM/platform secret, TOFU). So
  possessing Windows' owner private key = being the owner, from any host.

## The stored blob
Registry: `HKU\S-1-5-19\Software\Synaptics\PairingData`, value name = sensor id `F7007AD929C60000`
(1788 B). Also backed up by `win-unpair-verimark.ps1` to
`<Desktop>\verimark-unpair-backup\HKEY_USERS_S-1-5-19_Software_Synaptics_PairingData.reg`.

Layout:
```
[0:16]   Synaptics wrapper: 01000000 00000000 e6050000 06010000
         (e6050000=0x5e6=1510, 06010000=0x106=262; 1510+262=1772=1788-16 = DPAPI blob length parts)
[16: ]   DPAPI blob (1772 B), begins 01000000 d08c9ddf0115d1118c7a00c04fc297eb
```
**Strip 16 bytes, not 20** (offset 16 is the DPAPI `dwVersion`).

## DPAPI parameters (verified from the DLL)
- API: **`CryptUnprotectData`** (crypt32; thunk `0x1800a3a80`, wrapper `0x18004cc60`). Read path:
  `FUN_180003f3c` (reg read) → `_unwrapPairingData 0x180069a30` → helper `0x18006d4b0` → wrapper →
  thunk. Write mirror via `_wrapPairingData 0x18006ada0`.
- **`pOptionalEntropy = NULL`** (`xor r8d,r8d` at unprotect site `0x18004d0b8` and protect site
  `0x18004c67c`). HIGH confidence.
- **`dwFlags = 0`** (never sets `CRYPTPROTECT_LOCAL_MACHINE`). ⇒ **user-scoped, under LOCAL SERVICE
  (S-1-5-19).** Decrypt AS LOCAL SERVICE (scheduled task `/RU "LOCAL SERVICE"`), or offline as SYSTEM
  with the S-1-5-19 master key (`C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\
  Protect\S-1-5-19\`) + the `DPAPI_SYSTEM` LSA secret (pypykatz/impacket).

## Decrypted plaintext = Synaptics TagVal container
Serializer `0x180042580` / parser `0x1800430d0`; 6 entries. TLV framing (big-endian):
```
repeat: [ tag:u16 BE ][ length:u32 BE ][ data:length ]
```
Fields include the host EC **private key (~68 B / 0x44)** and **two 400-B certs** (host cert type-0 +
sensor cert). Exact tag→field mapping is not a static constant (generic parser) — identify
empirically after decrypt: the two 400-B blobs are the certs, the ~68-B blob is the priv key; the
**sensor cert** is the one whose ECDSA sig verifies against this sensor's `10.1-kf` pubkey
(findings/28), the other 400-B is the **host/owner cert**.

## Recipe (implemented in tools/extract-pairing-key.py)
1. Reconstruct the 1788-B value (from the backup `.reg`, or live `HKCU` as LOCAL SERVICE).
2. `dpapi = value[16:]` (must begin `01000000 d08c9ddf`).
3. `CryptUnprotectData(dpapi, entropy=NULL, flags=0)` **as LOCAL SERVICE**.
4. Parse the TagVal TLV → dump all 6 entries (tag, len, hex).
5. On Linux (rev): pick the 68-B priv + host cert + sensor cert, emit rev's `SensorPairingData`
   (68 priv ‖ 400 host_cert ‖ 400 sensor_cert), `sensor.initialize(pdata)`, retry `0x96`/`0x99`.

## Residual risk
If MOC-owner binding is NOT purely the keypair (some non-key state), the owner key alone won't lift
`0x0405` — but findings/DECISION makes that unlikely. If it fails here, the only remaining
non-destructive MOC path is exhausted (host-readout `0x7f` looks dead on this firmware, findings/31).

## Key addresses
CryptUnprotectData thunk `0x1800a3a80` / wrapper `0x18004cc60`; `_unwrapPairingData 0x180069a30`;
`_wrapPairingData 0x18006ada0`; TagVal serializer `0x180042580`, parser `0x1800430d0`; cert getter
`0x1800413a0` (400 B). Entropy NULL; flags 0; header 16 B; blob@16.
