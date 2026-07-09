# findings/46 — rev's HS signing key is byte-identical to the FW10.1 driver (Hyp-2 DEAD)

**Date:** 2026-07-09. During the "way forward" synthesis, Agent 2 flagged an **unverified assumption**
underpinning the whole project: that `rev`'s hardcoded HS-key constants (in `genhskey.py`) actually
match *this* VeriMark FW10.1 device. If they didn't, `rev` would be signing its host certificate with
the **wrong** HS key — the sensor would TOFU-accept the `0x93` pairing but could defer a genuine-host
check to the MOC gate → `0x0405`. That would have been a **Linux-only fix** (regenerate the key,
re-pair, retry). This finding closes that thread: **the constants are identical; there is no HS-key
mismatch.**

## What `rev` uses (`re/synaTudor-rev/.../sensor_keys/genhskey.py`)
The HS key is derived, not stored: TLS1.2-PRF-SHA256 over hardcoded constants.
- `secret    = 717cd72d0962bc4a2846138dbb2c2419` (16 B)
- `prf_input = 2512a76407065f383846139d4bec2033aaaa` (18 B)
- `label     = "HS_KEY_PAIR_GEN"`; PRF output (32 B, little-endian) → SECP256R1 private key.

## What the shipping DLL does (`synaWudfBioUsb132.dll`, Ghidra base 0x180000000)
Decompiled the function referencing the `HS_KEY_PAIR_GEN` string (`FUN_1800a5a70`) and its whole
derivation chain (`re/ghidra-out/hskey-check/`):
- **`palSynaKmGet`** assembles a **32-byte constant** from four 8-byte constant emitters
  (`FUN_1800a6120/6210/6300/63f0`) — a global constant, **not** device/install-specific:
  - `KmGet[0:16]  = 71 7c d7 2d 09 62 bc 4a 28 46 13 8d bb 2c 24 19`
  - `KmGet[16:32] = 25 12 a7 64 07 06 5f 38 38 46 13 9d 4b ec 20 33`
- **`FUN_1800a64e0`** (the "transform" fed the decoy 32-byte blob `b3 49 44 …`) **ignores its input**
  and `memset`s a 2-byte buffer to `0xaa` → returns `aa aa`.
- Then `palSymKeyGen(secret = KmGet[0:16], label = "HS_KEY_PAIR_GEN", seed = KmGet[16:32] ‖ 0xaaaa)`
  = TLS1.2 PRF-SHA256.

## The match (32-of-34 constant bytes exact + the 2-byte transform)
| Piece | DLL | rev |
|---|---|---|
| PRF secret (16 B) | `KmGet[0:16]` = `717cd72d0962bc4a2846138dbb2c2419` | `secret` = **identical** |
| PRF seed head (16 B) | `KmGet[16:32]` = `2512a76407065f383846139d4bec2033` | `prf_input[0:16]` = **identical** |
| PRF seed tail (2 B) | `FUN_1800a64e0` → `aa aa` | `prf_input[16:18]` = `aaaa` = **identical** |
| label | `"HS_KEY_PAIR_GEN"` | `"HS_KEY_PAIR_GEN"` = **identical** |
| PRF | `palSymKeyGen` = TLS1.2-PRF-SHA256 | TLS1.2-PRF-SHA256 = **identical** |

⇒ `genhskey.py` is a **byte-faithful reproduction** of this exact DLL's HS-key derivation. The 32-byte
blob in `FUN_1800a5a70` is a decoy (its consumer discards it). `rev` signs host certs with the genuine,
correct, global Synaptics HS key for FW10.1.

**Endianness closed (added after independent re-verification).** `palSymKeyGen` emits only 32 raw PRF
bytes; the scalar interpretation is in the consumer chain `palGenHSPrivKey → FUN_1800a9740 → sign in
FUN_1800a7f80`. `FUN_1800a9740` copies the PRF bytes into the scalar slot then calls `FUN_1800abcb0`,
an **in-place byte reversal**, and `FUN_1800a7f80` imports the result via
`BCryptImportKeyPair(BCRYPT_ECCPRIVATE_BLOB)` — which reads `d` **big-endian**. So DLL scalar
`= int.from_bytes(reverse(PRF),"big") = int.from_bytes(PRF,"little")` = **exactly** rev's
`int.from_bytes(prf_output,"little")`. This matters because rev is little-endian while CNG ECC blobs
are big-endian — a naive read predicts a mismatch; the DLL's byte-reversal reconciles them. Concrete:
`PRF32 = 866ab3019c09d4352e643fdb60e2e8c74041ae9c47efb0acd6546265b6a2a2e8`, shared private scalar
`= 0xe8a2a2b6656254d6acb0ef479cae4140c7e8e260db3f642e35d4099c01b36a86` (< curve order). Artifacts:
`re/prf-check/` (palPRF/prfTLS12, hskey-consumers, keyimport dumps).

## Consequence
- **Hyp-2 (stale HS constants) is DEAD.** No Linux-only re-key fix exists.
- Strengthens findings/43/44: at the HS-signature layer, our Linux host cert and a genuine Windows
  host cert are **cryptographically indistinguishable** (same key signs both). So the `0x0405` enroll
  gate is **not** an HS-identity check the driver could fail — consistent with the gate being a
  sensor-side per-slot authorization state, not a host-crypto check.
- This also means the HS key is a **global secret shared by every Synaptics Tudor host**, so it cannot
  distinguish the additive foreign-Windows host (enrolls) from Linux (`0x0405`) — the distinguishing
  action must be **behavioral** (a transaction on a virgin host's first enroll), not key identity.

## Artifacts
`re/ghidra-out/hskey-check/` — `FUN_1800a5a70.c` (HS-key builder, refs `HS_KEY_PAIR_GEN`),
`palSynaKmGet.c` + `FUN_1800a6120/6210/6300/63f0.c` (the 32-B secret), `FUN_1800a64e0.c`
(transform → `aaaa`), `palSymKeyGen.c`.
