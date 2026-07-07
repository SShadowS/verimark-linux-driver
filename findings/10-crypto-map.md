# 10 — Crypto & handshake map (static, Phase 2)

Source: static triage of `synaWudfBioUsb132.dll` (v6.0.9.1132) — PE import table
(`objdump -p`) + string analysis. No decompilation yet; no dynamic capture. This
is behavioral/structural evidence, sufficient to answer the go/no-go binding
question. Method notes at bottom.

## TL;DR

The secure channel is a **Synaptics "Tudor"-family custom TLS 1.2** stack with
**server(device)-authentication only** and **trust-on-first-use pairing**. The host
holds **no TPM/firmware/Windows-sealed identity**: it generates an **ephemeral ECC
key pair** itself, and the pairing state lives in a **partition inside the sensor**
(travels with the device). → The host side is reimplementable in open software.

## 1. Crypto primitives actually imported (the ground truth)

`synaWudfBioUsb132.dll` imports **only** `bcrypt.dll` (CNG primitives) + `crypt32.dll`
(legacy CryptoAPI + DPAPI). **No `ncrypt.dll`, no `Tbs`/TPM, no Platform Crypto
Provider — anywhere in the whole package.**

From `bcrypt.dll` (the channel crypto):
- `BCryptGenerateKeyPair` + `BCryptFinalizeKeyPair` + `BCryptExportKey` — generate
  and export an **ephemeral** key pair (host side).
- `BCryptImportKeyPair` — import the peer (sensor) public key.
- `BCryptSecretAgreement` + `BCryptDeriveKey` — **ECDH** shared secret + KDF.
- `BCryptSignHash` + `BCryptVerifySignature` — **ECDSA** sign & verify.
- `BCryptGenerateSymmetricKey` + `BCryptEncrypt`/`BCryptDecrypt` — **AES** session
  cipher (strings confirm **AES-CBC**, **AES-GCM**, and **AES-CMAC**).

From `crypt32.dll`: `CryptDecodeObject`/`CryptEncodeObject` (ASN.1 cert/key),
`CryptGenRandom` (nonces/keys), `CryptCreateHash`/`CryptHashData` (SHA), and
**DPAPI**: `CryptProtectData`/`CryptUnprotectData` + `CryptProtectMemory` — used to
wrap the *local at-rest copy* of pairing data on Windows (see §4).

## 2. The handshake (from strings)

A custom TLS 1.2 implementation labelled `niseTlsLib` / `ssiTls*` / `tudorTls*`:
- `ssiTlsEstablish`, "STEP: Step 1/2 of TLS Handshake process", "TLS handshake done!"
- Client/server randoms (`client_randomp`, `server_randomp`), server cert
  (`server_certp`), `prfTLS12` / `prfAesCmac` (PRF/KDF), HMAC verification.
- **Two cipher suites only:** *"Only tlsSecurityTypeEcc and tlsSecurityTypePsk are
  supported in Tudor family sensors."*
  - **ECC:** ECDHE key exchange + **ECDSA** verify of the sensor's cert (server auth).
  - **PSK:** pre-shared key established at pairing time (see §3).

## 3. Pairing — the identity model (the decisive part)

Symbols: `CBiometricDevice::DoPairing` / `DoUnpairing` / `ProcessPairing`,
`_tudorSecurityBasicPairing`, `_tudorSecurityAdvancedPairing`,
`tudorSecurityGenHostKeyPair`, `_wrapPairingData`/`_unwrapPairingData`,
`tudorSecurityGetPairingData`, `tudorSecuritySetPairingData`.

What it means:
- On first use the host **generates its own key pair** (`GenHostKeyPair`) — not a
  factory/Windows/TPM identity — and pairs with the sensor. This is
  **trust-on-first-use**.
- Pairing establishes a **PSK** ("Adding PSK blob to pairing container"), later used
  by the PSK cipher suite.
- Two modes: **basic** vs **advanced** security. "Skipping pairing: sensor is not
  secure"; "Sensor is not provisioned. Unable to establish TLS" — sensor state
  gates whether a secure channel is required at all.
- Flow guards: "Host doesn't have pairing data. Need to perform pairing" /
  "Host has the pairing data" / `_isHostPartitionHasPairingInfo`.

## 4. Where the pairing state lives (why it isn't Windows-bound)

Symbols: `tudorHostPartitionRead/Write/Format/Validate`,
`tudorGetHostPartitionInfo`, `SSI_IOCTL_CODE_PARTITION_FORMAT`,
`VfmDevicePartitionFormat`, "update host partition in **sensor**", "host partition
is full", plus registry root `SOFTWARE\Syna`.

→ The authoritative pairing/PSK state is a **partition inside the sensor's own
flash**. It travels with the dongle. DPAPI (`CryptProtectData`) only protects a
*local mirror/cache* at rest on Windows — a Linux driver just keeps its own copy.
**No Windows/TPM sealing of the channel secret.**

## 5. Server authentication root

The sensor's cert chain roots in **"Microsoft ECC Devices Root Certificate
Authority 2017"** (the Windows-Hello device-attestation root). The host **verifies**
this chain (public operation, `BCryptVerifySignature` + `CryptDecodeObject`); it
does **not** present a cert of its own. (The DigiCert CAs in the binary are EV
code-signing of the DLL, unrelated to the channel.)

## 6. Answering the go/no-go crypto questions

| Question (RESEARCH-PROMPT §Phase 2) | Answer from static evidence |
|---|---|
| SDCP or proprietary TLS? | **Proprietary Synaptics "Tudor" TLS 1.2** (consistent with Blackwing: SDCP-capable silicon, but a custom TLS stack in practice). Sensor still uses a MS-Device-root cert for server auth. |
| Where do keys come from? | Host: **ephemeral ECC keypair generated on the host** (`BCryptGenerateKeyPair`, "ephemeral ECC public key"). Sensor: device cert + key in-sensor. |
| Which KDF? | TLS1.2 PRF (`prfTLS12`) and an AES-CMAC PRF (`prfAesCmac`); session protected by AES-CBC/GCM + HMAC/CMAC. |
| Server-auth-only or mutually-authenticated / TPM-bound? | **Server(device)-auth only.** Host is anonymous at the crypto-identity level; its keypair is ephemeral and self-generated. `BCryptSignHash` on the host signs handshake/key-confirmation material, **not** a persistent pre-trusted host identity. |
| Is the host secret TPM/firmware/Windows-sealed? | **No.** No `ncrypt`/TPM anywhere; pairing state lives in-sensor; DPAPI only wraps a local cache. |

**Net:** the channel is **impersonable from a stock Linux host** → the question that
was expected to kill the project resolves in the project's favor. See `DECISION.md`
for the revised verdict and the residual (non-crypto) risks.

## Method / reproduce

```
cd re/driver/Kensington-132\ _v6_0_9_1132_x64_inf_WHQL_pass
objdump -p synaWudfBioUsb132.dll | grep -iE 'DLL Name|BCrypt|Crypt|Cert'
strings -n 5 synaWudfBioUsb132.dll | grep -iE 'tudor|tls|pairing|ecdh|ecdsa|partition|nonce'
```

**Not yet done (would deepen, not change, the verdict):** Ghidra decompilation of
`DoPairing`/`ssiTlsEstablish` to extract exact byte layouts & the MOC command set;
a live USB/Frida capture to confirm the on-wire handshake. Both are Phase 3–4.
