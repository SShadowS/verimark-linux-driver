# findings/34 — Ownership forgeability: (A) FORGEABLE crypto, destructive+maybe-irreversible mechanism

**Date:** 2026-07-08. Fable's "static pre-check before the VM" gate. Full trace in
`re/ghidra-out/OWNERSHIP-FORGEABILITY-TRACE.md` (+ 21 dumps under `ownership-forge/`).
This is the decision-relevant summary.

## The question
Before building a Windows VM to capture the missing host-authorization/provisioning
transaction, determine what KIND of credential authorizes a host — because that decides
whether a Linux host can EVER replicate it (Fable's trichotomy):
- **A forgeable** — host-generated ephemeral (fresh EC key, self-signed) → Linux can synth → VM wins.
- **B embedded-cert** — static key/cert baked in → forgeable only if extractable+shared.
- **C non-forgeable** — sensor-held key / device attestation / MS-PKI challenge-response → wall.

## Verdict: **(A) FORGEABLE** on the crypto axis. B and C ruled out.
- **Decisive:** `palGenHSPrivKey` generates the host EC P-256 key **in-process** and
  **self-signs** its own cert (digest over 142 B → 145-B sig appended). Same primitives as the
  `0x93` pairing we already run live. No CA, no embedded signing key.
- **Rules out B:** import scan = `bcrypt` + DPAPI only; **zero `ncrypt`/TPM**. Nothing
  device/TPM-bound; no embedded host signing key/cert.
- **Rules out C:** the only device-bound key in pairing is the **sensor's own** pubkey, a
  **driver-baked per-family constant** (`DAT_18011d440`), used **server-auth** (sensor proves
  itself to host). The host presents nothing sensor-signed or MS-PKI-rooted. The "Microsoft ECC
  Devices Root 2017" string is only in TLS sensor-attestation (host verifies sensor) and is
  skippable. There is **no** host-side challenge-response: no code fetches a sensor nonce and
  signs it with a host key to prove ownership. If such a bind existed it would live in the `0x4f`
  builder — which is **absent**.

## Architecture correction (supersedes prior "NiseCore black box")
The pairing/ownership engine is NOT an opaque matcher — it's the fully-readable synaLib `tudor*`
dispatch table `DAT_18013df40`, every entry a named function in this DLL. The complete
`tudorIoctl` selector table was enumerated: **no selector builds `0x4f`/`0x10`/`0x0e`/`0x50`**;
the only raw-blob path (selector 3 `tudorSendAnyCommand`) has exactly two callers, neither an
ownership builder. Ownership opcodes exist **only as names** in the opcode-logger. ⇒ **The retail
driver never provisions** — "ownership" in its vocabulary IS the `0x93` TOFU pairing (it bumps a
`SetOwnershipFailureCount` registry counter on pair failure). On an already-owned sensor a fresh
`0x93` re-keys TLS but does not re-take ownership — matching our live `0x0405`. Provisioning is
**out-of-band** (factory / a manufacturing or reset tool we don't have).

## What still blocks us — NOT crypto, but two device-only facts
1. **We don't have the provisioning opcode's byte layout.** `0x4f/0x10/0x0e` payloads are absent
   from the binary (built by the out-of-band tool). A first-provisioning **capture** would yield
   them — and per the verdict they're built from Linux-reproducible primitives.
2. **Taking ownership is destructive + maybe irreversible.** Owner state is sensor-internal,
   single-owner, already bound to Windows. Re-owning from Linux needs `RESET_OWNERSHIP 0x10` →
   **wipes the user's Windows Hello fingerprints**. `OUT_OF_OTP` hints the owner slot may be
   OTP-limited → reset may not cleanly restore, and re-owning may be finite. This is a
   **sensor-firmware** property, **not statically resolvable** — only the device can answer it.

## Honest caveat
The `0x4f`/`0x10` payload itself is absent from the binary, so its forgeability is a **strong
inference** from the fully-forgeable surrounding primitives + the total absence of any
embedded/attestation material — not from reading a builder (there is none). The VM capture is
exactly what confirms the payload carries no non-forgeable residual.

## Real-world base rate on the irreversibility fear (web research, 2026-07-08)
The "re-owning might be a one-way door / finite OTP burn" fear has **no real-world support** and is
**contradicted by vendor documentation**:
- **Kensington's own docs** say the VeriMark is meant to move between machines and be reset/reused:
  *"can be registered again through the same account on a different device"*; for new-owner
  transfer, *"factory reset is possible"* / *"clearing fingerprints can be done via the Windows
  Hello fingerprint interface."* A mass-market reader sold to plug into any PC cannot be a one-time
  fuse without being an RMA disaster.
- **Windows Hello never syncs fingerprints across devices** (Microsoft) → *everyone* re-enrolls on
  each PC with any external reader. Routine, by design, harmless.
- **Dual-boot Win+Linux** contention is real but the documented fix is always a **soft reset +
  re-enroll** (BIOS "Reset Fingerprint Data" / Clear TPM), never a dead sensor.
- The only permanent-brick→RMA reports online are **phone sensors** where someone ran a hidden
  factory **calibration** tool or overwrote `/persist` — destroying *calibration/image* data, NOT
  *ownership*. Unrelated to `RESET_OWNERSHIP`/re-pair. **Zero** reports of a USB MOC reader bricked
  by being re-owned.
⇒ `OUT_OF_OTP_OWNERSHIP` almost certainly means "you are not the owner recorded in the OTP region"
(a permission statement), not "you exhausted a burn budget." Irreversibility risk revised
**down to single digits**.

## Recommendation
The crypto wall (case C) that would make this **permanent** is NOT there. The remaining wall is
**destructiveness + possible irreversibility** — a user-policy decision, not a technical one:
- User already authorized "don't need it in Windows" (destroying Hello is acceptable).
- The genuinely new risk is **irreversibility**: re-owning to Linux might be a one-way door
  (can't return to Windows; owner slot possibly finite). That is unknowable without trying it.
⇒ If the user accepts that risk, the VM capture of a fresh provisioning is the next step and is
odds-favoured to yield a replayable sequence. If preserving the option to return to Windows
matters, it's a wall **by policy**, not by cryptography.
