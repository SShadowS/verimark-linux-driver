# findings/43 — Owner-key impersonation: SOUND NEGATIVE (the crypto wall is real state, not identity)

> **⚠️ SUPERSEDED (2026-07-09, findings/49):** the enroll "ownership gate" (0x0405) was a 2-byte truncated command, not sensor-side ownership. See findings/49.

**Date:** 2026-07-09. Live on the Linux box, non-destructive (no sensor writes). Executes the
findings/42 plan end-to-end and settles it. Reviewed adversarially by Fable (no crypto mistake).

## What was tested
Present Windows' **OWNER** host EC keypair (DPAPI-extracted → `pairing-fields.json`) from Linux via
`rev`, so the sensor authenticates us AS the owner → hypothesis: MOC (`0x96`/`0x99`) unblocks.

- Builder: `prototype/build_owner_pdata.py` → `prototype/pdata/<sid>.owner.pdata`
  (68 B priv LE ‖ 400 host_cert ‖ 400 sensor_cert). Runs offline; **all validations passed**:
  - tag-3 (cert_type=0, 71-B DER sig) verifies against this sensor's `10.1-kf` pubkey ⇒ SENSOR cert;
    tag-1 (cert_type=2, 32-B sig) ⇒ owner HOST cert.
  - tag-3 sensor cert is **byte-identical** to the sensor cert in our P1 `.pdata` (same device) ✓
  - the tag-2 private scalar (LE) **derives to the tag-1 host-cert pubkey** ✓ (proves scalar
    endianness + cert pairing; a wrong endianness could not land on the curve).
  - owner host cert / priv **differ** from our Linux P1 identity ✓
- Probe: `prototype/p2_moc.py ownertest` (new) — TLS up with the owner pdata, then `0x96 01`
  create-enroll with **no finger** (auth is checked before frame-presence).

## Result — MOC gate UNCHANGED as the authenticated owner
```
TLS handshake (0xC02E)              -> established   (owner cert accepted)
0x96 01 create-enroll  (ownertest) -> 0x0405        host-not-authorized  (was 0x0405)
0x50 GET_CERT_EX       (diag)       -> 0x0401        host-not-authorized  (was 0x0401)
```
Presenting the genuine owner identity lifted **nothing** in the `0x04xx` family.

## Two caveats from Fable — both closed live, making the negative airtight

**(A) Does the sensor actually verify client proof-of-possession, or only see the owner cert?**
In `rev` the TLS premaster is ephemeral ECDH (`tls/cipher/ecc.py:70,84`, independent of the host
key); the host **private** key is used only to sign the CertificateVerify over the transcript
(`ecc.py:79-81`). So "TLS established" alone could mean the sensor ignored client-auth.
**Test:** built a pdata with the owner certs but the **wrong** (Linux) private key and brought up TLS.
**Result:** the sensor returned a **remote TLS alert `ILLEGAL_PARAMETER` (47)** and refused the
handshake. ⇒ **the sensor DOES verify the client CertificateVerify** against the presented host cert.
Therefore the owner run genuinely proved possession of the owner private key and the sensor accepted
it. Real mutual auth, real owner — still `0x0405`.

**(B) Did the sensor map our session to the "owner slot"? (read host-partition pid 2 as owner.)**
`p2_moc.py partinfo` as owner vs as the Linux non-owner returned **byte-identical** pid-2 content
(`0100900100003f5f170041bcea99…`). ⇒ **pid-2 is a SINGLE SHARED partition, not per-host** — this
**corrects findings/30's "per-host" claim.** The 1246-B type-2 blob currently in pid-2 is our own
**findings/37 leftover** (its tag-1 cert pubkey starts `41bcea99` = the Linux host cert, NOT the
owner's `6b3b740d`), and it carries a **valid version-tag + pairing container (SHA-256 OK)** — yet
MOC is still `0x0405`. So partition *content* is conclusively **not** the gate (re-confirms
findings/37 interpretation (iii)), and pid-2 was the wrong instrument for "owner-slot mapping."

## Verdict
**No mistake — the strong hypothesis is simply wrong.** "Owner = keypair, so authenticating with the
keypair = being the owner for MOC" is false on this firmware. The sensor cryptographically verified us
as the owner (client cert + CertificateVerify proof-of-possession) and **still** denied MOC and cert
reads. The `0x04xx` gate is a **sensor-side ownership-authorization STATE** set by a one-time
provisioning transaction (findings/39: NiseCore `0x4f`/`0xe`/`0x10`, zero callers in the shipped USB
DLL, absent from `rev`) that is reproduced by **none** of: the `0x93` pairing, TLS host-key identity
(even verified-owner), or host-partition content.

## Consequence
The **non-destructive owner-key path (findings/42) is EXHAUSTED.** On this single Windows-owned unit,
every non-destructive lever is now spent:
- reset/take-ownership (`0x10`/`0x4f`) — owner-gated / no builder (findings/36/39),
- cert_type — the sensor's grant, not a host input (findings/41); and findings/42 confirms the
  **owner's own** host cert is `cert_type=2`, same as ours ⇒ cert_type carries no owner signal,
- partition content — inert (findings/37 + this),
- owner keypair over verified mutual TLS — inert (this).

Remaining routes are unchanged and all heavy/destructive: a **fresh-Windows t=0 "add this machine"
capture** (Frida CNG plaintext) to read the exact post-TLS/pre-`0x96` authorize sequence, or reversing
the **NiseCore** engine, or the **factory-fresh 2nd unit paired FIRST from Linux** (findings/32 GO
path). The built-in Synaptics `06cb:0126` remains the working reader.

## Artifacts
`prototype/build_owner_pdata.py` (offline builder+validator), `prototype/p2_moc.py`
(`mode_ownertest` + `VERIMARK_PDATA` env override), `prototype/pdata/<sid>.owner.pdata` (git-ignored;
holds the owner private key). Input `pairing-fields.json` / `plain.bin` are git-ignored secrets.
