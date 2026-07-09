# 2026-07-09 — VeriMark driver P2: owner-key impersonation is a SOUND NEGATIVE

## Problem
On-chip MOC enroll/verify (`0x96`/`0x99`) on the Kensington VeriMark Desktop (`047d:00f2`) is gated
`0x0405` "host-not-authorized" for our Linux host, which paired *second* (findings/30). The
findings/42 plan: extract Windows' **owner** host EC keypair via DPAPI (delivered as
`pairing-fields.json`), present it from Linux via `rev`, and — since owner identity is just the
keypair (no TPM; findings/DECISION/34) — get an authorized session that unblocks MOC.

## What was done (non-destructive; device + passwordless sudo)
- Set up a repo-root `.venv` (cryptography + pyusb; system python 3.14 had neither).
- **`prototype/build_owner_pdata.py`** — offline builder/validator: parses the Synaptics TagVal
  entries, loads the tag-2 32-B scalar (LE) → P-256 priv, identifies the sensor cert (tag-3, verifies
  against `10.1-kf`) vs owner host cert (tag-1), and writes `<sid>.owner.pdata` in rev's
  `SensorPairingData` format. **All checks passed**: sensor cert byte-identical to our P1 pdata's
  (same device); the private scalar derives to the host-cert pubkey (proves endianness + pairing);
  owner identity distinct from our Linux P1 key.
- **`prototype/p2_moc.py`**: added `VERIMARK_PDATA` env override + a no-finger `ownertest` mode
  (TLS up → `0x96 01` gate probe).

## Result — negative, and now airtight (Fable-reviewed)
- Owner pdata → TLS **established** (owner cert accepted), but `0x96 01` → **`0x0405`** and
  `0x50 GET_CERT_EX` → **`0x0401`**: presenting the genuine owner identity lifted nothing.
- Asked **Fable** "did we make a mistake, should've worked?" → verdict **SOUND NEGATIVE, no crypto
  bug** (the LE scalar + cert-ID are self-validating). It flagged two caveats; both closed live:
  - **(A) Sensor verifies client proof-of-possession?** Built an owner-cert + **wrong-priv** pdata;
    TLS handshake was **refused with a remote alert `ILLEGAL_PARAMETER`**. ⇒ the sensor *does* verify
    the client CertificateVerify (`rev tls/cipher/ecc.py:79-81`), so the owner run truly authenticated
    as owner. Real mutual auth, real owner — still `0x0405`.
  - **(B) Did the sensor map us to the owner slot? (read pid-2 as owner.)** `partinfo` as owner vs
    non-owner returned **byte-identical** pid-2 ⇒ **pid-2 is a shared partition, not per-host**
    (corrects findings/30). Its content is our findings/37 leftover (valid version-tag + pairing,
    SHA-256 OK) and MOC is still blocked ⇒ partition content is conclusively not the gate.

## Conclusion
The strong hypothesis is wrong: the `0x04xx` gate is a **sensor-side ownership STATE** set by the
one-time NiseCore provisioning transaction (`0x4f`/`0xe`/`0x10`, out-of-DLL, absent from `rev`;
findings/39), reproduced by none of `0x93` pairing, verified-owner TLS identity, or partition content.
**The non-destructive owner-key path (findings/42) is EXHAUSTED** — every non-destructive lever on
this Windows-owned unit is now spent. Unchanged heavy routes: fresh-Windows t=0 "add this machine"
Frida capture, reverse NiseCore, or a **factory-fresh 2nd unit paired FIRST from Linux** (findings/32).
Built-in Synaptics `06cb:0126` remains the working reader.

## Artifacts
`findings/43-owner-key-impersonation-NEGATIVE.md`; `prototype/build_owner_pdata.py`;
`prototype/p2_moc.py` (`ownertest` + `VERIMARK_PDATA`); git-ignored `prototype/pdata/<sid>.owner.pdata`
+ input secrets `pairing-fields.json`/`plain.bin` (added to `.gitignore` along with `.venv/`).

## Open next steps
No non-destructive local options remain. A GO result still requires either the fresh-Windows
provisioning capture / NiseCore RE, or the ~$50 second-unit "pair-first-from-Linux" experiment.
