# findings/45 — Prior-art survey: no public technique makes a foreign host enroll-authorized

> **⚠️ SUPERSEDED (2026-07-09, findings/49):** the enroll "ownership gate" (0x0405) was a 2-byte truncated command, not sensor-side ownership. See findings/49.

**Date:** 2026-07-09. Deep multi-source research (99-agent fan-out, 17 primary sources, 25 claims
adversarially verified, 18 confirmed / 7 refuted) surveying every open-source Linux fingerprint
driver + RE effort for a solution to our MOC ownership blocker. **Verdict: none exists.**

## Direct answer to the blocker
There is **no known open-source technique** to make a second/foreign host enroll-authorized on an
already-owned Synaptics "Tudor"/Prometheus sensor. **No** surveyed repo reverse-engineered the
`0x4f`/`0x10`/`0x0e` (TAKE_OWNERSHIP_EX2 / RESET_OWNERSHIP / PROVISION) path from the non-owner side.

## Synaptics Tudor projects — all hit our exact wall
| Repo | Reaches | Enroll? |
|---|---|---|
| **Popax21/synaTudor** `rev` (our base) | pairing + TLS + DB reads | ✗ — no on-chip enroll; host-side matching only |
| Popax21/synaTudor `relink` (default) | wraps the Windows DLL | ✗ — "split off after RE hit dead ends"; UMDF-1.x/COM blocks 047d:00f2 (issue #51) |
| **todorz/synaTudor-USB052** | fork of `relink` | ✗ — same relink dead end |
| **MarcelineVPQ/elitebook840-fingerprint** | ~90% `rev` PORT to FS7605 (06cb:00f0, fw **10.1**) — pairs, TLS, reads secure DB | ✗ — **"Dead end — needs a secure enroll the open driver can't do"; `Enrollment failed (104)` = BMKT_OUT_OF_MEMORY.** Same firmware family, same wall as us. |

The MarcelineVPQ port is the closest public analog — an independent effort that reached the identical
layer on the same fw 10.1 Tudor family and stopped at exactly our gate. Strong external corroboration
that the wall is the architecture, not our implementation.

## The ONE demonstrated enroll-on-owned technique — Blackwing "A Touch of Pwn"
The only public case of enrolling on an already-owned Synaptics sensor. It is **host-credential
cloning, NOT ownership reset/claim** (verified 3-0; the over-reach "valid TLS cred alone = enroll, no
gate" was **refuted 0-3**):
- The sensor stores the host client cert/key as **"an encrypted blob in a readable flash region on
  the sensor,"** encrypted "by a key derived from the machine's **product name and serial number** —
  retrieved from BIOS via ACPI (also on the laptop's bottom sticker)."
- Attack: read blob → decrypt with product-name+serial → negotiate TLS as the incumbent host →
  enumerate template IDs → enroll. **Impersonation of the existing owner; no `0x4f`/`0x10`/`0x0e`.**

### Reconciliation with our findings/42/43 (important)
**We already did credential cloning — and it FAILED on this unit.** findings/42 extracted the owner
keypair (via Windows DPAPI), findings/43 presented it over verified mutual TLS (sensor accepted the
owner identity; wrong-priv → `ILLEGAL_PARAMETER` proves it validated possession) → MOC still `0x0405`.
Blackwing's key derivation (product-name+serial) is only the **decryption key for the blob**; once
decrypted it yields the same host keypair we already hold from DPAPI. So Blackwing's method reduces to
what we tried. Two explanations for the success/fail split, neither a free win:
1. **Firmware/model:** Blackwing hit built-in laptop sensors (Windows-Hello-bypass context); our
   VeriMark fw 10.1 may enforce a stricter per-unit enroll gate. findings/43 is direct evidence this
   unit refuses even the verified owner identity, and MarcelineVPQ (fw 10.1) hit the same wall.
2. **Unread sensor-flash context:** Blackwing recovered from *sensor flash*; we recovered from the
   *Windows registry*. If the sensor holds owner-binding state beyond the keypair in a flash region we
   haven't dumped (we only read STORAGE partition pid-2; descriptors exist for pid types 1/2/3), that
   could differ. **Low probability** (the keypair is the credential, and findings/43 proved the keypair
   authenticates), but it's the one cheap untried thread.

## Partition sweep (the survey's one cheap thread) — CHECKED, nothing new
`p2_moc.py partsweep` + a pid sweep read every STORAGE partition non-destructively. `0x3e` shows 3
partition types: type-1 @0x51000000 cap 647168 (the DB2 template store), type-2 @0x5109f000 cap 4096
(host partition), type-3 @0x5109e000 cap 4096. Raw-read (`0x40`) results:
- **pid-2 → readable**: our own findings/37 leftover (TLV version-tag + 1246-B pairing container; cert
  magic at off 82 = the **Linux** host cert). No owner credential.
- **pid-1 → `0x06e7`** (not raw-readable): it's the DB2 secure object store — visible only via DB2 cmds
  (`0x9f` lists the Windows template GUIDs), not a credential blob.
- **pid-3 → `0x06e7`** (not raw-readable): the one partition that *could* hold owner-binding state, but
  it refuses raw reads with a **non-auth** error (0x06xx family, not 0x04xx).
- pids 0/4/5 → `0x0403` (nonexistent).
- **`0x50` GET_CERT_EX (the Blackwing target — the host client cert) → `0x0401` on all args.**
⇒ No additional *readable* owner-binding state exists for a non-owner host. The Blackwing "read the
credential from a readable flash region" weakness is effectively **closed on this fw-10.1 unit**: the
only raw-readable partition is our own, the unknown partition (pid-3) refuses raw reads, and the cert
read is authorization-gated. This reinforces findings/43 — we are not one unread blob away from a fix.

## Other MOC families — nothing transferable (all verified)
- **Goodix** (goodix-fp-dump, neodyme): host **writes** a hardcoded white-box PSK (`preset_psk_write`),
  no owner gate, freely re-provisionable (TOFU re-claim regenerates a random PSK). No owner concept →
  nothing to port to a first-pairer-wins gate.
- **EgisTec/SDCP** (TenSeventy7, antoskuu forks): host **self-generates ephemeral ECDH** per session,
  no persistent owner slot; the fork fixes are enrollment **persistence**, not authorization.
- **Validity90/vfs009x/python-validity**: match-on-**host** (image output), freely re-pairable, never
  hit an owner gate — protocol lineage only.

## Authoritative docs (SDCP / ESS)
Microsoft SDCP + ESS confirm the enroll-authorization gate is **deliberate** but enforce it **host-side
in a VBS trustlet** (`id ← MAC(s,"enroll"||n)`, an "authorized enrollment database") — and document
**no** device reset / ownership reset / re-pairing procedure. (Our unit uses Synaptics' custom TLS, not
SDCP, per Blackwing — but the docs still offer no reset path.)

## Bottom line / best base
Best base remains **Popax21/synaTudor `rev`** (what we already use) — the furthest-advanced clean-room
Synaptics MOC code; no fork extends past the enroll-authorization wall. The decisive non-destructive
path is unchanged: **a factory-fresh second unit paired FIRST from Linux** (TOFU claims the empty owner
slot). Sources: Popax21/synaTudor (+issue #51), todorz/synaTudor-USB052, MarcelineVPQ/elitebook840-
fingerprint, blackwinghq.com "A Touch of Pwn", goodix-fp-dump, neodyme.io, TenSeventy7/antoskuu
egismoc-sdcp, microsoft/SecureDeviceConnectionProtocol, MS ESS docs, nmikhailov/Validity90.
