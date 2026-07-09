# findings/48 — 10-agent adversarial review swarm: standing conclusions pressure-tested

**Date:** 2026-07-09. Before committing to the next (expensive) move, a 10-reviewer adversarial swarm
was run against the project's standing conclusions — especially the findings/44/45 "CLOSED /
irreversible OTP-ownership" verdict. Each reviewer was tasked to *break* a specific claim and report a
verdict with load-bearing evidence, not to confirm. **Net result: the "closed" verdict is OVERTURNED
to "not found," the ownership framing is retracted (per findings/47), and one best-supported,
never-run, non-destructive experiment is promoted to the top of the queue.** This finding records each
verdict and the corrected project state.

## Per-reviewer verdicts

| # | Claim under test | Verdict | Load-bearing evidence |
|---|---|---|---|
| 1 | HS signing key correct for this FW10.1 unit | **HOLDS (verified)** | rev `genhskey.py` == DLL derivation, byte-exact; Hyp-2 dead |
| 2 | "Foreign never-owner Windows host enrolled additively" | **SHAKY / over-read** | machine-2 enroll never captured; the one capture is owner re-pair |
| 3 | findings/44 "no host-side path EXISTS" | **REOPENED (category error)** | 0x96/0x99 also have "no builder" yet are emitted via passthrough |
| 4 | Hyp-1 enroll-time authorization command | **named forms REFUTED**; virgin form untestable | rev is a strict opcode superset of Windows; 0x0e/0x50/0x4f/0x10 in zero plaintext logs |
| 5 | Hyp-3 owner-key re-pair | **WORTH TESTING (strongest lever)** | Windows reuses persistent owner key on every re-pair (222730 == pairing-fields.json) |
| 6 | Capture runbook sufficiency | **design OK, load-bearing bug** | authoritative layer is USB wire (0x93 cleartext), not CNG plaintext |
| 7 | Unpair main PC to re-virgin it | **correct, no self-reset** | DoUnpairing/OnResetOwnership emit nothing to sensor |
| 8 | 0x04xx == "ownership" family | **MAJOR correction** | 0x0401/04/05 = BAD_CMD/OP_DENIED/BAD_PARAM; OTP codes never fire |
| 9 | rev init handshake completeness | **complete (superset)** | rev sends every pre-TLS opcode Windows sends, plus more |
| 10 | Prior art / public technique | **still none public** | 0x4f/0x0e/0x10 named in enums, built nowhere; one unverified lead |

### 1 — HS-KEY IDENTITY (HOLDS, verified) → see findings/46
rev's `genhskey.py` HS signing key is **byte-identical** to the FW10.1 DLL's derivation. `palSynaKmGet`
assembles the 32-byte const `[0:16]=secret 717cd72d…`, `[16:32]=prf_input head 2512a764…`;
`FUN_1800a64e0` transform → `aaaa`; `palSymKeyGen` = TLS1.2-PRF-SHA256. Endianness closed: the DLL
byte-reverses the PRF then imports `BCRYPT_ECCPRIVATE_BLOB` (big-endian) == rev's
`int.from_bytes(…,"little")`; shared scalar `0xe8a2a2b6…01b36a86`. ⇒ **Hyp-2 (stale HS constants /
Linux-only re-key) is DEAD.** The HS key is a *global* Synaptics secret, so it cannot be the `0x0405`
discriminator — the distinguishing action must be behavioral, not key identity.

### 2 — CROSS-MACHINE ADDITIVE (SHAKY / over-read; corollary REFUTED)
The claim "a never-owner foreign Windows host enrolled additively" is **UNVERIFIED**. Machine-2's
enroll was **never captured** — the only source is the user's memory of swapping machines
(`CROSS-MACHINE-OWNERSHIP-CAPTURE.md` §RESULT, sourced to findings/36). The one captured "fresh
pairing" (`captures/win-cng-early-20260708-222730.log` + `…222731-hub5.pcap`) is confirmed at **both**
layers (wire + decrypted CNG) to be the **standing OWNER re-pairing**: no `0x4f/0x10/0x0e/0x6c`, no
storage-write `0x3f/0x41` ⇒ a pre-provisioned re-pair. Innocent explanations fit every byte (the "other
machines" were likely each PRIOR OWNERS of this dongle, or a silent single-owner transfer occurred).
Our own Linux second-host pairing was a **JOIN** (didn't wipe the Windows templates), **not** an
additive **ENROLL** — and still hit `0x0405`. ⇒ the corollary "a host-side authorization path exists"
is **not** supported by this observation. (Does not by itself refute Hyp-3; it just removes a claimed
proof.)

### 3 — findings/44 REOPENING ("CLOSED" was a category error)
The load-bearing inference "no builder for `0x4f/0x0e/0x10` ⇒ never emitted ⇒ closed" is **invalid**,
because `0x96/0x99` **also** have "no builder" yet are demonstrably emitted — via the generic
passthrough **`tudorSendAnyCommand` (`FUN_180062270`)**, where `opcode = blob[0]` produced by the
statically-linked matcher/VFM via an **indirect vtable call** (`tudorIoctl` has zero static callers).
That opcode set is **matcher-data-dependent, not statically bounded**; `0x4f/0x0e/0x10` can ride the
same path on a state branch static analysis cannot exclude. findings/44 must be **downgraded** from "no
host-side path EXISTS" to "**none FOUND via static builder-scan + already-authorized captures.**"
findings/44's own cited sources already hedged this (`OWNERSHIP-PROVISION-TRACE §6/§7`,
`PAIRING-DELTA-TRACE §5/§6`: "not specifiable / needs a virgin capture").

### 4 — Hyp-1 ENROLL-TIME TRANSACTION (named candidates refuted; virgin form untestable)
A full opcode census of every `captures/win-cng-*.log` shows Windows sends **no opcode rev cannot** —
rev is a strict **superset** (it even sends `0x50`, which Windows never does). `0x0e/0x50/0x4f/0x10`
appear in **zero** plaintext logs, including the successful-enroll log. ⇒ **no enroll-time
authorization command exists**; only a first-**pairing**-time (t=0) form survives, decidable solely by
a virgin capture. This narrows Hyp-1 to the pairing window and hands the question to reviewer #6's
runbook.

### 5 — Hyp-3 OWNER-KEY RE-PAIR (WORTH TESTING — strongest untried non-destructive lever)
Byte-verified that Windows **reuses its persistent owner key on every re-pair**: capture 222730's
exported EC key == the DPAPI owner keypair in `pairing-fields.json` exactly. ⇒ ownership is bound to
the **persistent key value**, not an ephemeral. The **untested cell**: `0x93` re-pair **with the owner
key**, *then* `0x96`. P1 used a fresh non-owner key (⇒ `0x0405`); findings/43 **skipped `0x93`** and ran
with a stale Linux host-partition (⇒ `0x0405`). Hyp-3 is exactly the Windows-222730 procedure, **never
run from Linux**. Low risk / reversible (Windows re-derives from DPAPI); one low-probability
irreversible tail — an OTP ownership slot — but a **same-owner re-pair shouldn't burn a new slot**.

### 6 — CAPTURE SUFFICIENCY (design OK, runbook had a load-bearing error)
For a **virgin** capture the **authoritative layer is the pre-TLS USB wire** (`0x93` content, `0x3f/41`),
**not** the frida CNG plaintext — `0x93` is cleartext and bypasses bcrypt, so a CNG-only rig would miss
the decisive bytes. Fixes to the runbook: **USBPcap MANDATORY**; switch best-effort `--early-attach`
→ **deterministic t=0 injection** (IFEO `Debugger` → `frida.spawn` + gadget) so the init handshake
window cannot be lost; add **`BCryptSignHash`** to the hook; and document that **if the TOFU model
holds, the success case is a NULL result** (byte-identical wire, enroll still granted) — trustworthy
only with full coverage. ncrypt/TPM is statically ruled out (bcrypt + crypt32 only); WBDI IOCTL hooking
is unnecessary.

### 7 — UNPAIR MAIN PC (correct, no self-reset)
`tools/win-unpair-verimark.ps1` clears only host-side registry + `WinBioDatabase`; it sends **nothing**
to the sensor. Decompiled `DoUnpairing` / `OnResetOwnership` / `vfmSecurityUnPair` emit no
`0x10/0x4f/0x3f` to the sensor; the authorized owner has **no driver path to clear its own sensor
seat** (`0x10/0x4f` have no builder). ⇒ the main PC **cannot** be made virgin again; a genuinely
never-owner host is required for a virgin capture. Caveat raised: if single-owner TOFU holds, even a
fresh 3rd PC on this already-owned sensor yields a **null**.

### 8 — FRAMING CHALLENGE (MAJOR correction) → see findings/47
`0x0401 = SENSOR_BAD_CMD`, `0x0404 = GEN_OPERATION_DENIED`, `0x0405 = GEN_BAD_PARAM`. The firmware's
real ownership codes (`OUT_OF_OTP_OWNERSHIP=207`, `NEED_TO_RESET_OWNER=204`) are **never** emitted on
our failures. It is **not identity** (the owner key didn't lift it — findings/43), and `0x0405` also
fires for a wrong sub-arg on the *working* `0x9f` (findings/29 l.83). Better framing: a **missing
per-session enroll STATE/MODE** (likely the NiseCore `0x6c` continuation), **not ownership**. Cheapest
experiment: owner pdata + FULL choreography (the untested cell — reviewer #5's lever plus finger
choreography).

### 9 — rev INIT COMPLETENESS (complete — superset)
rev sends every pre-TLS opcode Windows sends — `0x01` GET_VERSION, `0x8e` READ_IOTA (09/1a), `0x19`
GET_START_INFO, `0x93` — **plus** more (`0x8e` 2e/2f, `0x82`). The gate is **not** a missing or
malformed init command.

### 10 — PRIOR ART (still nobody public)
No public artifact shows the first-enroll authorization transaction; `0x4f/0x0e/0x10` are named in
enums but built nowhere. MarcelineVPQ `error 104` is a **bmkt PARSER bug**, distinct from our `0x0405`
authorization failure. **One UNVERIFIED lead:** libfprint **MR !595** ("Kensington VeriMark DT driver,"
author *s-celles*) — could **not** be confirmed (GitLab anti-bot wall); may be confabulation; needs a
manual browser check at
`https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/595`. **Do NOT rely on it.**

## Corrected project state
The standing "**closed / irreversible sensor-ownership**" verdict (findings/44, findings/45) is
**OVERTURNED**. Two independent reviewers dismantle it: #3 shows the "no builder ⇒ never emitted"
inference is a category error (the same argument would wrongly "close" `0x96/0x99`, which *are* sent),
and #8 shows the `0x04xx` codes we actually receive are generic `BAD_CMD`/`BAD_PARAM`, **not** the
firmware's OTP-ownership codes. The block is **most likely a reproducible missing per-session enroll
state/mode**, not an OTP-fuse ownership lock. The decisive data was **never as closed as claimed** —
findings/44 should read "no host-side path **FOUND** (static builder-scan + already-authorized
captures)," and the mechanism section of findings/44/45 is retracted per findings/47. What *does* still
hold: the HS key is correct (#1), rev's init is complete (#9), the main PC cannot self-reset (#7), and
no public technique exists (#10).

## Go-forward (ranked)
1. **Hyp-3 + full choreography — owner-key `0x93` re-pair, then guided enroll, on the existing
   device.** Cheapest, decisive, and it tests the best-supported hypothesis (#5 + #8): the never-run
   cell of owner *persistent key* re-pairing followed by real-finger `0x96` choreography. Being wired
   up as a new `p2_moc.py ownerpair` mode. Reversible; low irreversible tail (same-owner re-pair
   shouldn't burn an OTP slot).
2. **Fresh-never-owner Windows t=0 capture — hardened runbook** (#6): **mandatory USBPcap** + **t=0
   injection**, now aimed at finding the **state/mode-entry sequence**, not "proving ownership." Note
   the **null-result caveat** — under TOFU the success case is a byte-identical wire, meaningful only
   with full coverage. Requires the dongle back on Windows + a genuinely never-owner host (#7).
3. **Reverse the matcher's `tudorSendAnyCommand` blob-builders** (#3; static, heavy). The only way to
   learn the `0x4f/0x0e/0x10` argument layout **without** a virgin capture — follow the indirect
   vtable call out of the statically-linked matcher/VFM into the blob constructors.

**Note:** the ~$50 second-unit path (factory-fresh unit paired FIRST from Linux, findings/32) remains
the guaranteed-GO route, but is **user-excluded** and so is omitted from the ranking above.
