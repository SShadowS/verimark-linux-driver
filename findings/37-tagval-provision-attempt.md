# findings/37 — TagVal-container provision (the PAIRING-DELTA fix): NEGATIVE but diagnostic

**Date:** 2026-07-08. Per PAIRING-DELTA-TRACE §5: findings/30 wrote the WRONG pid-2 type-2 blob
(rev's raw `SensorPairingData` = priv‖host_cert‖sensor_cert, 868 B, incl. host private key).
Windows writes a **TagVal container** (tags 1=host_cert, 4=P256 params, 3=sensor_cert, 0=version).
Rewrote it correctly (`p2_moc.py mode_provision2`, using rev's `WinTagValContainer`) and re-probed.

## Method
`provision2`: TLS from saved pdata → build container `[tag:u16 LE][len:u32 LE][data]` per entry
with tags 1/3/0 (tag-4 P256 params omitted first pass — needs the 420-B `DAT_180142130` dump;
`TAG4=1` knob added for later) → `0x3f` FORMAT pid 2 → `0x41` WRITE → read-back → probe `0x50`+`0x96 01`.

## Result — NEGATIVE (gate unchanged) but the write behavior is informative
```
TagVal container: tags=[0,1,3]  type2 len=820
0x41 WRITE pid=2 off=0 len=896 -> status=0x0000 written=896   ACCEPTED
read-back: OK                                                  stored VERBATIM
gate 0x50 GET_CERT -> 0x0401   (was 0x0401)                    UNCHANGED
gate 0x96 01       -> 0x0405   (was 0x0405)                    UNCHANGED
```
- The correct-format TagVal write was **accepted (0x0000)** and **stored byte-for-byte** (read-back
  verbatim), yet the enroll/cert gate **did not lift.**

## Interpretation (with Fable's pre-registered ambiguity)
A negative here does **NOT** refute the partition-content hypothesis; it is **ambiguous** across:
- **(i)** format still subtly wrong (e.g. tag-4 P256 params required — untested this pass), OR
- **(ii)** the sensor expects a **firmware-key-wrapped** partition (NOT DPAPI — DPAPI is
  self-contradictory: sensor firmware can't unwrap a Windows-keyed blob, so DPAPI applies only to
  the host **registry cache**, not the sensor write), OR
- **(iii)** — **now the leading read** — the sensor treats pid-2 as **host-side scratch it does NOT
  gate enroll on**; enroll-auth keys off the pairing/TLS identity in firmware, not partition content.

**Why (iii) is now favored:** the write was accepted with success AND stored verbatim (dumb store),
and the gate was unaffected. Per the diagnostics Fable requested (write-status + read-back): an
"accepted + verbatim + gate-unchanged" partition looks like scratch storage, not an authorization
oracle. The static trace proves Windows *writes* pid-2 but **never proves the sensor *reads* pid-2
to gate enroll** — that premise is unverified, and this result leans against it.

## Corrected model (Fable review of the phase list)
- "Host-authorization" is **not a distinct protocol phase** (no post-`0x93` wire command exists) —
  it's an enroll-authorized **state** that should emerge from pairing done right. Relabelled.
- Pairing (phase B) mechanics are proven live; its **authorization-conferring** side is unvalidated
  (= exactly this gap). Not "fully proven."
- The `0x93` request + host cert are byte-identical to Windows (PAIRING-DELTA) — pairing bytes are
  NOT the delta.

## UPDATE — full container WITH tag-4 (P256 params) also NEGATIVE → (i) format ruled out
Dumped the real 420-B P-256 params from Ghidra (`DAT_180142130` → `prototype/p256_params.bin`;
verified: contains P-256 prime/order/Gx/Gy in little-endian). Re-ran with `TAG4=1` = the COMPLETE
Windows container, tags **1/4/3/0**, type2=1246 B:
```
0x41 WRITE pid=2 len=1322 -> status=0x0000 written=1322   ACCEPTED
read-back: OK                                              VERBATIM
gate 0x50 -> 0x0401   gate 0x96 01 -> 0x0405               UNCHANGED
```
⇒ The byte-exact Windows partition content does NOT lift the gate. **(i) "format still wrong" is
now RULED OUT** — we wrote the exact tag set with correct params. Remaining: **(ii) firmware-wrapped**
or, strongly favored, **(iii) the sensor does not gate enroll on pid-2 at all** (accepted + verbatim
+ inert = scratch storage). The partition-content hypothesis (c) is now **most likely wrong**: the
enroll gate almost certainly keys off the pairing/TLS host identity in firmware, not pid-2 content.

## Next (per plan): a fresh-Windows t=0 capture is now the ground truth
The static surface is exhausted; only a **fresh-Windows "add this machine" capture** resolves it —
it shows, in cleartext-inside-TLS (needs the Frida CNG plaintext hook), the EXACT pid-2 `0x41`
bytes Windows writes (settling (i) format and plaintext-vs-wrapped (ii)) AND definitively whether
ANY sensor command besides `0x93`+`0x3e/0x3f/0x40/0x41` precedes the first `0x96` (settling (iii)).
Two cheap things still worth trying on the current unit before/instead:
- **`TAG4=1`** with the real 420-B `DAT_180142130` params (rules in/out (i)).
- Re-confirm the user's **additive multi-machine** premise still holds (does machine A still auth
  after switching to B?) — if it's actually silent single-owner transfer, the whole partition model
  is the wrong shape.

## Reversibility / safety
Non-destructive: `0x3f` FORMAT re-empties pid 2; Windows' own pid-2 is a *different per-host*
partition; the 3 Windows templates (DB2) were never touched. `mode_provision2` kept alongside the
old `mode_provision` (the 868-B version) for the record.
