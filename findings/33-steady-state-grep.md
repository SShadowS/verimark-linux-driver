# findings/33 — Grep of steady-state Windows captures for the ownership opcodes: ABSENT

**Date:** 2026-07-08. Fable's "step 0" before building a VM: check whether the missing
host-authorization opcodes (`0x6c/0x4f/0x10/0xe/0x50`) already appear in our existing
decrypted Windows plaintext. If they did, ownership is re-run per operation and we already
own the sequence → no VM needed. If absent, ownership is a distinct one-time provisioning
event → the fresh-host capture is earned.

## Method (read-only)
Both CNG plaintext logs decrypt the TLS channel to `PLAINTEXT-OUT`/`PLAINTEXT-IN` lines
(first byte = VCSFW opcode):
- `captures/win/win-cng-4868.log`  — enroll + verify session
- `captures/win/win-cng-62340.log` — enroll + verify session (larger, incl. `0x39` LED path)

## Result — the ownership family is ABSENT from both
Distinct OUT opcodes across **both** logs:
```
19 39 80 81 86 87 96 99 9e a0 a3
```
Direct search for `0x6c / 0x4f / 0x10 / 0xe / 0x50` as an OUT command first-byte: **0 hits** in
either log.

Corroboration that these are genuine **already-authorized steady-state** sessions (i.e. the
place ownership would live if it were per-operation):
- `0x99 01` identify → `0905` (LE `0x0509`, dedup/no-match OK) — **not** the `0x0405` gate.
- `0x96 01` create-enroll → `000000000000` (success); `0x96 02` add-sample → 82-B records with
  the coverage bitmask climbing `01→03→07→0f→1f…` toward `0x7f` — the enroll actually runs.
- **Zero** `0x0405`/`0x0401` gate errors anywhere in either log. On Linux those same commands
  return `0x0405`. ⇒ the Windows host in these captures is authorized; ours is not.
- Neither log opens with any provisioning — first OUT is `0x19` (session tag) then straight into
  `0x86/0x87` event setup and `0x80/0x81` frame capture. No `0x93` pair, no ownership.

## Conclusion
Ownership/authorization is **NOT** a per-operation step folded into enroll/verify — it does not
appear in steady-state traffic at all. It is a **distinct, earlier, one-time provisioning event**
that our captures never covered (they all start from an already-provisioned Windows host).

⇒ The grep did **not** moot the VM; it **earned** it. The only capture that can contain the
host-authorization handshake is one taken while a **fresh, never-provisioned host** provisions
from scratch. Confirms the plan in the P1/advisor thread: fresh Windows VM + USB passthrough +
in-VM Frida CNG hook, diff vs `0x93`-only, extract the extra `0xe/0x4f/0x10/0x6c/0x50` sequence.

Caveats carried forward (from Fable): the in-VM Frida hook is the only dependable capture
(usbmon sees only `17 03 03` ciphertext); build the VM with **swtpm/vTPM + Secure Boot** or
Hello may refuse biometric enroll; and even a clean capture may reveal a **non-forgeable**
credential (per-device / MS-PKI attestation) that a Linux host cannot synthesize — Fable's odds:
~30% unblock / ~50% hard wall / ~20% inconclusive.
