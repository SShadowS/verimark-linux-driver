# findings/36 — RESET_OWNERSHIP (0x10) attempt on the current unit: owner-gated (0x0401)

> **RETRACTION (2026-07-08, later):** the HEADLINE conclusion below — "this unit can't be taken
> over from Linux" — is **retracted as premature.** It tested the WRONG operation. The user
> pointed out (empirically) that a **fresh Windows machine gains enroll-authorization against this
> already-owned sensor via ordinary Hello 'Sign-in Setup', every time they switch machines, with
> no reset.** So authorization is **additive & per-host**, not single-owner — and Windows never
> calls `RESET_OWNERSHIP` when adding a host. This `0x10 → 0x0401` result therefore proves ONLY
> the narrow fact that **reset is owner-gated** (which stands); it says nothing about whether Linux
> can gain the *additive* host-auth Windows does. Our own data agreed with the user all along:
> Windows' 3 templates SURVIVED our Linux pairing (additive, not a burn). The real gap: Windows'
> setup performs a per-host authorization our `rev`-based `0x93` does not — most likely because our
> pairing is a **basic variant** of Windows' **advanced** host-cert pairing (findings/37). See
> findings/37 for the reopened investigation. Fable retracted its VM-kill and single-owner model.

---


**Date:** 2026-07-08. Per the user's decision (after the base-rate research lowered the
irreversibility fear, findings/34), attempt to clear THIS unit's owner slot with
`0x10 RESET_OWNERSHIP` so the Linux host could re-claim it as first-pairer (findings/35 TOFU).

## Method
`prototype/p2_reset.py` — careful single-shot probe: re-establish TLS from saved pdata (proven
read-only), read provision-state via `GET_VERSION` BEFORE, send **one** `0x10` (no retry/mutation
loop), read state AFTER. USB `dev.reset()` at start to clear lingering-session `0x0315` desync.
We do NOT have the `0x10` wire format (rev/proto.txt names it only; no builder in the shipping
DLL — findings/34), so tried the two natural minimal forms.

## Result — BOTH variants: status 0x0401, provision_state unchanged (PROVISIONED)
| variant | bytes | status | prov before→after |
|---|---|---|---|
| `empty` | `10` | **0x0401** | 3 → 3 |
| `u32z`  | `10 00000000` | **0x0401** | 3 → 3 |

- `0x0401` = the **host-not-authorized** gate — the *same `0x04xx` family* as the `0x0405` we get
  on MOC enroll. The device **understood** the command (structured gate status, not a format/desync
  error like `0x0689`/`0x0315`) and **refused it because we are not the owner.**
- Both payload lengths give the identical `0x0401` ⇒ the rejection is **authorization, not payload
  format.** (A length/format problem would differ between the two.)
- Provision state stayed `3` (PROVISIONED). **No change to the device. Windows enrollments intact.**
  Non-destructive outcome — the sensor validated and refused, exactly as it does for every
  unauthorized op.

## Interpretation — this CONFIRMS the TOFU model and closes the current-unit route
`RESET_OWNERSHIP` is **owner-gated**: you must already BE the owner to clear ownership. Our Linux
host is a paired-but-not-owner host (Windows owns the slot), so it cannot reset. This is exactly
what the first-pairer-wins model predicts:
- The owner (Windows) can reset/re-provision (that's the documented Windows Hello "remove + re-add"
  and the vendor's "factory reset is possible").
- A non-owner host (our Linux, or any second host) is **locked out** of both enroll (`0x96`→`0x0405`)
  AND ownership-reset (`0x10`→`0x0401`).

⇒ **This specific unit cannot be taken over from Linux**, because the only ways to free the owner
slot are (a) the Windows owner running its reset (in-band, on Windows — which just hands ownership
back to Windows), or (b) a factory/manufacturing path we don't have. The wall on THIS unit is now
**empirically confirmed**, not inferred.

## What this does NOT rule out (the remaining GO path is unchanged)
The TOFU model's core claim — that a host claims ownership by being the **first** to `0x93`-pair an
**unowned** sensor — is untouched by this result. `0x0401` here is precisely because the slot is
already owned. A **factory-fresh second unit** (owner slot empty) paired first from Linux would hit
no owner gate. So findings/35 Probe 2 (~$50 second unit, paired first from Linux) remains the one
open, non-destructive path to a working Linux driver.

## Cleanup / safety notes
- `p2_reset.py` does ONE attempt per invocation, explicit `RESET` confirmation gate, no payload
  mutation loop. Do not extend it into a fuzzer against this unit.
- The recurring `0x0315` between back-to-back runs = TLS session left open on the device; fixed by
  the `dev.reset()` at start. Harmless (cleartext GET_VERSION colliding with a live session).
- Device health verified throughout: reads PROVISIONED before and after every attempt; Windows'
  3 templates untouched (never issued a delete).

## USER DECISION (2026-07-08): ownership transfer / breaking Windows is ACCEPTABLE
The user stated explicitly they **do not care if ownership is transferred** or if the reader stops
working on their Windows machines. ⇒ the additive-vs-transfer distinction is **moot** and no longer
gates anything; **destructive routes are fully on the table.** The objective is simply: make the
Linux host enroll-authorized (`0x96` returns success instead of `0x0405`), by whatever mechanism —
replicate Windows' advanced pairing (findings/37 / PAIRING-DELTA-TRACE) even if it takes/transfers
ownership. No need to preserve the Windows enrollments.
