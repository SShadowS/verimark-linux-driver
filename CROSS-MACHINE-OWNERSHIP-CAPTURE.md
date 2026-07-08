# Cross-machine ownership-capture plan (VeriMark 047d:00f2)

## RESULT / CORRECTION (2026-07-08 — after the first attempt)
The first attempt (Phase A on machine 2 + Phase B = machine 1 return leg) **did not** capture the
authorization. Machine 1's return-leg capture (`captures/win-cng-early-20260708-222730.log` +
`win-usb-...222731-hub5.pcap`) showed: a fresh `0x93` pairing on the wire, TLS, and a **successful
enroll** (`0x96`×10, `0x99`→`0x0509`, all `0x0000`) — but **zero ownership opcodes**
(`0x4f`/`0x10`/`0x0e`/`0x6c`) on the wire *or* in the decrypted plaintext.

**Lessons:**
1. There is **no separate on-wire "take ownership" transaction for an already-provisioned host.**
   Authorization is durable per-host state in sensor flash. Machine 1 is a long-provisioned host —
   its slot persists, so a re-pair just refreshes it and enroll works. **Machine 1 can NEVER reveal
   the first-time authorization; stop using its return leg.**
2. Machine 2 (foreign host) enrolled successfully AND machine 1 came back still authorized →
   **multi-owner / additive** model (each host keeps its own slot), not exclusive single-owner.
   Tentative but important: Linux may be able to **add its slot without wiping Windows** (would
   overturn the "ownership is destructive" conclusion in findings/30/34).
3. **The authorization fires only on a host's FIRST-EVER enroll.** Capture must run on a **fresh
   host** (never enrolled this sensor), with the rig live **before the sensor first touches it**.

⇒ Use the **CORRECTED PROCEDURE** below (fresh machine + rig-first). The old Phase-A/Phase-B flow is
kept at the bottom for history but is superseded.

---


**Goal:** capture the sensor **ownership** transaction (`0x4f` TAKE_OWNERSHIP / `0x10`
RESET_OWNERSHIP / `0x0e` PROVISION / `0x6c` PairingContext) as decrypted plaintext. It never fires
on the RE box because that box already owns the sensor. Force it by making a *different* host own
the sensor, then capture the RE box re-acquiring ownership.

**Why this and not unplug/unpair tricks:** ownership is durable state in the sensor's flash
(survives power-cycle and host-side unpair). Only a `RESET`/`TAKE` command — or another host taking
it — changes it. See findings/30, findings/38.

**Everything here is destructive to fingerprint enrollments on BOTH machines. That is fine — it is
an RE exercise. Do not run this on a machine whose Windows Hello you care about.**

---

## Roles
- **Machine 1** = the RE box (has the capture rig: `tools/win-capture.py`, frida, USBPcap). Currently
  owns the sensor.
- **Machine 2** = any *other* Windows box with the Synaptics VeriMark driver. Ownership is NOT tied
  to a specific Windows install (findings/DECISION: ephemeral self-generated host key, no TPM/DPAPI
  binding), so any Windows works. If Machine 2 has never seen the device, plugging it in should pull
  the driver via Windows Update (needs internet, may take a few minutes).

## What we expect (and the fork we are testing)
A foreign host (one that does NOT own the sensor) attempting to enroll must first acquire ownership.
The open question: does Windows **auto-`RESET`+`TAKE`** for a foreign sensor, or does it **hard-refuse**
(strict single-owner)?
- If auto-take → the transaction fires and we capture it. 
- If hard-refuse → we capture the *refusal* path (still reveals the opcodes/attempt). Either way, data.

The ownership acquisition can be captured on **either** foreign-host event: Machine 2 taking it from
Machine 1, OR Machine 1 re-taking it from Machine 2 on return. Machine 1's return leg is easiest
(rig already there). Capturing Machine 2 too (if you can rig it) is the robust option and is the only
way to see the refusal case if Machine 2 can't enroll.

---

## CORRECTED PROCEDURE — fresh machine, rig-first, first-ever enroll
Machine 3 = any Windows box that has **never enrolled this sensor**. This captures the additive
authorization a brand-new host performs on its first enroll.

**Setup on Machine 3 (once):**
1. Install Python 3, then `pip install frida-tools`.
2. Copy `tools\win-capture.py`, `tools\frida-hook-cng.js`, `tools\capture.bat` from this repo to
   Machine 3 (same relative layout: a `tools\` folder; `captures\` is created next to it).
3. (Optional, for wire bytes) install USBPcap from usbpcap.com. Without it the rig runs frida-only
   (still gets the decrypted plaintext — that's the part we need).

**Capture (order is critical):**
4. **Do NOT plug the sensor into Machine 3 yet.** Keep it first-time.
5. Start the rig: `tools\capture.bat --early-attach` → wait for "early-attach poller running".
6. **Now plug the sensor into Machine 3 for the first time.** Windows installs the driver (needs
   internet, or pre-stage it via `pnputil /add-driver <syna .inf> /install` from Machine 1's
   `C:\Windows\System32\DriverStore\FileRepository\*syna*`). The poller catches the WUDFHost the
   moment it spawns — watch for `[early] WUDFHost ... attaching` then `BIOMETRIC-HOST ... arming`.
7. First-ever enroll: Settings > Accounts > Sign-in options > Fingerprint > **Set up**.
8. Press ENTER to stop. Copy `captures\` back for analysis.

**What to look for** (the whole point):
- Any opcode in PLAINTEXT-OUT that machine 1 never showed — especially `0x4f`/`0x10`/`0x0e`/`0x6c`
  (ownership) or `0x50` (cert). Verify with:
  ```bash
  LOG=$(ls -t captures/win-cng-early-*.log | head -1)
  grep -oE "PLAINTEXT-OUT \([0-9]+\): [0-9a-f]{2}" "$LOG" | grep -oE "[0-9a-f]{2}$" | sort | uniq -c
  ```
- Compare its fresh `0x93` pairing (wire) to `rev`'s `0x93`: if the ownership is *in the pairing*
  (hypothesis H2), the difference lives there, not in a separate opcode.

---

## (SUPERSEDED — history) Phase A / Phase B
### Phase A — dispossess Machine 1 (make Machine 2 the owner)
1. **Machine 1:** confirm the sensor is plugged in and working (a WUDFHost is hosting
   synaWudfBioUsb). Optionally run `tools\win-unpair-verimark.ps1` here to wipe Machine 1's
   host-side pairing (clean "foreign host" state for the return leg).
2. **Move the sensor to Machine 2.**
3. **Machine 2:** Settings > Accounts > Sign-in options > Fingerprint > **Set up**, and enroll a
   finger.
   - *(Optional but recommended — rig Machine 2 too):* before enrolling, run the same capture rig on
     Machine 2 (`tools\capture.bat --early-attach`), then enroll. This captures Machine 2 acquiring
     ownership from a Machine-1-owned sensor — the purest "acquire ownership" event.
   - **Decision point:** if enroll **succeeds** → Machine 2 is now owner; continue to Phase B.
     If enroll **fails / stalls** → the sensor is hard single-owner. Save Machine 2's capture log
     (it holds the refusal) and STOP; report back — the plan's assumption is false and we pivot to
     the static RE (subagent) or a `RESET` we issue ourselves.

### Phase B — capture Machine 1 re-acquiring ownership
4. **Machine 1:** start the capture FIRST:
   ```
   tools\capture.bat --early-attach
   ```
   Wait for "early-attach poller running".
5. **Plug the sensor back into Machine 1** (capture is live; the poller catches the respawned host).
6. **Machine 1:** Settings > Fingerprint > **Set up**, and enroll a finger. Machine 1 is now a
   foreign/dispossessed host facing a Machine-2-owned sensor → it must re-acquire ownership → the
   `0x4f`/`0x10`/`0x0e`/`0x6c` transaction should fire here, on camera.
7. Finish the enroll, then press **ENTER** in the capture window to stop and save.

### Phase C — verify the capture
8. Find the newest log and check for the ownership opcodes in the decrypted plaintext:
   ```bash
   LOG=$(ls -t captures/win-cng-early-*.log | head -1)
   grep -oE "PLAINTEXT-OUT \([0-9]+\): [0-9a-f]+" "$LOG" \
     | grep -oiE ": (4f|10|0e|6c|50)[0-9a-f]*$" | sort | uniq -c
   ```
   - Non-empty → **we caught the ownership transaction.** Copy `captures/` for byte-mapping.
   - Also watch the status flow: a non-owner sees `0x0401`/`0x0405`; after a successful take you
     should see those turn into `0x0000`, and dedup `0x99` return `0x0509` (as in findings/38).

## Cleanup / restore
- The sensor ends up owned by whichever machine took it last, and both machines' Hello enrollments
  are wiped through this. To return a machine to normal, just enroll a finger there again.

## If it works
Combine the captured ownership opcodes with findings/38 (enroll/verify already decoded) → the Linux
driver has the full MOC path. Cost: single-owner — the sensor becomes Linux-owned, so simultaneous
Windows Hello won't work until re-provisioned. Acceptable for a Linux-primary user.
