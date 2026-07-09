# Runbook — capture a virgin Windows host's first-ever VeriMark enroll

> **⚠️ LIKELY UNNECESSARY (2026-07-09):** the enroll gate was resolved as a truncated-command bug (findings/49) — enroll now returns 0x0000 from Linux. This capture is no longer the critical path; keep only if the full guided enroll+verify unexpectedly fails.

**Goal:** record the ONE thing we've never seen — the authorization transaction a brand-new host
performs between "TLS established" and "first `0x96` ENROLL returns success". Diffing that wrapped
command stream against `rev` tells us exactly what to send from Linux.

**Machine:** a Windows PC that is a **VERIFIED never-owner** of this sensor (047d:00f2) — Windows Hello
fingerprint was **never** set up on THIS dongle on that PC. Do **not** plug the sensor into it until
step 5.

> 🔒 **Prerequisite — the PC must be a true never-owner, or the run proves nothing.** Ownership is
> first-pairer-wins state *in the sensor*; a PC that ever enrolled this dongle is a **prior owner**, and
> its "first" enroll is just a re-pair that would succeed on any theory. Before plugging in, verify on
> that PC:
> - **No fingerprint enrolled for this device** — Settings → Accounts → Sign-in options → Fingerprint
>   shows nothing set up (and you personally never set it up here).
> - **No prior Synaptics/VeriMark pairing** — `reg query "HKLM\SOFTWARE\Synaptics" /s 2>nul` and the
>   Hello DB (`C:\Windows\System32\WinBioDatabase\`) show no VeriMark/`047d` entries.
>
> If in doubt, use a different PC — a contaminated host silently invalidates the entire capture.

> ⚠️ **Read this first — coverage is what makes the result trustworthy.** For THIS experiment the
> authoritative layer is the **pre-TLS USB wire** (the `0x93` PAIR content + any `0x3f`/`0x41`
> partition writes), NOT the frida plaintext — the pairing happens before TLS and never passes through
> the bcrypt hook. So:
> - **USBPcap is MANDATORY, not optional.** A "we saw nothing new" result is only believable if USBPcap
>   provably recorded `047d:00f2` traffic. Do not run without it.
> - **The success case may be a NULL result.** If ownership is sensor-internal (the leading model), a
>   virgin host's bytes will look identical to ours and enroll will still be granted — that *is* the
>   finding, and it's only decisive with complete two-layer coverage.
> - Ideal instrumentation is **deterministic t=0 injection** (frida attached before the driver's entry
>   point), not best-effort early-attach which can lose the init handshake window. See "Instrumentation
>   notes" at the bottom.

---

## Step 0 — try the cheaper Linux-side test FIRST (before you borrow the PC)
Borrowing a 3rd Windows PC is the expensive last resort. The leading hypothesis (findings/47) is that
the gate is a **missing per-session enroll state/mode**, *not* host ownership — and that is testable for
free on Linux, non-destructively, with the owner key we already extracted:

```
sudo VERIMARK_CONFIRM=1 $PWD/.venv/bin/python prototype/p2_moc.py ownerpair
```
(run from the repo root with the sensor plugged in; the `VERIMARK_CONFIRM=1` guard is required because
this sends a `0x93` PAIR **write**. You'll need to tap the sensor during the guided enroll loop.)

This re-pairs (`0x93`) with the extracted **owner** key and then runs the **full guided enroll
choreography** — the one cell findings/47 flags as never-yet-run (owner identity + real frame
choreography *together*). Rationale and exact design live in **findings/47** and **findings/48** — don't
duplicate them here.

- If enroll **succeeds** → done; no Windows capture needed.
- **Only if `0x96 01` still returns `0x0405`** (BAD_PARAM) is the Windows virgin-host capture below
  worth the effort.

---

# Windows virgin-host capture — do this ONLY if Step 0 returned `0x0405`

## 0. One-time setup on the virgin PC
1. Install Python 3 (python.org), then in an **Administrator** PowerShell/cmd: `pip install frida-tools`.
2. Copy this repo's `tools\` folder to the PC (needs `win-capture.py`, `frida-hook-cng.js`,
   `capture.bat`). A `captures\` folder will be created next to it.
3. **Install USBPcap (MANDATORY)** from https://desowin.org/usbpcap/ (reboot if it asks). This is the
   **authoritative layer**, not an optional extra: the pre-TLS `0x93` pairing and the storage
   `0x3f`/`0x41` writes — the actual discriminator we're testing — are cleartext on the wire and NEVER
   pass through the frida CNG hook. Frida is the **secondary** layer (it only sees post-TLS plaintext).
   Do not run the capture without USBPcap.
4. (If Windows won't auto-fetch the driver in step 5 without internet, pre-stage it: from your main PC
   copy `C:\Windows\System32\DriverStore\FileRepository\*syna*` and `pnputil /add-driver <the .inf>
   /install` on the virgin PC. Usually not needed if it has internet.)

## 1. Arm the capture (ORDER IS CRITICAL — rig must be live before the sensor first appears)

**Prefer deterministic t=0 injection.** `--early-attach` is best-effort — its own docstring in
`win-capture.py` warns it is "NOT a hard guarantee": if the driver finishes its init/handshake crypto
within frida's inject latency (~100–300 ms) of the host spawning, we lose the in-TLS init window *and
its session key*, and a "nothing new" result is then **untrustworthy**. Pick one:

**Option A (preferred) — IFEO Debugger on WUDFHost.exe (deterministic).** frida `spawn()` IS supported
on Windows (only `enable_spawn_gating` is not), so a relauncher can start WUDFHost under frida from its
first instruction. Point the Image File Execution Options `Debugger` key at a small relauncher:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WUDFHost.exe" ^
  /v Debugger /t REG_SZ /d "C:\Python\python.exe C:\path\to\tools\ifeo-frida-launch.py" /f
```
where `ifeo-frida-launch.py` (you write it, ~10 lines) does `frida.spawn(sys.argv[1:])` of WUDFHost
with `frida-hook-cng.js` (or frida-gadget), then `resume()`. The hook is guaranteed in place before the
driver runs.
> ⚠️ **REMOVE the key the moment the run is done** — it intercepts *every* WUDFHost launch (printers,
> BLE, the built-in reader), so leaving it wired will break other devices:
> ```
> reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WUDFHost.exe" /v Debugger /f
> ```

**Option B (fallback) — best-effort early-attach.** If wiring IFEO is too much, from `tools\`:
```
capture.bat --early-attach
```
Wait until it prints **"early-attach poller running"**. (Use `--early-attach`, NOT `--pairing` — the
one-shot `--pairing` mode orphans frida across the driver's replug respawn and logs zero crypto. This
was the bug that wasted earlier runs.) **A null result from Option B is "best-effort, not
conclusive"** — it cannot tell "no new command" apart from "we missed the init window." Only Option A
makes a frida null decisive.

6. **Confirm USBPcap is live** — `capture.bat` launches it; watch for `capturing \\.\USBPcapN -> ...`.
   USBPcap is the authoritative layer here and captures regardless of the frida timing race above, so it
   must be running before the sensor first appears.

## 2. Trigger the first-ever enroll
7. **Now plug the sensor into the virgin PC for the first time.** Windows installs/loads the driver.
   Option A: the IFEO launcher spawns the hooked WUDFHost automatically. Option B: the poller catches
   the WUDFHost the moment it spawns — watch for `[early] WUDFHost ... attaching` then
   `BIOMETRIC-HOST ... arming`.
8. Settings → Accounts → Sign-in options → Fingerprint → **Set up**. Enroll a finger (swipe until it
   completes — the sensor needs coverage to reach 0x7f, ~8 touches).
9. When enrollment reports success, press **ENTER** in the capture window to stop and save.

## 3. Collect
10. Zip the whole `captures\` folder and copy it back to the Linux box (into this repo's `captures/`).
    Key files: `win-usb-*.pcap` (**authoritative** wire bytes — the `0x93` pair + `0x3f`/`0x41`
    storage) and `win-cng-early-*.log` (secondary: post-TLS decrypted plaintext + session key).

---

## What I'll do with it (Linux side)
We are hunting the **per-session enroll state/mode entry sequence** — the session setup a virgin host
carries into MOC that our byte-identical `rev` commands lack (findings/47: the gate is `GEN_BAD_PARAM` /
missing-state, **not** an "ownership opcode"). So:
- Census every `PLAINTEXT-OUT` opcode *and* the pre-TLS wire in the window **TLS-established → first
  `0x96` == `0x0000`**, and diff against what `rev`/`p2_moc.py` emit — looking for a state-establishing
  command, or an argument/order difference, rather than a single magic take-ownership opcode.
- Byte-map that sequence's request/response layout (including any `0x6c` PairingContext continuation).
- Add it to `rev` before its `0x96` call and re-test enroll from Linux.

## Quick self-check you can run on the PC before copying back

**First — did USBPcap actually record the dongle?** A "nothing new" verdict is meaningless if the wire
capture is empty. After copying back to Linux:
```
./tools/extract-usb-payloads.py captures/win-usb-*.pcap --min-len 8 | head
```
This MUST show `047d:00f2` traffic (the `0x93` pair, storage `0x3f`/`0x41`). If it's empty, USBPcap
missed the hub — re-run the capture; do **not** trust any conclusion drawn from that run.

Then the CNG plaintext:
```
# from tools\ , newest CNG log — did enroll actually succeed and what opcodes fired?
powershell "$l=(gci captures\win-cng-early-*.log|sort LastWriteTime|select -last 1).FullName; \
  Select-String -Path $l -Pattern 'PLAINTEXT-OUT \(\d+\): ([0-9a-f]{2})' -AllMatches | \
  %{$_.Matches}|%{$_.Groups[1].Value}|Group-Object|Sort-Object Count -Descending"
```
A healthy capture shows `0x96` several times and ends with status `0x0000`; the interesting part is
any opcode you DON'T see in `reference/protocol/command-reference.json`'s rev column — especially
`0x0e`, `0x4f`, `0x10`, `0x50` (or a changed argument/order on a command rev already sends).

---

## Instrumentation notes / logical limits
- **No ncrypt/TPM hook needed.** Static RE (findings/DECISION, `10-crypto-map`) shows the driver uses
  **bcrypt + crypt32 only** — no `ncrypt.dll`, no TPM/`ncrypt` key storage. The `ncrypt.dll` entries
  in `frida-hook-cng.js` TARGETS are harmless no-ops here (they simply never resolve/fire). The added
  `BCryptSignHash`/`BCryptVerifySignature`/`BCryptGenerateKeyPair`/`BCryptFinalizeKeyPair` hooks are
  cheap insurance — they capture the host-cert self-signing input (`SIGN-HASH-IN`) in cleartext.
- **No WBDI IOCTL hooking.** The WBDI IOCTL surface is **host → driver** (Windows Biometric Framework
  down into the UMDF driver), which sits *above* the sensor channel we care about. It carries no sensor
  wire bytes and no session state — hooking it adds noise, not signal.
- **Interpreting the result:**
  - If the single-owner-TOFU / missing-state model holds, **SUCCESS looks like a NULL result**:
    the virgin host's bytes are byte-identical to ours, yet enroll is granted. That *is* the finding —
    but it is decisive **only** with full two-layer coverage (USBPcap + frida) AND deterministic t=0
    injection (Option A). A null under best-effort early-attach (Option B) proves nothing.
  - If instead the 3rd PC **enrolls with something extra** on the wire or in plaintext, capture the
    whole **TLS-established → first `0x96`** window plus the pre-TLS `0x93`, and diff both against `rev`.
