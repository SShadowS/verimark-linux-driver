# Windows pairing-capture runbook (VeriMark Desktop 047d:00f2)

Goal: record the **fresh `0x93` pairing + host-authorization** flow that a first-time Windows
setup performs, so we can reproduce it on Linux. All our prior captures were already-paired
steady-state; this one forces pairing to happen *on camera*.

Capture is **dual-layer** and both matter:
- **USBPcap** → the pre-TLS wire bytes (cleartext `0x93`, partition `0x3e/0x3f/0x41` writes).
- **Frida CNG hook** → the in-TLS plaintext + session key (anything after TLS comes up, incl. any
  authorization command we've never seen). This is the layer that actually answers the question.

## Prerequisites (one-time, on the Windows debug box)
1. **Python 3** on PATH (`python --version`). `capture.bat` will `pip install frida-tools` on first run.
2. **USBPcap** installed → https://desowin.org/usbpcap/  (reboot after install). Without it you only
   get the Frida plaintext, not the wire bytes. Verify: `C:\Program Files\USBPcap\USBPcapCMD.exe` exists.
3. Copy this whole `verimark-driver` folder to the Windows box (or at least `tools\`).

## The capture — run in THIS order
> Ordering is critical: pairing fires the instant the driver re-inits the device, so **capture must
> already be running before you replug.** The unpair step only clears state; it does not capture.

1. **Unpair** — right-click `tools\win-unpair-verimark.ps1` → *Run with PowerShell* (it self-elevates).
   It backs up + deletes the Synaptics `PairingData` registry, clears the Hello DB, and removes the
   PnP device instance. Leaves the machine looking like a brand-new host to the sensor.
   - If the reader is currently plugged, that's fine — leave it; you'll replug in step 3.

2. **Start capture** — double-click `tools\capture-pairing.bat` (self-elevates). Wait until it prints
   the `PAIRING CAPTURE MODE` box and confirms `capturing \\.\USBPcapN -> ...`. Now it's recording.
   - (equivalent: `capture.bat --pairing`, or `python tools\win-capture.py --pairing`)

3. **Trigger fresh pairing (while recording):**
   a. **Unplug the VeriMark, wait 3s, plug it back in.** (Re-enumeration → driver init → `0x93`.)
   b. Settings → Accounts → Sign-in options → **Fingerprint recognition → Set up** → enroll a finger,
      swipe until complete. This first post-unpair setup runs pairing + host-authorization.
   c. Optional: *Remove* the finger, then set up again / verify once, to also catch steady-state.

4. **Stop** — return to the capture window and press **ENTER**. It stops USBPcap + Frida and lists
   artifacts in `captures\`:
   - `win-cng-<pid>.log`  — session key + `PLAINTEXT-OUT/-IN` (the decrypted protocol)
   - `win-usb-*-hubN.pcap` — the raw wire capture (multiple root hubs; we filter on Linux)

5. **Copy the whole `captures\` folder back to the Linux box**, into `verimark-driver/captures/win/`.

## What we'll diff on Linux (so you know it worked)
- The **`win-cng` log should now contain `0x93`** (it never did before) plus **whatever command(s)
  run between `0x93` and the first `0x96`** — that gap is the host-authorization we're missing.
- Cross-check the **USBPcap** for the cleartext `0x93` request bytes and any `0x41` partition write,
  to confirm the exact type-2 content Windows commits (plaintext vs wrapped) — settles findings/37.
- Sanity: `PLAINTEXT-OUT` first opcodes should start at pairing/init, not at `0x19` steady-state.

## Troubleshooting
- **"Could not uniquely identify the VeriMark WUDFHost"** → the biometric host process wasn't up yet.
  Plug the reader in, open Sign-in options once, then re-run. Or pass `--pid <N>` from `frida-ps`.
- **"refused to load frida-agent" / injection fails** → `win-capture.py` already relocates the
  frida-agent tmp dir with RX for LOCAL/NETWORK SERVICE; make sure you ran it **elevated** (the .bat
  self-elevates). Core Isolation/Memory Integrity can also block it — toggle off if needed.
- **No `0x93` in the resulting log** → the device paired before capture started (missed the window).
  Re-run: unpair (step 1) → start capture (step 2) → *then* replug (step 3). The replug MUST be after
  capture is live.
- **USBPcap missing** → you still get the Frida plaintext (which is the important layer); install
  USBPcap and re-run if we also need the raw wire bytes.
```
