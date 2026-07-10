# RESUME — VeriMark libfprint driver: on-device tuning → shippable

**Paste this whole file as the opening prompt of a fresh session to continue.**

## TL;DR — where we are
The clean-room **C libfprint driver** for the Kensington VeriMark Desktop
(USB `047d:00f2`, Synaptics "Tudor" match-on-chip) **works end-to-end on real
hardware through fprintd**: a finger *enrolled* and then *verified (matched)*.
The offline port, the libfprint **1.94.10** build, and a reversible
SELinux-safe install are all done and committed. We are now in on-device
**speed/UX tuning** to make it shippable. The latest speed fix (phantom-press
async drain) is **deployed and verified swipe-free** but **not yet confirmed
with a real-finger enroll** — that confirmation is step 1 below.

## Goal for this session
Finish making the driver shippable: confirm/complete the speed tuning on the
device, strip the temporary instrumentation, close the small deferred
device-behaviour items, and land a clean committed driver (ideally
upstream-quality).

## How to work here (READ FIRST)
- **Repo:** `/home/sshadows/nogit/LocalChanges/verimark-driver` (git; remote
  `github.com/SShadowS/verimark-linux-driver`, **public**). Commit as the user:
  `sudo -u sshadows git ...` (keeps file ownership sane). **Never commit
  secrets** — `pairing-fields.json`, `prototype/pdata/*.pdata`,
  `reference/protocol/transcripts/` are git-ignored; the `0x96 03` finalize SID
  in `verimark-moc.c` is a redacted placeholder synthesized from the local uid.
- **You (assistant) are ROOT** in this session. The user (`sshadows`) has **no
  passwordless sudo** — so **YOU** do all on-device system steps (rebuild,
  deploy, install, systemctl); the **USER only physically swipes the sensor**.
  Do not tell the user to run sudo commands; do them yourself.
- **SELinux is ENFORCING.** fprintd runs confined (`fprintd_t`) and **cannot
  load a libfprint out of `/home`** — the built lib MUST live in a `lib_t`
  system path (see deploy recipe). `usbmon`/debugfs is blocked (no USB sniffing).
- **Device `047d:00f2` is plugged in.** Templates are disposable
  (`fprintd-delete "$USER"` then re-enroll freely).
- **Reference implementation (proven on this device):** `prototype/p2_moc.py`
  (+ `prototype/control_comm.py`) — the Python driver the C port mirrors.
  Backstory: `findings/49` (13-byte truncated-command breakthrough),
  `findings/51` (enroll+verify working in Python), `findings/52` (C port).

## Build tree + deploy recipe
- Upstream libfprint 1.94.10 clone: `/home/sshadows/verimark-libfprint`.
- Work copy with `verimark` registered + built:
  `/home/sshadows/verimark-build/libfprint` (configured
  `-Ddrivers=verimark -Dgtk-examples=false -Ddoc=false -Dintrospection=false`).
- **Deployed lib:** `/usr/local/lib64/verimark-libfprint/libfprint-2.so.2.0.0`
  (label `lib_t`). fprintd drop-in
  `/etc/systemd/system/fprintd.service.d/10-verimark-libfprint.conf` points
  `LD_LIBRARY_PATH` there.
- **After editing `driver/*.c`, rebuild + redeploy:**
  ```bash
  \cp -f driver/verimark*.c driver/verimark*.h \
     /home/sshadows/verimark-build/libfprint/libfprint/drivers/verimark/
  meson compile -C /home/sshadows/verimark-build/libfprint/build
  install -m0755 /home/sshadows/verimark-build/libfprint/build/libfprint/libfprint-2.so.2.0.0 \
     /usr/local/lib64/verimark-libfprint/libfprint-2.so.2.0.0
  chcon -t lib_t /usr/local/lib64/verimark-libfprint/libfprint-2.so.2.0.0
  systemctl restart fprintd 2>/dev/null || systemctl start fprintd
  ```
  (`cp` is aliased to `cp -i` in this shell — use `\cp -f`.)
- Automation: `driver/setup-libfprint-build.sh` (deps + clone upstream +
  register + build), `driver/install-verimark.sh` (relocate to `lib_t` +
  drop-in + udev; `--uninstall` reverts). Both work; the manual recipe above is
  faster for the edit→test loop.

## Reproduce / test
- **Swipe-free** (no finger, great for dev_open + phantom-press work):
  `timeout 8 fprintd-enroll 2>&1 | tail -3` as root — opens the device
  (dev_open = pairing `0x93` + TLS handshake, ~330 ms), then press-wait should
  **pend** until the timeout (a phantom press instead shows
  `press-wait SUCCESS (0/1 ms)`).
- **Full enroll/verify** (needs the USER to swipe, ~8 press-and-hold taps to
  coverage `0x7f`): `fprintd-delete "$USER"; fprintd-enroll` then
  `fprintd-verify`.
- **Driver logs:** `journalctl -u fprintd --since "2 min ago"` (or `-f`). The
  temporary instrumentation logs `VMK-TIME:` lines (g_warning) — grep for them.

## THE debug-loop lesson (do not relearn the hard way)
**Never issue a synchronous USB transfer (`g_usb_device_*_transfer`) inside the
async `FpiSsm` flow** — it corrupts in-flight async EP0 reads and truncates the
next wrapped MOC response (`unwrap: truncated record body`). Use only async
`FpiUsbTransfer` in SSM states. Synchronous transfers are OK **only** in
`dev_open` (its TLS handshake is deliberately synchronous).

## Fixes already made (the journey)
1. **RT1 handshake** — the sensor returns a **non-standard TLS ServerHello
   version `0x0383`**; the C parser rejected anything but `0x0303`. Dropped the
   version check (`verimark-tls.c`). *(committed)*
2. **SELinux** — relocate the built lib to `/usr/local/lib64` + `chcon lib_t`;
   `install-verimark.sh` does this + a reversible fprintd drop-in. *(committed)*
3. **install/build script bugs** — pipefail driver-detection (`nm|grep -q`
   SIGPIPE), stale/old-fork work-tree reuse, upstream dict-format meson
   registration, the `python3-embed` red herring (it was the *old synaTudor
   fork's* Python-embedding `tudor` driver, not ours). *(committed)*
4. **Speed/UX — IN PROGRESS, deployed, NOT yet real-finger-confirmed:** the
   sensor **echoes a genuine `FINGER_PRESS` packet `01 00 00 00 00 00 <seq>`
   ~0–3 ms after every arm of the finger-event mask** (`0x86 EVENT_CONFIG`) — a
   phantom press that armed a frame-wait for a finger that wasn't there and
   burned the frame timeout, looping (this was the "painfully slow" +
   "enroll-retry-scan" the user saw). Fixed with an **async** drain
   (`verimark_intr_drain_async`, `verimark-transport.c`) called in
   `CAP_WAIT_PRESS` before arming the real press-wait; frame timeout cut
   `5000→1500 ms`; plus a **synchronous** drain in `dev_open` (safe there).
   Verified swipe-free: press-wait now pends (zero phantoms). **Temp `VMK-TIME`
   timing instrumentation is still in the source** (behind a `VMK_TIME()` macro).

## NEXT STEPS
1. **Confirm the speed fix with ONE real enroll** — ask the user to
   `fprintd-delete "$USER"; fprintd-enroll` and swipe; capture `VMK-TIME`
   per-tap timing. Expect ~1 s/tap, no stalls, completes, and `fprintd-verify`
   matches. If any step still drags, tune (per-tap add-sample round-trip, the
   3× `0x86 EVENT_CONFIG` re-arm round-trips per capture, poll cadence).
2. **Strip the temp instrumentation** — remove everything tagged
   `TEMP timing instrumentation` / `VMK-TIME` / the `VMK_TIME()` macro across
   `driver/*.c` / `driver/verimark.h`; rebuild + redeploy clean.
3. **Commit the finalized speed fix** (clean, no instrumentation).
4. **Deferred device-behaviour items** (findings/51 §5, findings/52):
   - minted template-id vs the `0x9f` DB-list id (driver stores both) — verify
     `fprintd-list`/`-delete` address the slot the enroll created.
   - driver-synthesized SID acceptance at `0x96 03` — it worked in the first
     enroll; confirm it's robust.
   - `0xa5 DB2_FORMAT` clear payload is a best-effort guess — verify
     `fprintd-delete`/clear-storage works.
   - defensive: close/reset the TLS session on handshake failure (a failed
     handshake can leave the sensor mid-handshake, alerting the next attempt
     until it resets).
5. **Shippable polish** — consider migrating the crypto core off the legacy
   `EC_KEY` API (currently `OPENSSL_API_COMPAT 0x10100000L`) to modern EVP; a
   code-review pass; and optionally preparing an upstream libfprint MR.

## Key files
`driver/verimark.c` (FpDevice glue: `dev_open` pair+handshake, vfuncs, dev_open
drain), `driver/verimark-moc.c` (capture/enroll/verify/storage SSMs + the
phantom async-drain call in `CAP_WAIT_PRESS`), `driver/verimark-transport.c`
(EP0 async transport, `verimark_intr_wait_async`, `verimark_intr_drain_async`,
`verimark_intr_drain_sync`), `driver/verimark-tls.c` (handshake + record layer),
`driver/verimark-tls-crypto.c` (PRF/GCM/ECDH/ECDSA — offline-tested),
`driver/verimark-pairing.c` (`0x93` + 868-B pdata), `driver/verimark.h`
(opcodes/constants/`FpiDeviceVerimark`). Offline tests: `driver/tests/`
(12/12 — `meson test -C driver/tests/build`). Plans/notes:
`driver/PORTING-PLAN.md`, `findings/49`, `findings/51`, `findings/52`.
