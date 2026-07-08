# Resume prompt — VeriMark Linux driver (Fedora box)

Paste the block below into a fresh Claude Code session on the Linux box to continue.
It is self-contained: it names the state, the hard facts (so you don't re-derive
them), what's reusable, what's left, and the first actions.

---

You are resuming a reverse-engineering → driver project. The Windows RE phase is
**complete** and the verdict is **GO**. Your job now is the Linux side: write a
**libfprint driver** for the Kensington VeriMark Desktop fingerprint reader
(**USB `047d:00f2`**, Synaptics silicon).

**First, read these committed findings in order — they are ground truth, live-verified:**
- `findings/24-libfprint-map.md` — the reuse map + GO verdict (read first).
- `findings/23-command-bytemap.md` — the command opcode byte-map.
- `findings/22-live-secure-channel.md` — the secure channel + captured TLS handshake.
- `findings/25-struct-layouts-and-recapture.md` — response struct field offsets.
- `findings/30-synatudor-port.md` — synaTudor build status on this Fedora box.
- `findings/20-protocol.md`, `findings/21-command-reference.md` — USB transport + IOCTL map.

**Hard facts already established (do NOT re-RE these):**

- **USB transport:** iface1 is vendor-class with a **single endpoint — `0x83`
  interrupt-IN, 8 bytes.** There is **NO bulk pipe and no OUT pipe.** Commands go out
  as **EP0 control transfers**; responses/events arrive on the **interrupt-IN `0x83`**
  (TLS records chunked across transfers). iface0 is HID (unused for this).
- **Secure channel:** TLS 1.2, negotiated suite
  **`0xC02E` = TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384**. **Static ECDH** P-256 (not
  ECDHE): premaster = ECDH(host-ephemeral-priv, device-cert key). Server-auth only, **no
  client cert**. Server certificate is a **400-byte custom Synaptics container (NOT
  X.509)**. App-data record layout, verified byte-for-byte (480/480):
  `17 03 03 ‖ len16 ‖ explicit_nonce[8] ‖ AES-256-GCM-ciphertext ‖ tag[16]`
  (GCM nonce = 4-byte per-direction salt ‖ 8-byte explicit; two directional keys). The
  handshake is carried inside VCSFW command **`0x44` TLS_DATA** (`44 00 00 00 ‖ record`).
- **Command set = Synaptics Tudor "VCSFW", identical to the `06cb` MOC sensors** (8/10
  opcodes matched a public reference byte-for-byte). Opcodes seen live:

  | op | name | role |
  |---|---|---|
  | `0x19` | GET_START_INFO | open/version (68-B resp) |
  | `0x39` | LED_EX2 | LED animation (optional) |
  | `0x44` | TLS_DATA | carries the TLS handshake |
  | `0x80`/`0x81` | FRAME_ACQ / FRAME_FINISH | frame capture |
  | `0x86`/`0x87` | EVENT_CONFIG / EVENT_READ | event-driven capture loop |
  | `0x93` | PAIR | one-time provisioning (not captured; synaTudor has it) |
  | `0x96` | **MOC enroll-step** | resp = coverage bitmask `01→7f` + quality (**genuine RE gap**) |
  | `0x99` | **MOC identify** | returns 177-B matched template (GUID+SID) or `0x0509` no-match (**genuine RE gap**) |
  | `0x9e`/`0x9f`/`0xa0`/`0xa1`/`0xa3` | DB2 GET_DB_INFO / GET_OBJ_LIST / GET_OBJ_INFO / GET_OBJ_DATA / DELETE_OBJ | on-sensor template store (max ~100 slots) |

  Responses are framed `u16 status (LE, 0x0000=OK) ‖ body`. Field offsets for each are
  in `findings/25`.

**Reuse map (this is the leverage):**
- **`Popax21/synaTudor` `rev` branch is the reference reimplementation** — a from-scratch
  pure-Python Tudor driver: full TLS-1.2 ECDHE/ECDH-ECDSA-AES256-GCM stack, VCSFW command
  enum (`pydrv/tudor/comm.py`), protocol RE doc (`rev/proto.txt`), custom-cert parsing,
  and a native `libfprint/.../drivers/tudor.c`. It targets `06cb:00be`. **Reuse its whole
  secure layer + DB2 storage + pairing.** Two caveats: (1) it does **image capture + host
  NBIS matching, not on-chip MOC** — so it does *not* implement `0x96`/`0x99`; (2) it
  assumes **bulk** endpoints — our device has none.
- **Upstream libfprint `synaptics` driver is the WRONG protocol** (bmkt, cleartext) —
  ~zero reuse. Do not start from it.

**What you must build (the delta):**
1. A **USB transport shim**: EP0 control-out + interrupt-IN `0x83` (replace synaTudor's
   bulk assumption). See `findings/20`/`21` for the exact primitives.
2. **MOC enroll/identify** using `0x96` (enroll-step, coverage bitmask progress → drive
   `fpi_device_enroll_progress`) and `0x99` (identify/match). These two opcodes are the
   only ones no public RE mapped — use `findings/23` semantics + the git-ignored
   `re/ghidra-out/moc/` decompiles of `synaFpAdapter132.dll` (our lead source) if present.
3. The **libfprint driver glue** (enroll/verify/delete/list callbacks → the opcodes).

**Constraints & notes:**
- **Clean-room:** document/implement *behavior* only (opcodes, sizes, framing). Do not
  copy vendor code. synaTudor's `rev` is an independent reimplementation you may study.
- The Windows box still has the **capture rig** (`tools/win-capture.py` + `capture.bat`)
  as a reproducible **oracle** — if you hit an unknown exchange, ask the human to capture
  it there. Note `0x9f`/`0xa1`/`0x93` were confirmed **not reachable from the Windows UI**
  (use synaTudor's format for them).
- The **raw captures are NOT in git** (large + PII); every byte-level fact is already in
  the findings. `re/` (Ghidra output + synaTudor clone) is also git-ignored and was built
  on this Fedora box per `findings/30`.
- This repo uses the **superpowers** skill workflow: start with `brainstorming`, then
  `writing-plans` before writing driver code.

**First actions:**
1. Read the findings above. Confirm the device: `lsusb -d 047d:00f2` and re-check the
   `re/synaTudor` build state from `findings/30` (it built cleanly on this box).
2. Brainstorm the driver architecture (transport shim ↔ reuse synaTudor TLS/DB2 ↔ MOC
   `0x96`/`0x99`), then write an implementation plan.
3. Bring up the transport + TLS handshake first — get a secure session established and a
   `GET_START_INFO` (`0x19`) round-trip working end-to-end before touching enroll/verify.

---
