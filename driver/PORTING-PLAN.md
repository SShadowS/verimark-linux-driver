# Porting plan — Python prototype → C libfprint driver

**Goal:** turn the working Python prototype (`prototype/p2_moc.py`, which does full
match-on-chip enroll+verify from Linux on the Kensington VeriMark `047d:00f2`) into a
native C libfprint driver under `driver/`. All hard protocol problems are already
solved (findings/27 transport, findings/46 HS key, findings/49 truncated-command,
findings/51 enroll+verify working). This is an **engineering port**, not more RE.

The reference implementation to mirror is the `rev`-based prototype:
`prototype/control_comm.py` (EP0 transport) + `re/synaTudor-rev/pydrv/tudor/` (TLS,
sensor, pairing) + `prototype/p2_moc.py` (MOC choreography). Read those alongside
this plan — every phase cites the exact file + function it reproduces.

---

## 1. Honest assessment of the existing `driver/` skeleton

The skeleton (`verimark.h`, `verimark.c`, `verimark-tls.h`, `meson.build`) predates
the protocol breakthrough. It was written from **findings/21**, the *Windows IOCTL
adapter surface*, **not** the real Tudor wire protocol. Treat it as a structural
starting point, not a correct spec.

| Skeleton item | Verdict | Why |
|---|---|---|
| `FpDeviceClass` boilerplate, `id_table`, GObject `G_DEFINE_TYPE` | **Reuse** | Correct. `047d:00f2`, `FP_TYPE_DEVICE`, feature flags all right. |
| Feature flags (`IDENTIFY\|VERIFY\|STORAGE\|STORAGE_LIST/DELETE/CLEAR`) | **Reuse** | Correct for a MOC/identify device. |
| SSM decomposition (open / enroll / verify / list / delete / clear) | **Reuse shape** | The *state enums* are close; the *state bodies* are all placeholders (`g_assert_not_reached`). |
| `VerimarkCmd` opcode enum (`0x440004`, `0x44200c`, …) | **DELETE / rewrite** | These are Windows IOCTL function indices, **not** wire opcodes. Real opcodes are Tudor bytes: `0x93 0x96 0x99 0x80 0x81 0x87 0x9e 0x9f 0xa0 0xa3 0x50 0x3e 0x3f 0x40 0x41` (see `tudor/comm.py` `Command`). |
| `verimark_cmd()` transport (`bmRequestType=0x41`, TODO SETUP fields) | **Rewrite** | Real transport is bulk-over-EP0-control: WRITE `0x40/0x16/wValue=(len&7)`, READ `0xc0/0x17` (findings/27, `control_comm.py`). Not a single vendor OUT. |
| `verimark-tls.h` record format (`IV[16] + AES-CBC + HMAC-SHA256`, overhead `0x45`) | **Rewrite** | Negotiated suite is **`0xC02E` = ECDH-ECDSA-AES256-GCM-SHA384** (AEAD), not CBC+HMAC. See `tudor/tls/cipher/encr.py::TlsAEADEncryptionAlgorithm`. |
| `verimark-tls.c` | **Does not exist** | The whole secure channel must be written. |
| `ENROLL_UPDATE` 72-byte struct, `VMK_REGION_*` bitmask | **DELETE** | Fictional. Real add-sample response: coverage at `resp[22]`, quality at `resp[42]`; completion when coverage == `0x7f` (findings/51). |
| `open` = RESET→CONNECT_SECURE→PAIR→GET_STATUS | **Rework** | Real bring-up is `GET_VERSION`→(iotas)→`GET_START_INFO`→verify sensor cert→TLS handshake→`FRAME_STATE_GET` (see `sensor.py::reset/initialize`). |

**Net:** keep ~20% (class wiring, SSM skeleton, USB identity in `verimark.h`).
Rewrite the opcode layer, the transport, and author the entire TLS channel.

---

## 2. Target architecture

```
 fprintd / PAM
      │  (D-Bus)
 ┌────▼──────────────────────────────────────────────┐
 │ FpDevice class  (verimark.c)                       │  dev_open/close/enroll/
 │   FpiSsm state machines per operation              │  verify/identify/list/
 └────┬──────────────────────────────────────────────┘  delete/clear_storage
      │  verimark_cmd(opcode, payload) → status,resp
 ┌────▼──────────────────────────────────────────────┐
 │ MOC command layer  (verimark.c / verimark-moc.c)   │  0x99/0x96 01-04/0x80/
 │   enroll & verify choreography, DB2 storage ops    │  0x81/0x87/0x9e/0x9f/0xa*
 └────┬──────────────────────────────────────────────┘
 ┌────▼──────────────────────────────────────────────┐
 │ TLS 1.2 channel  (verimark-tls.c)  ★ biggest port  │  wrap/unwrap AES-GCM
 │   custom handshake + record layer over libcrypto   │  records; handshake SM
 └────┬──────────────────────────────────────────────┘
 ┌────▼──────────────────────────────────────────────┐
 │ Command/response codec + EP0 transport (verimark.c)│  build 0x40/0x16 WRITE,
 │   async gusb control transfers; interrupt-IN 0x83  │  0xc0/0x17 READ, chunk/pad
 └────┬──────────────────────────────────────────────┘
      │  gusb / FpiUsbTransfer
    USB 047d:00f2  iface 1 (vendor), EP0 control + EP 0x83 interrupt-IN
```

**Ports 1:1 from the prototype (logic identical, language differs):**
- EP0 chunking/padding — `control_comm.py::_ctrl_write/_ctrl_read`.
- TLS handshake message flow + PRF/key-schedule — `tudor/tls/*` (pure algorithm).
- MOC command literals + choreography — `p2_moc.py` (`moc_capture`, `_run_enroll`, `mode_verify`).
- Pairing (`0x93`) + host-cert build + HS-key derivation — `sensor.py::pair`, `pair.py`, findings/46.

**New C work (no prototype equivalent to copy):**
- Everything async: libfprint is a single-threaded event loop; the prototype is
  blocking/synchronous. Every `send_command` becomes a `FpiUsbTransfer` chain driven
  by `FpiSsm`. This is the bulk of the effort even though the *bytes* are known.
- TLS handshake re-expressed as an SSM (or a synchronous helper that pumps the async
  transport — see risk #2).
- Pairing-blob persistence to disk (libfprint has no KV store for this).

---

## 3. The hard parts, ranked by risk

### #1 — The custom TLS 1.2 channel in C (`verimark-tls.c`)  — HIGHEST
There is **no C implementation to lean on.** The bundled `re/synaTudor-rev/libfprint/
.../drivers/tudor.c` is a CPython-embedding shim (it `dlopen`s Python and calls the
`rev` module) for a *different* device (`06cb:00be`, an image sensor) — not a native
port. So the channel must be hand-written.

**You cannot use OpenSSL/GnuTLS's TLS stack** — this is a *non-standard* TLS 1.2
(the `rev` code is littered with `#BROKEN` for exactly the deviations). Specifics that
force a hand-rolled handshake (all in `tudor/tls/`):
- **No ServerKeyExchange / not ECDHE.** Premaster = `ECDH(ephemeral_client_priv,
  sensor_cert.pub_key)` — the client's ephemeral key against the sensor's **static
  cert** public key (`ecc.py::end_handshake`, line 84).
- **Client authenticates:** sends `Certificate` (the host cert) + `CertificateVerify`
  (ECDSA-SHA256 over the transcript), i.e. mutual auth via the pairing keypair.
- **Transcript hash is SHA-256** (`handshake.py` `self.msg_digest = hashlib.sha256()`)
  but the **PRF/Finished/key-expansion hash is SHA-384** (suite `0xC02E`). Mixed —
  do not assume one hash throughout.
- **Finished is excluded from the transcript** and **no compression method is
  advertised** (both flagged `#BROKEN`). Replicate the quirks exactly or the server
  `Finished` verify fails.
- ClientHello advertises **both** `0xC005` (CBC) and `0xC02E` (GCM); the sensor picks
  `0xC02E`. Advertise both suite IDs; only implement the GCM encryption path.

Use **libcrypto** (OpenSSL, like `egismoc`/`goodixmoc` link) for primitives only:
SECP256R1 keygen, ECDSA sign/verify, ECDH, AES-256-GCM, SHA-256/384, and a **TLS 1.2
PRF** (must be written — modern OpenSSL doesn't expose `tls1_prf` cleanly; port
`data.py::tls_prf`). Record layer (`encr.py::TlsAEADEncryptionAlgorithm`):
- encrypt: explicit nonce = 8 random bytes; full GCM IV = `encr_iv(4) ‖ nonce(8)`;
  AAD = `seq_num(8, big-endian) ‖ content_type ‖ version(2) ‖ plaintext_len(2)`;
  output = `nonce ‖ ciphertext ‖ tag(16)`.
- key expansion: `PRF-SHA384(master, "key expansion", server_random ‖ client_random …)`
  → `encr_key(32) decr_key(32) encr_iv(4) decr_iv(4)`.
- master secret: `PRF-SHA384(premaster, "master secret", client_random ‖ server_random, 48)`.

**Effort estimate: 1–2 weeks.** This is the make-or-break component. Build it as a
standalone, unit-testable module first (§7) before wiring it to USB.

### #2 — Sync-crypto vs async-USB impedance mismatch — HIGH
The handshake is naturally sequential (send ClientHello, read ServerHello+Cert+Done,
send ClientKeyExchange+CCS+Finished, read server Finished) but libfprint forbids
blocking the main loop. Two options:
- **(a)** Model the handshake as its own `FpiSsm` with a state per round-trip. Cleanest,
  most libfprint-idiomatic; more code.
- **(b)** Keep the TLS module synchronous and give it an I/O callback
  (`VerimarkTlsIo`, already sketched in `verimark-tls.h`) that runs one control
  WRITE+READ; drive it from an SSM state that yields between round-trips. Faster to
  port from `session.py::establish` (which is a simple `while has_data()` loop) but you
  must ensure the callback pumps the async transport without a nested main loop.

Recommend **(b)** for the handshake (few round-trips, matches `establish()` 1:1) and
plain async `FpiSsm` for the steady-state MOC commands.

### #3 — EP0 async control transport — MEDIUM
`FpiUsbTransfer` supports control transfers (`fpi_usb_transfer_fill_control`). The
chunking/padding logic (`_ctrl_write`: pad to /8, `wValue=len&7` on the last chunk,
`0x8000` continuation flag, 4096 cap; `_ctrl_read`: retry on errno-110/timeout) ports
directly but each chunk becomes an async submit+callback. The retry-on-not-ready read
loop needs a timer (`fpi_device_add_timeout`) rather than `time.sleep`.

### #4 — Interrupt-EP event model in the async loop — MEDIUM
Finger PRESS (`0x01`) arrives on **interrupt EP `0x83`**; frame-ready (`0x18`) arrives
via the `0x87 EVENT_READ` command (findings/51). An async interrupt-IN transfer with a
completion callback replaces `read_intr`. The capture choreography
(`moc_capture`) is a small SSM: arm press mask → await 0x83 → arm frame mask →
`FRAME_ACQ` → poll `EVENT_READ` for `0x18` → `FRAME_FINISH`.

### #5 — Pairing/TOFU persistence — MEDIUM
The 868-byte pairing blob (`0x44` priv scalar LE ‖ 400 B host cert ‖ 400 B sensor
cert; `pair.py::save`) must survive across sessions. libfprint has **no driver KV
store.** Options: write a file keyed by sensor id (like `tudor.c`’s
`/etc/tudor/<sid>.pdata`), e.g. under `/var/lib/fprint/verimark/<sid>.pdata`, created
0600 root. **Open design question** — see §9.

---

## 4. Phased milestones

Each phase is independently testable and has a hard exit criterion. Build TLS
(P2) as an offline unit before touching hardware where possible.

### P0 — Build skeleton + USB open/claim
- **Files:** `verimark.c` (`dev_open`/`dev_close`), `verimark.h`, `meson.build`.
- **Do:** strip the fictional `VerimarkCmd` enum; add the real Tudor opcode `#define`s
  (from `tudor/comm.py::Command`). Claim iface 1, find EP `0x83`, wire the class into a
  libfprint checkout (`drivers/verimark/`, add to `meson.build` `drivers`, udev rule).
- **Exit:** driver loads; `fp_device_open` succeeds and closes cleanly (no I/O yet).
- **Test:** `fprintd` sees the device, or a libfprint example (`examples/manager`).

### P1 — EP0 transport + unencrypted GET_VERSION / GET_START_INFO
- **Files:** `verimark.c` transport (`verimark_cmd`, `verimark_ctrl_write/read`).
- **Mirrors:** `control_comm.py::_ctrl_write/_ctrl_read/send_command` (raw, no TLS),
  `sensor.py::reset` (parses `GET_VERSION` 0x26-byte struct → fw 10.1, provision state).
- **Do:** async control WRITE (`0x40/0x16`) + READ (`0xc0/0x17`) with chunk/pad; send
  `0x01 GET_VERSION`, parse FW major/minor/`prov_state`/sensor-id; send `0x19
  GET_START_INFO`.
- **Exit:** logs `FW 10.1 PROVISIONED` + 6-byte sensor id, matching `p0_ctrl.py`.
- **Test:** on-device; diff bytes against `p0_ctrl.py` output.

### P2 — Pairing (0x93) + TLS bring-up + one wrapped round-trip  ★
- **Files:** `verimark-tls.c` (new), `verimark.c` (`OPEN_PAIR`, `OPEN_TLS` states).
- **Mirrors:** `sensor.py::pair` + `pair.py` (host-cert build, HS-key sign),
  findings/46 (HS-key derivation constants + endianness), `tls/handshake.py`,
  `tls/session.py::establish`, `tls/cipher/ecc.py`, `tls/cipher/encr.py`.
- **Do:** (1) if no stored pdata: derive HS key (PRF-SHA256 over the findings/46
  constants, little-endian scalar), gen host EC keypair, build+sign the 400-byte host
  cert, send `0x93`, parse the 800-byte response (new host cert + sensor cert), persist
  868-byte pdata. (2) verify sensor cert ECDSA against the bundled `10.1-kf` sensor
  pubkey (`sensor_keys/10.1-kf.tsk`). (3) run the custom handshake; confirm
  `remote_tls_status` (`0xc0/0x14`) is established. (4) send a wrapped command (e.g.
  `0x9e DB2_GET_DB_INFO`) and unwrap the reply.
- **Exit:** `remote_tls_status()==established` and a wrapped `0x9e`/`0x9f` returns
  status `0x0000` — reproduces `p1_pair.py` + `p2_dbinfo.py`.
- **Test:** on-device; also a **differential unit test** (§7) against captured records.

### P3 — Event/frame-capture SSM (the 0x18 gating)
- **Files:** `verimark.c` (or `verimark-moc.c`): capture SSM + interrupt-IN handling.
- **Mirrors:** `p2_moc.py::moc_capture`, `wait_intr_event`, `evt_read`;
  `event.py::set_event_mask` (`0x86 EVENT_CONFIG`), `EVENT_READ` (`0x87`).
- **Do:** arm press mask (`0x86` with `1<<1|1<<2`) → async interrupt read on `0x83`,
  await byte[0]==`0x01` → arm frame mask (`1<<24`) → `0x80 FRAME_ACQ` (17-byte arg;
  `0x0c` for enroll, `0x14` for dedup/verify) → poll `0x87 EVENT_READ` until event
  type `0x18` (treat status `0x0405/6/7` as "none yet, retry") → `0x81 FRAME_FINISH`.
- **Exit:** `mode_events`-equivalent trace: press+frame-ready seen for a physical tap.
- **Test:** on-device manual — press-and-hold; confirm `0x18` observed.

### P4 — Enroll SSM (create / sample-loop / finalize / commit) + FpPrint
- **Files:** `verimark.c` enroll SSM.
- **Mirrors:** `p2_moc.py::_run_enroll`, `build_finalize`/`WIN_FINALIZE`; goodixmoc
  `fp_enroll_sm_run_state` for the libfprint enroll shape.
- **Do:** `0x99 01` dedup (13-byte literal) → `0x96 01` create (13-byte) → loop{capture
  (P3) → `0x96 02` add-sample; read coverage `resp[22]`, quality `resp[42]`; emit
  `fpi_device_enroll_progress`} until coverage==`0x7f` → capture minted id `resp[2:18]`
  → `0x96 03` finalize (splice id into `[19:35]`; build SID from local user, see §5) →
  `0x96 04` commit → store the 16-byte id in the `FpPrint` (see §5) →
  `fpi_device_enroll_complete`.
- **Exit:** a finger enrolls; `0x9f` list grows by one; `FpPrint` persists with the id.
- **Test:** `fprintd-enroll`; cross-check `p2_moc.py list`.

### P5 — Verify / identify SSM
- **Files:** `verimark.c` verify SSM.
- **Mirrors:** `p2_moc.py::mode_verify`; goodixmoc `fp_verify_sm_run_state` +
  `fpi_device_verify_report`/`identify_report`.
- **Do:** capture (P3, `0x14` acq) → `0x99 01` (177-byte response). Status `0x0000` +
  matched id at `resp[2:18]` → find the `FpPrint` whose stored id matches → report
  match; `0x0509` → report no-match. Handle identify (report against the gallery).
- **Exit:** enrolled finger verifies (match), a different finger does not.
- **Test:** `fprintd-verify`; PAM dry-run.

### P6 — list / delete / clear-storage
- **Files:** `verimark.c` `dev_list/dev_delete/dev_clear_storage`.
- **Mirrors:** `p2_moc.py::_list` (`0x9f`), `mode_delete` (`0xa0` lookup child → `0xa3`
  delete), `0xa5 DB2_FORMAT` for clear.
- **Do:** `0x9f` → enumerate GUIDs → build `GPtrArray` of `FpPrint` (resolve the minted
  vs list-id discrepancy, §5). Delete: `0xa0 GET_OBJ_INFO` to find child, `0xa3
  DELETE_OBJ`. Clear: `0xa5 DB2_FORMAT`.
- **Exit:** list matches the sensor DB; delete removes one; clear empties it.
- **Test:** `fprintd-list` / `fprintd-delete`; verify against `p2_moc.py list`.

### P7 — fprintd integration + PAM (login / sudo) end-to-end
- **Do:** install the driver into system libfprint, ship the udev rule, register with
  fprintd; configure `pam_fprintd` for `sudo` and login.
- **Exit:** `sudo` and the display-manager accept the enrolled finger via this driver
  end-to-end, no Python in the loop.
- **Test:** real `sudo` + login prompt. (Note the machine's built-in `06cb:0126` reader
  also works — make sure fprintd targets the VeriMark for the test.)

---

## 5. Print / template mapping

Follow the **goodixmoc pattern** (`goodix.c` `FP_ENROLL_COMMIT`): store the sensor's
16-byte template id in the `FpPrint`’s `fpi-data` as a GVariant, set
`fpi_print_set_type(print, FPI_PRINT_RAW)` and `fpi_print_set_device_stored(print,
TRUE)`. Suggested layout: `(y@ay@ay)` = finger, tid(16), user_id.

- **Minted-id vs `0x9f` list-id discrepancy (findings/51, open).** The template id
  minted at enroll / returned by verify (e.g. `abac73…`) differs from the id the `0x9f`
  DB object-list reports for that slot (e.g. `adf2dd…`). Mint==verify is internally
  consistent, so **matching uses the minted id**; the `0x9f` id appears
  derived/hashed. **Resolve before P6:** determine the mapping (likely `0xa0
  GET_OBJ_INFO` returns both the list id and a child/leaf id) so `dev_list` and
  `dev_delete` address the same slot the enroll stored. Until resolved, store **both**
  ids in `fpi-data`.
- **The finalize SID (`WIN_FINALIZE[49:77]`, open design question).** The prototype
  splices a captured Windows user SID (currently zeroed to `S-1-5-21-0-0-0-1001`) into
  `0x96 03`. It is an opaque match-label; matching worked with the captured value, and
  it is untested whether a generic SID matches. **Driver should synthesize the SID from
  the local user** (uid → a synthetic `S-1-5-21-…` or a stable per-install value), not
  hardcode one. Flagged as a decision: confirm on-device that a driver-built SID
  enrolls+verifies before committing to a scheme.

---

## 6. Testing strategy

- **Unit-testable codec (no device).** Factor the TLS record layer, the PRF, the
  cert (de)serialization, and the command framing into pure functions. Test vectors:
  the 868-byte `prototype/pdata/<sid>.pdata`, the sensor `10.1-kf.tsk` key, and any
  captured `17 03 03` records. Assert C `wrap`/`unwrap` == the `rev` Python output for
  identical inputs (import the same keys).
- **Python prototype as a differential oracle.** For every phase, run the matching
  `p2_moc.py` mode and byte-diff responses. The prototype is the ground truth — the C
  driver is "done" for a phase when its wire bytes match.
- **On-device manual steps.** Press-and-hold (tap, not swipe — touch/area sensor).
  P3: observe `0x18`. P4: enroll to coverage `0x7f` (~7 samples). P5: match/no-match.
  Keep `p2_moc.py delete` handy to clean test templates (findings/51 notes ~8 cruft
  templates accumulate).
- **fprintd/PAM.** `fprintd-enroll/verify/list/delete`, then `pam_fprintd` for `sudo`.

---

## 7. Risks & open questions

- **TLS effort (risk #1).** The custom handshake is the schedule driver. De-risk by
  writing `verimark-tls.c` as an offline module validated against the prototype before
  any USB wiring.
- **No UMDF/Windows dependency.** Unlike the earlier `synaTudor` `relink` dead-end
  (findings/40), this port touches no Windows components — pure Linux + libcrypto.
- **SID synthesis (§5).** Does a driver-built SID enroll+verify, or must it be stable
  per user/install? Untested.
- **Minted-id vs list-id (§5).** Must be mapped before list/delete are correct.
- **Multi-finger enroll / gallery.** Verify the `0x99` identify path reports against a
  multi-print gallery correctly (goodixmoc handles this in `identify_report`).
- **Cancellation / error paths.** `dev_cancel` must abort in-flight interrupt reads and
  discard a half-open enroll context (there is no explicit enroll-discard opcode in the
  prototype — investigate whether `0x96` needs an abort, else rely on session reset).
- **Suspend/resume + idle timeout.** `SET_IDLE_TIMEOUT` (`0x57`) exists; the sensor may
  drop the TLS session on suspend. Decide whether to re-handshake lazily on the next
  operation (cheap: pdata is persisted) vs keep-alive.
- **Persistence location/permissions (risk #5).** Where to store the pdata and with
  what ownership so fprintd (running as root) can read it but it is not world-readable
  (it contains the host private key).
- **Pairing is a one-time write.** First run performs `0x93` (TOFU). Ensure this only
  happens when no pdata exists, and never clobbers a working pairing.

---

## 8. Task checklist

**P0 — skeleton**
- [ ] Replace `VerimarkCmd` IOCTL enum with real Tudor opcode `#define`s (`tudor/comm.py`).
- [ ] `dev_open`: claim iface 1, find EP `0x83`; `dev_close`: release.
- [ ] Wire into a libfprint checkout (`meson.build` drivers list + udev rule).

**P1 — transport**
- [ ] Async EP0 WRITE `0x40/0x16` with pad-to-8 + chunking + `wValue` flags.
- [ ] Async EP0 READ `0xc0/0x17` with not-ready retry (timer, not sleep).
- [ ] `GET_VERSION` (0x01) + `GET_START_INFO` (0x19) parse; log fw/prov/id.

**P2 — pairing + TLS (`verimark-tls.c`)**
- [ ] TLS 1.2 PRF (SHA-256 and SHA-384) — port `data.py::tls_prf`.
- [ ] HS-key derivation (findings/46 constants, LE scalar) + host-cert build/sign.
- [ ] `0x93` pair, parse 800-byte response, persist 868-byte pdata.
- [ ] Sensor-cert ECDSA verify against `10.1-kf.tsk`.
- [ ] Handshake: ClientHello (advertise `0xC005`+`0xC02E`) → ServerHello/Cert/Done →
      Certificate + ClientKeyExchange (raw EC point) + CertificateVerify + CCS +
      Finished → verify server Finished. Honor the SHA-256-transcript /
      SHA-384-PRF split and the Finished-excluded-from-transcript quirk.
- [ ] AES-256-GCM record wrap/unwrap (nonce, AAD, tag) — `encr.py`.
- [ ] Wrapped `0x9e`/`0x9f` round-trip returns `0x0000`.

**P3 — capture**
- [ ] `0x86 EVENT_CONFIG` mask arming; async interrupt read on `0x83`.
- [ ] Capture SSM: press(0x01)→`0x80 FRAME_ACQ`→`0x87 EVENT_READ` for `0x18`→`0x81`.

**P4 — enroll**
- [ ] 13-byte `0x99 01` dedup + `0x96 01` create literals.
- [ ] add-sample loop `0x96 02`; coverage `resp[22]`, quality `resp[42]`, progress cb.
- [ ] `0x96 03` finalize (splice minted id `resp[2:18]`; driver-built SID).
- [ ] `0x96 04` commit; store id in `FpPrint` `fpi-data`; `enroll_complete`.

**P5 — verify/identify**
- [ ] `0x99 01` (177-byte) → status `0x0000`+id vs `0x0509`; verify/identify report.

**P6 — storage**
- [ ] `dev_list` (`0x9f`); resolve minted-vs-list id mapping.
- [ ] `dev_delete` (`0xa0`→`0xa3`); `dev_clear_storage` (`0xa5`).

**P7 — integration**
- [ ] Install, udev, fprintd registration; `pam_fprintd` for sudo+login end-to-end.

**Cross-cutting**
- [ ] `dev_cancel` aborts in-flight transfers + half-open enroll.
- [ ] pdata persistence path + permissions decided and implemented.
- [ ] Differential tests vs `p2_moc.py` green for each phase.
