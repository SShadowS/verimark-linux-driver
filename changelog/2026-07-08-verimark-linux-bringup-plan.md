# 2026-07-08 — VeriMark Linux driver: bring-up prep + transport correction

Resumed the driver project on the Linux box from `RESUME-LINUX.md` (Windows RE phase
done, verdict GO). Goal of this session: confirm state, verify the reuse assets are
actually present, and produce the architecture/plan before writing driver code.

## What was done

1. **Confirmed the device** is present: `047d:00f2` on bus 003.
2. **Verified the reuse leverage — and fixed a missing asset.** The whole reuse strategy
   (`findings/24`) depends on the `synaTudor` **`rev`** branch (a pure-Python Tudor
   reimplementation), but the local clone `re/synaTudor` was a single-branch checkout of
   **`relink`** (the DLL-relinker `findings/30` built) — **`rev` was not on the box.**
   Fetched `origin/rev`; confirmed it carries the promised assets: `pydrv/tudor/comm.py`
   (VCSFW enum), `pydrv/tudor/tls/*` (full TLS-1.2 ECDH-ECDSA-AES256-GCM stack + custom
   cert parsing), `pydrv/tudor/sensor/{sensor,pair,capture,event}.py`, `sensor_keys/`.
3. **Cross-checked the command enum** against our findings: `comm.py`'s `VCSFW_CMD_*`
   values match **byte-for-byte** on every shared opcode (`0x19 0x44 0x80 0x81 0x86 0x87
   0x93 0x9e 0x9f 0xa0 0xa1 0xa3`), and `0x96`/`0x99` (the MOC enroll/identify) are
   **absent** — exactly as predicted (synaTudor does host-side NBIS matching, not on-chip
   MOC). Reuse map validated.
4. **Transport, settled empirically — with a self-correction** (`findings/26`). First I
   *mis-corrected* the brief, claiming the command channel was iface0 EP `0x01`/`0x81`
   (based on the 132 DLL's `WinUsb_WritePipe` decompiles). A live probe (`prototype/
   p0_probe*.py`) refuted that: writing to iface0 returned a **CTAPHID `ERR_INVALID_
   CHANNEL`** frame (`00000000 bf 0001 0b`) — i.e. **iface0 is the FIDO U2F interface**,
   not biometric (its HID report descriptor is a pure `U2FAuthenticatorDevice` collection).
   The biometric channel is **iface1** (vendor), whose *only* endpoint is the 8-byte
   interrupt-IN `0x83` — **no OUT/bulk endpoint, no alt settings** — so commands go out
   via **EP0 vendor control transfers** (`palUsbDriverCtrlRequest` → `WinUsb_Control
   Transfer`; mgmt requests `0x19/0x1a/0x1b` seen). **This confirms the original brief;
   the `WinUsb_WritePipe` path is a `transport-select` branch for bulk-capable sibling
   sensors (06cb), not 047d.**

## Artifacts

- `findings/26-transport-endpoints.md` — corrected transport map (iface0=FIDO,
  iface1=biometric EP0-control) + the CTAPHID-error evidence.
- `prototype/p0_probe*.py` — how iface0 was ruled out (FIDO). **Not** the bring-up path.
- `re/synaTudor` now has the **`rev`** branch fetched (git-ignored tree).

5. **P0 first-light DONE — transport recovered + verified live** (`findings/27`). Chose
   the Ghidra route; dumped `palUsbDriverCtrlRequest` + the send/recv layer and found the
   biometric channel is **bulk-over-EP0-control**: command WRITE = vendor `bmReqType=0x40,
   bRequest=0x16, wValue=(len&7), wIndex=0`, data **padded to /8** (chunked at 4096);
   response READ = `0xc0, 0x17` (retry-on-timeout); **responses come on control-IN, not
   `0x83`** (that's events only). Built `prototype/p0_ctrl.py` and ran it read-only against
   the device: **GET_VERSION → FW 10.1, PROVISIONED; GET_START_INFO → 68 B byte-matching
   `findings/25`**, both status `0x0000`. FW **10.1** ⇒ `rev`'s `sensor_keys/10.1.tsk` is
   the right key (no extraction). Sensor is **provisioned to the Windows host** → TLS needs
   a fresh Linux-host pair (P1).

6. **P0b DONE — full `rev` stack runs over the shim, read-only.** Built
   `prototype/control_comm.py` (`ControlComm(CommunicationInterface)` = the EP0-control
   transport, incl. 4096-chunk read/write + retry) and `prototype/p0b_bringup.py`. Ran
   `tudor.sensor.Sensor(comm)` + `initialize(None)` against the device: `GET_VERSION` +
   **READ_IOTA ×4 (0x09/0x1a/0x2e[3580 B]/0x2f)** + **`load_sensor_key`→`10.1-kf`** +
   `GET_START_INFO`, all status OK, then stopped at the gate `Exception('No pairing data
   given')` — **no TLS write**. Confirms: the whole reuse stack (comm/IOTA/key/start-info)
   works unchanged; the 3580-B IOTA validated multi-chunk reads; sensor pubkey loads
   (TLS-ready); **key_flag is set → key = `10.1-kf.tsk`**.

## Open next steps

- **P1 (first sensor WRITE — needs explicit consent):** `0x93 PAIR` a Linux-host identity
  via `rev`'s `pair.py`, then `initialize(pairing_data)` establishes TLS and a wrapped
  `GET_START_INFO` round-trips. Sensor already holds a Windows host entry (multi-host
  partitions supported); pairing adds/refreshes ours.
- MOC `0x96`/`0x99` and the libfprint glue unchanged.
- `prototype/p0_probe*.py` (iface0/FIDO dead-end) can be removed; `p0_ctrl.py` +
  `control_comm.py` are the transport references.
