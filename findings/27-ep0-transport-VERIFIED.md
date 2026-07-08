# 27 — Tudor transport = bulk-over-EP0-control. RECOVERED + VERIFIED LIVE.

**Date:** 2026-07-08. Closes the blocker `findings/26` left open. The exact
command/response encoding for the biometric channel (iface1, no bulk pipe) was recovered
from the 132 DLL decompiles and then **confirmed against the real device** with two raw
query commands returning correct, status-OK Tudor responses. Clean-room: behaviour only
(request codes, framing) — no vendor code copied. This is the authoritative transport spec.

## The encoding

The sensor's logical bulk channel is **tunnelled over EP0 vendor control transfers**
(the driver calls this mode "Ep0InEp0Out"). Two vendor requests:

```
command  WRITE:  bmRequestType = 0x40 (host->dev, vendor, device)
                 bRequest      = 0x16
                 wValue        = (true_len & 7)      # low 3 bits of the unpadded length
                 wIndex        = 0
                 data          = command bytes, PADDED to a multiple of 8
                 wLength       = padded length   (chunked at 0x1000 = 4096)

response READ:   bmRequestType = 0xc0 (dev->host, vendor, device)
                 bRequest      = 0x17
                 wValue        = 0
                 wIndex        = 0
                 wLength       = up to 0x1000 per chunk; retry on timeout until ready
```

- **8-byte padding:** the write rounds the payload up to a multiple of 8 and stashes the
  real length's low 3 bits in `wValue` so the device recovers the exact length.
- **Chunking (only for payloads > 4096 B — i.e. large TLS records):** each 4096-B
  continuation chunk ORs flag bits into `wValue` — `0x4000` on non-first chunks,
  `0x8000` on full-4096 chunks (from the `param_2` templates `0x80004007` write /
  `0x80004000` read). Single-shot for anything ≤4096 B, which covers all plain commands.
- **A command transaction = WRITE (0x16) then READ (0x17)** as two separate control
  transfers; the device buffers the response and returns it on the 0x17 read. The read
  **retries on timeout** (errno 110 / Win `0x79`) because the response may not be ready
  immediately.
- **Responses come back on control-IN (0xc0/0x17), NOT on `0x83`.** iface1's 8-byte
  `0x83` interrupt-IN is the **async event pipe only** (2-byte finger/keepalive), read by
  a separate device-event thread. This settles the last transport question.
- Auxiliary requests seen (not the main command path): `0x40/0x15` write-only,
  `0xc0/0x14` status read (2-B TLS-session-status), `0x40/0x19|0x1a|0x1b` device mgmt.

### Provenance (decompiles, `re/ghidra-out/ctrl-path/`)

`tudorUsbProtoIoControl` → `FUN_18005ef80` (send+recv) → `FUN_180044370(…,0x16,…)` /
`FUN_180044210(…,0x17,…)`. Those branch on a transport-mode field `dev+0xb8`: mode 0 =
real bulk pipes (06cb siblings); **mode 1 = `palWinUsbBulkWriteEp0InEp0Out` +
`palWinUsbBulkReadEP0` = everything over EP0 control (047d, no bulk pipe)**. Both Ep0
functions build the setup packet above and call the `WinUsb_ControlTransfer` wrapper
(vtable `+0x58`). `palUsbDriverCtrlRequest` is the simple single-shot variant used by the
mgmt/status requests.

## Live verification (`prototype/p0_ctrl.py`, this device, READ-ONLY)

Two raw pre-TLS commands, no sensor write:

**GET_VERSION (0x01) → 38 B, status 0x0000 OK:**
```
00 00 52 2d df 5e f5 5d 31 00 0a 01 01 41 01 c1 00 00 f7 00
7a d9 29 c6 0b a1 00 00 00 00 00 00 00 00 00 00 00 03
```
Decoded (synaTudor `rev` struct): **FW 10.1**, product id `0x41`, sensor id
`f7007ad929c6`, **provision state = 3 (PROVISIONED)**.

**GET_START_INFO (0x19) → 68 B, status 0x0000 OK:**
```
00 00 02 00 21 00 01 10 f3 f6 2d bc 70 c8 15 9f ac 60 f0 fd 00 00 00 00 …
```
`+2: 02 00 21 00 01 10` = **byte-exact match** to the documented `0x19` layout in
`findings/25`. (The `9b6f…` region is the per-boot instance id.)

Both transactions used `ctrl-OUT 0x40/0x16 wValue=1` (len 1 → padded to 8) then
`ctrl-IN 0xc0/0x17`. Transport works end-to-end.

## Triple-confirmed on the Windows wire (2026-07-08)

The Windows USBPcap set (now on a USB drive; VeriMark = hub2) confirms the decode
independently. `tshark` on `win-usb-20260708-103815-hub2.pcap`, vendor control transfers
(bRequest shown decimal):

| bmReqType | bRequest | wValue | wLength | meaning |
|---|---|---|---|---|
| `0x40` | 22 (`0x16`) | `0x0001` | 8 | 1-B cmd padded to 8, `wValue=len&7=1` (== our GET_VERSION) |
| `0x40` | 22 (`0x16`) | `0x0002` | 56 | cmd, len&7=2 |
| `0x40` | 22 (`0x16`) | `0x0000` | 624 | large cmd (len multiple of 8; 616 B data) |
| `0xc0` | 23 (`0x17`) | `0x0000` | 68 | **GET_START_INFO response** |
| `0xc0` | 23 (`0x17`) | `0x0000` | 38 | **GET_VERSION response** |
| `0xc0` | 23 (`0x17`) | `0x8000` | 4096 | full-4096 read chunk (the `0x8000` continuation flag) |
| `0xc0` | 20 (`0x14`) | `0x0000` | 2 | TLS-session-status read |
| `0x40` | 25 (`0x15`) / 27 (`0x1b`) / `0xc0` 26 (`0x1a`) | — | — | aux/mgmt requests |

So decompile → live probe → captured wire all agree. **Bonus:** these pcaps contain the
exact OUT bytes of every command (handshake included) — a replay/validation oracle for
P0b/P1/MOC.

## Implications

1. **Transport shim is solved and proven.** synaTudor `rev`'s stack above
   `CommunicationInterface` can be reused unchanged; only its `USBCommunication` is
   replaced by an EP0-control `send_command` implementing the above (write 0x16 → read
   0x17, 8-byte pad, wValue=len&7, 4096 chunking, retry-on-timeout). No bulk, no `0x83`
   for responses.
2. **Sensor key already in hand.** FW **10.1** ⇒ `rev`'s `sensor_keys/10.1.tsk`
   (or `10.1-kf.tsk` if `key_flag` set) is the correct device pubkey — no extraction
   needed. (`key_flag` = bit 0x20 of flags2 — check on the parsed struct before picking.)
3. **The unit is PROVISIONED to the Windows host.** `is_paired()` is true, but our Linux
   host has no matching `pairing_data`, so establishing TLS (`initialize()` path) needs a
   **fresh pair** (`0x93 PAIR`) for this host — a sensor **write** (P1, still gated).
   Raw pre-TLS commands (version/start-info) work today without any of that.

## Next (P0b / P1)

- Build the Python `ControlComm(CommunicationInterface)` shim; wire in `rev`'s
  `tudor.tls` + `Sensor`; try `initialize()` — it will read version/start-info raw, then
  stop at TLS because we're unpaired. That confirms the full stack up to the pairing gate.
- Then decide P1: pairing writes the sensor host partition. `rev`'s `pair.py` implements
  it; the unit already has a Windows host entry (multi-host partitions are supported).
- `prototype/p0_probe*.py` (iface0/FIDO dead-end) can be deleted; `p0_ctrl.py` is the
  real transport reference.
