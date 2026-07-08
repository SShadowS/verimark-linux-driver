#!/usr/bin/env python3
"""
P2b/P2c — on-chip MOC enroll / verify over the live TLS session (findings/29).

Subcommands:
  events    READ-ONLY. Arm finger events and print every interrupt (0x83) + EVENT_READ
            (0x87) record as you TOUCH and LIFT the sensor. Teaches the event semantics
            on THIS device before we drive enroll. No writes.
  enroll    WRITE. Guided MOC enroll: 0x99 begin -> 0x96 01 create -> loop{ wait finger,
            FRAME_ACQ/FINISH, 0x96 02 add-sample } until coverage 0x7f -> 0x96 04 commit.
            Extracts the sensor-minted GUID and saves it to prototype/prints/.
  verify    Drive 0x99 identify; print 177-B match record (GUID) or 0x0509 no-match.
  list      READ-ONLY. 0x9f object list.
  delete <hexGUID>   WRITE. Roll back a template: 0xa0 lookup child -> 0xa3 delete.

Run as root. Reuses rev's tudor.tls/tudor.sensor over the EP0 transport.
"""
import os, sys, io, time, struct, logging, array

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

import usb.core, usb.util
import tudor
import tudor.sensor
from tudor.comm import LogCommunicationProxy, Command, CommandFailedException
from tudor.sensor.pair import SensorPairingData
from control_comm import ControlComm

VID, PID = 0x047d, 0x00f2
PDATA_DIR = os.path.join(HERE, "pdata")
PRINTS_DIR = os.path.join(HERE, "prints")

# MOC command literals (findings/29)
C_BEGIN_ID   = bytes.fromhex("99" + "01000000" + "00000000" + "0000")   # 0x99 begin-identify (13 B)
C_ENR_CREATE = bytes.fromhex("96" + "01000000" + "00000000" + "0000")   # 0x96 create-enroll (13 B)
C_ENR_SAMPLE = bytes.fromhex("96" + "02000000")                          # 0x96 add-sample (5 B)
C_ENR_COMMIT = bytes.fromhex("96" + "04000000")                          # 0x96 commit (5 B)
C_FRAME_ACQ  = bytes.fromhex("800c000000010000000100000801010100")       # 0x80 FRAME_ACQ (17 B, arg 0x0c)
C_FRAME_FIN  = bytes.fromhex("81")                                        # 0x81 FRAME_FINISH


def u16(b, o=0): return struct.unpack_from("<H", b, o)[0]


def open_sensor():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise SystemExit("device not found")
    comm = LogCommunicationProxy(ControlComm(dev))
    sensor = tudor.sensor.Sensor(comm)
    return sensor, comm


def tls_up(sensor, comm):
    sid = sensor.id.hex()
    pfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
    if not os.path.exists(pfile):
        raise SystemExit("no pairing data at %s — run p1_pair.py first" % pfile)
    with open(pfile, "rb") as f:
        pdata = SensorPairingData.load(io.BytesIO(f.read()))
    sensor.initialize(pdata)
    if not comm.proxied.remote_tls_status():
        raise SystemExit("TLS did not establish")
    return sid


def read_intr(raw, timeout_ms=800):
    """One bounded interrupt-IN (0x83) read; None on timeout."""
    buf = array.array("B", [0] * 8)
    try:
        n = raw.intr_ep.read(buf, timeout_ms)
        return bytes(buf[:n])
    except usb.core.USBError:
        return None


FINGER_PRESS, FINGER_REMOVE = 0x01, 0x02   # interrupt byte[0] (verified via events probe)


def wait_finger(sensor, comm, deadline, kind=FINGER_PRESS):
    """Arm finger events; block (bounded) until a PRESS (or given kind) arrives on the
    0x83 interrupt endpoint. Returns the event seq (byte[6]), or None on timeout.
    Interrupt layout on this device: [type][00 00 00 00 00][seq]."""
    raw = comm.proxied
    sensor.event_handler.set_event_mask([1, 2])    # deliver press/release on 0x83
    while time.time() < deadline:
        ev = read_intr(raw, 500)
        if ev and len(ev) >= 1 and ev[0] == kind:
            return ev[6] if len(ev) > 6 else 0
    return None


# --------------------------- modes ---------------------------

def mode_events(sensor, comm):
    tls_up(sensor, comm)
    raw = comm.proxied
    eh = sensor.event_handler
    print("\n>>> EVENT PROBE (read-only). Arming finger events; touch and lift the sensor.")
    print(">>> 20 s window. Ctrl-C to stop early.\n")
    eh.set_event_mask([1, 2])   # FINGER_PRESS|FINGER_REMOVE (mask 0x06, as Windows arms)
    deadline = time.time() + 20
    last = None
    while time.time() < deadline:
        ev = read_intr(raw, 500)
        if ev is not None:
            print("  intr(0x83): %s   seq=%d" % (ev.hex(), ev[5] & 0x1f))
            # read the queued event records too
            try:
                r = comm.send_command(struct.pack("<BHHI", Command.EVENT_READ, eh.event_seq_num, 32, 1), 390, raw=True)
                nevt, npend = struct.unpack_from("<xxHH", r, 0)
                for i in range(nevt):
                    etype = r[6 + i*12]
                    print("      EVENT_READ: type=0x%02x  (npend=%d)" % (etype, npend))
                    eh.event_seq_num = (eh.event_seq_num + 1) & 0xffff
            except Exception as e:
                print("      EVENT_READ err: %r" % e)
    eh.set_event_mask([])
    print("\n=== event probe done ===")


def capture_frame(sensor, comm, deadline, acq=C_FRAME_ACQ):
    """Wait for a finger press, then acquire+finish a frame (MOC: no 0x7f read).
    The frame stays on-chip for the next MOC step to consume. False on timeout."""
    seq = wait_finger(sensor, comm, deadline)
    if seq is None:
        return False
    comm.send_command(acq, 2)          # FRAME_ACQ
    time.sleep(0.05)                    # let the frame settle on-chip
    comm.send_command(C_FRAME_FIN, 2)  # FRAME_FINISH
    return True


def mode_enroll(sensor, comm):
    os.makedirs(PRINTS_DIR, exist_ok=True)
    sid = tls_up(sensor, comm)

    print("\n>>> DB before:")
    _list(comm)

    overall_deadline = time.time() + 150

    # dedup check needs a captured frame first (0x99 = identify-this-frame)
    print("\n>>> TAP the sensor for the dedup check ...")
    if not capture_frame(sensor, comm, min(time.time() + 30, overall_deadline),
                         acq=bytes.fromhex("8014000000010000000100000801010100")):
        raise SystemExit("no finger for dedup frame")
    r = comm.send_command(C_BEGIN_ID, 2, raw=True)
    print("    0x99 dedup -> 0x%04x %s" % (u16(r), "(no-match/proceed)" if u16(r) == 0x0509 else ""))

    print(">>> create-enroll ...")
    r = comm.send_command(C_ENR_CREATE, 6, raw=True)
    if u16(r) != 0:
        raise SystemExit("create-enroll failed: 0x%04x" % u16(r))

    print("\n>>> GUIDED ENROLL — tap the sensor, lift, repeat. Coverage must reach 0x7f.\n")
    coverage, guid, samples = 0, None, 0
    while coverage != 0x7f and time.time() < overall_deadline:
        print("  [sample %d] TAP the sensor now ..." % (samples + 1))
        if not capture_frame(sensor, comm, min(time.time() + 25, overall_deadline)):
            print("    (no finger detected; keep tapping)")
            continue
        # feed the captured frame to on-chip enroll
        resp = comm.send_command(C_ENR_SAMPLE, 82, raw=True)
        st = u16(resp)
        if st != 0:
            print("    add-sample status=0x%04x (rejected) — try again" % st)
            continue
        new_cov, counter, quality = resp[22], resp[24], resp[41]
        if new_cov == coverage:
            print("    sample not accepted (coverage still 0x%02x) — reposition & tap again" % coverage)
            continue
        coverage = new_cov
        samples += 1
        print("    accepted: coverage=0x%02x  counter=0x%02x  quality=%d" % (coverage, counter, quality))
        if coverage == 0x7f:
            guid = resp[4:20]
            print("\n>>> COVERAGE COMPLETE. sensor-minted GUID = %s" % guid.hex())

    if coverage != 0x7f:
        raise SystemExit("enroll did not complete (coverage=0x%02x). Commit skipped." % coverage)

    comm.send_command(struct.pack("<BB", Command.DB2_GET_DB_INFO, 1), 0x28)   # informational
    print(">>> commit ...")
    r = comm.send_command(C_ENR_COMMIT, 2, raw=True)
    if u16(r) != 0:
        raise SystemExit("commit failed: 0x%04x" % u16(r))
    print(">>> committed OK.")

    pf = os.path.join(PRINTS_DIR, "%s.guid" % guid.hex())
    with open(pf, "w") as f:
        f.write(guid.hex() + "\n")
    print(">>> saved GUID -> %s" % pf)

    print("\n>>> DB after:")
    _list(comm)
    print("\n=== P2b ENROLL DONE ===")


def mode_verify(sensor, comm):
    tls_up(sensor, comm)
    print("\n>>> VERIFY — TAP the finger to match ...")
    if not capture_frame(sensor, comm, time.time() + 30,
                         acq=bytes.fromhex("8014000000010000000100000801010100")):
        raise SystemExit("no finger for verify frame")
    r = comm.send_command(C_BEGIN_ID, 177, raw=True)
    st = u16(r)
    if st == 0x0509:
        print(">>> 0x0509 NO MATCH")
    elif st == 0x0000 and len(r) >= 34:
        guid = r[2:18]
        print(">>> MATCH: template GUID = %s  (record %d B)" % (guid.hex(), len(r)))
    else:
        print(">>> unexpected: status=0x%04x len=%d %s" % (st, len(r), r[:32].hex()))
    print("\n=== verify done ===")


def evt_read(sensor, comm, deadline, want=None):
    """Poll EVENT_READ (0x87) until an event arrives (status 0x0405/6/7 = none yet, retry).
    Returns list of event type bytes, or [] on timeout. Updates event_seq_num."""
    eh = sensor.event_handler
    while time.time() < deadline:
        req = struct.pack("<BHHI", Command.EVENT_READ, eh.event_seq_num, 32, 1)
        r = comm.send_command(req, 390, raw=True)
        st = u16(r)
        if st in (0x0405, 0x0406, 0x0407):
            time.sleep(0.015); continue
        if st != 0:
            raise Exception("EVENT_READ status 0x%04x" % st)
        nevt = struct.unpack_from("<xxH", r, 0)[0]
        types = [r[6 + i * 12] for i in range(nevt)]
        eh.event_seq_num = (eh.event_seq_num + nevt) & 0xffff
        if types:
            return types
        time.sleep(0.015)
    return []


EV_FINGER = [1, 2]     # FINGER_PRESS|FINGER_REMOVE  (mask 0x06)
EV_FRAME  = [24]       # frame-ready, event type 0x18 (mask 1<<24 = 0x01000000)
C_FRAME_ACQ14 = bytes.fromhex("8014000000010000000100000801010100")


def moc_capture(sensor, comm, deadline, verbose=False):
    """Windows MOC frame-capture choreography (dedup cycle tx1-8):
       arm[1,2] -> read finger ; arm[24] -> FRAME_ACQ -> read frame-ready(0x18) ; FRAME_FINISH.
    Leaves a valid frame on-chip for the next MOC step. Returns True if 0x18 was seen."""
    eh = sensor.event_handler
    def log(m):
        if verbose: print("      %s" % m)
    # Arm finger events, then catch a fresh PRESS transition (finger down NOW).
    eh.set_event_mask(EV_FINGER)
    pressed = False
    while time.time() < deadline:
        t = evt_read(sensor, comm, min(time.time() + 4, deadline)); log("finger evt: %s" % t)
        if 0x01 in t:
            pressed = True; break
        # re-arm baseline and keep waiting for the next tap
        eh.set_event_mask([]); eh.set_event_mask(EV_FINGER)
    if not pressed:
        return False
    # Finger is down — acquire immediately while it's held.
    eh.set_event_mask([]); eh.set_event_mask(EV_FRAME)
    comm.send_command(C_FRAME_ACQ14, 2)                       # FRAME_ACQ
    t = evt_read(sensor, comm, min(time.time() + 4, deadline)); log("after FRAME_ACQ: %s" % t)
    got_frame = 0x18 in t
    eh.set_event_mask([])
    comm.send_command(C_FRAME_FIN, 2)                         # FRAME_FINISH
    return got_frame


def mode_probe1(sensor, comm):
    """Single capture+identify with full visibility, using the arm/read choreography."""
    tls_up(sensor, comm)
    print("\n>>> PROBE1 — TAP the sensor (press, brief hold, the loop drives the rest).\n")
    deadline = time.time() + 30
    got = moc_capture(sensor, comm, deadline, verbose=True)
    print(">>> frame-ready seen: %s" % got)
    print(">>> 0x99 identify ...")
    r = comm.send_command(C_BEGIN_ID, 177, raw=True)
    print("    0x99 -> status=0x%04x len=%d %s" % (u16(r), len(r), r[:40].hex()))
    print("\n=== probe1 done ===")


def mode_probe2(sensor, comm):
    """Full dedup->create->add-sample pipeline with logging. Do a deliberate press-and-hold
    (~2 s) each time it says TAP."""
    tls_up(sensor, comm)
    dl = lambda s: time.time() + s
    print("\n>>> [1] TAP+HOLD for dedup frame ...")
    if not moc_capture(sensor, comm, dl(30), verbose=True):
        raise SystemExit("no frame")
    r = comm.send_command(C_BEGIN_ID, 2, raw=True)
    print("    0x99 dedup (post-finish) -> 0x%04x" % u16(r))
    print("    0x96 01 create-enroll -> ", end="")
    r = comm.send_command(C_ENR_CREATE, 6, raw=True)
    print("0x%04x  raw=%s" % (u16(r), r.hex()))
    # PROCEED REGARDLESS: the decisive test is whether add-sample advances coverage.
    print("\n>>> [2] TAP+HOLD for first enroll sample ...")
    if moc_capture(sensor, comm, dl(30), verbose=True):
        r = comm.send_command(C_ENR_SAMPLE, 82, raw=True)
        st = u16(r)
        print("    0x96 02 add-sample -> 0x%04x  len=%d  raw=%s" % (st, len(r), r.hex()))
        if len(r) >= 42:
            print("       coverage=0x%02x counter=0x%02x quality=%d" % (r[22], r[24], r[41]))
    print("\n=== probe2 done ===")


def mode_probe3(sensor, comm):
    """Decisive frame-presence test: capture then call 0x99 with the finger STILL DOWN,
    both before and after FRAME_FINISH. PRESS AND HOLD FIRMLY, DO NOT LIFT until told."""
    tls_up(sensor, comm)
    eh = sensor.event_handler
    dl = time.time() + 40
    print("\n>>> PRESS AND HOLD FIRMLY now — DO NOT LIFT until it says 'lift'.\n")
    # wait for press
    eh.set_event_mask(EV_FINGER)
    pressed = False
    while time.time() < dl:
        t = evt_read(sensor, comm, min(time.time() + 4, dl))
        if 0x01 in t:
            pressed = True; break
        eh.set_event_mask([]); eh.set_event_mask(EV_FINGER)
    if not pressed:
        raise SystemExit("no press")
    print(">>> got press; FRAME_ACQ ...")
    eh.set_event_mask([]); eh.set_event_mask(EV_FRAME)
    comm.send_command(C_FRAME_ACQ14, 2)
    t = evt_read(sensor, comm, min(time.time() + 4, dl))
    print("    frame-ready: %s" % t)
    # 0x99 BEFORE finish, finger still down
    r = comm.send_command(C_BEGIN_ID, 177, raw=True)
    print("    0x99 (pre-finish, finger DOWN) -> 0x%04x len=%d %s" % (u16(r), len(r), r[:24].hex()))
    eh.set_event_mask([])
    comm.send_command(C_FRAME_FIN, 2)
    # 0x99 AFTER finish
    r = comm.send_command(C_BEGIN_ID, 177, raw=True)
    print("    0x99 (post-finish) -> 0x%04x len=%d %s" % (u16(r), len(r), r[:24].hex()))
    print("\n>>> you may LIFT now. === probe3 done ===")


def _tlv(entries):
    """Build a host-partition image: each entry = [type:u16][len:u16][sha256:32][data]."""
    import hashlib
    out = b""
    for typ, data in entries:
        out += struct.pack("<HH", typ, len(data)) + hashlib.sha256(data).digest() + data
    return out


def _read_part(comm, pid, cap):
    r = comm.send_command(struct.pack("<BBBHII", 0x40, pid, 0, 0xffff, 0, cap), cap + 0x20, raw=True)
    retlen = struct.unpack_from("<I", r, 2)[0]
    return u16(r), r[8:8 + retlen]


def mode_provision2(sensor, comm):
    """WRITE (sensor flash). PAIRING-DELTA-TRACE fix: write host partition pid 2 type-2 as the
    Windows **TagVal container** (tags 1=host_cert, 4=P256 params, 3=sensor_cert, 0=version word),
    NOT rev's raw SensorPairingData (which findings/30 wrongly used — it had wrong framing and even
    leaked the host private key into flash). Container per-entry framing = [tag:u16 LE][len:u32 LE][data].
    Then probe 0x50/0x96 to see if the enroll gate lifts. Reversible (0x3f format re-empties pid 2).

    Env knobs:
      TAG4=1   include tag-4 P-256 curve params (needs prototype/p256_params.bin, 420 B from
               Ghidra DAT_180142130). Default off (test whether tags 1/3/0 suffice first).
    """
    import io as _io
    from tudor.sensor.pair import SensorPairingData
    from tudor.win.tagval import WinTagValContainer

    sid = tls_up(sensor, comm)

    # load our pairing data -> host_cert / sensor_cert (400 B each)
    pfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
    with open(pfile, "rb") as f:
        pdata = SensorPairingData.load(_io.BytesIO(f.read()))
    host_cert = pdata.host_cert.tobytes()
    sensor_cert = pdata.sensor_cert.tobytes()
    assert len(host_cert) == 400 and len(sensor_cert) == 400, (len(host_cert), len(sensor_cert))

    c = WinTagValContainer()
    c[1] = host_cert                       # tag 1: host cert (400)
    if os.environ.get("TAG4") == "1":
        p4 = os.path.join(HERE, "p256_params.bin")
        if not os.path.exists(p4):
            raise SystemExit("TAG4=1 but %s missing (dump DAT_180142130, 420 B)" % p4)
        c[4] = open(p4, "rb").read()       # tag 4: P-256 curve params (420)
    c[3] = sensor_cert                     # tag 3: sensor cert (400)
    c[0] = struct.pack("<H", 0)            # tag 0: version word 0 (2)
    type2 = c.tobytes()
    print(">>> TagVal container: tags=%s  type2 len=%d" % (sorted(c.vals), len(type2)))

    # capacity
    r = comm.send_command(struct.pack("<B", 0x3e), 0x200, raw=True)
    count = u16(r, 0x0e); cap = None
    for i in range(count):
        o = 0x10 + i * 12
        if r[o] == 2:
            cap = struct.unpack_from("<I", r, o + 8)[0]
    if not cap:
        raise SystemExit("no type-2 host partition descriptor")
    print(">>> host partition pid=2 capacity=%d" % cap)

    image = _tlv([(1, bytes.fromhex("01000000")), (2, type2)])
    print(">>> partition image: %d bytes (type-1 40B + type-2 %dB)" % (len(image), len(type2) + 0x24))
    assert len(image) <= cap, "image exceeds capacity (%d > %d)" % (len(image), cap)

    st, cur = _read_part(comm, 2, cap)
    nonff = sum(1 for b in cur if b != 0xff)
    print(">>> current pid=2: status=0x%04x non-0xff=%d" % (st, nonff))

    print(">>> 0x3f FORMAT pid=2 ...")
    r = comm.send_command(struct.pack("<BB", 0x3f, 2), 2, raw=True)
    print("    -> 0x%04x" % u16(r))
    if u16(r) != 0:
        raise SystemExit("format failed")

    print(">>> 0x41 WRITE pid=2 off=0 len=%d ..." % len(image))
    cmd = struct.pack("<BBBHII", 0x41, 2, 0, 0xffff, 0, len(image)) + image
    r = comm.send_command(cmd, 6, raw=True)
    written = struct.unpack_from("<I", r, 2)[0] if len(r) >= 6 else -1
    print("    -> status=0x%04x written=%d" % (u16(r), written))
    if u16(r) != 0:
        raise SystemExit("write failed")

    st, back = _read_part(comm, 2, cap)
    ok = back[:len(image)] == image
    print(">>> read-back: %s" % ("OK" if ok else "MISMATCH"))

    # gate probes
    r = comm.send_command(struct.pack("<BB", 0x50, 0), 0x200, raw=True)
    print(">>> gate 0x50 GET_CERT   -> status=0x%04x  (was 0x0401)" % u16(r))
    r = comm.send_command(C_ENR_CREATE, 0x40, raw=True)
    print(">>> gate 0x96 01 create  -> status=0x%04x  (was 0x0405)" % u16(r))
    print("\n=== provision2 done. If both gates are 0x0000 -> content was the delta. ===")


def mode_provision(sensor, comm):
    """WRITE (sensor flash). Provision this Linux host: write host partition pid 2 with a
    type-1 version tag + type-2 pairing blob (each SHA-256-tagged), per
    re/ghidra-out/HOST-PROVISION-TRACE.md. This is what makes the sensor treat us as a
    provisioned owner and (hypothesis) unblocks 0x96/0x99 MOC. pid 2 is per-host & currently
    empty on this host, so Windows' provisioning is unaffected. Reversible: re-run 0x3f format."""
    sid = tls_up(sensor, comm)

    # capacity
    r = comm.send_command(struct.pack("<B", 0x3e), 0x200, raw=True)
    count = u16(r, 0x0e); cap = None
    for i in range(count):
        o = 0x10 + i * 12
        if r[o] == 2:
            cap = struct.unpack_from("<I", r, o + 8)[0]
    if not cap:
        raise SystemExit("no type-2 host partition descriptor")
    print(">>> host partition pid=2 capacity=%d" % cap)

    # safety: confirm currently empty (all 0xff) before we format/write
    st, cur = _read_part(comm, 2, cap)
    nonff = sum(1 for b in cur if b != 0xff)
    print(">>> current pid=2: status=0x%04x  non-0xff bytes=%d" % (st, nonff))
    if nonff > 0:
        print("    !! partition is NOT empty — aborting to avoid clobbering existing data.")
        print("    first 64B: %s" % cur[:64].hex())
        return

    # build image: type-1 version tag (data 01 00 00 00) + type-2 pairing blob
    pfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
    with open(pfile, "rb") as f:
        pairing_blob = f.read()
    image = _tlv([(1, bytes.fromhex("01000000")), (2, pairing_blob)])
    print(">>> built partition image: %d bytes (type-1 40B + type-2 %dB)" % (len(image), len(pairing_blob) + 0x24))
    assert len(image) <= cap, "image exceeds capacity"

    print(">>> STORAGE_PART_FORMAT (0x3f) pid=2 ...")
    r = comm.send_command(struct.pack("<BB", 0x3f, 2), 2, raw=True)
    print("    -> 0x%04x" % u16(r))
    if u16(r) != 0:
        raise SystemExit("format failed")

    print(">>> STORAGE_PART_WRITE (0x41) pid=2 offset=0 len=%d ..." % len(image))
    cmd = struct.pack("<BBBHII", 0x41, 2, 0, 0xffff, 0, len(image)) + image
    r = comm.send_command(cmd, 6, raw=True)
    written = struct.unpack_from("<I", r, 2)[0] if len(r) >= 6 else -1
    print("    -> status=0x%04x written=%d" % (u16(r), written))
    if u16(r) != 0:
        raise SystemExit("write failed")

    # read back & verify
    st, back = _read_part(comm, 2, cap)
    ok = back[:len(image)] == image
    print(">>> read-back verify: %s (%d bytes match)" % ("OK" if ok else "MISMATCH", len(image)))

    # quick gate test: does GET_CERTIFICATE_EX (0x50) now pass (no longer 0x0401)?
    r = comm.send_command(struct.pack("<BB", 0x50, 0), 0x200, raw=True)
    print(">>> gate test 0x50 GET_CERT -> status=0x%04x (was 0x0401 pre-provision)" % u16(r))
    print("\n=== provision done. Try `enroll` next. ===")


def mode_partinfo(sensor, comm):
    """READ-ONLY. Decode STORAGE_INFO (0x3e) + read the host partition (pid 2) and parse its
    TLV entries. Shows whether pid 2 currently holds Windows' pairing data (safety check
    before any provisioning write). Byte layout per re/ghidra-out/HOST-PROVISION-TRACE.md."""
    tls_up(sensor, comm)
    print("\n>>> STORAGE_INFO (0x3e) ...")
    r = comm.send_command(struct.pack("<B", 0x3e), 0x200, raw=True)
    print("    raw: %s" % r.hex())
    count = u16(r, 0x0e)
    print("    status=0x%04x  count=%d" % (u16(r), count))
    host_pid, host_cap = None, None
    for i in range(count):
        o = 0x10 + i * 12
        if o + 12 > len(r):
            break
        typ, flags = r[o], r[o + 1]
        size4 = struct.unpack_from("<I", r, o + 4)[0]
        val8 = struct.unpack_from("<I", r, o + 8)[0]
        print("    desc[%d]: type=%d flags=%d size@4=%d(0x%x) val@8=%d(0x%x)"
              % (i, typ, flags, size4, size4, val8, val8))
        if typ == 2:
            host_pid = 2
            host_cap = val8 if val8 else size4
    if host_pid is None:
        print("    !! no descriptor with type==2 (host partition) found"); return

    cap = host_cap
    print("\n>>> STORAGE_PART_READ (0x40) pid=2 offset=0 length=%d ..." % cap)
    cmd = struct.pack("<BBBHII", 0x40, 2, 0, 0xffff, 0, cap)
    r = comm.send_command(cmd, cap + 8 + 0x10, raw=True)
    st = u16(r)
    retlen = struct.unpack_from("<I", r, 2)[0]
    data = r[8:8 + retlen]
    print("    status=0x%04x retLen=%d  (got %d data bytes)" % (st, retlen, len(data)))
    print("    first 64B: %s" % data[:64].hex())

    # parse TLV entries: [type:u16][len:u16][digest:32][data:len], stride len+0x24
    import hashlib
    print("\n>>> TLV entries:")
    off, n = 0, 0
    while off + 0x24 <= len(data):
        etype = u16(data, off)
        elen = u16(data, off + 2)
        digest = data[off + 4:off + 36]
        edata = data[off + 36:off + 36 + elen]
        if etype == 0 and elen == 0:
            break
        calc = hashlib.sha256(edata).digest()
        ok = "OK" if calc == digest else "MISMATCH"
        label = {1: "version-tag", 2: "pairing-data"}.get(etype, "?")
        print("    [%d] type=%d (%s) len=%d sha256=%s  data=%s%s"
              % (n, etype, label, elen, ok, edata[:32].hex(), "…" if elen > 32 else ""))
        off += elen + 0x24
        n += 1
    if n == 0:
        print("    (no TLV entries — partition empty/unprovisioned for any host)")
    print("\n=== partinfo done (read-only) ===")


def mode_diag(sensor, comm):
    """READ-ONLY probes to characterize host/storage state vs the MOC enroll precondition."""
    tls_up(sensor, comm)
    print("\n>>> DIAG (read-only). host storage / partition / cert state:\n")
    probes = [
        ("0x3e STORAGE_INFO_GET", struct.pack("<B", 0x3e)),
        ("0x3e +01",             struct.pack("<BB", 0x3e, 1)),
        ("0x50 GET_CERT_EX",     struct.pack("<BB", 0x50, 0)),
        ("0x9e DB2_GET_DB_INFO", struct.pack("<BB", 0x9e, 1)),
        ("0x82 FRAME_STATE_GET", struct.pack("<HxxxxxBB", 0x82, 2, 7)),
    ]
    for desc, cmd in probes:
        try:
            r = comm.send_command(cmd, 0x200, raw=True)
            print("  %-22s -> status=0x%04x len=%d  %s" % (desc, u16(r), len(r), r[:48].hex()))
        except Exception as e:
            print("  %-22s -> %r" % (desc, e))
    print("\n=== diag done ===")


def _list(comm):
    r = comm.send_command(struct.pack("<BB", Command.DB2_GET_OBJ_LIST, 1), 0x400, raw=True)
    st, count = u16(r, 0), u16(r, 2)
    print("    0x9f list: status=0x%04x count=%d" % (st, count))
    for i in range(count):
        print("      GUID[%d] = %s" % (i, r[4 + i*16:20 + i*16].hex()))


def mode_list(sensor, comm):
    tls_up(sensor, comm); print(); _list(comm)


def mode_delete(sensor, comm, guid_hex):
    tls_up(sensor, comm)
    guid = bytes.fromhex(guid_hex)
    assert len(guid) == 16
    print(">>> lookup child of %s ..." % guid_hex)
    r = comm.send_command(struct.pack("<BI", Command.DB2_GET_OBJ_INFO, 2) + guid, 0x34, raw=True)
    child = r[20:36]
    print("    child = %s" % child.hex())
    print(">>> delete child ...")
    r = comm.send_command(struct.pack("<BI", Command.DB2_DELETE_OBJ, 1) + child, 4, raw=True)
    print("    0xa3 -> %s" % r.hex())
    print("\n>>> DB after:"); _list(comm)


def main():
    logging.basicConfig(level=tudor.LOG_INFO, format="%(message)s")
    mode = sys.argv[1] if len(sys.argv) > 1 else "events"
    sensor, comm = open_sensor()
    try:
        if mode == "events":   mode_events(sensor, comm)
        elif mode == "enroll": mode_enroll(sensor, comm)
        elif mode == "verify": mode_verify(sensor, comm)
        elif mode == "probe1": mode_probe1(sensor, comm)
        elif mode == "probe2": mode_probe2(sensor, comm)
        elif mode == "probe3": mode_probe3(sensor, comm)
        elif mode == "diag":   mode_diag(sensor, comm)
        elif mode == "partinfo": mode_partinfo(sensor, comm)
        elif mode == "provision": mode_provision(sensor, comm)
        elif mode == "provision2": mode_provision2(sensor, comm)
        elif mode == "list":   mode_list(sensor, comm)
        elif mode == "delete": mode_delete(sensor, comm, sys.argv[2])
        else: print("unknown mode: %s" % mode); return 2
        return 0
    except KeyboardInterrupt:
        print("\n(interrupted)"); return 130
    finally:
        try:
            if sensor.initialized: sensor.uninitialize()
        except Exception: pass
        try: comm.proxied.close()
        except Exception: pass


if __name__ == "__main__":
    sys.exit(main())
