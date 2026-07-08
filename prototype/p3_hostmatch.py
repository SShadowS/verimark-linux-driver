#!/usr/bin/env python3
"""
P3 (host-side matching pivot) — capture a real fingerprint IMAGE from the sensor.

On-chip MOC (0x96/0x99) is gated behind a destructive ownership transaction (findings/30);
host-side matching sidesteps it: FRAME_ACQ (0x80) -> FRAME_READ (0x7f, NOT gated) -> image via
rev's native libnative.so. This proves we can get a usable fingerprint image out on Linux with
only the working TLS pairing (no ownership, no risk to Windows).

`capture` mode: bring up TLS, run the frame-capture choreography (findings/29) but READ the
frame (0x7f) instead of feeding an on-chip MOC step, convert to an image, save PNG(s).

Run as root. Reuses rev's tudor.tls/tudor.sensor + libnative over the EP0 transport.
"""
import os, sys, io, time, struct, logging, array, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

import usb.core
import tudor
import tudor.sensor
from tudor.comm import LogCommunicationProxy, Command
from tudor.sensor.pair import SensorPairingData
from control_comm import ControlComm

VID, PID = 0x047d, 0x00f2
PDATA_DIR = os.path.join(HERE, "pdata")
IMG_DIR = os.path.join(HERE, "images")
STATUS_PATH = os.path.join(IMG_DIR, "status.json")
_t0 = time.time()


def _status(state, detail="", **extra):
    """Write live status for the GUI to poll (p3_gui.py). Also prints to stdout."""
    import json
    rec = {"state": state, "detail": detail, "t": round(time.time() - _t0, 1)}
    rec.update(extra)
    try:
        with open(STATUS_PATH, "w") as f:
            json.dump(rec, f)
    except Exception:
        pass
    print(">> [%s] %s" % (state, detail))

EV_FINGER = [1, 2]
EV_FRAME = [24]
C_FRAME_ACQ14 = bytes.fromhex("8014000000010000000100000801010100")
C_FRAME_FIN = bytes.fromhex("81")


def u16(b, o=0): return struct.unpack_from("<H", b, o)[0]


def notify(title, body=""):
    """Best-effort desktop popup to sshadows' session (we run as root)."""
    import subprocess
    try:
        subprocess.run(["sudo", "-u", "sshadows",
                        "DISPLAY=:0", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                        "notify-send", "-t", "3000", title, body],
                       check=False, timeout=3,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={"PATH": "/usr/bin:/bin"})
    except Exception:
        pass


def read_intr(raw, ms=500):
    buf = array.array("B", [0] * 8)
    try:
        n = raw.intr_ep.read(buf, ms); return bytes(buf[:n])
    except usb.core.USBError:
        return None


def evt_read(sensor, comm, deadline):
    eh = sensor.event_handler
    while time.time() < deadline:
        r = comm.send_command(struct.pack("<BHHI", Command.EVENT_READ, eh.event_seq_num, 32, 1), 390, raw=True)
        st = u16(r)
        if st in (0x0405, 0x0406, 0x0407):
            time.sleep(0.015); continue
        if st != 0:
            raise Exception("EVENT_READ 0x%04x" % st)
        nevt = struct.unpack_from("<xxH", r, 0)[0]
        types = [r[6 + i * 12] for i in range(nevt)]
        eh.event_seq_num = (eh.event_seq_num + nevt) & 0xffff
        if types:
            return types
        time.sleep(0.015)
    return []


def save_png_gray(path, img):
    """Minimal grayscale PNG writer (no deps). img = SensorImage (img[x,y])."""
    w, h = img.width, img.height
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter type 0
        for x in range(w):
            raw.append(img[x, y] & 0xff)
    def chunk(typ, data):
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)
    png = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


# FRAME_ACQ in HOST-READOUT mode (mode 1) per FRAME-READOUT-132-TRACE.md:
#   80 14000000 01000000 0100 00 08 00 01 00 00  — differs from MOC only at bytes 0x0d/0x0f (00,00)
C_FRAME_ACQ_READ = struct.pack("<BIIHxBBBBB", 0x80, 0x14, 1, 1, 8, 0, 1, 0, 0)


def capture_one_frame(sensor, comm, deadline, verbose=True):
    """arm[1,2]->press ; arm frame-ready(0x18) ; FRAME_ACQ(mode1) ; wait 0x18 ;
    FRAME_READ(0x7f) loop (132: 10-B header, seq 0,1,… until last/lifted) ; FINISH.
    Returns the (last) frame bytes, or None."""
    eh = sensor.event_handler
    fsize = sensor.frame_capturer.frame_size
    eh.set_event_mask(EV_FINGER)
    pressed = False
    while time.time() < deadline:
        if 0x01 in evt_read(sensor, comm, min(time.time() + 4, deadline)):
            pressed = True; break
        eh.set_event_mask([]); eh.set_event_mask(EV_FINGER)
    if not pressed:
        return None
    _status("READING", "reading frame — KEEP HOLDING until it turns GREEN")
    eh.set_event_mask([]); eh.set_event_mask(EV_FRAME)    # arm FRAME-READY (event 0x18)
    comm.send_command(C_FRAME_ACQ_READ, 2)                # host-readout acquire (mode 1), seq->0
    t = evt_read(sensor, comm, min(time.time() + 4, deadline))   # expect a type-0x18 record
    if verbose:
        print("    frame-ready evt: %s" % t)
    # FRAME_READ loop: response header is 10 B on the 132; seq auto-increments per read.
    frame = None
    seq = 0
    dl = min(time.time() + 6, deadline)
    while time.time() < dl:
        resp = comm.send_command(struct.pack("<BHxxHH", Command.FRAME_READ, seq, 0xffff, 3),
                                 10 + fsize, raw=True, timeout=3000)
        st = u16(resp)
        if st == 0x0689 or len(resp) < 10:
            time.sleep(0.03); continue
        if st != 0:
            if verbose:
                print("    FRAME_READ status=0x%04x (%dB)" % (st, len(resp)))
            break
        flags = struct.unpack_from("<H", resp, 2)[0] & 3   # bit0=last, bit1=finger-lifted
        idx = struct.unpack_from("<H", resp, 6)[0]
        if verbose:
            print("    FRAME_READ seq=%d flags=0x%x idx=%d bytes=%d" % (seq, flags, idx, len(resp) - 10))
        if flags & 2:            # finger lifted -> abort
            break
        frame = resp[10:10 + fsize]
        seq += 1
        if flags & 1:            # last frame
            break
    eh.set_event_mask([])
    comm.send_command(C_FRAME_FIN, 2)
    return frame


def mode_capture(sensor, comm, n=3):
    os.makedirs(IMG_DIR, exist_ok=True)
    _status("STARTING", "bringing up TLS session…", count=0, target=n)
    tls_up(sensor, comm)
    fc = sensor.frame_capturer
    print("\n>>> product_id=%s  frame=%dx%d  frame_size=%d" %
          (sensor.product_id, fc.width, fc.height, fc.frame_size))
    print(">>> Target %d image(s). One 60s window — tap/press the sensor, lift, repeat.\n" % n)
    deadline = time.time() + 60
    saved = 0
    while saved < n and time.time() < deadline:
        _status("WAITING", "PRESS & HOLD the sensor — keep your finger DOWN, don't tap (%d/%d)" % (saved + 1, n),
                count=saved, target=n)
        frame = capture_one_frame(sensor, comm, deadline)
        if frame is None:
            break  # window elapsed
        try:
            img = fc.frame_to_image(frame)
        except Exception as e:
            _status("ERROR", "frame_to_image failed: %s" % e, count=saved, target=n); continue
        png_path = os.path.join(IMG_DIR, "frame_%d.png" % saved)
        with open(os.path.join(IMG_DIR, "frame_%d.bin" % saved), "wb") as f:
            f.write(frame)
        save_png_gray(png_path, img)
        nz = sum(1 for x in range(img.width) for y in range(img.height) if img[x, y] not in (0, 255))
        saved += 1
        _status("CAPTURED", "image %d/%d saved — non-flat px=%d, coverage=%s" %
                (saved, n, nz, img.enough_coverage),
                count=saved, target=n, last_png=png_path, nz=nz)
        time.sleep(0.6)
    _status("DONE", "%d image(s) saved to images/" % saved, count=saved, target=n,
            last_png=os.path.join(IMG_DIR, "frame_%d.png" % (saved - 1)) if saved else "")
    print("\n=== captured %d image(s) -> %s ===" % (saved, IMG_DIR))


def mode_diagread(sensor, comm):
    """One swipe: after press + FRAME_ACQ(readout), log every interrupt + FRAME_READ status
    for 5s, to reveal the frame-ready signal. HOLD the finger down the whole time."""
    os.makedirs(IMG_DIR, exist_ok=True)
    _status("STARTING", "TLS…", count=0, target=1)
    tls_up(sensor, comm)
    raw = comm.proxied
    eh = sensor.event_handler
    fsize = sensor.frame_capturer.frame_size
    _status("WAITING", "PRESS AND HOLD firmly — do not lift", count=0, target=1)
    dl = time.time() + 30
    eh.set_event_mask(EV_FINGER)
    while time.time() < dl and 0x01 not in evt_read(sensor, comm, min(time.time() + 4, dl)):
        eh.set_event_mask([]); eh.set_event_mask(EV_FINGER)
    _status("READING", "acquiring — KEEP HOLDING", count=0, target=1)
    print(">> press seen; FRAME_ACQ(readout); logging 5s (hold!)")
    eh.set_event_mask([]); eh.set_event_mask(EV_FRAME)
    comm.send_command(C_FRAME_ACQ_READ, 2)
    t = time.time()
    it = 0
    while time.time() - t < 5:
        it += 1
        ev = read_intr(raw, 150)
        if ev:
            print("   intr: %s (type=0x%02x)" % (ev.hex(), ev[0]))
        # 0x87 event read — show FULL payload (frame index lives here)
        try:
            r = comm.send_command(struct.pack("<BHHI", Command.EVENT_READ, eh.event_seq_num, 32, 1), 390, raw=True)
            if u16(r) == 0:
                nevt = struct.unpack_from("<xxH", r, 0)[0]
                if nevt:
                    print("   evt87: %s  types=%s" % (r[:6 + nevt * 12].hex(), [r[6 + i * 12] for i in range(nevt)]))
                    eh.event_seq_num = (eh.event_seq_num + nevt) & 0xffff
        except Exception:
            pass
        # FRAME_READ at seqs 0..3 — log ALL statuses (incl 0x0689) once per iteration
        line = []
        for seq in (0, 1, 2, 3):
            rr = comm.send_command(struct.pack("<BHxxHH", Command.FRAME_READ, seq, 0xffff, 3), 10 + fsize, raw=True, timeout=2000)
            st = u16(rr)
            line.append("s%d=0x%04x(%dB)" % (seq, st, len(rr)))
            if st == 0 and len(rr) > 20:
                print("   *** FRAME_READ seq=%d GOT DATA len=%d flags=0x%x ***" %
                      (seq, len(rr), struct.unpack_from("<H", rr, 2)[0] & 3))
        if it % 3 == 1:
            print("   7f: %s" % " ".join(line))
        time.sleep(0.2)
    eh.set_event_mask([])
    comm.send_command(C_FRAME_FIN, 2)
    _status("DONE", "diag done — you can lift", count=0, target=1)
    print(">> diag done")


def tls_up(sensor, comm):
    sid = sensor.id.hex()
    pfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
    with open(pfile, "rb") as f:
        pdata = SensorPairingData.load(io.BytesIO(f.read()))
    sensor.initialize(pdata)
    if not comm.proxied.remote_tls_status():
        raise SystemExit("TLS did not establish")
    return sid


def main():
    logging.basicConfig(level=tudor.LOG_INFO, format="%(message)s")
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise SystemExit("device not found")
    comm = LogCommunicationProxy(ControlComm(dev))
    sensor = tudor.sensor.Sensor(comm)
    mode = sys.argv[1] if len(sys.argv) > 1 else "capture"
    try:
        if mode == "diagread":
            mode_diagread(sensor, comm)
        else:
            mode_capture(sensor, comm, n)
        return 0
    finally:
        try:
            if sensor.initialized:
                sensor.uninitialize()
        except Exception:
            pass
        try:
            comm.proxied.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
