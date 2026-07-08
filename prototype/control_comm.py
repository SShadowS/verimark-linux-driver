"""
ControlComm — a synaTudor `rev` CommunicationInterface that speaks the VeriMark
(047d:00f2) bulk-over-EP0-control transport (findings/27).

Drop-in for `rev`'s USBCommunication: everything above CommunicationInterface
(tudor.tls, tudor.sensor.Sensor, DB2, pairing) is reused unchanged. Only the wire
transport differs — this device has no bulk pipe, so the sensor's logical bulk
channel is tunnelled over EP0 vendor control transfers:

  WRITE  bmRequestType=0x40 bRequest=0x16 wValue=(len&7)  data padded to /8, chunked 4096
  READ   bmRequestType=0xc0 bRequest=0x17 wValue=0        chunked 4096, retry-on-timeout

remote_tls_status (0xc0/0x14) and write_dft (0x40/0x15) already match rev's impl.
Events arrive on iface1 interrupt-IN 0x83 (get_event_data).
"""
import struct, time, array
import usb.core, usb.util
from tudor.comm import CommunicationInterface, SUCCESS_STATUS, CommandFailedException

MAXCHUNK = 0x1000  # 4096 — WinUsb control data-stage cap per chunk


class ControlComm(CommunicationInterface):
    def __init__(self, dev, iface=1):
        self.dev = dev
        self.iface = iface
        self.tls_session = None
        self._detached = False
        try:
            if dev.is_kernel_driver_active(iface):
                dev.detach_kernel_driver(iface)
                self._detached = True
        except usb.core.USBError:
            pass
        usb.util.claim_interface(dev, iface)
        intf = dev.get_active_configuration()[(iface, 0)]
        self.intr_ep = usb.util.find_descriptor(
            intf, custom_match=lambda e:
                usb.util.endpoint_type(e.bEndpointAddress) == usb.util.ENDPOINT_TYPE_INTR
                and usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)

    # --- lifecycle ---
    def close(self):
        try: usb.util.release_interface(self.dev, self.iface)
        except Exception: pass
        if self._detached:
            try: self.dev.attach_kernel_driver(self.iface)
            except Exception: pass
        usb.util.dispose_resources(self.dev)

    def release(self):            # LogCommunicationProxy.close() calls proxied.release()
        self.close()

    def reset(self):
        # NB: no USB port reset — the sensor answers fine in its current state and a
        # dev.reset() reboots it into a transient post-reset state (findings/26/27).
        self.tls_session = None

    # --- EP0 control transport ---
    def _ctrl_write(self, data, timeout):
        truelen = len(data)
        buf = bytes(data) + b"\x00" * ((-truelen) % 8)   # pad to /8
        total = len(buf)
        if total == 0:
            self.dev.ctrl_transfer(0x40, 0x16, truelen & 7, 0, b"", timeout)
            return
        off, first = 0, True
        while off < total:
            chunk = buf[off:off + MAXCHUNK]
            islast = (off + len(chunk)) >= total
            wValue = 0 if first else 0x4000
            if islast:
                wValue |= (truelen & 7)          # low bits of the unpadded length
            elif len(chunk) == MAXCHUNK:
                wValue |= 0x8000                 # full continuation chunk
            self.dev.ctrl_transfer(0x40, 0x16, wValue, 0, chunk, timeout)
            off += len(chunk)
            first = False

    def _ctrl_read(self, maxlen, timeout, retries=25):
        out = b""
        remaining = max(maxlen, 1)
        first = True
        while remaining > 0:
            want = min(remaining, MAXCHUNK)
            wValue = 0 if first else 0x4000
            if want == MAXCHUNK:
                wValue |= 0x8000
            data = None
            for _ in range(retries):
                try:
                    data = bytes(self.dev.ctrl_transfer(0xc0, 0x17, wValue, 0, want, timeout))
                    break
                except usb.core.USBError as e:
                    if getattr(e, "errno", None) == 110:   # not ready yet — retry
                        time.sleep(0.02); continue
                    raise
            if data is None:
                raise usb.core.USBError("control read timed out after retries")
            out += data
            first = False
            if len(data) < want:      # short read -> transfer complete
                break
            remaining -= len(data)
        return out

    def send_command(self, cmd, resp_size, timeout=2000, raw=False):
        wcmd = self.tls_session.wrap(cmd) if self.tls_session is not None else cmd
        self._ctrl_write(wcmd, timeout)
        if self.tls_session is not None:
            resp_size += 0x45
        wresp = self._ctrl_read(resp_size, timeout)
        resp = self.tls_session.unwrap(wresp) if self.tls_session is not None else wresp
        if not raw:
            if len(resp) < 2:
                raise Exception("Invalid response (%d bytes)" % len(resp))
            status = struct.unpack("<H", resp[:2])[0]
            if status not in SUCCESS_STATUS:
                raise CommandFailedException(status)
        return resp

    # --- aux (already control transfers in rev; identical here) ---
    def set_tls_session(self, session):
        self.tls_session = session

    def remote_tls_status(self):
        return struct.unpack("<Bx", self.dev.ctrl_transfer(0xc0, 0x14, 0, 0, 2, 2000))[0] != 0

    def write_dft(self, data):
        self.dev.ctrl_transfer(0x40, 0x15, 0, 0, data, 2000)

    def get_event_data(self):
        buf = array.array("B", [0] * 8)
        while True:
            try:
                n = self.intr_ep.read(buf, 1000)
                break
            except usb.core.USBTimeoutError:
                pass
        return bytes(buf[:n])
