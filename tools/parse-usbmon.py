#!/usr/bin/env python3
"""Dependency-free parser for Linux usbmon pcap captures (DLT_USB_LINUX_MMAPPED=220).

Extracts a per-URB timeline — direction, transfer type, endpoint, control SETUP,
and payload hex — without tshark/pyshark/scapy. Annotates payloads that begin with
a TLS record header (the VeriMark vendor channel is TLS-1.2, `17 03 03 ..`).

Usage:
  ./parse-usbmon.py capture.pcap [--dev N] [--min-len N] [--ep 0xNN] [--tls-only]
"""
import sys, struct, argparse

XFER = {0: "ISO", 1: "INTR", 2: "CTRL", 3: "BULK"}
TLS_CT = {0x14: "CCS", 0x15: "Alert", 0x16: "Handshake", 0x17: "AppData"}
HS = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
      8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
      13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
      16: "ClientKeyExchange", 20: "Finished"}


def tls_tag(b: bytes) -> str:
    if len(b) >= 5 and b[0] in TLS_CT and b[1] == 0x03 and b[2] in (0x01, 0x03):
        ln = (b[3] << 8) | b[4]
        extra = ""
        if b[0] == 0x16 and len(b) >= 6:
            extra = " " + HS.get(b[5], f"hs{b[5]}")
        return f"  <<TLS {TLS_CT[b[0]]} v1.{b[2]-1} len={ln}{extra}>>"
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--dev", type=int, default=None)
    ap.add_argument("--min-len", type=int, default=0)
    ap.add_argument("--ep", default=None, help="filter endpoint, e.g. 0x83")
    ap.add_argument("--tls-only", action="store_true")
    a = ap.parse_args()
    ep_filt = int(a.ep, 16) if a.ep else None

    data = open(a.pcap, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        le = magic == b"\xd4\xc3\xb2\xa1"
    else:
        sys.exit("not a classic pcap")
    en = "<" if le else ">"
    net = struct.unpack(en + "I", data[20:24])[0]
    if net != 220:
        print(f"# warning: linktype {net} (expected 220 usbmon mmapped)", file=sys.stderr)

    off = 24
    n = 0
    devs, eps = {}, {}
    while off + 16 <= len(data):
        ts_s, ts_us, incl, orig = struct.unpack(en + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < 64:
            continue
        # usbmon mmapped header (64 bytes)
        (urb_id, ev_type, xfer, epnum, devnum, busnum, flag_setup, flag_data,
         tsec, tusec, status, length, len_cap) = struct.unpack(en + "QBBBBHbbqiiII", pkt[:40])
        setup = pkt[40:48]
        payload = pkt[64:64 + len_cap]
        ev = chr(ev_type)
        d_in = bool(epnum & 0x80)
        ep = epnum & 0x7f
        devs[devnum] = devs.get(devnum, 0) + 1
        eps[(devnum, epnum, XFER.get(xfer))] = eps.get((devnum, epnum, XFER.get(xfer)), 0) + 1

        if a.dev is not None and devnum != a.dev:
            continue
        if ep_filt is not None and epnum != ep_filt:
            continue

        n += 1
        dirs = "D>H" if d_in else "H>D"
        line = f"[{n:04d}] {ev} {XFER.get(xfer,'?'):4} dev{devnum} ep0x{epnum:02x} {dirs}"
        if xfer == 2 and flag_setup == 0:  # setup packet present
            bmr, breq, wval, widx, wlen = struct.unpack("<BBHHH", setup)
            line += f"  SETUP[bmReq=0x{bmr:02x} bReq=0x{breq:02x} wVal=0x{wval:04x} wIdx=0x{widx:04x} wLen={wlen}]"
        tag = tls_tag(payload)
        if a.tls_only and not tag:
            continue
        if len(payload) >= a.min_len:
            hx = payload.hex()
            if len(hx) > 240:
                hx = hx[:240] + f"...(+{len(payload)-120}B)"
            line += f"  len={len(payload)} {hx}{tag}"
        else:
            line += f"  len={len(payload)}"
        print(line)

    print("\n# device URB counts:", devs, file=sys.stderr)
    print("# (dev,ep,xfer) counts:", {f"d{k[0]}/ep0x{k[1]:02x}/{k[2]}": v for k, v in eps.items()}, file=sys.stderr)


if __name__ == "__main__":
    main()
