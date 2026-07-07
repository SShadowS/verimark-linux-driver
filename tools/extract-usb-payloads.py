#!/usr/bin/env python3
"""Extract USB payloads to/from the VeriMark from a pcapng capture.

Prints a timeline:  <time>  <dir>  ep=<addr>  len=<n>  <hex>
where dir is H>D (host->device, OUT) or D>H (device->host, IN).

Works with usbmon (Linux) and USBPcap (Windows) captures via pyshark/tshark.

Usage:
  ./extract-usb-payloads.py capture.pcapng [--dev N] [--min-len N] [--tls]

  --dev N      only usb.device_address == N (see find-device.sh)
  --min-len N  skip payloads shorter than N bytes (default 1)
  --tls        annotate lines whose payload starts with a TLS record header
"""
import sys
import argparse

try:
    import pyshark
except ImportError:
    sys.exit("need pyshark:  pip install --user pyshark  (and install tshark)")

TLS_CT = {0x14: "CCS", 0x15: "Alert", 0x16: "Handshake", 0x17: "AppData"}


def tls_tag(raw: bytes) -> str:
    if len(raw) >= 5 and raw[0] in TLS_CT and raw[1] == 0x03:
        ln = (raw[3] << 8) | raw[4]
        return f"  <TLS {TLS_CT[raw[0]]} v1.{raw[2]-1} len={ln}>"
    return ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--dev", type=int, default=None)
    ap.add_argument("--min-len", type=int, default=1)
    ap.add_argument("--tls", action="store_true")
    a = ap.parse_args()

    disp = "usb.capdata"
    if a.dev is not None:
        disp += f" and usb.device_address == {a.dev}"

    cap = pyshark.FileCapture(a.pcap, display_filter=disp, keep_packets=False)
    count = 0
    for pkt in cap:
        try:
            usb = pkt.usb
            data = getattr(usb, "capdata", None)
            if not data:
                continue
            raw = bytes.fromhex(data.replace(":", ""))
            if len(raw) < a.min_len:
                continue
            ep = getattr(usb, "endpoint_address", "?")
            # usbmon exposes direction bit; fall back to endpoint high bit
            d = getattr(usb, "endpoint_address_direction", None)
            if d is None:
                try:
                    d = "1" if (int(str(ep), 0) & 0x80) else "0"
                except ValueError:
                    d = "?"
            dirn = "D>H" if d == "1" else "H>D"
            note = tls_tag(raw) if a.tls else ""
            print(f"{pkt.sniff_timestamp}  {dirn}  ep={ep}  len={len(raw):3d}  "
                  f"{raw.hex()}{note}")
            count += 1
        except AttributeError:
            continue
    cap.close()
    if count == 0:
        print("(no usb.capdata payloads matched — check --dev or the filter)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
