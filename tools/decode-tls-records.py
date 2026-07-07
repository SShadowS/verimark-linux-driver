#!/usr/bin/env python3
"""Scan a byte stream for TLS record framing and label each record.

The VeriMark's vendor channel carries `17 03 03 ..` = TLS 1.2 Application Data.
This tells handshake (0x16, with the handshake message type) apart from encrypted
app-data (0x17), and prints record lengths — useful for finding the ClientHello/
ServerHello/Certificate/KeyExchange sequence at the *start* of a session (which
determines whether the channel is server-auth-only or mutually authenticated).

Usage:
  ./decode-tls-records.py capture-hex.txt        # file of hex (any whitespace/':')
  echo '160303004a0100...' | ./decode-tls-records.py
"""
import sys
import re

CONTENT_TYPE = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
}
HANDSHAKE = {
    0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
    13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
    16: "ClientKeyExchange", 20: "Finished",
}


def load_hex() -> bytes:
    src = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", src))


def main() -> None:
    b = load_hex()
    i = 0
    n = 0
    while i + 5 <= len(b):
        ct, vmaj, vmin = b[i], b[i + 1], b[i + 2]
        length = (b[i + 3] << 8) | b[i + 4]
        # a valid record: known content type, TLS major version 0x03, sane length
        if ct not in CONTENT_TYPE or vmaj != 0x03 or length == 0 or length > 0x4000:
            i += 1  # not a record boundary; slide one byte
            continue
        body = b[i + 5:i + 5 + length]
        extra = ""
        if ct == 0x16 and body:  # cleartext handshake → show the message type
            extra = f" -> {HANDSHAKE.get(body[0], f'hs?{body[0]}')}"
        preview = body[:16].hex() + ("..." if length > 16 else "")
        print(f"[{n:3d}] off={i:6d}  {CONTENT_TYPE[ct]:16s} TLS1.{vmin - 1} "
              f"len={length:<5d}{extra}  {preview}")
        i += 5 + length
        n += 1
    if n == 0:
        print("no TLS records found — traffic may be pre-handshake vendor framing "
              "or not aligned to a record boundary in this slice.")


if __name__ == "__main__":
    main()
