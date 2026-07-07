# tools/ — reusable scripts for the VeriMark driver project

Built once so we don't rewrite them every session. Run `setup-linux-tools.sh`
first. Most talk to the live device or to captures; several need `sudo`.

| Script | Host | Purpose |
|---|---|---|
| `setup-linux-tools.sh` | Linux | Install the RE + dev toolchain (pyusb, pyshark, tshark, frida-tools, dotnet+ilspycmd, libfprint build deps, usbmon). |
| `find-device.sh` | Linux | Locate `047d:00f2`: sysfs path, bus/dev numbers, interfaces, hidraw nodes. Other scripts `source` it. |
| `usb-capture.sh` | Linux | Capture the device's USB traffic via `tshark`+`usbmon` into `captures/`. (Authoritative *handshake* capture is Windows/USBPcap — this is for Linux-side experiments & prototype validation.) |
| `extract-usb-payloads.py` | any | Parse a `.pcapng` (usbmon or USBPcap) → clean hex timeline of URB payloads to/from the device. |
| `decode-tls-records.py` | any | Walk a byte/hex stream and label TLS record framing (Handshake `0x16` vs AppData `0x17`, versions, lengths). For the `17 03 03` traffic. |
| `usb-claim.py` | Linux | Detach the kernel driver from an interface, claim it via pyusb, send/recv on its endpoints. For poking interface 1 (vendor) or 0 (FIDO). |
| `frida-hook-cng.js` | Windows | Frida hook on CNG (`bcrypt`/`ncrypt`) to dump the ECDH secret / derived session key from `WUDFHost.exe` — the shortcut to decrypting the channel. |
| `ghidra-headless.sh` | Linux/any | `analyzeHeadless` import + auto-analyze a driver binary into a Ghidra project so the GUI/GhidraMCP can attach. |

## Typical flow

```
./tools/setup-linux-tools.sh
./tools/find-device.sh                       # sanity: device visible?
# --- on Windows: capture + key-dump ---
frida -n WUDFHost.exe -l tools/frida-hook-cng.js   # + Wireshark/USBPcap, then enroll
# --- back on Linux: analyze ---
./tools/extract-usb-payloads.py captures/win-enroll.pcapng --min-len 8
./tools/decode-tls-records.py <(some hex)          # find handshake vs app-data
GHIDRA_HOME=/opt/ghidra ./tools/ghidra-headless.sh re/driver/synaWudfBioUsb.dll
```

Outputs live in `../captures/`, `../findings/`, `../prototype/`.
