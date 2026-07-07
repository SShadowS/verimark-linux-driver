# Research kickoff prompt — VeriMark Desktop protocol RE

> Hand this whole file to a capable coding/RE agent (e.g. Claude Code) with the
> Ghidra + ILSpy MCP servers attached, **or** follow it yourself as a runbook.
> It assumes you've read `README.md`, `device-facts.md`, `prior-art.md`, and
> `plan.md` in this folder. Don't duplicate their content — build on it.

---

## Role & mission

You are a reverse-engineering engineer. The owner has a **Kensington VeriMark
Desktop (`047d:00f2`)** fingerprint dongle and wants a **Linux `libfprint`
driver** for it. The fingerprint sits behind a **Synaptics match-on-chip sensor
on a TLS-encrypted vendor channel** (USB interface 1; see `device-facts.md`).
Your job in *this* phase is **protocol research**, ending at a single decision:

> **GO/NO-GO (from `plan.md` §1): is the secure channel impersonable from a
> stock Linux host, or is its key bound to Windows/TPM/firmware (→ infeasible)?**

Everything below serves that decision. Produce clean-room protocol documentation,
not copied vendor code.

## Scope & ground rules

- Legitimate **interoperability RE** on **hardware the owner possesses**, for a
  **free/open Linux driver**. Personal use.
- **Do NOT** redistribute Kensington/Synaptics binaries, firmware, or any keys
  you extract. Keep them local (under `re/`, which is git-ignored).
- For anything destined for upstream `libfprint`: document the protocol
  **behaviorally** (message shapes, state machine) and write **original** driver
  code. Never paste decompiler output into the driver. This keeps the IP clean
  and upstreamable.
- Record everything reproducibly: captures → `captures/`, decompiler/analysis
  notes → `findings/`, scratch code → `prototype/`.

## Environment

- **Linux host** (this ThinkPad): device probing, USB capture of the Linux side,
  pyusb prototyping, the eventual libfprint build. Run `./tools/setup-linux-tools.sh`.
- **Windows box or VM** with USB pass-through (the sensor must enroll/verify
  under Windows): this is where the driver binary runs and where the authoritative
  handshake capture + Frida key-dump happen. A Windows 11 VM with the physical
  dongle passed through works.

---

## Phase 0 — Acquire the Windows driver & software

Target files (Synaptics WBDI user-mode driver + Kensington app):

- **INF**: `synaWudfBioUsbKensProd.inf` (Kensington-branded Synaptics WBF driver).
- **Driver DLLs**: `synaWudfBioUsb*.dll` / `synaFpAdapter*.dll` and any Synaptics
  crypto/service DLLs it loads. These are **WUDF user-mode** → hosted in
  `WUDFHost.exe`. **Native code → Ghidra.**
- **Kensington installer / companion app**: may be **.NET** → **ILSpy**.

Sources (try in this order):
1. Kensington VeriMark setup page → Desktop driver (v5.5.3536.1066, Apr 2023):
   https://www.kensington.com/software/verimark-setup/verimark-desktop-setup-guide/
2. Windows Update → Optional updates → "Synaptics Incorporated – Biometric".
3. Microsoft Update Catalog: https://www.catalog.update.microsoft.com/Search.aspx?q=Synaptics+Fingerprint+Driver
4. Extract the installed driver from a working Windows install:
   `C:\Windows\System32\DriverStore\FileRepository\synawudfbiousb*` and the
   companion service under `Program Files`.

Save under `re/driver/` (git-ignored). Note versions in `findings/00-inventory.md`.

## Phase 1 — Triage the binaries (managed vs native)

For each binary decide **.NET (managed)** vs **native**:
- `file`, or check for a CLR header (`ilspycmd --help`; managed assemblies load in
  ILSpy, native ones error).
- **.NET → ILSpy** (`ilspycmd` or the ILSpy MCP): decompile to C#, dump types.
- **Native (.dll/.sys) → Ghidra** (headless import via `./tools/ghidra-headless.sh`,
  then drive with GhidraMCP).

Write `findings/00-inventory.md`: each file, type, tool, one-line role.

## Phase 2 — Static RE: locate the crypto & handshake

In the native Synaptics driver (Ghidra / GhidraMCP), hunt the secure channel:
- **Imports** from `bcrypt.dll` / `ncrypt.dll` (CNG). Flag especially:
  `BCryptSecretAgreement`, `BCryptDeriveKey`, `BCryptGenerateSymmetricKey`,
  `BCryptEncrypt/Decrypt`, `BCryptImportKeyPair`, ECDH (`BCRYPT_ECDH_P256`),
  cert APIs (`CertGetCertificateChain`, `crypt32`).
- Strings: `SDCP`, `ECDH`, `P-256`, `TLS`, `handshake`, `session`, `attest`,
  `cert`, `nonce`, Synaptics protocol tags.
- The **enroll / identify / delete** command builders (the plaintext protocol you
  ultimately need). Trace what gets wrapped by the crypto layer.

For .NET companion (ILSpy / MCP): usually just orchestration, but check for any
key provisioning, pairing, or config that reveals protocol constants.

Deliverable: `findings/10-crypto-map.md` — where keys come from, which KDF, is
the sensor **server-auth-only** or **mutually authenticated / TPM-bound**? This
directly answers GO/NO-GO.

## Phase 3 — Dynamic: dump the live session key (the decisive shortcut)

Static crypto RE is slow; hooking the live process is fast. On Windows:
1. Start `./tools/frida-hook-cng.js` against `WUDFHost.exe` (or the Synaptics
   service): `frida -n WUDFHost.exe -l tools/frida-hook-cng.js`.
2. Enroll/verify a finger. Capture the **ECDH shared secret + derived session
   key** the hook prints.
3. Simultaneously capture USB with **Wireshark + USBPcap** on Windows
   (authoritative), saving to `captures/`.
4. Decrypt the `17 03 03` records with the recovered key(s): feed the pcap +
   keys to Wireshark, or `./tools/decode-tls-records.py` to map framing first.

Now you can read the plaintext command protocol.

## Phase 4 — Extract the protocol & decide

- Reconstruct the state machine: `open/handshake → enroll(N) → identify →
  list/delete → close`. Document in `findings/20-protocol.md` (message tables,
  byte layouts, sequence diagrams).
- Cross-check against libfprint's **`synaptics`** driver command set (`plan.md`
  §2): is this the same MOC protocol under TLS? If so, driver work collapses to
  "secure-channel shim + reuse known commands."
- **State the GO/NO-GO verdict** in `findings/DECISION.md` with evidence:
  - **GO** if a stock Linux host can complete the handshake (server-auth-only,
    key derivable host-side) → proceed to `plan.md` §4–§5 (pyusb prototype →
    libfprint driver).
  - **NO-GO** if host authentication needs a Windows/TPM/firmware-sealed secret →
    document it, post to the community hub (`prior-art.md` §2), stop.

---

## MCP tooling appendix

### GhidraMCP (native binaries) — https://github.com/lauriewired/ghidramcp
1. Install Ghidra (needs JDK 21): https://ghidra-sre.org/
2. Download the GhidraMCP release; in Ghidra: `File → Install Extensions →` add
   the zip; enable the **GhidraMCP** plugin (`File → Configure → Developer`).
   It serves an HTTP bridge (default `http://127.0.0.1:8080/`).
3. Register the MCP bridge with your client (Claude Code):
   ```bash
   claude mcp add ghidra -- python /path/to/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
   ```
   Then open a program in Ghidra (or import via `./tools/ghidra-headless.sh`) and
   the agent can `decompile_function`, `list_methods`, `rename`, `list_imports`, etc.

### ILSpy (.NET binaries)
- **Reliable CLI**: `dotnet tool install --global ilspycmd` →
  `ilspycmd Kensington.exe > findings/ilspy/Kensington.cs` (whole-assembly),
  `ilspycmd -l c Kensington.exe` (list types).
- **MCP option** (lets the agent drive decompilation): `ilspy-mcp-server`
  (https://pypi.org/project/ilspy-mcp-server/, `pip install ilspy-mcp-server`)
  or `@iffrce/mcp-dotnetdc` (npm, wraps `ilspycmd`). Register e.g.:
  ```bash
  claude mcp add ilspy -- npx -y @iffrce/mcp-dotnetdc
  ```
  Use whichever installs cleanly; `ilspycmd` alone is enough if MCPs are flaky.

### Frida (dynamic, Windows)
- `pip install frida-tools` on the Windows RE box; scripts in `tools/`.

---

## What to hand back

At minimum: `findings/00-inventory.md`, `findings/10-crypto-map.md`,
`findings/20-protocol.md` (if you got that far), and **`findings/DECISION.md`**
(the GO/NO-GO with evidence). Keep all binaries/keys/captures local and
git-ignored. If GO, the next prompt is `plan.md` §4 (pyusb prototype).
