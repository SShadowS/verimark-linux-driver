# reference/protocol — decrypted MOC command reference

Structured, machine-usable capture of the VeriMark (047d:00f2, Synaptics Tudor) VCSFW command
channel — what Windows sends vs. what our Linux prototype sends, with responses on both sides.
Source: Frida CNG plaintext captures (`captures/win-cng-*.log`, 2026-07-08) + live Linux results
(`prototype/p2_moc.py`, findings/28/30/43). Analysis: `findings/44`.

## Files
| File | What | Committed? |
|---|---|---|
| `command-reference.json` | **Merged Windows-vs-Linux command table**: per opcode, the sample payload, response length, status(es), and the divergence verdict. The primary reference. SID/GUIDs redacted. | yes |
| `transcripts/*.json` | **Full ordered command→response transcripts** per session (replay oracle): every `PLAINTEXT-OUT` paired with its `PLAINTEXT-IN`, opcode/sub/status decoded. Contains the Windows user SID → **git-ignored**. | no (local) |
| `../../tools/extract-cng-plaintext.py` | Reusable parser: `extract-cng-plaintext.py <cng.log>... -o out.json`. Point it at any future capture. | yes |

## Key result (see `command-reference.json` → `divergence_summary`)
Every non-gated op returns `0x0000` on both Linux and Windows — our channel and framing are correct.
The only divergences are the three **authorization-gated** ops, where **byte-identical** input yields
success on Windows but `0x04xx` on Linux:
- `0x50` GET_CERTIFICATE_EX → Linux `0x0401` (Windows uses a cached cert, never sends it)
- `0x99:01` IDENTIFY → Windows `0x0509`/`0x0000`, Linux `0x0405`
- `0x96:01` ENROLL create → Windows `0x0000`, Linux `0x0405`

⇒ the sensor gates on host identity, not payload.

## Untested lead
`0x14` (SESSION_INIT?) — Windows sends it first thing every from-boot session (16 B + a fresh 12-B
nonce); we have never sent it. The one command whose omission hasn't been ruled out as the gate.

## Regenerate
```
python3 tools/extract-cng-plaintext.py captures/win-cng-early-20260708-222730.log \
    -o reference/protocol/transcripts/win-enroll-222730.json
```
