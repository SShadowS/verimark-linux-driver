// frida-hook-cng.js — dump Windows CNG key material used by the VeriMark driver.
//
// Run on the WINDOWS RE box against the process hosting the Synaptics WUDF
// driver (usually WUDFHost.exe) or the Synaptics/Kensington service:
//
//     frida -n WUDFHost.exe -l frida-hook-cng.js
//     (list candidates:  frida-ps | findstr /i "WUDF Synaptics Kensington")
//
// Goal: capture the ECDH shared secret and/or derived session key so you can
// decrypt the `17 03 03` TLS application-data in your USB capture and read the
// plaintext fingerprint protocol. Enroll/verify a finger while this is attached.
//
// TWO INJECTION MODES, one code path:
//   * attach mode (win-capture.py default): we attach to the already-running
//     biometric WUDFHost. bcrypt + synaWudfBioUsb are already mapped, so tryArm()
//     arms immediately at load.
//   * spawn-gate mode (win-capture.py --spawn-gate): we are injected at t=0 into a
//     freshly-spawned WUDFHost *before its entry point runs*, so neither the driver
//     nor bcrypt is mapped yet. We DON'T know if this host is the biometric one. So
//     we defer: watch LdrLoadDll, and only arm once BOTH synaWudfBioUsb AND bcrypt
//     are present. Non-biometric hosts never load synaWudfBioUsb -> stay inert.
'use strict';

// Frida 17 auto-prints console.log to the injector's stdout but does NOT deliver
// it to the Python message handler, so it never reaches the capture logfile.
// Route everything through send() so win-capture.py persists the key material.
function out(line) { send(line); }

function hex(buf) {
  return Array.prototype.map
    .call(new Uint8Array(buf), b => ('0' + b.toString(16)).slice(-2))
    .join('');
}

function dumpKey(ptr, len, label) {
  try {
    const data = ptr.readByteArray(len);
    if (data) out('  ' + label + ' (' + len + '): ' + hex(data));
  } catch (e) {
    out('  (' + label + ' dump failed: ' + e + ')');
  }
}

// Read a length that may be passed by value or by pointer (pcbResult).
function readLen(arg, maxCap) {
  try {
    const n = arg.toInt32();
    if (n >= 0 && n <= maxCap) return n;
  } catch (e) {}
  try {
    const n = arg.readU32();
    if (n >= 0 && n <= maxCap) return n;
  } catch (e) {}
  return -1;
}

// The VeriMark channel is AES-256-GCM (not CBC): pbIV is null and the nonce/tag
// live in a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO struct passed as pPaddingInfo.
// x64 layout: cbSize@0x00 dwInfoVersion@0x04 pbNonce@0x08 cbNonce@0x10
// pbAuthData@0x18 cbAuthData@0x20 pbTag@0x28 cbTag@0x30 ...  (sizeof = 0x60)
function gcmInfo(pInfo) {
  if (!pInfo || pInfo.isNull()) return null;
  try {
    const cbSize = pInfo.readU32();
    if (cbSize < 0x50 || cbSize > 0x200) return null;   // not the AEAD struct
    return {
      pbNonce: pInfo.add(0x08).readPointer(), cbNonce: pInfo.add(0x10).readU32(),
      pbTag:   pInfo.add(0x28).readPointer(), cbTag:   pInfo.add(0x30).readU32(),
    };
  } catch (e) { return null; }
}

function dumpGcmField(ptr, len, label) {   // nonces/tags are small
  if (ptr && !ptr.isNull() && len > 0 && len <= 64) dumpKey(ptr, len, label);
}

function dumpPayload(ptr, len, label) {    // record plaintext/ciphertext (can be large)
  if (ptr && !ptr.isNull() && len > 0 && len <= 65536) dumpKey(ptr, len, label);
}

const TARGETS = {
  'bcrypt.dll': [
    'BCryptSecretAgreement',       // ECDH: produces the shared secret handle
    'BCryptDeriveKey',             // KDF: shared secret -> key bytes (arg3=out, arg4=len)
    'BCryptGenerateSymmetricKey',  // AES/GCM session key import (arg2=key handle, arg3=obj, arg5=secret, arg6=len)
    'BCryptExportKey',
    'BCryptEncrypt',
    'BCryptDecrypt',
    'BCryptImportKeyPair',
    // Cheap insurance for the pairing/host-cert path: the host self-signs its
    // ephemeral cert before the 0x93 pair. BCryptSignHash's pbInput (the hash
    // being signed) is cleartext here; the sign/keygen calls also mark exactly
    // when the host identity is minted. These never pass through the wire capture.
    'BCryptSignHash',              // pbInput (arg2) = the hash being self-signed
    'BCryptVerifySignature',
    'BCryptGenerateKeyPair',
    'BCryptFinalizeKeyPair',
  ],
  'ncrypt.dll': [
    'NCryptSecretAgreement',
    'NCryptDeriveKey',
  ],
};

// Install the CNG interceptors. Assumes the target modules are mapped (guaranteed
// by tryArm's gate). Emits a "hooked <mod>!<fn>" line per hook so win-capture.py
// can count installed hooks.
function armAll() {
  Object.keys(TARGETS).forEach(function (mod) {
    TARGETS[mod].forEach(function (fn) {
      const m = Process.findModuleByName(mod);
      const addr = m ? m.findExportByName(fn) : null;
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.fn = fn;
          // Snapshot the arg pointers now: frida's `args` proxy is only valid during
          // onEnter. Reading it in onLeave throws "invalid operation" (frida 17), so
          // we keep the NativePointers and dereference the output buffers on return.
          this.a = [args[0], args[1], args[2], args[3], args[4],
                    args[5], args[6], args[7], args[8], args[9]];
          // BCrypt{En,De}crypt run IN-PLACE (pbInput == pbOutput). So the plaintext
          // must be grabbed at the right phase:
          //  - Encrypt: pbInput is the outgoing command PLAINTEXT *before* the call;
          //    after the call the same buffer holds ciphertext. Read it here.
          //  - Decrypt: pbInput is the incoming record CIPHERTEXT (the wire bytes).
          // BCryptEncrypt(hKey, pbInput, cbInput, *pad, pbIV, cbIV, pbOutput, ...)
          if (this.fn === 'BCryptEncrypt') {
            const cin = readLen(args[2], 65536);
            dumpPayload(args[1], cin, 'PLAINTEXT-OUT');
            const g = gcmInfo(args[3]);
            if (g) dumpGcmField(g.pbNonce, g.cbNonce, 'gcm.nonce.out');
          }
          // BCryptSignHash(hKey, *pPaddingInfo, pbInput, cbInput, pbOutput, ...)
          // pbInput is the hash the host is self-signing for its ephemeral cert.
          if (this.fn === 'BCryptSignHash') {
            const cin = readLen(args[3], 4096);
            dumpPayload(args[2], cin, 'SIGN-HASH-IN');
          }
          if (this.fn === 'BCryptDecrypt') {
            const cin = readLen(args[2], 65536);
            dumpPayload(args[1], cin, 'CIPHERTEXT-IN');    // wire bytes (17 03 03 body)
            const g = gcmInfo(args[3]);
            if (g) {
              dumpGcmField(g.pbNonce, g.cbNonce, 'gcm.nonce.in');
              dumpGcmField(g.pbTag, g.cbTag, 'gcm.tag.in');
            }
          }
        },
        onLeave: function (retval) {
          out('[' + this.fn + '] ret=' + retval);
          // BCryptDeriveKey(hSecret, pwszKDF, *params, pbDerivedKey, cbDerivedKey, *pcbResult, flags)
          if (this.fn === 'BCryptDeriveKey' || this.fn === 'NCryptDeriveKey') {
            const pbuf = this.a[3];
            const clen = this.a[4].toInt32();
            if (pbuf && !pbuf.isNull() && clen > 0 && clen < 4096) {
              dumpKey(pbuf, clen, 'derivedKey');
            }
          }
          // BCryptGenerateSymmetricKey(hAlg, *phKey, *pbKeyObject, cbKeyObject, pbSecret, cbSecret, flags)
          // pbSecret is the raw AES session-key material -> the prize for decrypting the channel.
          if (this.fn === 'BCryptGenerateSymmetricKey') {
            const pbSecret = this.a[4];
            const cbSecret = this.a[5].toInt32();
            if (pbSecret && !pbSecret.isNull() && cbSecret > 0 && cbSecret < 4096) {
              dumpKey(pbSecret, cbSecret, 'symKeySecret');
            }
          }
          // BCryptExportKey(hKey, hExportKey, pszBlobType, pbOutput, cbOutput, *pcbResult, flags)
          // Grabs exported public keys / EC blobs used in the pairing/handshake.
          if (this.fn === 'BCryptExportKey') {
            const pbuf = this.a[3];
            const clen = readLen(this.a[5], 8192);   // pcbResult (actual bytes written)
            if (pbuf && !pbuf.isNull() && clen > 0) dumpKey(pbuf, clen, 'exportedBlob');
          }
          // In-place encrypt: pbInput now holds the CIPHERTEXT that went on the wire;
          // the GCM tag was written into the mode-info struct by the call.
          if (this.fn === 'BCryptEncrypt') {
            const cin = readLen(this.a[2], 65536);
            dumpPayload(this.a[1], cin, 'CIPHERTEXT-OUT');
            const g = gcmInfo(this.a[3]);
            if (g) dumpGcmField(g.pbTag, g.cbTag, 'gcm.tag.out');
          }
          // BCryptDecrypt(hKey, pbInput, cbInput, *pad, pbIV, cbIV, pbOutput, cbOutput, *pcbResult, flags)
          // In-place decrypt: pbOutput now holds the response PLAINTEXT.
          if (this.fn === 'BCryptDecrypt') {
            const pout = this.a[6], cout = readLen(this.a[8], 65536);
            if (pout && !pout.isNull() && cout > 0) dumpKey(pout, cout, 'PLAINTEXT-IN');
          }
        },
      });
      out('hooked ' + mod + '!' + fn);
    });
  });
  out('CNG hooks installed. Enroll/verify a finger on Windows now.');
  out('Key material: symKeySecret / derivedKey.  Plaintext protocol: PLAINTEXT-OUT/-IN.');
  out('Tip: also capture USB with Wireshark+USBPcap; feed the dumped key');
  out('     into Wireshark or tools/decode-tls-records.py to decrypt the 17 03 03 records.');
}

// --- self-select + deferred arming -----------------------------------------
// The biometric host loads a module matching /synawudfbiousb/ (the umdf package).
// A non-biometric WUDFHost (printer, BLE, built-in reader UWP pkg) never does, so
// it stays inert. We arm only once that driver AND bcrypt are both mapped.
let armed = false;

function biometricPresent() {
  try {
    return Process.enumerateModules().some(function (m) {
      return /synawudfbiousb/i.test(m.name);
    });
  } catch (e) { return false; }
}

function tryArm() {
  if (armed) return;
  if (!biometricPresent()) return;                 // not the biometric host (yet)
  if (!Process.findModuleByName('bcrypt.dll')) return;  // CNG not mapped yet
  armed = true;
  out('BIOMETRIC-HOST: synaWudfBioUsb + bcrypt present -> arming CNG hooks (pid=' +
      Process.id + ')');
  armAll();
}

// Re-check on every module load (early-attach: driver/bcrypt arrive after we attach).
// NOTE frida 17 removed the static Module.getExportByName(mod, fn); use the same
// instance-method idiom armAll() uses (Process.findModuleByName -> findExportByName).
try {
  const ntdll = Process.findModuleByName('ntdll.dll');
  const ldr = ntdll ? ntdll.findExportByName('LdrLoadDll') : null;
  if (ldr) {
    Interceptor.attach(ldr, { onLeave: function () { tryArm(); } });
  } else {
    out('(LdrLoadDll not found — arming only works if driver already loaded at attach)');
  }
} catch (e) {
  out('(LdrLoadDll watch failed: ' + e + ' — attach-mode arming still works)');
}

// Attach-mode: modules already present -> arms right now. Spawn-gate on a
// biometric host that already finished loading before we ran -> also arms now.
tryArm();

if (!armed) {
  out('waiting: not the biometric host yet (no synaWudfBioUsb) — will arm on driver load');
}
