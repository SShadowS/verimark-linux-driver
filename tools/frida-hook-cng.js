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
'use strict';

function hex(buf) {
  return Array.prototype.map
    .call(new Uint8Array(buf), b => ('0' + b.toString(16)).slice(-2))
    .join('');
}

function dumpKey(ptr, len, label) {
  try {
    const data = Memory.readByteArray(ptr, len);
    if (data) console.log('  ' + label + ' (' + len + '): ' + hex(data));
  } catch (e) {
    console.log('  (' + label + ' dump failed: ' + e + ')');
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

const TARGETS = {
  'bcrypt.dll': [
    'BCryptSecretAgreement',       // ECDH: produces the shared secret handle
    'BCryptDeriveKey',             // KDF: shared secret -> key bytes (arg3=out, arg4=len)
    'BCryptGenerateSymmetricKey',  // AES/GCM session key import (arg2=key handle, arg3=obj, arg5=secret, arg6=len)
    'BCryptExportKey',
    'BCryptEncrypt',
    'BCryptDecrypt',
    'BCryptImportKeyPair',
  ],
  'ncrypt.dll': [
    'NCryptSecretAgreement',
    'NCryptDeriveKey',
  ],
};

Object.keys(TARGETS).forEach(function (mod) {
  TARGETS[mod].forEach(function (fn) {
    const addr = Module.findExportByName(mod, fn);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.fn = fn;
        this.a = args;
      },
      onLeave: function (retval) {
        console.log('[' + this.fn + '] ret=' + retval);
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
        // AES-CBC runs through BCrypt{Encrypt,Decrypt}; dumping the buffers yields the
        // *plaintext* Tudor command/response protocol directly - no pcap decryption needed.
        // BCryptEncrypt(hKey, pbInput, cbInput, *pad, pbIV, cbIV, pbOutput, cbOutput, *pcbResult, flags)
        if (this.fn === 'BCryptEncrypt') {
          const pin = this.a[1], cin = readLen(this.a[2], 65536);
          const piv = this.a[4], civ = readLen(this.a[5], 64);
          if (piv && !piv.isNull() && civ > 0) dumpKey(piv, civ, 'enc.IV');
          if (pin && !pin.isNull() && cin > 0) dumpKey(pin, cin, 'PLAINTEXT-OUT');
        }
        // BCryptDecrypt(hKey, pbInput, cbInput, *pad, pbIV, cbIV, pbOutput, cbOutput, *pcbResult, flags)
        if (this.fn === 'BCryptDecrypt') {
          const pout = this.a[6], cout = readLen(this.a[8], 65536);
          if (pout && !pout.isNull() && cout > 0) dumpKey(pout, cout, 'PLAINTEXT-IN');
        }
      },
    });
    console.log('hooked ' + mod + '!' + fn);
  });
});

console.log('CNG hooks installed. Enroll/verify a finger on Windows now.');
console.log('Key material: symKeySecret / derivedKey.  Plaintext protocol: PLAINTEXT-OUT/-IN.');
console.log('Tip: also capture USB with Wireshark+USBPcap; feed the dumped key');
console.log('     into Wireshark or tools/decode-tls-records.py to decrypt the 17 03 03 records.');
