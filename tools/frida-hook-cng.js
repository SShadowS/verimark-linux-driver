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
        if (this.fn === 'BCryptGenerateSymmetricKey') {
          const pbSecret = this.a[4];
          const cbSecret = this.a[5].toInt32();
          if (pbSecret && !pbSecret.isNull() && cbSecret > 0 && cbSecret < 4096) {
            dumpKey(pbSecret, cbSecret, 'symKeySecret');
          }
        }
      },
    });
    console.log('hooked ' + mod + '!' + fn);
  });
});

console.log('CNG hooks installed. Enroll/verify a finger on Windows now.');
console.log('Tip: also capture USB with Wireshark+USBPcap; feed the dumped key');
console.log('     into Wireshark or tools/decode-tls-records.py to decrypt.');
