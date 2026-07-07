# Per-driver meson snippet for libfprint integration.
# In libfprint/meson.build add 'verimark' to the `drivers` list and, if the secure
# channel uses OpenSSL, ensure the crypto dep is available (see egismoc-sdcp).
#
# Sources compiled into libfprint when the 'verimark' driver is enabled:
verimark_sources = [
  'drivers/verimark/verimark.c',
  'drivers/verimark/verimark-tls.c',
]

# Secure channel crypto (ECDH P-256, ECDSA verify, AES-CBC, HMAC-SHA256):
#   openssl_dep = dependency('libcrypto', version: '>=3.0.0')
# add openssl_dep to the libfprint deps when 'verimark' is in drivers.

# udev / autosuspend rule (install into the generated 60-libfprint-2.rules):
#   SUBSYSTEM=="usb", ATTRS{idVendor}=="047d", ATTRS{idProduct}=="00f2", ...
