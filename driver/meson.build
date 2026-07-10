# Per-driver meson snippet for libfprint integration.
# In libfprint/meson.build add 'verimark' to the `drivers` list and, if the secure
# channel uses OpenSSL, ensure the crypto dep is available (see egismoc-sdcp).
#
# Source of truth: prototype/p2_moc.py + findings/49, findings/51. Being rebuilt
# per driver/PORTING-PLAN.md.
#
# Sources compiled into libfprint when the 'verimark' driver is enabled:
verimark_sources = [
  'drivers/verimark/verimark.c',
  'drivers/verimark/verimark-transport-framing.c',  # PORTING-PLAN.md P1 — pure
                                                      # EP0 chunk/pad framing math,
                                                      # no gusb/FpiSsm dependency.
  'drivers/verimark/verimark-transport.c',           # PORTING-PLAN.md P1 — async
                                                      # EP0 control transport
                                                      # (verimark_cmd()) built on
                                                      # the framing helpers above.
  'drivers/verimark/verimark-tls.c',            # docs/superpowers/plans/2026-07-10-
                                                  # verimark-tls-channel.md Tasks 2-6 —
                                                  # hand-rolled handshake SM + record layer.
  'drivers/verimark/verimark-tls-crypto.c',      # crypto core (PRF/derive/cert/GCM/ECDH/ECDSA).
  'drivers/verimark/verimark-pairing.c',         # same plan, Task 7 — 0x93 TOFU pairing +
                                                  # 868-byte pdata persistence.
  'drivers/verimark/verimark-moc.c',             # docs/superpowers/plans/2026-07-10-
                                                  # verimark-moc.md — MOC operations layer:
                                                  # pure framing helpers (offline-TDD,
                                                  # driver/tests/test_moc.c) + the
                                                  # capture/enroll/verify/identify/list/
                                                  # delete/clear FpiSsm state machines
                                                  # (device-deferred; needs fpi-device.h/
                                                  # fpi-ssm.h, so only built here — the
                                                  # standalone driver/tests/meson.build
                                                  # project compiles it with
                                                  # -DVERIMARK_MOC_PURE_ONLY instead).
]

# Standalone unit test for the pure framing helpers (verimark-transport-framing.c)
# — deliberately glib-only (no gusb/libfprint), so it can run without a device or
# the full libfprint build environment. Uncomment once this snippet is wired into
# libfprint's actual libfprint/meson.build (needs a `test()` + the glib-2.0 dep
# already available there); see driver/tests/test_transport_framing.c.
# verimark_transport_framing_test = executable(
#   'test-verimark-transport-framing',
#   [
#     'drivers/verimark/tests/test_transport_framing.c',
#     'drivers/verimark/verimark-transport-framing.c',
#   ],
#   dependencies: [glib_dep],
# )
# test('verimark-transport-framing', verimark_transport_framing_test)

# Secure channel crypto (ECDH P-256, ECDSA verify, AES-CBC, HMAC-SHA256):
#   openssl_dep = dependency('libcrypto', version: '>=3.0.0')
# add openssl_dep to the libfprint deps when 'verimark' is in drivers.

# udev / autosuspend rule (install into the generated 60-libfprint-2.rules):
#   SUBSYSTEM=="usb", ATTRS{idVendor}=="047d", ATTRS{idProduct}=="00f2", ...
