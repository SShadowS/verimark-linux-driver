project('verimark-tls-core-tests', 'c',
  default_options : ['c_std=c11', 'warning_level=2'])

glib_dep   = dependency('glib-2.0')
crypto_dep = dependency('libcrypto', version : '>=3.0.0')

# Legacy EC_KEY/ECDH_compute_key path used by the module builds warning-clean here.
add_project_arguments('-DOPENSSL_API_COMPAT=0x10100000L', language : 'c')

tls_core_test = executable('test_tls_core',
  ['test_tls_core.c', '../verimark-tls-crypto.c'],
  dependencies : [glib_dep, crypto_dep])

test('tls_prf', tls_core_test, args : ['-p', '/verimark/prf'])
test('tls_keys', tls_core_test, args : ['-p', '/verimark/derive'])
test('tls_cert', tls_core_test,
  args : ['-p', '/verimark/cert'],
  env  : ['VERIMARK_PDATA=' + meson.current_source_dir() + '/../../prototype/pdata/f7007ad929c60000.pdata'])
test('tls_gcm', tls_core_test, args : ['-p', '/verimark/gcm'])
test('tls_ecc', tls_core_test, args : ['-p', '/verimark/ecc'])

# TLS channel + pairing (docs/superpowers/plans/2026-07-10-verimark-tls-channel.md).
# -DVERIMARK_TESTING exposes the determinism-pin + per-task test seams declared in
# verimark-tls.h / verimark-pairing.h; production builds never define it.
tls_channel_test = executable('test_tls_channel',
  ['test_tls_channel.c', '../verimark-tls.c', '../verimark-pairing.c', '../verimark-tls-crypto.c'],
  c_args : ['-DVERIMARK_TESTING'],
  dependencies : [glib_dep, crypto_dep])
tls_channel_env = ['VERIMARK_PDATA=' + meson.current_source_dir() + '/../../prototype/pdata/f7007ad929c60000.pdata']
test('tls_channel', tls_channel_test, args : ['-p', '/verimark/channel'], env : tls_channel_env)
test('tls_pairing', tls_channel_test, args : ['-p', '/verimark/pairing'], env : tls_channel_env)

# Transport EP0 framing (pure chunk/pad/wValue math, PORTING-PLAN.md P1) — glib only.
framing_test = executable('test_transport_framing',
  ['test_transport_framing.c', '../verimark-transport-framing.c'],
  dependencies : [glib_dep])
test('transport_framing', framing_test)

# MOC operations layer (docs/superpowers/plans/2026-07-10-verimark-moc.md, Tasks 1-3).
# -DVERIMARK_MOC_PURE_ONLY compiles only the pure framing helpers (builders,
# parsers, finalize splicer, SID synth) — no fpi-device.h/fpi-ssm.h, so this
# standalone glib-only project stays buildable without a libfprint checkout.
# The FpiSsm state-machine half of verimark-moc.c (capture/enroll/verify/
# list/delete/clear) is guarded out here; it needs a real libfprint build
# (device-deferred, see verimark-moc.h banner).
moc_test = executable('test_moc',
  ['test_moc.c', '../verimark-moc.c'],
  c_args : ['-DVERIMARK_MOC_PURE_ONLY'],
  dependencies : [glib_dep])
test('moc_build', moc_test, args : ['-p', '/verimark/moc/build'])
test('moc_parse', moc_test, args : ['-p', '/verimark/moc/parse'])
test('moc_finalize', moc_test, args : ['-p', '/verimark/moc/finalize'])
# Task 4 offline fallback (no libfprint here to link a full mock-transport
# FpiSsm smoke test against) — pins the capture SSM's state ordering instead.
test('moc_capture_state_order', moc_test, args : ['-p', '/verimark/moc/capture'])
