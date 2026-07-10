/*
 * Kensington VeriMark Desktop (Synaptics "Tudor" MOC) libfprint driver
 * USB 047d:00f2 — match-on-chip fingerprint over a server-auth TLS 1.2 channel.
 *
 * SKELETON — structure + protocol constants are from the reverse-engineering in
 * ../findings/21-command-reference.md (and 10/20). Items marked TODO(capture) need
 * a live Windows working-session capture (USBPcap + Frida key-dump) to finalize the
 * encrypted command bodies / exact handshake bytes; everything else is RE-derived.
 *
 * Clean-room: written from behavioral notes, not vendor code.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Source of truth: prototype/p2_moc.py + findings/49, findings/51. Being rebuilt
 * per driver/PORTING-PLAN.md. Earlier contents were derived from the Windows IOCTL
 * surface (findings/21) before the wire protocol was known and were fictional —
 * removed. */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"

/* VerimarkPairing is a plain, fully-defined struct (not opaque, unlike
 * VerimarkTls below) -- needed by value/pointer in FpiDeviceVerimark itself
 * (the dev_open()-cached pairing, verimark.c), so pull in its definition
 * here rather than forward-declaring it. */
#include "verimark-tls-crypto.h"

/* ---- USB identity / transport (findings/21 "USB transport") ------------------ */
#define VERIMARK_VID              0x047d
#define VERIMARK_PID              0x00f2

#define VERIMARK_IFACE            1        /* vendor-specific interface */
#define VERIMARK_EP_INTR_IN       0x83     /* 8-byte interrupt-IN: events/responses  */
#define VERIMARK_INTR_MAXPKT      8
/* Commands go OUT via EP0 vendor control transfers; there is NO bulk/OUT pipe.     */
#define VERIMARK_CTRL_TIMEOUT_MS  5000
#define VERIMARK_INTR_TIMEOUT_MS  0        /* 0 = no timeout (finger-wait/wake)      */

/* EP0 control-transfer request constants (prototype/control_comm.py::ControlComm
 * ._ctrl_write/_ctrl_read — bulk-over-EP0-control per findings/27). WRITE carries
 * the (TLS-wrapped, once paired) command bytes padded to a multiple of 8 and
 * chunked at VERIMARK_CTRL_MAXCHUNK; wValue on the last (or only) chunk carries
 * the unpadded length's low 3 bits. READ polls for the response, retrying while
 * the sensor answers "not ready" (Linux errno 110 / ETIMEDOUT on the control
 * transfer) until data arrives or a short read signals completion. */
#define VERIMARK_CTRL_REQTYPE_WRITE  0x40  /* bmRequestType, host->device vendor  */
#define VERIMARK_CTRL_REQ_WRITE      0x16  /* bRequest                            */
#define VERIMARK_CTRL_REQTYPE_READ   0xc0  /* bmRequestType, device->host vendor  */
#define VERIMARK_CTRL_REQ_READ       0x17  /* bRequest                            */
#define VERIMARK_CTRL_MAXCHUNK       0x1000 /* 4096 — WinUsb control data-stage cap */

/* ---- Command surface — real Tudor wire opcodes, taken verbatim from
 * re/synaTudor-rev/pydrv/tudor/comm.py::Command. Single-byte opcodes sent over
 * the EP0 bulk-over-control transport (findings/27); once paired, most are
 * wrapped in the TLS channel (verimark-tls.*) via TLS_DATA framing. See
 * prototype/p2_moc.py + prototype/control_comm.py for live usage, and
 * findings/49/51 for the wire-confirmed MOC (0x96/0x99) behavior. */
#define VERIMARK_CMD_GET_VERSION          0x01
#define VERIMARK_CMD_REST                 0x05
#define VERIMARK_CMD_PEEK                 0x07
#define VERIMARK_CMD_POKE                 0x08
#define VERIMARK_CMD_PROVISION            0x0e
#define VERIMARK_CMD_RESET_OWNERSHIP      0x10
#define VERIMARK_CMD_GET_START_INFO       0x19
#define VERIMARK_CMD_LED_EX2              0x39
#define VERIMARK_CMD_STORAGE_INFO_GET     0x3e
#define VERIMARK_CMD_STORAGE_PART_FORMAT  0x3f
#define VERIMARK_CMD_STORAGE_PART_READ    0x40
#define VERIMARK_CMD_STORAGE_PART_WRITE   0x41
#define VERIMARK_CMD_TLS_DATA             0x44
#define VERIMARK_CMD_DB_OBJECT_CREATE     0x47
#define VERIMARK_CMD_TAKE_OWNERSHIP_EX2   0x4f
#define VERIMARK_CMD_GET_CERTIFICATE_EX   0x50
#define VERIMARK_CMD_SET_IDLE_TIMEOUT     0x57
#define VERIMARK_CMD_BOOTLOADER_PATCH     0x7d
#define VERIMARK_CMD_FRAME_READ           0x7f
#define VERIMARK_CMD_FRAME_ACQ            0x80
#define VERIMARK_CMD_FRAME_FINISH         0x81
#define VERIMARK_CMD_FRAME_STATE_GET      0x82
#define VERIMARK_CMD_EVENT_CONFIG         0x86
#define VERIMARK_CMD_EVENT_READ           0x87
#define VERIMARK_CMD_FRAME_STREAM         0x8b
#define VERIMARK_CMD_READ_IOTA            0x8e
#define VERIMARK_CMD_PAIR                 0x93
#define VERIMARK_CMD_DB2_GET_DB_INFO      0x9e
#define VERIMARK_CMD_DB2_GET_OBJ_LIST     0x9f
#define VERIMARK_CMD_DB2_GET_OBJ_INFO     0xa0
#define VERIMARK_CMD_DB2_GET_OBJ_DATA     0xa1
#define VERIMARK_CMD_DB2_DELETE_OBJ       0xa3  /* NB: comm.py::Command aliases
                                                  * DB2_CLEANUP to this same 0xa3 */
#define VERIMARK_CMD_DB2_FORMAT           0xa5

/* MOC (match-on-chip) enroll/identify opcodes — wire-confirmed live (findings/49,
 * findings/51; prototype/p2_moc.py) but NOT present in tudor/comm.py::Command
 * (that enum predates the MOC discovery on this device). Included here because
 * they are the two opcodes the enroll/verify SSMs (P4/P5) actually drive. */
#define VERIMARK_CMD_ENROLL               0x96  /* sub-op in payload byte 0:
                                                  * 01 create, 02 add-sample,
                                                  * 03 finalize, 04 commit */
#define VERIMARK_CMD_IDENTIFY             0x99  /* sub-op 01 = begin-identify;
                                                  * also used for dedup during
                                                  * enroll (p2_moc.py C_BEGIN_ID) */

/* 0x96/0x99 MOC response field offsets (findings/51, byte offsets into the
 * decrypted response body):
 *   resp[0:2]   status (u16 LE) — 0x0000 ok, 0x0405/0x0401 not-authorized (MOC
 *               gate, see findings/43-45), 0x0509 no-match (verify/identify).
 *   resp[2:18]  template id (16 B) — sensor-minted on enroll create, echoed on
 *               a matching identify.
 *   resp[22]    coverage (u8) — add-sample progress; enroll complete at 0x7f.
 *   resp[42]    quality (u8) — per-sample quality score.
 * `0x96 03` finalize additionally splices the minted id into offset [19:35] of
 * a 124-byte payload before `0x96 04` commit (see prototype/p2_moc.py
 * WIN_FINALIZE / build_finalize). */

/* Enroll stages libfprint asks the user for (guided enroll ~ 8-12 presses). */
#define VERIMARK_ENROLL_STAGES    8

/* ---- Secure channel — see verimark-tls.h for the real (non-standard) TLS 1.2
 * channel description (cipher 0xC02E, AEAD, mutual-auth-capable, TOFU pairing).
 * The record-format notes that used to live here (AES-CBC + HMAC-SHA256) were
 * wrong; removed. */

typedef struct _VerimarkTls VerimarkTls;   /* opaque secure-channel context (verimark-tls.c) */

/* ---- Device object ----------------------------------------------------------- */
G_DECLARE_FINAL_TYPE (FpiDeviceVerimark, fpi_device_verimark, FPI, DEVICE_VERIMARK,
                      FpDevice)

struct _FpiDeviceVerimark {
  FpDevice     parent;

  guint8       iface;            /* claimed vendor interface number (VERIMARK_IFACE
                                   * mirrored here rather than re-read from the
                                   * macro, for symmetry with ep_intr_in below and
                                   * in case a future revision needs to probe it) */
  guint8       ep_intr_in;       /* interrupt-IN endpoint address, located and
                                   * verified at dev_open() time (expected to equal
                                   * VERIMARK_EP_INTR_IN); 0 when not open          */

  VerimarkTls *tls;              /* secure channel state (handshake keys, session) */
  guint8      *pairing_data;     /* TOFU pairing blob: host EC P-256 privkey + host
                                   * cert + sensor cert (PORTING-PLAN.md §3 #5);
                                   * see prototype pdata/<sid>.pdata for the layout.
                                   * Superseded by the typed `pairing` field below
                                   * (added once verimark-tls-crypto.h's typed
                                   * VerimarkPairing existed) -- kept unused rather
                                   * than removed per the integration pass's
                                   * additive-only-fields rule; dev_open()/close()
                                   * always leave it NULL/0 now. */
  gsize        pairing_len;

  gchar           *sid;          /* 6-byte sensor id, hex-encoded (GET_VERSION
                                   * resp[18:24], prototype/p0_ctrl.py:101-107);
                                   * keys the pdata filename (verimark_pairing_path(),
                                   * verimark-pairing.h). Set at dev_open(), freed at
                                   * dev_close(). NOT the MOC finalize SID (a
                                   * different, 28-byte, Windows-style value synthesized
                                   * by verimark_moc_synth_sid(), verimark-moc.h). */
  VerimarkPairing *pairing;      /* cached typed pairing credential -- loaded from
                                   * disk or freshly TOFU-paired (0x93) at dev_open(),
                                   * handed to verimark_tls_set_pairing() (which
                                   * copies it), kept for the lifetime of the open
                                   * session, freed at dev_close(). */

  FpiSsm      *task_ssm;         /* current operation state machine                */
  guint8       intr_buf[VERIMARK_INTR_MAXPKT];

  /* enroll bookkeeping */
  FpPrint     *enroll_print;
  guint        enroll_stage;
  guint8       enroll_coverage;      /* TODO(P4): last add-sample coverage byte
                                       * (resp[22]); enroll done at 0x7f          */
  guint8       enroll_template_id[16]; /* sensor-minted id (findings/51), stashed
                                         * at the coverage==0x7f add-sample and
                                         * consumed by the 0x96 03 finalize step
                                         * (driver/verimark-moc.c) */

  /* MOC event-sequence tracking (mirrors tudor.sensor.event.
   * SensorEventHandler.event_seq_num) — must persist across capture/
   * EVENT_READ calls within a session, not be reset per-call (verimark-moc.c). */
  guint16      event_seq_num;
};
