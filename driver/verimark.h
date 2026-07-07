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

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"

/* ---- USB identity / transport (findings/21 "USB transport") ------------------ */
#define VERIMARK_VID              0x047d
#define VERIMARK_PID              0x00f2

#define VERIMARK_IFACE            1        /* vendor-specific interface */
#define VERIMARK_EP_INTR_IN       0x83     /* 8-byte interrupt-IN: events/responses  */
#define VERIMARK_INTR_MAXPKT      8
/* Commands go OUT via EP0 vendor control transfers; there is NO bulk/OUT pipe.     */
#define VERIMARK_CTRL_TIMEOUT_MS  5000
#define VERIMARK_INTR_TIMEOUT_MS  0        /* 0 = no timeout (finger-wait/wake)      */

/* ---- Command surface (findings/21 "MASTER IOCTL -> handler table") -----------
 * On Windows these are SSI IOCTL codes at the adapter<->driver boundary; each maps
 * to one Tudor command the driver sends over the secure channel. We reuse the low
 * function-index as our logical opcode namespace: 0x440xx = sensor, 0x442xx = engine.
 */
typedef enum {
  /* sensor */
  VMK_CMD_GET_ATTRIBUTES   = 0x440004,
  VMK_CMD_RESET            = 0x440008,
  VMK_CMD_CALIBRATE        = 0x44000c,
  VMK_CMD_GET_STATUS       = 0x440010,   /* out: 20B status struct                  */
  VMK_CMD_CAPTURE          = 0x440014,   /* in: 32B capture params                  */
  VMK_CMD_GET_ALGORITHMS   = 0x44001c,
  VMK_CMD_LED_GET          = 0x440020,
  VMK_CMD_LED_SET          = 0x440024,
  VMK_CMD_CONNECT_SECURE   = 0x44002c,   /* TLS handshake (ssiTlsEstablish)         */
  VMK_CMD_NOTIFY_WAKE      = 0x440034,   /* arm finger-on-wake -> interrupt event   */
  /* engine / matcher */
  VMK_CMD_ENROLL_CREATE    = 0x44200c,   /* in 8B mode-flag, out 40B ack            */
  VMK_CMD_ENROLL_UPDATE    = 0x442010,   /* out 72B enroll-progress struct          */
  VMK_CMD_ENROLL_CHECKDUP  = 0x442014,   /* out 80B                                 */
  VMK_CMD_ENROLL_COMMIT    = 0x442018,   /* store template                          */
  VMK_CMD_ENROLL_DISCARD   = 0x44201c,
  VMK_CMD_DB_ERASE         = 0x442028,
  VMK_CMD_DB_COUNT         = 0x44202c,   /* out 8B; >9 => DB full                    */
  VMK_CMD_STORAGE_QUERY    = 0x442030,   /* enumerate records                       */
  VMK_CMD_DELETE           = 0x442034,   /* delete template                         */
  VMK_CMD_RESET_OWNERSHIP  = 0x442040,   /* unpair                                  */
  VMK_CMD_GET_TEMPLATE     = 0x442050,
  VMK_CMD_SET_TEMPLATE_LIST= 0x442054,
  VMK_CMD_IDENTIFY         = 0x442058,   /* in 4232B / out 6316B (opaque)           */
} VerimarkCmd;

/* ---- Result / status codes (WINBIO_* observed in the adapter) ----------------- */
#define VMK_ST_OK                 0x00000000
#define VMK_ST_MORE_SAMPLES       0x80098008  /* enroll: keep capturing              */
#define VMK_ST_DB_FULL            0x80098018  /* >9 templates                        */
#define VMK_ST_ENROLL_ERROR       0x8009800f

/* enroll coverage / guided-enroll region bitmask (UpdateEnrollment out +0x2c) */
#define VMK_REGION_CENTER         0x01
#define VMK_REGION_UP             0x02
#define VMK_REGION_DOWN           0x04
#define VMK_REGION_LEFT           0x08
#define VMK_REGION_RIGHT          0x10

/* Enroll stages libfprint asks the user for (guided enroll ~ 8-12 presses). */
#define VERIMARK_ENROLL_STAGES    8

/* ---- Secure channel (findings/10, 20: server-auth TLS 1.2) -------------------
 * Record: 17 03 03 | len16 | IV[16] | AES-CBC(payload) | HMAC-SHA256[32]  (overhead 0x45)
 * Handshake: 2-RTT, ClientHello -> ServerHello+Cert+SKE -> ClientKeyEx+CCS+Fin -> server Fin.
 * Cipher suites: ECC (ECDHE-P256 + ECDSA server cert) or PSK. Host presents NO cert.
 */
#define VMK_TLS_RECORD_OVERHEAD   0x45   /* 69 = 5 hdr + 16 IV + 32 HMAC + <=16 pad  */
#define VMK_TLS_MASTER_SECRET_LEN 48

typedef struct _VerimarkTls VerimarkTls;   /* opaque secure-channel context (verimark-tls.c) */

/* ---- Device object ----------------------------------------------------------- */
G_DECLARE_FINAL_TYPE (FpiDeviceVerimark, fpi_device_verimark, FPI, DEVICE_VERIMARK,
                      FpDevice)

struct _FpiDeviceVerimark {
  FpDevice     parent;

  VerimarkTls *tls;              /* secure channel state (handshake keys, session) */
  guint8      *pairing_data;     /* host pairing blob (P-256 host key + PSK)        */
  gsize        pairing_len;

  FpiSsm      *task_ssm;         /* current operation state machine                */
  guint8       intr_buf[VERIMARK_INTR_MAXPKT];

  /* enroll bookkeeping */
  FpPrint     *enroll_print;
  guint        enroll_stage;
  guint8       enroll_region_done;   /* bitmask of covered regions                 */
};
