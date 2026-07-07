/*
 * Kensington VeriMark Desktop (Synaptics "Tudor" MOC) libfprint driver — SKELETON.
 *
 * Structure mirrors the RE in ../findings/21-command-reference.md:
 *   open  : RESET -> CONNECT_SECURE(TLS) -> [pair if needed] -> GET_STATUS
 *   enroll: DB_COUNT -> ENROLL_CREATE -> {CAPTURE -> ENROLL_UPDATE}* -> CHECKDUP -> COMMIT
 *   verify: CAPTURE -> IDENTIFY
 *   list/delete/clear via the storage commands.
 *
 * Transport: WinUsb-equiv on iface 1 -> here: gusb control transfers OUT, interrupt-IN
 * reads on EP 0x83. Each command payload is wrapped in a TLS record by verimark-tls.c.
 *
 * TODO(capture) markers = fields/bytes that need a live working-session capture.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "verimark"

#include "drivers_api.h"
#include "verimark.h"

G_DEFINE_TYPE (FpiDeviceVerimark, fpi_device_verimark, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = VERIMARK_VID, .pid = VERIMARK_PID },
  { .vid = 0, .pid = 0, },
};

/* =============================================================================
 * Transport — control-OUT command + interrupt-IN response  (findings/21)
 *
 * verimark_cmd() wraps `cmd`+payload in a TLS record (once the channel is up),
 * submits it as a vendor control transfer, then reads the reply on EP 0x83.
 * Both the exact SETUP fields and the pre-handshake framing are TODO(capture).
 * ============================================================================= */

typedef void (*VerimarkCmdCb) (FpiDeviceVerimark *self,
                               const guint8      *resp,
                               gsize              resp_len,
                               guint32            status,
                               GError            *error,
                               gpointer           user_data);

static void
verimark_cmd (FpiDeviceVerimark *self,
              VerimarkCmd        cmd,
              const guint8      *payload,
              gsize              payload_len,
              gsize              expect_resp_len,
              VerimarkCmdCb      callback,
              gpointer           user_data)
{
  /* 1. build the Tudor command buffer  [ opcode(le32) | payload ]
   * 2. verimark_tls_wrap() -> 17 03 03 record (AES-CBC + HMAC-SHA256)   (verimark-tls.c)
   * 3. gusb control transfer OUT (bmRequestType=0x41 vendor, TODO(capture) bRequest/wValue)
   * 4. read EP 0x83 interrupt-IN, verimark_tls_unwrap() -> plaintext response
   * 5. parse status (first u32) + body, invoke callback.
   *
   * Implemented via FpiUsbTransfer chained in the async libfprint style; omitted
   * here for the skeleton. The response's leading u32 is the VMK_ST_* status. */
  (void) self; (void) cmd; (void) payload; (void) payload_len;
  (void) expect_resp_len; (void) callback; (void) user_data;
  g_assert_not_reached (); /* TODO: implement transport */
}

/* =============================================================================
 * OPEN  —  reset -> secure connect (TLS handshake) -> pair -> status
 * ============================================================================= */
enum open_states {
  OPEN_RESET,
  OPEN_CONNECT_SECURE,   /* VMK_CMD_CONNECT_SECURE: run the 2-RTT TLS handshake  */
  OPEN_CHECK_PAIRING,    /* is host pairing data present? (host partition)       */
  OPEN_PAIR,             /* tudorSecurityDoPair: P-256 host key + server-auth ECDH */
  OPEN_GET_STATUS,       /* VMK_CMD_GET_STATUS                                    */
  OPEN_NUM_STATES,
};

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_RESET:
      /* verimark_cmd(self, VMK_CMD_RESET, ...) then fpi_ssm_next_state on reply */
      break;

    case OPEN_CONNECT_SECURE:
      /* verimark_tls_handshake(self->tls, ...): ClientHello -> ServerHello+Cert+SKE
       * -> verify server cert chain (Microsoft ECC Devices Root CA 2017, server-auth
       * only, NO client cert) -> ClientKeyExchange+CCS+Finished -> server Finished.
       * TODO(capture): exact ClientHello cipher-suite list + record bytes. */
      break;

    case OPEN_CHECK_PAIRING:
      /* if self->pairing_data == NULL -> OPEN_PAIR else skip to OPEN_GET_STATUS */
      if (self->pairing_data == NULL)
        fpi_ssm_next_state (ssm);          /* -> OPEN_PAIR */
      else
        fpi_ssm_jump_to_state (ssm, OPEN_GET_STATUS);
      return;

    case OPEN_PAIR:
      /* verimark_pair(self): gen P-256 host keypair, fetch sensor pubkey, ECDH,
       * store the pairing blob (host-side + sensor host-partition). Basic mode =
       * server-auth (host anonymous). TODO(capture): pairing command bodies. */
      break;

    case OPEN_GET_STATUS:
      /* verimark_cmd(self, VMK_CMD_GET_STATUS, ...) -> 20B status; validate ready */
      break;
    }
  fpi_ssm_next_state (ssm); /* placeholder: real code advances from cmd callbacks */
}

static void
open_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (dev);

  if (!g_usb_device_claim_interface (usb, VERIMARK_IFACE, 0, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  /* TODO: load persisted pairing_data (libfprint storage) into self->pairing_data */
  self->tls = NULL; /* verimark_tls_new() */

  self->task_ssm = fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES);
  fpi_ssm_start (self->task_ssm, open_done);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  GError *error = NULL;

  /* verimark_tls_close(self->tls) — send TLS close_notify; free session keys */
  g_clear_pointer (&self->pairing_data, g_free);
  g_usb_device_release_interface (usb, VERIMARK_IFACE, 0, &error);
  fpi_device_close_complete (dev, error);
}

/* =============================================================================
 * ENROLL  —  count -> create -> {capture -> update}* -> checkdup -> commit
 * ============================================================================= */
enum enroll_states {
  ENROLL_DB_COUNT,       /* VMK_CMD_DB_COUNT: bail with FP_DEVICE_ERROR_DATA_FULL if >9 */
  ENROLL_CREATE,         /* VMK_CMD_ENROLL_CREATE                                       */
  ENROLL_CAPTURE,        /* VMK_CMD_CAPTURE: wait for finger press                      */
  ENROLL_UPDATE,         /* VMK_CMD_ENROLL_UPDATE: 72B progress; loop while MORE_SAMPLES */
  ENROLL_CHECKDUP,       /* VMK_CMD_ENROLL_CHECKDUP                                      */
  ENROLL_COMMIT,         /* VMK_CMD_ENROLL_COMMIT: store template                        */
  ENROLL_NUM_STATES,
};

static void
enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_DB_COUNT:
      /* on reply: if count > 9 -> fpi_ssm_mark_failed(DATA_FULL) */
      break;

    case ENROLL_CREATE:
      break;

    case ENROLL_CAPTURE:
      /* VMK_CMD_CAPTURE then wait for the EP-0x83 finger-present event */
      break;

    case ENROLL_UPDATE:
      /* parse 72B progress struct:
       *   +0x00 status ; +0x2c region bitmask (VMK_REGION_*).
       * emit fpi_device_enroll_progress(dev, ++self->enroll_stage, print, NULL);
       * if status == VMK_ST_MORE_SAMPLES -> fpi_ssm_jump_to_state(ENROLL_CAPTURE)
       * else -> fpi_ssm_next_state (CHECKDUP). */
      break;

    case ENROLL_CHECKDUP:
      /* if duplicate -> fail; else next */
      break;

    case ENROLL_COMMIT:
      /* store template id in FpPrint; fpi_print_set_device_stored(print, TRUE) */
      break;
    }
  fpi_ssm_next_state (ssm); /* placeholder */
}

static void
enroll_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  if (error)
    fpi_device_enroll_complete (dev, NULL, error);
  else
    fpi_device_enroll_complete (dev, g_object_ref (self->enroll_print), NULL);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  fpi_device_get_enroll_data (dev, &self->enroll_print);
  self->enroll_stage = 0;
  self->enroll_region_done = 0;
  self->task_ssm = fpi_ssm_new (dev, enroll_run_state, ENROLL_NUM_STATES);
  fpi_ssm_start (self->task_ssm, enroll_done);
}

/* =============================================================================
 * VERIFY / IDENTIFY  —  capture -> identify (match-on-chip)
 * ============================================================================= */
enum verify_states {
  VERIFY_CAPTURE,
  VERIFY_IDENTIFY,       /* VMK_CMD_IDENTIFY: on-chip match; returns matched template id */
  VERIFY_NUM_STATES,
};

static void
verify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIFY_CAPTURE:
      break;
    case VERIFY_IDENTIFY:
      /* on match: find the FpPrint whose stored id == returned id,
       * fpi_device_verify_report/ fpi_device_identify_report accordingly. */
      break;
    }
  fpi_ssm_next_state (ssm);
}

static void
verify_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);
}

static void
dev_verify_identify (FpDevice *dev)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (dev);

  self->task_ssm = fpi_ssm_new (dev, verify_run_state, VERIFY_NUM_STATES);
  fpi_ssm_start (self->task_ssm, verify_done);
}

/* =============================================================================
 * STORAGE  —  list / delete / clear   (VMK_CMD_STORAGE_QUERY / DELETE / DB_ERASE)
 * ============================================================================= */
static void
dev_list (FpDevice *dev)
{
  /* VMK_CMD_STORAGE_QUERY -> enumerate on-sensor template ids -> build GPtrArray
   * of FpPrint; fpi_device_list_complete(dev, prints, NULL). */
  fpi_device_list_complete (dev, g_ptr_array_new_with_free_func (g_object_unref), NULL);
}

static void
dev_delete (FpDevice *dev)
{
  /* VMK_CMD_DELETE with the template id from the FpPrint. */
  fpi_device_delete_complete (dev, NULL);
}

static void
dev_clear_storage (FpDevice *dev)
{
  /* VMK_CMD_DB_ERASE. */
  fpi_device_clear_storage_complete (dev, NULL);
}

static void
dev_cancel (FpDevice *dev)
{
  /* abort the in-flight interrupt read / SSM (e.g. VMK_CMD_ENROLL_DISCARD). */
  (void) dev;
}

/* =============================================================================
 * GObject / class boilerplate
 * ============================================================================= */
static void
fpi_device_verimark_init (FpiDeviceVerimark *self)
{
  (void) self;
}

static void
fpi_device_verimark_class_init (FpiDeviceVerimarkClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id               = "verimark";
  dev_class->full_name        = "Kensington VeriMark Desktop (Synaptics Tudor MOC)";
  dev_class->type             = FP_DEVICE_TYPE_USB;
  dev_class->id_table         = id_table;
  dev_class->scan_type        = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = VERIMARK_ENROLL_STAGES;
  dev_class->features         = FP_DEVICE_FEATURE_IDENTIFY |
                                FP_DEVICE_FEATURE_VERIFY |
                                FP_DEVICE_FEATURE_STORAGE |
                                FP_DEVICE_FEATURE_STORAGE_LIST |
                                FP_DEVICE_FEATURE_STORAGE_DELETE |
                                FP_DEVICE_FEATURE_STORAGE_CLEAR;

  dev_class->open           = dev_open;
  dev_class->close          = dev_close;
  dev_class->enroll         = dev_enroll;
  dev_class->verify         = dev_verify_identify;
  dev_class->identify       = dev_verify_identify;
  dev_class->list           = dev_list;
  dev_class->delete         = dev_delete;
  dev_class->clear_storage  = dev_clear_storage;
  dev_class->cancel         = dev_cancel;
}
