/*
 * Betterlife 347d:0302 fingerprint reader driver for libfprint
 *
 * Copyright (C) 2026 huellero project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Ported from Light-log/betterlife-347d-0304-fingerprint-linux for 347d:0302.
 *
 * Image-based (FpImageDevice) driver for the Blestech/Betterlife USB sensor
 * (347d:0302). The device speaks an SM2/SM3/SM4 secure channel: this file
 * carries the framing codec (bl_frame_*), the bring-up (open/init: plaintext
 * queries, SM2/SM3 key exchange, sealed-channel proof), the capture flow
 * (0xB5 finger-detect, 0xB4/0-2 chunked image download with byte-sum
 * verification) and the driver skeleton; the crypto lives in
 * betterlife_crypto.c (bl_crypto_*). Task 5 decides the matcher.
 */

#define FP_COMPONENT "betterlife"
#include "fpi-log.h"

#include "drivers_api.h"
#include "betterlife.h"
#include "betterlife_crypto.h"

#include <string.h>

/* CRC-32 (zlib polynomial, reflected 0xEDB88320) over the raw frame bytes
 * before the trailing CRC field. */
static guint32
crc32f (const guint8 *p,
        gsize         n)
{
  guint32 c = 0xffffffffu;

  for (gsize i = 0; i < n; i++)
    {
      c ^= p[i];
      for (int k = 0; k < 8; k++)
        c = (c >> 1) ^ (0xEDB88320u & (guint32) -(gint) (c & 1));
    }
  return ~c;
}

/* Hard transmit whitelist (plan ruling R7): see betterlife.h. Anything the
 * ratified list does not cover — notably the firmware/maintenance opcodes —
 * can never leave this driver. */
static gboolean
bl_opcode_allowed (guint8 cmd)
{
  switch (cmd)
    {
    case BL_CMD_QUERY_FW_VERSION:
    case BL_CMD_QUERY_MODULE_SCHEME:
    case BL_CMD_KEY_EXCHANGE:
    case BL_CMD_FP_COUNT:
    case BL_CMD_CAPTURE:
    case BL_CMD_DETECT_FINGER:
    case BL_CMD_QUERY_UID:
    case BL_CMD_QUERY_SENSOR_INFO:
      return TRUE;

    default:
      return FALSE;
    }
}

static guint32
le32_read (const guint8 *p)
{
  return (guint32) p[0] | (guint32) p[1] << 8 | (guint32) p[2] << 16 | (guint32) p[3] << 24;
}

static void
le32_write (guint8  *p,
            guint32  v)
{
  p[0] = v;
  p[1] = v >> 8;
  p[2] = v >> 16;
  p[3] = v >> 24;
}

gssize
bl_frame_build (guint8       *out,
                gsize         cap,
                guint8        cmd,
                guint8        sub,
                guint16       seq,
                const guint8 *payload,
                gsize         plen,
                gboolean      encrypted,
                GError      **error)
{
  gsize pad = (16 - ((plen + BL_FRAME_BODY_HEADER_LEN) & 15)) & 15;
  gsize blen = BL_FRAME_BODY_HEADER_LEN + plen + pad; /* multiple of 16 */
  gsize crcoff = BL_FRAME_HEADER_LEN + blen;
  gsize total = crcoff + BL_FRAME_CRC_LEN;
  guint8 *body;
  guint32 crc;

  if (plen > 0 && payload == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "Payload is NULL but plen is nonzero");
      return -1;
    }

  if (plen > G_MAXUINT32 - BL_FRAME_OVERHEAD)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "Payload is too large");
      return -1;
    }

  if (!bl_opcode_allowed (cmd))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                   "Opcode 0x%02x is not in the transmit whitelist", cmd);
      return -1;
    }

  if (total > cap)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NO_SPACE,
                           "Frame does not fit into the output buffer");
      return -1;
    }

  out[0] = BL_FRAME_MAGIC;
  body = out + BL_FRAME_HEADER_LEN;
  memset (body, 0, blen);
  body[0] = BL_FRAME_BODY_MAGIC;
  body[1] = cmd;
  body[2] = sub;
  body[4] = seq;
  body[5] = seq >> 8;
  le32_write (body + 6, (guint32) plen);
  if (plen)
    memcpy (body + BL_FRAME_BODY_HEADER_LEN, payload, plen);

  if (encrypted)
    {
      guint8 nonce[BL_NONCE_LEN];
      guint8 framekey[BL_FRAMEKEY_LEN];

      if (!bl_crypto_random_bytes (nonce, sizeof nonce, error) ||
          !bl_crypto_derive_framekey (nonce, framekey, error))
        return -1;
      memcpy (out + 5, nonce, sizeof nonce);
      if (!bl_crypto_seal_body (framekey, body, blen, error))
        return -1;
    }
  else
    {
      memset (out + 5, 0, BL_NONCE_LEN);
    }

  le32_write (out + 1, (guint32) (16 + blen + 4));

  crc = crc32f (out, crcoff);
  le32_write (out + crcoff, crc);
  return (gssize) total;
}

gboolean
bl_frame_parse (guint8  *buf,
                gsize    len,
                BlFrame *frame,
                GError **error)
{
  guint32 flen;
  gsize total, blen;
  guint8 *body;
  const guint8 *nonce;
  guint32 plen;

  /* A minimal frame is header + one 16B body block + CRC. */
  if (buf == NULL || frame == NULL ||
      len < BL_FRAME_HEADER_LEN + 16 + BL_FRAME_CRC_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame buffer is missing or too short");
      return FALSE;
    }

  if (buf[0] != BL_FRAME_MAGIC)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame magic missing");
      return FALSE;
    }

  flen = le32_read (buf + 1);
  if (flen < 20) /* len must cover the nonce and the CRC */
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame length field is too small");
      return FALSE;
    }

  total = (gsize) flen + 5;
  if (total > len)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame is incomplete");
      return FALSE;
    }

  blen = (gsize) flen - 20;
  if (blen < 16 || (blen & 15) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame body has an invalid length");
      return FALSE;
    }

  if (crc32f (buf, total - BL_FRAME_CRC_LEN) != le32_read (buf + total - BL_FRAME_CRC_LEN))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame CRC mismatch");
      return FALSE;
    }

  nonce = buf + 5;
  body = buf + BL_FRAME_HEADER_LEN;

  /* A zero nonce marks a plaintext body; anything else is sealed under
   * framekey = SM4(rootkey, nonce) (responses reuse the request's nonce). */
  if (nonce[0] | nonce[1] | nonce[2] | nonce[3] | nonce[4] | nonce[5] | nonce[6] | nonce[7] |
      nonce[8] | nonce[9] | nonce[10] | nonce[11] | nonce[12] | nonce[13] | nonce[14] | nonce[15])
    {
      guint8 framekey[BL_FRAMEKEY_LEN];

      if (!bl_crypto_derive_framekey (nonce, framekey, error) ||
          !bl_crypto_open_body (framekey, body, blen, error))
        return FALSE;
    }

  if (body[0] != BL_FRAME_BODY_MAGIC)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Body magic missing after decode");
      return FALSE;
    }

  plen = le32_read (body + 6);
  if (plen > blen - BL_FRAME_BODY_HEADER_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Frame payload length is out of range");
      return FALSE;
    }

  frame->cmd = body[1];
  frame->sub = body[2];
  frame->seq = (guint16) (body[4] | body[5] << 8);
  frame->payload = body + BL_FRAME_BODY_HEADER_LEN;
  frame->plen = plen;
  return TRUE;
}

gint
bl_frame_count (const guint8 *buf,
                gsize         len)
{
  gsize off = 0;
  gint n = 0;

  while (off + 5 <= len)
    {
      guint32 flen;
      gsize total;

      if (buf[off] != BL_FRAME_MAGIC)
        break;
      flen = le32_read (buf + off + 1);
      if (flen < 20)
        break;
      total = (gsize) flen + 5;
      if (off + total > len)
        break;
      off += total;
      n++;
    }
  return n;
}

/* Image checksum: plain byte add, wrapping mod 2^32 (PROTOCOL.md §4). */
guint32
bl_bytesum (const guint8 *data,
            gsize         len)
{
  guint32 sum = 0;

  for (gsize i = 0; i < len; i++)
    sum += data[i];
  return sum;
}

/* ---------------------------------------------------------------------- */
/* Driver skeleton                                                         */
/* ---------------------------------------------------------------------- */

/* Bulk EPs 0x02 OUT / 0x81 IN, wMaxPacketSize 64 (full speed). */
#define BL_EP_OUT (0x02 | FPI_USB_ENDPOINT_OUT)
#define BL_EP_IN  (0x01 | FPI_USB_ENDPOINT_IN)

/* IN-pipe drain before the handshake: flushes stale session bytes left over
 * from a previous run (ported from the 0304 driver). Short reads and
 * timeouts are expected and ignored here. */
#define BL_DRAIN_READS      24
#define BL_DRAIN_TIMEOUT_MS 120
#define BL_DRAIN_LEN        16384

/* Request/response timeout for the open/init exchanges. Like the 0304
 * driver we wait patiently for this weak bus-powered firmware instead of
 * retransmitting (the Windows driver retransmits every 1 s up to a 2.03 s
 * overall timeout for these commands, PROTOCOL.md §2; v1 has no retransmit
 * loop). */
#define BL_XCHG_TIMEOUT_MS 4000

/* Handshake attempts before open() fails (0304 driver: 8). */
#define BL_HS_RETRIES 8

/* IN reassembly buffer: open/init responses are <= 153 B today; sized like
 * the 0304 driver so the capture frames of Task 4 fit too. */
#define BL_RX_CAP 16384

struct _FpiDeviceBetterlife
{
  FpImageDevice parent;

  FpiSsm *ssm;

  /* Open/init: IN reassembly plus the command whose response is expected. */
  guint8   rx[BL_RX_CAP];
  gsize    rx_got;
  gint     rx_want_frames;
  guint8   rx_expect_cmd;

  /* SM2 key-exchange state for the open/init SSM. */
  BlHandshake *hs;
  gint         hs_retries;

  /* Device-reported image geometry (0xC1 response at init; live 112x96),
   * consumed by the capture flow (Task 4). */
  guint16 img_w;
  guint16 img_h;

  /* Capture (bl_cap_ssm): chunked image download. img accumulates the raw
   * 8-bit grayscale frame (img_w*img_h bytes, stride = width). */
  guint8  *img;
  guint32  img_total;      /* bytes to fetch: Start metadata total (= w*h) */
  gsize    img_got;
  guint32  img_expect_sum; /* byte-sum the assembled image must verify against */
  gboolean img_have_meta;  /* 9B Start metadata received (finger present) */

  guint8   cap_kind;       /* BL_CAP_WAIT_*: frame matcher + timeout policy */
  guint16  cap_seq;        /* sequence number of the next chunk request */
  guint16  cap_expect_seq; /* sequence number of the chunk response awaited */
  gint     cap_attempts;   /* Start attempts made while awaiting metadata */
  gboolean cap_started;    /* 0xB4/0 Start sent: an abort needs a 0xB4/2 */
  guint    cap_timeout_ms; /* per-read timeout of the wait in flight */

  /* Debug hooks from the Task 4 brief (bl_capture_hooks(): env-var gated,
   * zero behavior change when unset). */
  guint32  cap_max_chunk;
  guint16  cap_corrupt_seq;

  gint     drain_left;
  gboolean deactivating;
};

G_DEFINE_TYPE (FpiDeviceBetterlife, fpi_device_betterlife, FP_TYPE_IMAGE_DEVICE)

/* Open/init SSM (structure ported from the 0304 btl_open_ssm, opcodes per
 * the 0302 live protocol — VALIDATION.md §1.3/§1.4): drain the IN pipe, run
 * the plaintext bring-up queries (0xA0 firmware version, 0xA1 module scheme,
 * 0xC1 sensor info → image geometry), do the SM2/SM3 key exchange (0xA2) and
 * prove the sealed channel with an encrypted read-only round trip (0xB3).
 *
 * Firmware policy (staging 1, log-only): the 0xA0 version is logged but
 * nothing is ever flashed — v1 has no firmware path at all (the update
 * opcodes are not even transmittable, see betterlife.h), and VALIDATION.md
 * §4 shows the device already runs the current firmware (01.03.10.00).
 *
 * Each *_SEND state consumes the response of the previous exchange first
 * (bl_open_take_response); a *_READ state awaits one complete response frame. */
enum open_states {
  OPEN_DRAIN,
  OPEN_A0_SEND,
  OPEN_A0_READ,
  OPEN_A1_SEND,
  OPEN_A1_READ,
  OPEN_C1_SEND,
  OPEN_C1_READ,
  OPEN_A2_SEND,
  OPEN_A2_READ,
  OPEN_DERIVE,
  OPEN_PROVE_SEND,
  OPEN_PROVE_READ,
  OPEN_PROVE_CHECK,
  OPEN_NUM_STATES,
};

static void bl_drain_submit (FpiDeviceBetterlife *self, FpiSsm *ssm);

static void
bl_drain_cb (FpiUsbTransfer *transfer,
             FpDevice       *dev,
             gpointer        user_data,
             GError         *error)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  /* The drain tolerates errors of any kind: it only flushes the IN pipe. */
  g_clear_error (&error);

  if (self->deactivating)
    {
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }

  if (--self->drain_left <= 0)
    {
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  bl_drain_submit (self, transfer->ssm);
}

static void
bl_drain_submit (FpiDeviceBetterlife *self,
                 FpiSsm             *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk (t, BL_EP_IN, BL_DRAIN_LEN);
  fpi_usb_transfer_submit (t, BL_DRAIN_TIMEOUT_MS,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bl_drain_cb, NULL);
}

/* ---- open/init request-response plumbing -------------------------------- */

static gchar *
bl_hex (const guint8 *p,
        gsize         n)
{
  GString *s = g_string_sized_new (n * 2 + 1);

  for (gsize i = 0; i < n; i++)
    g_string_append_printf (s, "%02x", p[i]);
  return g_string_free (s, FALSE);
}

static void
bl_log_response (const gchar   *what,
                 const BlFrame *frame)
{
  g_autofree gchar *payload = bl_hex (frame->payload, frame->plen);

  fp_dbg ("%s response: sub=0x%02x seq=%u payload(%zu)=%s",
          what, frame->sub, frame->seq, frame->plen, payload);
}

/* Send completion: same as fpi_ssm_usb_transfer_cb(), but a deactivating
 * device completes the SSM instead of failing it (bl_dev_deactivate()).
 * Shared by the open/init and capture SSMs. */
static void
bl_tx_cb (FpiUsbTransfer *transfer,
          FpDevice       *dev,
          gpointer        user_data,
          GError         *error)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }

  fpi_ssm_usb_transfer_cb (transfer, dev, user_data, error);
}

/* Build and send one framed request; the response is awaited in the next
 * *_READ state. The request buffer is owned by the transfer. */
static void
bl_open_send (FpiDeviceBetterlife *self,
              FpiSsm             *ssm,
              guint8              cmd,
              guint8              sub,
              const guint8       *payload,
              gsize               plen,
              gboolean            encrypted)
{
  g_autoptr(GError) error = NULL;
  FpiUsbTransfer *t;
  gsize cap = BL_FRAME_OVERHEAD + plen + 15;
  guint8 *buf = g_malloc (cap);
  gssize flen;

  flen = bl_frame_build (buf, cap, cmd, sub, 0, payload, plen, encrypted, &error);
  if (flen < 0)
    {
      g_free (buf);
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  self->rx_got = 0;
  self->rx_expect_cmd = cmd;

  t = fpi_usb_transfer_new (FP_DEVICE (self));
  t->ssm = ssm;
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, BL_EP_OUT, buf, (gsize) flen, g_free);
  fpi_usb_transfer_submit (t, BL_XCHG_TIMEOUT_MS,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bl_tx_cb, NULL);
}

static void bl_open_rx_submit (FpiDeviceBetterlife *self, FpiSsm *ssm);

/* Read completion: same as bl_drain_cb() but a short read buffer is not a
 * flush — errors fail the exchange (after the deactivation check). */
static void
bl_open_rx_cb (FpiUsbTransfer *transfer,
               FpDevice       *dev,
               gpointer        user_data,
               GError         *error)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  self->rx_got += transfer->actual_length;

  if (bl_frame_count (self->rx, self->rx_got) >= self->rx_want_frames ||
      transfer->actual_length == 0 ||
      self->rx_got >= sizeof self->rx)
    {
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  bl_open_rx_submit (self, transfer->ssm);
}

static void
bl_open_rx_submit (FpiDeviceBetterlife *self,
                   FpiSsm             *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (t, BL_EP_IN, self->rx + self->rx_got,
                                   sizeof self->rx - self->rx_got, NULL);
  fpi_usb_transfer_submit (t, BL_XCHG_TIMEOUT_MS,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bl_open_rx_cb, NULL);
}

/* Read until want_frames complete frames are buffered (responses can share a
 * transfer with stale frames; see bl_frame_count()). */
static void
bl_open_rx_start (FpiDeviceBetterlife *self,
                  FpiSsm             *ssm,
                  gint                want_frames)
{
  self->rx_got = 0;
  self->rx_want_frames = want_frames;
  bl_open_rx_submit (self, ssm);
}

/* Pick the buffered response frame of the request in flight. Stale frames
 * (e.g. a leftover 0xB5 push stream from a previous session) are skipped;
 * a missing or malformed response fails the exchange (error is set). */
static gboolean
bl_open_take_response (FpiDeviceBetterlife *self,
                       BlFrame             *frame,
                       GError             **error)
{
  gsize off = 0;

  while (off + BL_FRAME_HEADER_LEN + 16 + BL_FRAME_CRC_LEN <= self->rx_got)
    {
      /* Outer length field: total frame size minus the 5 magic/len bytes. */
      gsize total = (gsize) le32_read (self->rx + off + 1) + 5;

      if (off + total > self->rx_got)
        break;

      if (!bl_frame_parse (self->rx + off, self->rx_got - off, frame, error))
        return FALSE;

      if (frame->cmd == self->rx_expect_cmd)
        return TRUE;

      fp_warn ("ignoring stale frame cmd=0x%02x while waiting for 0x%02x",
               frame->cmd, self->rx_expect_cmd);
      off += total;
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "No response frame for command 0x%02x", self->rx_expect_cmd);
  return FALSE;
}

/* Consume the 0xA2 response: derive the session root key and verify the
 * handshake MAC (inside bl_crypto_handshake_derive()), then install it. The
 * response carries session secrets and is deliberately not logged. */
static gboolean
bl_open_derive_rootkey (FpiDeviceBetterlife *self,
                        GError             **error)
{
  BlFrame frame = { 0 };
  guint8 rootkey[BL_SESSKEY_LEN];
  gboolean ok;

  ok = bl_open_take_response (self, &frame, error) &&
       bl_crypto_handshake_derive (self->hs, frame.payload, frame.plen,
                                   rootkey, error);
  if (ok)
    {
      bl_crypto_set_rootkey (rootkey);
      memset (rootkey, 0, sizeof rootkey);
      fp_dbg ("key exchange complete: %zu-byte response, MAC verified, "
              "session root key installed", frame.plen);
    }

  return ok;
}

static void
bl_open_ssm (FpiSsm   *ssm,
             FpDevice *dev)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);
  g_autoptr(GError) error = NULL;

  /* Deactivation contract (see bl_dev_deactivate): a running SSM notices and
   * completes; bl_open_complete() then reports the deactivation. */
  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_DRAIN:
      self->drain_left = BL_DRAIN_READS;
      bl_drain_submit (self, ssm);
      break;

    case OPEN_A0_SEND:
      bl_open_send (self, ssm, BL_CMD_QUERY_FW_VERSION, 0, NULL, 0, FALSE);
      break;

    case OPEN_A0_READ:
      bl_open_rx_start (self, ssm, 1);
      break;

    case OPEN_A1_SEND:
      {
        BlFrame frame;

        if (!bl_open_take_response (self, &frame, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            break;
          }
        bl_log_response ("0xA0 firmware version", &frame);
        bl_open_send (self, ssm, BL_CMD_QUERY_MODULE_SCHEME, 0, NULL, 0, FALSE);
        break;
      }

    case OPEN_A1_READ:
      bl_open_rx_start (self, ssm, 1);
      break;

    case OPEN_C1_SEND:
      {
        BlFrame frame;

        if (!bl_open_take_response (self, &frame, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            break;
          }
        bl_log_response ("0xA1 module scheme", &frame);
        bl_open_send (self, ssm, BL_CMD_QUERY_SENSOR_INFO, 0, NULL, 0, FALSE);
        break;
      }

    case OPEN_C1_READ:
      bl_open_rx_start (self, ssm, 1);
      break;

    case OPEN_A2_SEND:
      {
        BlFrame frame;
        guint8 pubkey[65];

        if (!bl_open_take_response (self, &frame, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            break;
          }
        bl_log_response ("0xC1 sensor info", &frame);

        /* Image geometry comes from the 0xC1 response: w = u16 LE at
         * payload[4..5], h = u16 LE at payload[6..7] (VALIDATION.md §2.1;
         * live units report 112x96). */
        if (frame.plen < 8)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "0xC1 response too short: %zu bytes",
                                                                frame.plen));
            break;
          }
        self->img_w = (guint16) (frame.payload[4] | frame.payload[5] << 8);
        self->img_h = (guint16) (frame.payload[6] | frame.payload[7] << 8);
        if (self->img_w == 0 || self->img_h == 0)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "0xC1 reported empty geometry: %ux%u",
                                                                self->img_w, self->img_h));
            break;
          }
        fp_dbg ("sensor geometry: %ux%u", self->img_w, self->img_h);

        if (!bl_crypto_handshake_pubkey (self->hs, pubkey))
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            break;
          }
        bl_open_send (self, ssm, BL_CMD_KEY_EXCHANGE, 0, pubkey, sizeof pubkey, FALSE);
        break;
      }

    case OPEN_A2_READ:
      bl_open_rx_start (self, ssm, 1);
      break;

    case OPEN_DERIVE:
      if (bl_open_derive_rootkey (self, &error))
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      if (self->hs_retries++ < BL_HS_RETRIES)
        {
          fp_dbg ("handshake attempt failed, retrying (%d/%d)",
                  self->hs_retries, BL_HS_RETRIES);
          g_clear_error (&error);
          fpi_ssm_jump_to_state (ssm, OPEN_DRAIN);
          break;
        }
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      break;

    case OPEN_PROVE_SEND:
      /* Encrypted round trip of a trivial read-only query. The response body
       * is sealed under the request's nonce, and bl_frame_parse() only
       * accepts it once SM4 decryption yields a valid 0x4C body — that is
       * the staging-1 proof of the secure channel. */
      bl_open_send (self, ssm, BL_CMD_FP_COUNT, 0, NULL, 0, TRUE);
      break;

    case OPEN_PROVE_READ:
      bl_open_rx_start (self, ssm, 1);
      break;

    case OPEN_PROVE_CHECK:
      {
        BlFrame frame;

        if (!bl_open_take_response (self, &frame, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            break;
          }
        bl_log_response ("0xB3 secure-channel round trip", &frame);
        fp_dbg ("secure channel verified");
        fpi_ssm_mark_completed (ssm);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
bl_open_complete (FpiSsm   *ssm,
                  FpDevice *dev,
                  GError   *error)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  self->ssm = NULL;
  g_clear_pointer (&self->hs, bl_crypto_handshake_free);

  /* When deactivation interrupted the SSM, the pending action is the
   * deactivation: report that one and never the open (see
   * bl_dev_deactivate()). The device stays open in that case, so an
   * already-installed session root key is kept. */
  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (dev), NULL);
      return;
    }

  /* A failed open leaves the device closed (img_close() does not run), so
   * drop any partially established session here. */
  if (error != NULL)
    bl_crypto_clear_rootkey ();

  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

/* ---------------------------------------------------------------------- */
/* Capture: 0xB5 finger-detect, 0xB4/0-2 chunked image download            */
/* ---------------------------------------------------------------------- */

/* Live capture flow (PROTOCOL.md §4; Task 1 run in VALIDATION.md §1.6):
 * 0xB5/0 finger-detect poll, 0xB4/0 Start (payload 4 zero bytes), then
 * 0xB4/1 chunk requests (u16 seq++, payload u32 len <= 8140) until the
 * image is assembled, verified against the plain byte-add checksum
 * (bl_bytesum(), mod 2^32) and handed to the core — or, when no finger was
 * present, ended on the clean no-finger path (bl_capture_complete()).
 * 0xB4/2 cancels an aborted round.
 *
 * The 9B Start metadata (status, u32 total, u32 checksum) is pushed only
 * with a finger on the sensor (VALIDATION.md §2.4, the 0304 push model):
 * its absence after a bounded wait means no finger and therefore a blank
 * all-zero frame whose byte-sum is 0. The verification still runs — against
 * 0 in that case, exactly the code path a finger-pressed frame takes against
 * the metadata checksum — so a corrupted transfer can never deliver a torn
 * image either way. The device serves chunk data regardless of the metadata
 * (VALIDATION.md §6), so the blank frame is fetched normally.
 *
 * Each wait matches on the expected cmd/sub/seq (bl_cap_pump()): the device
 * pushes a continuous stream of 0xB5 status frames while armed and responses
 * may arrive coalesced or split across transfers, so stale frames are
 * skipped and short reads reassembled instead of counting frames. */

/* Host-side request maximum 0x1FCC (PROTOCOL.md §4; the firmware caps
 * responses at 4096 bytes regardless — VALIDATION.md §2.5 — so a request is
 * answered with up to min(requested, 4096) bytes and the loop continues). */
#define BL_CAPTURE_CHUNK_MAX 8140
#define BL_CAPTURE_META_LEN  9 /* status u8 + u32 total + u32 checksum */

/* Per-wait read timeouts and retry budgets: the Task 1 probe values
 * (probe.c capture_once/wait_meta/wait_chunk). The metadata wait is bounded
 * twice over (2 Start attempts, 3 s each) so a no-finger capture completes
 * in well under the brief's 15 s ceiling. */
#define BL_DETECT_TIMEOUT_MS 1500
#define BL_META_TIMEOUT_MS   3000
#define BL_CHUNK_TIMEOUT_MS  5000
#define BL_LIFT_TIMEOUT_MS   3000
#define BL_META_ATTEMPTS     2

/* Pixels per millimeter for the produced FpImage (the 0304 driver's value;
 * the sensor DPI is not part of the RE docs and matching does not use it). */
#define BL_IMAGE_PPMM 19.685

/* Wait kinds: pick the frame matcher (bl_cap_classify()) and the timeout
 * policy (bl_cap_rx_cb()) for the read in flight. */
enum bl_cap_wait {
  BL_CAP_WAIT_DETECT,
  BL_CAP_WAIT_META,
  BL_CAP_WAIT_CHUNK,
  BL_CAP_WAIT_LIFT,
};

enum capture_states {
  CAP_DETECT_SEND,
  CAP_DETECT_READ,
  CAP_START_SEND,
  CAP_META_READ,
  CAP_CHUNK_SEND,
  CAP_CHUNK_READ,
  CAP_VERIFY,
  CAP_LIFT_SEND,
  CAP_LIFT_READ,
  CAP_NUM_STATES,
};

/* Debug hooks (Task 4 brief steps 4/5). Env-var gated: when unset, an
 * ordinary capture runs with zero behavior change.
 *  - BETTERLIFE_MAX_CHUNK=N caps each 0xB4/1 request at N bytes (1..8140);
 *    step 4 forces 64-byte chunks and expects the same image bytes.
 *  - BETTERLIFE_CORRUPT_SEQ=N corrupts one byte of the chunk with sequence
 *    N ("a bad checksum on one chunk"), so the byte-sum verification fails
 *    with a GError (step 5). One-shot per process: the next capture in the
 *    same run must succeed, per the brief. */
static gboolean bl_corrupt_used = FALSE;

static void
bl_capture_hooks (FpiDeviceBetterlife *self)
{
  const gchar *env;

  self->cap_max_chunk = BL_CAPTURE_CHUNK_MAX;
  self->cap_corrupt_seq = G_MAXUINT16;

  env = g_getenv ("BETTERLIFE_MAX_CHUNK");
  if (env != NULL && *env != '\0')
    {
      guint64 n = g_ascii_strtoull (env, NULL, 10);

      if (n >= 1 && n <= BL_CAPTURE_CHUNK_MAX)
        {
          self->cap_max_chunk = (guint32) n;
          fp_dbg ("hook BETTERLIFE_MAX_CHUNK: chunk requests capped at %u bytes",
                  self->cap_max_chunk);
        }
      else
        {
          fp_warn ("hook BETTERLIFE_MAX_CHUNK=%s ignored (want 1..%d)",
                   env, BL_CAPTURE_CHUNK_MAX);
        }
    }

  env = g_getenv ("BETTERLIFE_CORRUPT_SEQ");
  if (env != NULL && *env != '\0')
    {
      guint64 n = g_ascii_strtoull (env, NULL, 10);

      if (n <= G_MAXUINT16)
        {
          self->cap_corrupt_seq = (guint16) n;
          fp_dbg ("hook BETTERLIFE_CORRUPT_SEQ: will corrupt the chunk with seq %u%s",
                  self->cap_corrupt_seq,
                  bl_corrupt_used ? " (already used this process: inactive)" : "");
        }
      else
        {
          fp_warn ("hook BETTERLIFE_CORRUPT_SEQ=%s ignored (want a sequence number)",
                   env);
        }
    }
}

/* ---- capture request/response plumbing --------------------------------- */

/* Build and send one framed capture request. Responses are matched in
 * bl_cap_pump(); unlike the open path the receive buffer is kept across
 * requests, so nothing already buffered is lost. */
static void
bl_cap_send (FpiDeviceBetterlife *self,
             FpiSsm             *ssm,
             guint8              cmd,
             guint8              sub,
             guint16             seq,
             const guint8       *payload,
             gsize               plen)
{
  g_autoptr(GError) error = NULL;
  FpiUsbTransfer *t;
  gsize cap = BL_FRAME_OVERHEAD + plen + 15;
  guint8 *buf = g_malloc (cap);
  gssize flen;

  flen = bl_frame_build (buf, cap, cmd, sub, seq, payload, plen, TRUE, &error);
  if (flen < 0)
    {
      g_free (buf);
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  t = fpi_usb_transfer_new (FP_DEVICE (self));
  t->ssm = ssm;
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, BL_EP_OUT, buf, (gsize) flen, g_free);
  fpi_usb_transfer_submit (t, BL_XCHG_TIMEOUT_MS,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bl_tx_cb, NULL);
}

static void
bl_cap_cancel_cb (FpiUsbTransfer *transfer,
                  FpDevice       *dev,
                  gpointer        user_data,
                  GError         *error)
{
  /* The round is over either way; a failed cancel only means the device
   * keeps its capture state a little longer. */
  g_clear_error (&error);
}

/* Abort cleanup: 0xB4/2 (1 status byte), sent when a round is torn down
 * before its image is done (byte-sum mismatch, protocol error, user cancel).
 * Fire-and-forget, like the Task 1 probe's cancel — its response is
 * tolerated (and skipped) by the next wait — because the SSM is completing
 * or failing around it and must not depend on another exchange. A round
 * that ends normally does NOT cancel: the live device stalls the next
 * round's transfers right after a 0xB4/2 (see the Task 4 report). */
static void
bl_cap_cancel (FpiDeviceBetterlife *self)
{
  static const guint8 status_ok[1] = { 0 };
  g_autoptr(GError) error = NULL;
  FpiUsbTransfer *t;
  gsize cap = BL_FRAME_OVERHEAD + sizeof status_ok + 15;
  guint8 *buf = g_malloc (cap);
  gssize flen;

  flen = bl_frame_build (buf, cap, BL_CMD_CAPTURE, BL_CAPTURE_SUB_CANCEL, 0,
                         status_ok, sizeof status_ok, TRUE, &error);
  if (flen < 0)
    {
      fp_warn ("cannot build the 0xB4/2 cancel frame: %s", error->message);
      g_free (buf);
      return;
    }

  self->cap_started = FALSE;
  fp_dbg ("sending 0xB4/2 cancel (round aborted)");
  t = fpi_usb_transfer_new (FP_DEVICE (self));
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, BL_EP_OUT, buf, (gsize) flen, g_free);
  fpi_usb_transfer_submit (t, BL_XCHG_TIMEOUT_MS,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bl_cap_cancel_cb, NULL);
}

/* Drop everything the receive buffer holds except a trailing partial frame
 * (its continuation is still on the wire and must keep frame sync). Run at
 * round start: leftovers from the open exchanges or a previous round are not
 * part of this round. Walked on the plaintext outer lengths only. */
static void
bl_cap_flush_stale (FpiDeviceBetterlife *self)
{
  gsize off = 0;

  while (off + 5 <= self->rx_got)
    {
      gsize total;

      if (self->rx[off] != BL_FRAME_MAGIC)
        {
          off++;
          continue;
        }
      total = (gsize) le32_read (self->rx + off + 1) + 5;
      if (total < BL_FRAME_HEADER_LEN + 16 + BL_FRAME_CRC_LEN ||
          off + total > self->rx_got)
        break;
      off += total;
    }

  if (off > 0)
    {
      fp_dbg ("capture start: dropped %zu stale input bytes", off);
      memmove (self->rx, self->rx + off, self->rx_got - off);
      self->rx_got -= off;
    }
}

/* Frame acceptance for the wait in flight. */
typedef enum {
  BL_CAP_TAKE, /* the frame the wait is looking for (left at the head) */
  BL_CAP_SKIP, /* stale or irrelevant: drop it and keep scanning */
  BL_CAP_GAP,  /* protocol violation: fail the capture */
} BlCapAction;

static BlCapAction
bl_cap_classify (FpiDeviceBetterlife *self,
                 const BlFrame       *frame)
{
  gboolean is_meta = frame->cmd == BL_CMD_CAPTURE &&
                     frame->sub == BL_CAPTURE_SUB_START &&
                     frame->plen >= BL_CAPTURE_META_LEN;

  switch (self->cap_kind)
    {
    case BL_CAP_WAIT_DETECT:
      /* The 0xB5 answer, or a finger push that arrived before the Start. */
      return (frame->cmd == BL_CMD_DETECT_FINGER || is_meta) ? BL_CAP_TAKE : BL_CAP_SKIP;

    case BL_CAP_WAIT_META:
    case BL_CAP_WAIT_LIFT:
      return is_meta ? BL_CAP_TAKE : BL_CAP_SKIP;

    case BL_CAP_WAIT_CHUNK:
      if (frame->cmd != BL_CMD_CAPTURE || frame->sub != BL_CAPTURE_SUB_GET ||
          frame->plen == 0)
        return BL_CAP_SKIP;
      if (frame->seq == self->cap_expect_seq)
        return BL_CAP_TAKE;
      return frame->seq > self->cap_expect_seq ? BL_CAP_GAP : BL_CAP_SKIP;
    }

  return BL_CAP_SKIP;
}

/* What bl_cap_pump() found at the head of the receive buffer. */
typedef enum {
  BL_CAP_FRAME, /* the wanted frame: parsed and left at the head */
  BL_CAP_EMPTY, /* need more data before the head frame can be decided */
  BL_CAP_BAD,   /* undecodable input (error is set) */
} BlCapScan;

/* Consume stale frames until the wanted one is at the receive head. A
 * complete frame that fails to decode fails the capture (a torn transfer
 * must never deliver an image); a partial frame at the head waits for its
 * continuation ("response incomplete" is retried by another read). */
static BlCapScan
bl_cap_pump (FpiDeviceBetterlife *self,
             BlFrame             *frame,
             GError             **error)
{
  for (;;)
    {
      gsize total;

      if (self->rx_got < BL_FRAME_HEADER_LEN + 16 + BL_FRAME_CRC_LEN)
        return BL_CAP_EMPTY;

      if (self->rx[0] != BL_FRAME_MAGIC)
        {
          /* Lost sync (e.g. a transfer cut mid-frame): resync byte-wise. */
          fp_warn ("capture input lost frame sync, dropping a byte");
          memmove (self->rx, self->rx + 1, --self->rx_got);
          continue;
        }

      total = (gsize) le32_read (self->rx + 1) + 5;
      if (total < BL_FRAME_HEADER_LEN + 16 + BL_FRAME_CRC_LEN ||
          total > sizeof self->rx)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Capture frame length %zu is out of range", total);
          return BL_CAP_BAD;
        }

      if (self->rx_got < total)
        return BL_CAP_EMPTY;

      if (!bl_frame_parse (self->rx, self->rx_got, frame, error))
        return BL_CAP_BAD;

      switch (bl_cap_classify (self, frame))
        {
        case BL_CAP_TAKE:
          return BL_CAP_FRAME;

        case BL_CAP_SKIP:
          fp_dbg ("ignoring stale frame cmd=0x%02x sub=0x%02x seq=%u plen=%zu during capture",
                  frame->cmd, frame->sub, frame->seq, frame->plen);
          memmove (self->rx, self->rx + total, self->rx_got - total);
          self->rx_got -= total;
          break;

        case BL_CAP_GAP:
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Chunk sequence gap: got seq %u, expected %u",
                       frame->seq, self->cap_expect_seq);
          return BL_CAP_BAD;
        }
    }
}

/* Drop the frame at the receive head once its payload has been consumed
 * (bl_frame_parse() decoded the body in place). */
static void
bl_cap_consume (FpiDeviceBetterlife *self)
{
  gsize total = (gsize) le32_read (self->rx + 1) + 5;

  memmove (self->rx, self->rx + total, self->rx_got - total);
  self->rx_got -= total;
}

static void bl_cap_rx_submit (FpiDeviceBetterlife *self, FpiSsm *ssm);

/* Read completion: see the flow notes above. Timeout policies are per wait
 * kind; every path either continues the SSM or fails it. */
static void
bl_cap_rx_cb (FpiUsbTransfer *transfer,
              FpDevice       *dev,
              gpointer        user_data,
              GError         *error)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);
  FpiSsm *ssm = transfer->ssm;
  BlFrame frame = { 0 };

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (ssm);
      return;
    }

  if (error != NULL)
    {
      gboolean timed_out =
        g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);

      if (self->cap_kind == BL_CAP_WAIT_LIFT)
        {
          /* The lift watch is best-effort and any end of the metadata stream
           * ends the finger cycle: the image was already handed off. */
          g_clear_error (&error);
          fp_dbg ("finger lifted (%s)", timed_out ? "no further metadata" : "watch ended");
          fpi_ssm_mark_completed (ssm);
          return;
        }

      if (timed_out)
        {
          g_clear_error (&error);
          switch (self->cap_kind)
            {
            case BL_CAP_WAIT_DETECT:
              /* The 0xB5 answer is best-effort (probe.c: finger events may
               * require a press); ask the device to start anyway. */
              fpi_ssm_next_state (ssm);
              return;

            case BL_CAP_WAIT_META:
              /* No metadata: no finger on the sensor (VALIDATION.md §2.4).
               * Retry the Start once (the 0xB4/0 keepalive model), then fall
               * back to the 0xC1 geometry and fetch the blank frame anyway. */
              if (self->cap_attempts < BL_META_ATTEMPTS)
                {
                  fpi_ssm_jump_to_state (ssm, CAP_START_SEND);
                  return;
                }
              fp_dbg ("no Start metadata after %d attempts: no finger present, "
                      "expecting a blank frame (byte-sum 0)", self->cap_attempts);
              self->img_total = (guint32) self->img_w * self->img_h;
              self->img_expect_sum = 0;
              self->img_have_meta = FALSE;
              fpi_ssm_jump_to_state (ssm, CAP_CHUNK_SEND);
              return;

            case BL_CAP_WAIT_LIFT:
            case BL_CAP_WAIT_CHUNK:
              break;
            }
        }
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  self->rx_got += transfer->actual_length;

  switch (bl_cap_pump (self, &frame, &error))
    {
    case BL_CAP_EMPTY:
      if (self->rx_got >= sizeof self->rx)
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Capture reassembly buffer filled without a usable frame"));
      else
        bl_cap_rx_submit (self, ssm);
      return;

    case BL_CAP_BAD:
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;

    case BL_CAP_FRAME:
      break;
    }

  /* The wanted frame is at the head of the receive buffer. */
  if (self->cap_kind == BL_CAP_WAIT_CHUNK)
    {
      if (frame.plen > self->img_total - self->img_got)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Chunk seq %u overruns the image (%zu + %zu > %u)",
                                                              frame.seq, self->img_got,
                                                              frame.plen, self->img_total));
          return;
        }

      memcpy (self->img + self->img_got, frame.payload, frame.plen);
      if (!bl_corrupt_used && self->cap_corrupt_seq == self->cap_seq)
        {
          /* Hook (brief step 5): corrupt one chunk's data so the byte-sum
           * verification catches it below. */
          self->img[self->img_got] += 1;
          bl_corrupt_used = TRUE;
          fp_warn ("hook BETTERLIFE_CORRUPT_SEQ: corrupted the data of chunk seq %u",
                   self->cap_seq);
        }
      self->img_got += frame.plen;
      bl_cap_consume (self);

      fp_dbg ("chunk seq=%u received (%zu bytes), %zu/%u",
              self->cap_seq, frame.plen, self->img_got, self->img_total);

      if (self->img_got >= self->img_total)
        {
          fpi_ssm_next_state (ssm); /* CAP_VERIFY */
          return;
        }
      self->cap_seq += 1;
      fpi_ssm_jump_to_state (ssm, CAP_CHUNK_SEND);
      return;
    }

  /* A 0xB5 frame is only interesting for BL_CAP_WAIT_DETECT; everything
   * else this point can receive is Start metadata (see bl_cap_classify()). */
  if (frame.cmd == BL_CMD_DETECT_FINGER)
    {
      bl_log_response ("0xB5 finger detect", &frame);
      bl_cap_consume (self);
      fpi_ssm_next_state (ssm); /* CAP_START_SEND */
      return;
    }

  {
    guint32 total = le32_read (frame.payload + 1);
    guint32 sum = le32_read (frame.payload + 5);

    fp_dbg ("Start metadata: status=0x%02x total=%u checksum=0x%08x",
            frame.payload[0], total, sum);

    if (total != (guint32) self->img_w * self->img_h)
      {
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Start metadata size mismatch: %u bytes, sensor is %ux%u",
                                                            total, self->img_w, self->img_h));
        return;
      }

    self->img_total = total;
    self->img_expect_sum = sum;
    self->img_have_meta = TRUE;
    bl_cap_consume (self);
  }

  if (self->cap_kind == BL_CAP_WAIT_DETECT)
    fpi_ssm_next_state (ssm); /* CAP_START_SEND: metadata seen before Start */
  else if (self->cap_kind == BL_CAP_WAIT_META)
    fpi_ssm_next_state (ssm); /* CAP_CHUNK_SEND */
  else
    fpi_ssm_jump_to_state (ssm, CAP_LIFT_SEND); /* finger still on the sensor */
}

static void
bl_cap_rx_submit (FpiDeviceBetterlife *self,
                  FpiSsm             *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (t, BL_EP_IN, self->rx + self->rx_got,
                                   sizeof self->rx - self->rx_got, NULL);
  fpi_usb_transfer_submit (t, self->cap_timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bl_cap_rx_cb, NULL);
}

/* Read until bl_cap_pump() finds the frame the current wait wants. */
static void
bl_cap_rx_start (FpiDeviceBetterlife *self,
                 FpiSsm             *ssm,
                 guint               timeout_ms)
{
  self->cap_timeout_ms = timeout_ms;
  bl_cap_rx_submit (self, ssm);
}

static void
bl_cap_ssm (FpiSsm   *ssm,
            FpDevice *dev)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  /* Deactivation contract (see bl_dev_deactivate): a running SSM notices and
   * completes; bl_capture_complete() then reports the deactivation. */
  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_DETECT_SEND:
      bl_cap_flush_stale (self);
      self->cap_kind = BL_CAP_WAIT_DETECT;
      bl_cap_send (self, ssm, BL_CMD_DETECT_FINGER, 0, 0, NULL, 0);
      break;

    case CAP_DETECT_READ:
      bl_cap_rx_start (self, ssm, BL_DETECT_TIMEOUT_MS);
      break;

    case CAP_START_SEND:
      {
        static const guint8 start[4] = { 0, 0, 0, 0 };

        self->cap_attempts += 1;
        self->cap_started = TRUE;
        self->cap_kind = BL_CAP_WAIT_META;
        bl_cap_send (self, ssm, BL_CMD_CAPTURE, BL_CAPTURE_SUB_START, 0,
                     start, sizeof start);
        break;
      }

    case CAP_META_READ:
      if (self->img_have_meta)
        fpi_ssm_next_state (ssm); /* metadata already pushed (finger push) */
      else
        bl_cap_rx_start (self, ssm, BL_META_TIMEOUT_MS);
      break;

    case CAP_CHUNK_SEND:
      {
        guint32 want = MIN (self->img_total - self->img_got, self->cap_max_chunk);
        guint8 len[4];

        le32_write (len, want);
        self->cap_kind = BL_CAP_WAIT_CHUNK;
        self->cap_expect_seq = self->cap_seq;
        bl_cap_send (self, ssm, BL_CMD_CAPTURE, BL_CAPTURE_SUB_GET, self->cap_seq,
                     len, sizeof len);
        break;
      }

    case CAP_CHUNK_READ:
      bl_cap_rx_start (self, ssm, BL_CHUNK_TIMEOUT_MS);
      break;

    case CAP_VERIFY:
      {
        guint32 sum = bl_bytesum (self->img, self->img_total);
        FpImage *img;

        if (sum != self->img_expect_sum)
          {
            g_autoptr(GError) mismatch = fpi_device_error_new_msg (
              FP_DEVICE_ERROR_DATA_INVALID,
              "Image byte-sum mismatch: computed 0x%08x, expected 0x%08x",
              sum, self->img_expect_sum);

            bl_cap_cancel (self);
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&mismatch));
            break;
          }

        fp_dbg ("image %ux%u, %u bytes, byte-sum 0x%08x verified",
                self->img_w, self->img_h, self->img_total, sum);

        if (!self->img_have_meta)
          {
            /* Clean no-finger path (brief step 3): the blank frame was
             * fetched and verified above (the full chunked path), but it is
             * not handed to the core — zero-minutiae images are rejected
             * there ("No minutiae found", fp-image.c) — so the round ends
             * with a scan retry instead (bl_capture_complete()). */
            fpi_ssm_mark_completed (ssm);
            break;
          }

        img = fp_image_new (self->img_w, self->img_h);
        img->ppmm = BL_IMAGE_PPMM;
        memcpy (img->data, self->img, self->img_total);

        /* AWAIT_FINGER_ON -> CAPTURE for the hand-off, CAPTURE ->
         * AWAIT_FINGER_OFF with it (fpi-image-device.c). */
        fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
        fpi_image_device_image_captured (FP_IMAGE_DEVICE (dev), img);

        /* A real finger is on the sensor: wait for the lift before the round
         * ends (CAP_LIFT_*), like the 0304 driver, so an enroll stage gets a
         * distinct touch. */
        fpi_ssm_jump_to_state (ssm, CAP_LIFT_SEND);
        break;
      }

    case CAP_LIFT_SEND:
      {
        static const guint8 start[4] = { 0, 0, 0, 0 };

        self->cap_kind = BL_CAP_WAIT_LIFT;
        bl_cap_send (self, ssm, BL_CMD_CAPTURE, BL_CAPTURE_SUB_START, 0,
                     start, sizeof start);
        break;
      }

    case CAP_LIFT_READ:
      bl_cap_rx_start (self, ssm, BL_LIFT_TIMEOUT_MS);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
bl_capture_complete (FpiSsm   *ssm,
                     FpDevice *dev,
                     GError   *error)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);
  gboolean had_finger = self->img_have_meta;

  if (self->ssm == ssm)
    self->ssm = NULL;
  g_clear_pointer (&self->img, g_free);

  /* Deactivation contract (see bl_dev_deactivate): when deactivation
   * interrupted the SSM, the pending action is the deactivation and never
   * the capture. */
  if (self->deactivating)
    {
      if (self->cap_started)
        bl_cap_cancel (self);
      g_clear_error (&error);
      fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (dev), NULL);
      return;
    }

  if (error != NULL)
    {
      if (self->cap_started)
        bl_cap_cancel (self);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  /* Success: finish the finger cycle here, after self->ssm is cleared, so
   * the AWAIT_FINGER_ON of a follow-up enroll stage can start its own SSM
   * from change_state() without racing this one. */
  if (had_finger)
    {
      /* The image was handed off in CAP_VERIFY; the finger-off report ends
       * the cycle (non-enroll actions complete with fpi_device_capture_complete()
       * from fpi-image-device.c; enroll moves on to the next stage). */
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
      return;
    }

  /* No-finger path (brief step 3): report the scan retry. retry_scan()
   * expects CAPTURE state, hence the finger-status reports around it. */
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
  fpi_image_device_retry_scan (FP_IMAGE_DEVICE (dev), FP_DEVICE_RETRY_GENERAL);
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
}

/* FpDeviceClass->probe: identify the unit before open. The USB serial string
 * ("1.3.16.0" = firmware version on live units) becomes the device id used
 * for print storage. Probe is identity-only and never rejects the device: on
 * any trouble the default id is kept so bring-up still works. */
static void
bl_dev_probe (FpDevice *dev)
{
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  GError *error = NULL;
  g_autofree gchar *serial = NULL;

  if (fpi_device_emulation_mode_enabled (dev))
    {
      fpi_device_probe_complete (dev, "emulated-device", NULL, NULL);
      return;
    }

  if (g_usb_device_open (usb_dev, &error))
    {
      serial = g_usb_device_get_string_descriptor (usb_dev,
                                                   g_usb_device_get_serial_number_index (usb_dev),
                                                   &error);
      g_usb_device_close (usb_dev, NULL);
    }

  if (serial == NULL)
    {
      fp_dbg ("no USB serial for the device id, keeping the default: %s",
              error != NULL ? error->message : "empty descriptor");
      g_clear_error (&error);
    }

  fpi_device_probe_complete (dev, serial, NULL, NULL);
}

static void
bl_dev_open (FpImageDevice *dev)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);
  GError *error = NULL;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                     0, 0, &error))
    {
      fpi_image_device_open_complete (dev, error);
      return;
    }

  self->deactivating = FALSE;
  self->hs_retries = 0;
  self->img_w = 0;
  self->img_h = 0;

  self->hs = bl_crypto_handshake_new ();
  if (self->hs == NULL)
    {
      fpi_image_device_open_complete (dev, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  self->ssm = fpi_ssm_new (FP_DEVICE (dev), bl_open_ssm, OPEN_NUM_STATES);
  fpi_ssm_start (self->ssm, bl_open_complete);
}

static void
bl_dev_close (FpImageDevice *dev)
{
  GError *error = NULL;

  bl_crypto_clear_rootkey ();
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, &error);
  fpi_image_device_close_complete (dev, error);
}

static void
bl_dev_activate (FpImageDevice *dev)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  /* Activation is handshake-free: the capture SSM (0xB5 finger-detect,
   * 0xB4/0-2 chunked transfer) is started from change_state() when the core
   * asks for AWAIT_FINGER_ON. Each activation begins a fresh finger cycle,
   * so the deactivation notice of the previous one is cleared here (it is
   * only *set* across SSMs, never the other way round). */
  self->deactivating = FALSE;
  fpi_image_device_activate_complete (dev, NULL);
}

/* FpImageDeviceClass->change_state: each AWAIT_FINGER_ON runs one capture
 * SSM, which covers the whole finger cycle — download, image hand-off and
 * the finger-off report that ends it (the 0304 driver structure). */
static void
bl_dev_change_state (FpImageDevice      *dev,
                     FpiImageDeviceState state)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  if (state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    return;

  if (self->ssm != NULL)
    {
      fp_warn ("capture SSM already running, not starting another one");
      return;
    }

  if (self->img_w == 0 || self->img_h == 0)
    {
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev),
                                      fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  bl_capture_hooks (self);
  self->img = g_malloc ((gsize) self->img_w * self->img_h);
  self->img_total = 0;
  self->img_got = 0;
  self->img_expect_sum = 0;
  self->img_have_meta = FALSE;
  self->cap_seq = 0;
  self->cap_expect_seq = 0;
  self->cap_attempts = 0;
  self->cap_started = FALSE;

  self->ssm = fpi_ssm_new (FP_DEVICE (dev), bl_cap_ssm, CAP_NUM_STATES);
  fpi_ssm_start (self->ssm, bl_capture_complete);
}

static void
bl_dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceBetterlife *self = FPI_DEVICE_BETTERLIFE (dev);

  self->deactivating = TRUE;
  if (self->ssm == NULL)
    fpi_image_device_deactivate_complete (dev, NULL);
  /* Otherwise a running SSM notices deactivating and completes, and its
   * completion callback reports fpi_image_device_deactivate_complete() in
   * that case (bl_open_complete(), bl_capture_complete()). */
}

/* ---- registration ----------------------------------------------------- */

static const FpIdEntry id_table[] = {
  { .vid = 0x347d, .pid = 0x0302, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_betterlife_init (FpiDeviceBetterlife *self)
{
}

static void
fpi_device_betterlife_class_init (FpiDeviceBetterlifeClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Blestech Betterlife 347d:0302";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->probe = bl_dev_probe;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* Finger detection pushes status frames continuously once armed, which
   * libfprint's thermal model would read as overheating and disable
   * mid-operation; the bus-powered hardware tolerates it (as on 0304). */
  dev_class->temp_hot_seconds = -1;

  /* Image geometry is device-reported via opcode 0xC1 at init (live units:
   * 112x96, 8bpp) and stored in img_w/img_h; bl_cap_ssm sizes the FpImage
   * from those, so no constant img_width/img_height is provided here. */

  /* Matching uses the SIGFM (SIFT) matcher, not NBIS/bozorth3: the live NBIS
   * gate (Task 5) found plenty of mindtct minutiae on this 112x96 sensor
   * (10-16 per scan) but bozorth3 scored 0-4 out of 40 on every pair of
   * distinct same-finger presses, so same-finger verify would have rejected
   * 100% of the time. SIGFM (libfprint/sigfm/, from MR !418 by Matthieu
   * Charette, Natasha England-Elbro, Timur Mangliev; LGPL-2.1-or-later) is
   * built for small sensors; genuine prints score in the hundreds there.
   * score_threshold is the minimum SIGFM consistent-match count (prior art
   * ships 20 with genuine scores around 645). */
  img_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  img_class->score_threshold = 20;

  img_class->img_open = bl_dev_open;
  img_class->img_close = bl_dev_close;
  img_class->activate = bl_dev_activate;
  img_class->deactivate = bl_dev_deactivate;
  img_class->change_state = bl_dev_change_state;
}
