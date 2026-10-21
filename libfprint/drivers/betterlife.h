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
 */

/*
 * Frame layout (little-endian lengths):
 *   0xAA | u32 len | 16B nonce | body | u32 crc32 (zlib poly)
 * where len = 16 + body_len + 4 (i.e. total frame size minus the 5 leading
 * bytes) and
 *   body = 0x4C | cmd | sub | 0x00 | u16 seq | u32 plen | payload | zero-pad
 * padded to a nonzero multiple of 16 bytes. The CRC covers everything before
 * the trailing CRC field, i.e. the *sealed* body.
 *
 * A zero nonce marks a plaintext body (used before the key exchange).
 * Otherwise the body is sealed (SM4-ECB) under
 * framekey = bl_crypto_derive_framekey(nonce); responses reuse the request's
 * nonce, so one frame key covers a request/response pair.
 */

#pragma once

#include "fpi-image-device.h"

#define BL_FRAME_MAGIC          0xaa
#define BL_FRAME_BODY_MAGIC     0x4c

#define BL_FRAME_HEADER_LEN     21  /* magic + u32 len + 16B nonce */
#define BL_FRAME_BODY_HEADER_LEN 10 /* 0x4C cmd sub 0x00 u16 seq u32 plen */
#define BL_FRAME_CRC_LEN        4
#define BL_FRAME_OVERHEAD       (BL_FRAME_HEADER_LEN + BL_FRAME_BODY_HEADER_LEN + BL_FRAME_CRC_LEN)

/* Opcode whitelist (plan ruling R7), all live-verified as read-only queries
 * on 347d:0302. Firmware/maintenance opcodes (0xD0/0xD1/0xC2/0xC3) and the
 * template management block (0xB0-0xB2) must never be transmitted: v1 has no
 * firmware paths at all (device firmware 01.03.10.00 needs no update), and
 * bl_frame_build() refuses everything outside this list. */
#define BL_CMD_QUERY_FW_VERSION    0xa0
#define BL_CMD_QUERY_MODULE_SCHEME 0xa1
#define BL_CMD_KEY_EXCHANGE        0xa2
#define BL_CMD_FP_COUNT            0xb3
#define BL_CMD_CAPTURE             0xb4
#define BL_CMD_DETECT_FINGER       0xb5
#define BL_CMD_QUERY_UID           0xc0
#define BL_CMD_QUERY_SENSOR_INFO   0xc1

/* 0xB4 capture subcommands. */
#define BL_CAPTURE_SUB_START   0x00
#define BL_CAPTURE_SUB_GET     0x01
#define BL_CAPTURE_SUB_CANCEL  0x02

/* One parsed frame. payload points into the parsed buffer (decrypted in
 * place when the frame was sealed). */
typedef struct {
  guint8        cmd;
  guint8        sub;
  guint16       seq;
  const guint8 *payload;
  gsize         plen;
} BlFrame;

/* Build a framed packet into out (needs cap >= BL_FRAME_OVERHEAD + pad16(plen)).
 * A nonzero seq is written to the body header (chunk requests increment it).
 * When encrypted is TRUE the body is sealed under a fresh random nonce (the
 * session root key must be set); when FALSE the frame is plaintext with a
 * zero nonce. Returns the frame length, or -1 on failure (error is set). */
gssize bl_frame_build (guint8       *out,
                       gsize         cap,
                       guint8        cmd,
                       guint8        sub,
                       guint16       seq,
                       const guint8 *payload,
                       gsize         plen,
                       gboolean      encrypted,
                       GError      **error);

/* Validate and decode the first frame in buf (CRC checked first, then the
 * body is opened in place when sealed). Returns FALSE on a malformed frame
 * (error is set). */
gboolean bl_frame_parse (guint8  *buf,
                         gsize    len,
                         BlFrame *frame,
                         GError **error);

/* Number of complete frames buffered in buf, counted on the plaintext outer
 * length fields only (acked + metadata frames may arrive coalesced in one
 * bulk IN transfer). */
gint     bl_frame_count (const guint8 *buf,
                         gsize         len);

/* Plain byte-add checksum of an image buffer, mod 2^32 (the "byte-sum" of
 * PROTOCOL.md §4: the 0xB4/0 Start metadata carries the same sum of the
 * whole image and the assembled image must verify against it). */
guint32  bl_bytesum (const guint8 *data,
                     gsize         len);

G_DECLARE_FINAL_TYPE (FpiDeviceBetterlife, fpi_device_betterlife, FPI, DEVICE_BETTERLIFE, FpImageDevice)
