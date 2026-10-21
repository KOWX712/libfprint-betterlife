/*
 * Betterlife 347d:0302 secure-channel crypto (SM2/SM3/SM4)
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
 * The transport cipher is SM4-128-ECB (GM/T 0002-2012) and the key exchange
 * is SM2 ECDH + SM3 KDF/MAC (GM/T 0003.5-2012 / GM/T 0004-2012), the same
 * ShangMi suite as the 347d:0304 sibling, live-verified against 347d:0302.
 * AES is deliberately NOT implemented: the wire speaks SM4.
 *
 * Session state (the root key) is kept in this module so that the bl_crypto_*
 * seam stays a one-function-per-operation interface:
 *   framekey = SM4-ECB-encrypt(rootkey, nonce16)
 *   body     = SM4-ECB blocks under framekey (in place, zero-pad to 16)
 */

#pragma once

#include <gio/gio.h>
#include <glib.h>

#define BL_NONCE_LEN    16
#define BL_SESSKEY_LEN  16
#define BL_FRAMEKEY_LEN 16

/* Random bytes for frame nonces (OpenSSL RAND_bytes). */
gboolean bl_crypto_random_bytes (guint8  *out,
                                 gsize    len,
                                 GError **error);

/* Session root key handling (set after the 0xA2 key exchange). */
void     bl_crypto_set_rootkey   (const guint8 rootkey[BL_SESSKEY_LEN]);
void     bl_crypto_clear_rootkey (void);

/* framekey = SM4-ECB-encrypt(rootkey, nonce16). Fails when no root key is
 * set (e.g. a sealed frame parsed before the key exchange finished). */
gboolean bl_crypto_derive_framekey (const guint8 nonce[BL_NONCE_LEN],
                                    guint8       framekey[BL_FRAMEKEY_LEN],
                                    GError     **error);

/* SM4-ECB over the block-aligned buffer body/len, in place. seal encrypts,
 * open decrypts; len must be a nonzero multiple of 16. */
gboolean bl_crypto_seal_body (const guint8 framekey[BL_FRAMEKEY_LEN],
                              guint8      *body,
                              gsize        len,
                              GError     **error);
gboolean bl_crypto_open_body (const guint8 framekey[BL_FRAMEKEY_LEN],
                              guint8      *body,
                              gsize        len,
                              GError     **error);

/* SM2 ephemeral key agreement state (0xA2 key exchange). */
typedef struct _BlHandshake BlHandshake;

/* Generate an ephemeral SM2 keypair. NULL on failure. */
BlHandshake *bl_crypto_handshake_new  (void);
void         bl_crypto_handshake_free (BlHandshake *hs);

/* Our public key, 65 bytes: 0x04 || X(32) || Y(32). */
gboolean     bl_crypto_handshake_pubkey (BlHandshake  *hs,
                                         guint8        out65[65]);

/* Derive the root key from the 0xA2 response payload, which is
 *   [0x04]? || peerX(32) || peerY(32) || MAC(32) || encSessKey(16).
 * The KDF is SM3(Sx||Sy||00000001), sess = encSessKey XOR KDF[0:16] and the
 * MAC check is SM3(Sx||sess||Sy) == MAC. Verifies the MAC. */
gboolean     bl_crypto_handshake_derive (BlHandshake  *hs,
                                         const guint8 *payload,
                                         gsize         len,
                                         guint8        rootkey[BL_SESSKEY_LEN],
                                         GError      **error);
