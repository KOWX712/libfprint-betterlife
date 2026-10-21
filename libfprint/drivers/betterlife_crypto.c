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
 *
 * SM3 (GM/T 0004-2012) and SM4 (GM/T 0002-2012) come from the prior art's
 * portable sm3.c/sm4.c (minimal implementations from the standards, kept
 * verbatim below apart from becoming static helpers of this file). SM2 comes
 * from the prior art's betterlife347d-proto.c and uses OpenSSL 3.
 */

#include "betterlife_crypto.h"

#include <string.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* SM2 needs the OpenSSL 3 low-level EC API to recover the full shared point
 * (both X and Y); EVP_PKEY_derive only exposes X. These calls are flagged
 * deprecated-in-favour-of-EVP but remain supported. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/ec.h>
#include <openssl/bn.h>

/* ---------------------------------------------------------------------- */
/* SM3 hash (GM/T 0004-2012), from the prior art's sm3.c.                  */
/* ---------------------------------------------------------------------- */

/* rol() is identical in the prior art's sm3.c and sm4.c; shared here. */
static uint32_t
rol (uint32_t x, int n)
{
  return (x << n) | (x >> (32 - n));
}

static void
sm3_compress (uint32_t v[8], const uint8_t b[64])
{
  uint32_t w[68], w1[64];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t) b[4 * i] << 24 | (uint32_t) b[4 * i + 1] << 16 | (uint32_t) b[4 * i + 2] << 8 | b[4 * i + 3];
  for (int i = 16; i < 68; i++)
    {
      uint32_t x = w[i - 16] ^ w[i - 9] ^ rol (w[i - 3], 15);
      w[i] = (x ^ rol (x, 15) ^ rol (x, 23)) ^ rol (w[i - 13], 7) ^ w[i - 6];
    }
  for (int i = 0; i < 64; i++)
    w1[i] = w[i] ^ w[i + 4];
  uint32_t a = v[0], bb = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h = v[7];
  for (int i = 0; i < 64; i++)
    {
      uint32_t tj = i < 16 ? 0x79cc4519 : 0x7a879d8a;
      uint32_t ss1 = rol (rol (a, 12) + e + rol (tj, i % 32), 7);
      uint32_t ss2 = ss1 ^ rol (a, 12);
      uint32_t ff = i < 16 ? (a ^ bb ^ c) : ((a & bb) | (a & c) | (bb & c));
      uint32_t gg = i < 16 ? (e ^ f ^ g) : ((e & f) | (~e & g));
      uint32_t tt1 = ff + d + ss2 + w1[i];
      uint32_t tt2 = gg + h + ss1 + w[i];
      d = c; c = rol (bb, 9); bb = a; a = tt1;
      h = g; g = rol (f, 19); f = e; e = tt2 ^ rol (tt2, 9) ^ rol (tt2, 17);
    }
  v[0] ^= a; v[1] ^= bb; v[2] ^= c; v[3] ^= d; v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
}

static void
sm3 (const uint8_t *msg,
     size_t         len,
     uint8_t        out[32])
{
  uint32_t v[8] = { 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };
  uint8_t blk[64];
  size_t n = len;
  const uint8_t *p = msg;
  while (n >= 64)
    {
      sm3_compress (v, p);
      p += 64;
      n -= 64;
    }
  memset (blk, 0, 64);
  memcpy (blk, p, n);
  blk[n] = 0x80;
  if (n >= 56)
    {
      sm3_compress (v, blk);
      memset (blk, 0, 64);
    }
  uint64_t bits = (uint64_t) len * 8;
  for (int i = 0; i < 8; i++)
    blk[63 - i] = bits >> (8 * i);
  sm3_compress (v, blk);
  for (int i = 0; i < 8; i++)
    {
      out[4 * i] = v[i] >> 24;
      out[4 * i + 1] = v[i] >> 16;
      out[4 * i + 2] = v[i] >> 8;
      out[4 * i + 3] = v[i];
    }
}

/* ---------------------------------------------------------------------- */
/* SM4 block cipher (GM/T 0002-2012), from the prior art's sm4.c.         */
/* ---------------------------------------------------------------------- */

static const uint8_t S[256] = {
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static const uint32_t CK[32] = {
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static uint32_t
tau (uint32_t a)
{
  return (uint32_t) S[a >> 24] << 24 | (uint32_t) S[(a >> 16) & 0xff] << 16 | (uint32_t) S[(a >> 8) & 0xff] << 8 | S[a & 0xff];
}

static uint32_t
L (uint32_t b)
{
  return b ^ rol (b, 2) ^ rol (b, 10) ^ rol (b, 18) ^ rol (b, 24);
}

static uint32_t
Lk (uint32_t b)
{
  return b ^ rol (b, 13) ^ rol (b, 23);
}

static uint32_t
ld (const uint8_t *p)
{
  return (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | p[3];
}

static void
st (uint8_t *p,
     uint32_t v)
{
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v;
}

static void
sm4_key_schedule (const uint8_t key[16],
                  uint32_t       rk[32],
                  int            encrypt)
{
  uint32_t k[4];
  for (int i = 0; i < 4; i++)
    k[i] = ld (key + 4 * i) ^ FK[i];
  uint32_t tmp[32];
  for (int i = 0; i < 32; i++)
    {
      k[i & 3] ^= Lk (tau (k[(i + 1) & 3] ^ k[(i + 2) & 3] ^ k[(i + 3) & 3] ^ CK[i]));
      tmp[i] = k[i & 3];
    }
  if (encrypt)
    for (int i = 0; i < 32; i++)
      rk[i] = tmp[i];
  else
    for (int i = 0; i < 32; i++)
      rk[i] = tmp[31 - i];
}

static void
sm4_crypt_block (const uint32_t rk[32],
                 const uint8_t  in[16],
                 uint8_t        out[16])
{
  uint32_t x[4];
  for (int i = 0; i < 4; i++)
    x[i] = ld (in + 4 * i);
  for (int i = 0; i < 32; i++)
    {
      uint32_t t = x[0] ^ L (tau (x[1] ^ x[2] ^ x[3] ^ rk[i]));
      x[0] = x[1];
      x[1] = x[2];
      x[2] = x[3];
      x[3] = t;
    }
  st (out, x[3]);
  st (out + 4, x[2]);
  st (out + 8, x[1]);
  st (out + 12, x[0]);
}

/* SM4-ECB over nblocks 16-byte blocks (input is block-aligned, no padding). */
static void
sm4_ecb (const uint8_t key[16],
         const uint8_t *in,
         uint8_t      *out,
         int           nblocks,
         int           enc)
{
  uint32_t rk[32];

  sm4_key_schedule (key, rk, enc);
  for (int i = 0; i < nblocks; i++)
    sm4_crypt_block (rk, in + i * 16, out + i * 16);
}

/* ---------------------------------------------------------------------- */
/* bl_crypto_* seam                                                        */
/* ---------------------------------------------------------------------- */

static guint8  bl_rootkey[BL_SESSKEY_LEN];
static gboolean bl_have_rootkey = FALSE;

gboolean
bl_crypto_random_bytes (guint8  *out,
                        gsize    len,
                        GError **error)
{
  if (len > G_MAXINT)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "Random request too large");
      return FALSE;
    }

  if (RAND_bytes (out, (int) len) != 1)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "RAND_bytes failed");
      return FALSE;
    }

  return TRUE;
}

void
bl_crypto_set_rootkey (const guint8 rootkey[BL_SESSKEY_LEN])
{
  memcpy (bl_rootkey, rootkey, BL_SESSKEY_LEN);
  bl_have_rootkey = TRUE;
}

void
bl_crypto_clear_rootkey (void)
{
  memset (bl_rootkey, 0, sizeof bl_rootkey);
  bl_have_rootkey = FALSE;
}

gboolean
bl_crypto_derive_framekey (const guint8 nonce[BL_NONCE_LEN],
                           guint8       framekey[BL_FRAMEKEY_LEN],
                           GError     **error)
{
  if (!bl_have_rootkey)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_INITIALIZED,
                           "No session root key set");
      return FALSE;
    }

  sm4_ecb (bl_rootkey, nonce, framekey, 1, 1);
  return TRUE;
}

gboolean
bl_crypto_seal_body (const guint8 framekey[BL_FRAMEKEY_LEN],
                     guint8      *body,
                     gsize        len,
                     GError     **error)
{
  if (len == 0 || (len & 15) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Body length is not a nonzero multiple of 16");
      return FALSE;
    }

  sm4_ecb (framekey, body, body, (int) (len / 16), 1);
  return TRUE;
}

gboolean
bl_crypto_open_body (const guint8 framekey[BL_FRAMEKEY_LEN],
                     guint8      *body,
                     gsize        len,
                     GError     **error)
{
  if (len == 0 || (len & 15) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Body length is not a nonzero multiple of 16");
      return FALSE;
    }

  sm4_ecb (framekey, body, body, (int) (len / 16), 0);
  return TRUE;
}

/* ---------------------------------------------------------------------- */
/* SM2 key exchange, from the prior art's betterlife347d-proto.c.          */
/* ---------------------------------------------------------------------- */

/* SM2 recommended curve parameters, GM/T 0003.5-2012 (big-endian hex).
 * The group is built explicitly from these rather than using a named
 * curve, as some OpenSSL builds do not register SM2 as one. */
#define SM2_P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define SM2_A  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define SM2_B  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define SM2_GX "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define SM2_GY "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
#define SM2_N  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

static EC_GROUP *
sm2_group_new (BN_CTX *ctx)
{
  BIGNUM *p = NULL, *a = NULL, *b = NULL, *gx = NULL, *gy = NULL, *n = NULL;
  EC_GROUP *g = NULL;
  EC_POINT *gen = NULL;

  if (!BN_hex2bn (&p, SM2_P) || !BN_hex2bn (&a, SM2_A) || !BN_hex2bn (&b, SM2_B) ||
      !BN_hex2bn (&gx, SM2_GX) || !BN_hex2bn (&gy, SM2_GY) || !BN_hex2bn (&n, SM2_N))
    goto out;

  g = EC_GROUP_new_curve_GFp (p, a, b, ctx);
  if (!g)
    goto out;

  gen = EC_POINT_new (g);
  if (!gen ||
      EC_POINT_set_affine_coordinates (g, gen, gx, gy, ctx) != 1 ||
      EC_GROUP_set_generator (g, gen, n, BN_value_one ()) != 1)
    {
      EC_GROUP_free (g);
      g = NULL;
    }

out:
  BN_free (p); BN_free (a); BN_free (b);
  BN_free (gx); BN_free (gy); BN_free (n);
  EC_POINT_free (gen);
  return g;
}

struct _BlHandshake
{
  EC_GROUP *group;
  BIGNUM   *d;
  BN_CTX   *ctx;
};

void
bl_crypto_handshake_free (BlHandshake *hs)
{
  if (!hs)
    return;
  if (hs->d)
    BN_clear_free (hs->d);
  if (hs->group)
    EC_GROUP_free (hs->group);
  if (hs->ctx)
    BN_CTX_free (hs->ctx);
  g_free (hs);
}

BlHandshake *
bl_crypto_handshake_new (void)
{
  BlHandshake *hs = g_new0 (BlHandshake, 1);
  const BIGNUM *n;

  hs->ctx = BN_CTX_new ();
  hs->group = hs->ctx ? sm2_group_new (hs->ctx) : NULL;
  hs->d = BN_new ();
  if (!hs->ctx || !hs->group || !hs->d)
    goto fail;

  n = EC_GROUP_get0_order (hs->group);
  do
    {
      if (!BN_rand_range (hs->d, n))
        goto fail;
    }
  while (BN_is_zero (hs->d));
  return hs;

fail:
  bl_crypto_handshake_free (hs);
  return NULL;
}

gboolean
bl_crypto_handshake_pubkey (BlHandshake *hs,
                            guint8       out65[65])
{
  EC_POINT *q = EC_POINT_new (hs->group);
  BIGNUM *x = BN_new (), *y = BN_new ();
  gboolean ok = q && x && y &&
                EC_POINT_mul (hs->group, q, hs->d, NULL, NULL, hs->ctx) == 1 &&
                EC_POINT_get_affine_coordinates (hs->group, q, x, y, hs->ctx) == 1;

  if (ok)
    {
      out65[0] = 0x04;
      BN_bn2binpad (x, out65 + 1, 32);
      BN_bn2binpad (y, out65 + 33, 32);
    }
  EC_POINT_free (q);
  BN_free (x);
  BN_free (y);
  return ok;
}

gboolean
bl_crypto_handshake_derive (BlHandshake  *hs,
                            const guint8 *payload,
                            gsize         len,
                            guint8        rootkey[BL_SESSKEY_LEN],
                            GError      **error)
{
  gsize off = (len > 0 && payload[0] == 0x04) ? 1 : 0;
  const guint8 *mx_b, *my_b, *mac, *enc;
  BIGNUM *mx = NULL, *my = NULL, *sx = BN_new (), *sy = BN_new ();
  EC_POINT *qm = EC_POINT_new (hs->group), *s = EC_POINT_new (hs->group);
  guint8 sxb[32], syb[32], kd[32], sk[16], z[68], m[80], mo[32];
  gboolean ok;

  if (len < off + 64 + 32 + 16)
    {
      ok = FALSE;
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Key exchange response is too short");
      goto out;
    }

  mx_b = payload + off;
  my_b = payload + off + 32;
  mac = payload + off + 64;
  enc = payload + off + 96;

  mx = BN_bin2bn (mx_b, 32, NULL);
  my = BN_bin2bn (my_b, 32, NULL);
  ok = mx && my && sx && sy && qm && s &&
       EC_POINT_set_affine_coordinates (hs->group, qm, mx, my, hs->ctx) == 1 &&
       EC_POINT_is_on_curve (hs->group, qm, hs->ctx) == 1 &&
       EC_POINT_mul (hs->group, s, NULL, qm, hs->d, hs->ctx) == 1 &&
       EC_POINT_get_affine_coordinates (hs->group, s, sx, sy, hs->ctx) == 1;
  if (!ok)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Key exchange peer point is invalid");
      goto out;
    }

  BN_bn2binpad (sx, sxb, 32);
  BN_bn2binpad (sy, syb, 32);

  /* KDF = SM3(Sx || Sy || 00 00 00 01); sess = encSessKey XOR KDF[0:16] */
  memcpy (z, sxb, 32);
  memcpy (z + 32, syb, 32);
  z[64] = 0; z[65] = 0; z[66] = 0; z[67] = 1;
  sm3 (z, 68, kd);

  for (int i = 0; i < 16; i++)
    sk[i] = enc[i] ^ kd[i];

  /* MAC check = SM3(Sx || sess || Sy) */
  memcpy (m, sxb, 32);
  memcpy (m + 32, sk, 16);
  memcpy (m + 48, syb, 32);
  sm3 (m, 80, mo);
  ok = CRYPTO_memcmp (mo, mac, 32) == 0;
  if (ok)
    memcpy (rootkey, sk, BL_SESSKEY_LEN);
  else
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                         "Key exchange MAC mismatch");

out:
  BN_free (mx);
  BN_free (my);
  BN_free (sx);
  BN_free (sy);
  EC_POINT_free (qm);
  EC_POINT_free (s);
  return ok;
}

#pragma GCC diagnostic pop
