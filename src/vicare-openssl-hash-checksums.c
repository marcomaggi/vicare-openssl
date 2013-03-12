/*
  Part of: Vicare/OpenSSL
  Contents: OpenSSL for Vicare
  Date: Sat Mar  9, 2013

  Abstract

	Hash checksum functions.

  Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>

  This program is  free software: you can redistribute  it and/or modify
  it under the  terms of the GNU General Public  License as published by
  the Free Software Foundation, either  version 3 of the License, or (at
  your option) any later version.

  This program  is distributed in the  hope that it will  be useful, but
  WITHOUT   ANY  WARRANTY;   without  even   the  implied   warranty  of
  MERCHANTABILITY  or FITNESS  FOR A  PARTICULAR PURPOSE.   See  the GNU
  General Public License for more details.

  You  should have received  a copy  of the  GNU General  Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


/** --------------------------------------------------------------------
 ** Headers.
 ** ----------------------------------------------------------------- */

#include "vicare-openssl-internals.h"

typedef const unsigned char		ik_ssl_cuchar;


/** --------------------------------------------------------------------
 ** Helpers.
 ** ----------------------------------------------------------------- */



/** --------------------------------------------------------------------
 ** MD4.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_md4_init (ikpcb * pcb)
{
#ifdef HAVE_MD4_INIT
  MD4_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(MD4_CTX));
  if (ctx) {
    rv  = MD4_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MD4_UPDATE
  MD4_CTX *	ctx	= IK_MD4_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = MD4_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_MD4_FINAL
  ikptr		s_pointer	= IK_MD4_CTX_POINTER(s_ctx);
  MD4_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[MD4_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = MD4_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, MD4_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MD4
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[MD4_DIGEST_LENGTH];
  MD4(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, MD4_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** MD5.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_md5_init (ikpcb * pcb)
{
#ifdef HAVE_MD5_INIT
  MD5_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(MD5_CTX));
  if (ctx) {
    rv  = MD5_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md5_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MD5_UPDATE
  MD5_CTX *	ctx	= IK_MD5_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = MD5_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md5_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_MD5_FINAL
  ikptr		s_pointer	= IK_MD5_CTX_POINTER(s_ctx);
  MD5_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[MD5_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = MD5_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, MD5_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md5 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MD5
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[MD5_DIGEST_LENGTH];
  MD5(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, MD5_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** MDC2.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_mdc2_init (ikpcb * pcb)
{
#ifdef HAVE_MDC2_INIT
  MDC2_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(MDC2_CTX));
  if (ctx) {
    rv  = MDC2_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_mdc2_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MDC2_UPDATE
  MDC2_CTX *	ctx	= IK_MDC2_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = MDC2_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_mdc2_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_MDC2_FINAL
  ikptr		s_pointer	= IK_MDC2_CTX_POINTER(s_ctx);
  MDC2_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[MDC2_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = MDC2_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, MDC2_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_mdc2 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MDC2
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[MDC2_DIGEST_LENGTH];
  MDC2(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, MDC2_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** SHA1.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_sha1_init (ikpcb * pcb)
{
#ifdef HAVE_SHA1_INIT
  SHA_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(SHA_CTX));
  if (ctx) {
    rv  = SHA1_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha1_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA1_UPDATE
  SHA_CTX *	ctx	= IK_SHA_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = SHA1_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha1_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_SHA1_FINAL
  ikptr		s_pointer	= IK_SHA_CTX_POINTER(s_ctx);
  SHA_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[SHA_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = SHA1_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, SHA_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha1 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA1
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[SHA_DIGEST_LENGTH];
  SHA1(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, SHA_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** SHA224.
 ** ----------------------------------------------------------------- */

/* The   functions  for   SHA224  operate   on  the   context  structure
   "SHA256_CTX", as of  OpenSSL version 1.0.1e there  is no "SHA224_CTX"
   structure. */

typedef SHA256_CTX		SHA224_CTX;

ikptr
ikrt_sha224_init (ikpcb * pcb)
{
#ifdef HAVE_SHA224_INIT
  SHA224_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(SHA224_CTX));
  if (ctx) {
    rv  = SHA224_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha224_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA224_UPDATE
  SHA224_CTX *	ctx	= IK_SHA224_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = SHA224_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha224_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_SHA224_FINAL
  ikptr		s_pointer	= IK_SHA224_CTX_POINTER(s_ctx);
  SHA224_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[SHA224_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = SHA224_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, SHA224_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha224 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA224
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[SHA224_DIGEST_LENGTH];
  SHA224(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, SHA224_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** SHA256.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_sha256_init (ikpcb * pcb)
{
#ifdef HAVE_SHA256_INIT
  SHA256_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(SHA256_CTX));
  if (ctx) {
    rv  = SHA256_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha256_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA256_UPDATE
  SHA256_CTX *	ctx	= IK_SHA256_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = SHA256_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha256_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_SHA256_FINAL
  ikptr		s_pointer	= IK_SHA256_CTX_POINTER(s_ctx);
  SHA256_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[SHA256_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = SHA256_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, SHA256_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha256 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA256
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[SHA256_DIGEST_LENGTH];
  SHA256(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, SHA256_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** SHA384.
 ** ----------------------------------------------------------------- */

/* The   functions  for   SHA384  operate   on  the   context  structure
   "SHA512_CTX", as of  OpenSSL version 1.0.1e there  is no "SHA384_CTX"
   structure. */

typedef SHA512_CTX		SHA384_CTX;

ikptr
ikrt_sha384_init (ikpcb * pcb)
{
#ifdef HAVE_SHA384_INIT
  SHA384_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(SHA384_CTX));
  if (ctx) {
    rv  = SHA384_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha384_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA384_UPDATE
  SHA384_CTX *	ctx	= IK_SHA384_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = SHA384_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha384_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_SHA384_FINAL
  ikptr		s_pointer	= IK_SHA384_CTX_POINTER(s_ctx);
  SHA384_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[SHA384_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = SHA384_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, SHA384_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha384 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA384
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[SHA384_DIGEST_LENGTH];
  SHA384(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, SHA384_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** SHA512.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_sha512_init (ikpcb * pcb)
{
#ifdef HAVE_SHA512_INIT
  SHA512_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(SHA512_CTX));
  if (ctx) {
    rv  = SHA512_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha512_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA512_UPDATE
  SHA512_CTX *	ctx	= IK_SHA512_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = SHA512_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha512_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_SHA512_FINAL
  ikptr		s_pointer	= IK_SHA512_CTX_POINTER(s_ctx);
  SHA512_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[SHA512_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = SHA512_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, SHA512_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_sha512 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_SHA512
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[SHA512_DIGEST_LENGTH];
  SHA512(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, SHA512_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** RIPEMD160.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_ripemd160_init (ikpcb * pcb)
{
#ifdef HAVE_RIPEMD160_INIT
  RIPEMD160_CTX *	ctx;
  int		rv;
  ctx = malloc(sizeof(RIPEMD160_CTX));
  if (ctx) {
    rv  = RIPEMD160_Init(ctx);
    if (rv)
      return ika_pointer_alloc(pcb, (long)ctx);
    else
      free(ctx);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_ripemd160_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_RIPEMD160_UPDATE
  RIPEMD160_CTX *	ctx	= IK_RIPEMD160_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = RIPEMD160_Update(ctx, in, (unsigned long)in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_ripemd160_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_RIPEMD160_FINAL
  ikptr		s_pointer	= IK_RIPEMD160_CTX_POINTER(s_ctx);
  RIPEMD160_CTX *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  unsigned char	sum[RIPEMD160_DIGEST_LENGTH];
  int		rv = 0;
  if (ctx) {
    rv = RIPEMD160_Final(sum, ctx);
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, RIPEMD160_DIGEST_LENGTH) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_ripemd160 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_RIPEMD160
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)ik_generalised_c_buffer_len(s_input, s_input_len);
  unsigned char		sum[RIPEMD160_DIGEST_LENGTH];
  RIPEMD160(in, in_len, sum);
  return ika_bytevector_from_memory_block(pcb, sum, RIPEMD160_DIGEST_LENGTH);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** Still to be implemented.
 ** ----------------------------------------------------------------- */

#if 0
ikptr
ikrt_openssl_doit (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_DOIT
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
#endif

/* end of file */
