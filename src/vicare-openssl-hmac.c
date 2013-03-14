/*
  Part of: Vicare/OpenSSL
  Contents: OpenSSL for Vicare
  Date: Mon Mar 11, 2013

  Abstract

	HMAC functions.

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


/** --------------------------------------------------------------------
 ** Helpers.
 ** ----------------------------------------------------------------- */

static const EVP_MD *
integer_to_md (ikptr s_md)
{
  /* This mapping must  be kept in sync with the  Scheme function in the
     public library. */
  switch (ik_integer_to_int(s_md)) {
  case 0:	return EVP_md4();
  case 1:	return EVP_md5();
  case 2:	return EVP_mdc2();
  case 3:	return EVP_sha1();
  case 4:	return EVP_sha224();
  case 5:	return EVP_sha256();
  case 6:	return EVP_sha384();
  case 7:	return EVP_sha512();
  case 8:	return EVP_ripemd160();
  case 9:	return EVP_whirlpool();
  case 10:	return EVP_dss();
  case 11:	return EVP_dss1();
  default:
    return NULL;
  }
}


/** --------------------------------------------------------------------
 ** Initialisation.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_hmac_init (ikptr s_key, ikptr s_key_len, ikptr s_md, ikpcb * pcb)
/* This   version  of   the   function  performs   the   work  of   both
   "HMAC_CTX_init()" and "HMAC_Init()". */
{
#ifdef HAVE_HMAC_INIT
  HMAC_CTX *	ctx;
  ctx = malloc(sizeof(HMAC_CTX));
  if (ctx) {
    HMAC_CTX_init(ctx);
    const void *	key	= IK_GENERALISED_C_STRING(s_key);
    size_t		key_len	= ik_generalised_c_buffer_len(s_key, s_key_len);
    const EVP_MD *	md;
    int			rv;
    md = integer_to_md (s_md);
    if (md) {
      rv = HMAC_Init(ctx, key, (unsigned long)key_len, md);
      return (rv)? ika_pointer_alloc(pcb, (long)ctx) : IK_FALSE;
    }
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}

/* ------------------------------------------------------------------ */

#if 0
ikptr
ikrt_openssl_hmac_ctx_init (ikpcb * pcb)
/* This   version  of   the   function  performs   the   work  of
   "HMAC_CTX_init()" only. */
{
#ifdef HAVE_HMAC_CTX_INIT
  HMAC_CTX *	ctx;
  ctx = malloc(sizeof(HMAC_CTX));
  if (ctx) {
    HMAC_CTX_init(ctx);
    return ika_pointer_alloc(pcb, (long)ctx);
  } else
    return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_hmac_init (ikptr s_ctx, ikptr s_key, ikptr s_key_len, ikptr s_md, ikpcb * pcb)
/* This  version of  the  function performs  the  work of  "HMAC_Init()"
   only. */
{
#ifdef HAVE_HMAC_INIT
  HMAC_CTX *	ctx	= IK_HMAC_CTX(s_ctx);
  const void *	key	= IK_GENERALISED_C_STRING(s_key);
  size_t	key_len	= ik_generalised_c_buffer_len(s_key, s_key_len);
  const EVP_MD *md;
  int		rv;
  switch (ik_integer_to_int(s_md)) {
  case 0:	md = EVP_md4();		break;
  case 1:	md = EVP_md5();		break;
  case 2:	md = EVP_mdc2();	break;
  case 3:	md = EVP_sha1();	break;
  case 4:	md = EVP_sha224();	break;
  case 5:	md = EVP_sha256();	break;
  case 6:	md = EVP_sha384();	break;
  case 7:	md = EVP_sha512();	break;
  case 8:	md = EVP_ripemd160();	break;
  case 9:	md = EVP_dss();		break;
  case 10:	md = EVP_dss1();	break;
  default:
    return IK_FALSE;
  }
  rv = HMAC_Init(ctx, key, (unsigned long)key_len, md);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
#endif

/* ------------------------------------------------------------------ */

ikptr
ikrt_openssl_hmac_init_ex (ikpcb * pcb)
{
#ifdef HAVE_HMAC_INIT_EX
  /* rv = HMAC_Init_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** Initialisation and finalisation.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_hmac_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_HMAC_FINAL
  HMAC_CTX *		ctx = IK_HMAC_CTX(s_ctx);
  unsigned char		sum[HMAC_MAX_MD_CBLOCK];
  unsigned int		len;
  int			rv;
  rv = HMAC_Final(ctx, sum, &len);
  HMAC_CTX_cleanup(ctx);
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}

/* ------------------------------------------------------------------ */

#if 0
ikptr
ikrt_openssl_hmac_ctx_cleanup (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_HMAC_CTX_CLEANUP
  HMAC_CTX *	ctx = IK_HMAC_CTX(s_ctx);
  HMAC_CTX_cleanup(ctx);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_hmac_final (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_HMAC_FINAL
  HMAC_CTX *		ctx = IK_HMAC_CTX(s_ctx);
  unsigned char		sum[HMAC_MAX_MD_CBLOCK];
  unsigned int		len;
  int			rv;
  rv = HMAC_Final(ctx, sum, &len);
  return (rv)? ika_bytevector_from_memory_block(pcb, sum, len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
#endif


/** --------------------------------------------------------------------
 ** Context updating.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_hmac_update (ikptr s_ctx, ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_HMAC_UPDATE
  HMAC_CTX *	ctx	= IK_HMAC_CTX(s_ctx);
  const void *	in	= IK_GENERALISED_C_STRING(s_input);
  size_t	in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  int		rv;
  rv = HMAC_Update(ctx, in, in_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** Miscellaneous functions.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_hmac_ctx_copy (ikptr s_dst_ctx, ikptr s_src_ctx, ikpcb * pcb)
/* This OpenSSL function is undocumented as of version 1.0.1e. */
{
#ifdef HAVE_HMAC_CTX_COPY
  HMAC_CTX *	dst_ctx	= IK_HMAC_CTX(s_dst_ctx);
  HMAC_CTX *	src_ctx	= IK_HMAC_CTX(s_src_ctx);
  int		rv;
  rv = HMAC_CTX_copy(dst_ctx, src_ctx);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_hmac_ctx_set_flags (ikptr s_ctx, ikptr s_flags, ikpcb * pcb)
/* This OpenSSL function is undocumented as of version 1.0.1e. */
{
#ifdef HAVE_HMAC_CTX_SET_FLAGS
  HMAC_CTX *	ctx	= IK_HMAC_CTX(s_ctx);
  unsigned long	flags	= ik_integer_to_ulong(s_flags);
  HMAC_CTX_set_flags(ctx, flags);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** One-step computation.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_hmac (ikptr s_md,
	   ikptr s_key,   ikptr s_key_len,
	   ikptr s_input, ikptr s_input_len,
	   ikpcb * pcb)
{
#ifdef HAVE_HMAC
  const void *		key	= IK_GENERALISED_C_STRING(s_key);
  size_t		key_len	= ik_generalised_c_buffer_len(s_key, s_key_len);
  const void *		in	= IK_GENERALISED_C_STRING(s_input);
  size_t		in_len	= ik_generalised_c_buffer_len(s_input, s_input_len);
  const EVP_MD *	md;
  unsigned char		sum[HMAC_MAX_MD_CBLOCK];
  unsigned int		len;
  unsigned char *	rv;
  md = integer_to_md (s_md);
  if (md) {
    rv = HMAC(md, key, key_len, in, in_len, sum, &len);
    if (rv)
      return ika_bytevector_from_memory_block(pcb, sum, len);
  }
  return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** Still to be implemented.
 ** ----------------------------------------------------------------- */

#if 0
ikptr
ikrt_openssl_openssl_doit (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_DOIT
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
#endif

/* end of file */
