/*
  Part of: Vicare/OpenSSL
  Contents: Openssl for Vicare
  Date: Wed Mar 13, 2013

  Abstract

	EVP message digest functions.  Notice that the functions:

	   EVP_DigestInit()
	   EVP_DigestFinal()
	   EVP_MD_CTX_copy()

        are marked  as obsolete  in the manual  page of  OpenSSL version
        1.0.1e.

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
 ** EVP message digest functions C wrappers: creation and destruction.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_md_ctx_create (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_CREATE
  EVP_MD_CTX *	ctx;
  ctx = EVP_MD_CTX_create();
  return (ctx)? ika_pointer_alloc(pcb, (long)ctx) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_destroy (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_DESTROY
  EVP_MD_CTX *	ctx = IK_EVP_MD_CTX(s_ctx);
  EVP_MD_CTX_destroy(ctx);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_copy_ex (ikptr s_ou, ikptr s_in, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_COPY_EX
  EVP_MD_CTX *		ou = IK_EVP_MD_CTX(s_ou);
  const EVP_MD_CTX *	in = IK_EVP_MD_CTX(s_in);
  int			rv;
  rv = EVP_MD_CTX_copy_ex(ou, in);
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: initialisation and finalisation.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_digestinit_ex (ikptr s_ctx, ikptr s_md, ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTINIT_EX
  EVP_MD_CTX *		ctx = IK_EVP_MD_CTX(s_ctx);
  const EVP_MD *	md;
  int			rv;
  if (IK_IS_INTEGER(s_md)) {
    md = ik_openssl_integer_to_evp_md(s_md);
  } else {
    md = IK_POINTER_DATA_VOIDP(s_md);
  }
  if (md) {
    rv = EVP_DigestInit_ex(ctx, md, NULL);
    return IK_BOOLEAN_FROM_INT(rv);
  } else
    return IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_digestfinal_ex (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTFINAL_EX
  EVP_MD_CTX *		ctx = IK_EVP_MD_CTX(s_ctx);
  unsigned char		md_buf[EVP_MAX_MD_SIZE];
  unsigned int		md_len;
  int			rv;
  rv = EVP_DigestFinal_ex(ctx, md_buf, &md_len);
  return (rv)? ika_bytevector_from_memory_block(pcb, md_buf, md_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: context updating.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_digestupdate (ikptr s_ctx, ikptr s_buf, ikptr s_buf_len, ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTUPDATE
  EVP_MD_CTX *		ctx	= IK_EVP_MD_CTX(s_ctx);
  uint8_t *		buf	= IK_GENERALISED_C_BUFFER(s_buf);
  size_t		buf_len	= ik_generalised_c_buffer_len(s_buf, s_buf_len);
  int			rv;
  rv = EVP_DigestUpdate(ctx, buf, buf_len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: context inspection.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_md_ctx_size (ikptr s_ctx, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_MD_CTX_SIZE) && HAVE_DECL_EVP_MD_CTX_SIZE)
  const EVP_MD_CTX *	ctx = IK_EVP_MD_CTX(s_ctx);
  int			rv;
  rv = EVP_MD_CTX_size(ctx);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_block_size (ikptr s_ctx, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_MD_CTX_BLOCK_SIZE) && HAVE_DECL_EVP_MD_CTX_BLOCK_SIZE)
  const EVP_MD_CTX *	ctx = IK_EVP_MD_CTX(s_ctx);
  int			rv;
  rv = EVP_MD_CTX_block_size(ctx);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_type (ikptr s_ctx, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_MD_CTX_TYPE) && HAVE_DECL_EVP_MD_CTX_TYPE)
  const EVP_MD_CTX *	ctx = IK_EVP_MD_CTX(s_ctx);
  int			rv;
  rv = EVP_MD_CTX_type(ctx);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_md (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_MD
  const EVP_MD_CTX *	ctx = IK_EVP_MD_CTX(s_ctx);
  const EVP_MD*		rv;
  rv = EVP_MD_CTX_md(ctx);
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: context flags.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_md_ctx_set_flags (ikptr s_ctx, ikptr s_flags, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_SET_FLAGS
  EVP_MD_CTX *	ctx   = IK_EVP_MD_CTX(s_ctx);
  int		flags = ik_integer_to_int(s_flags);
  EVP_MD_CTX_set_flags(ctx, flags);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_clear_flags (ikptr s_ctx, ikptr s_flags, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_CLEAR_FLAGS
  EVP_MD_CTX *	ctx   = IK_EVP_MD_CTX(s_ctx);
  int		flags = ik_integer_to_int(s_flags);
  EVP_MD_CTX_clear_flags(ctx, flags);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_ctx_test_flags (ikptr s_ctx, ikptr s_flags, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_TEST_FLAGS
  const EVP_MD_CTX *	ctx   = IK_EVP_MD_CTX(s_ctx);
  int			flags = ik_integer_to_int(s_flags);
  int			rv;
  rv = EVP_MD_CTX_test_flags(ctx, flags);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: algorithm functions.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_md_null (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_NULL
  const EVP_MD *	rv;
  rv = EVP_md_null();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md2 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD2
  const EVP_MD *	rv;
  rv = EVP_md2();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md4 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD4
  const EVP_MD *	rv;
  rv = EVP_md4();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md5 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD5
  const EVP_MD *	rv;
  rv = EVP_md5();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_sha (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA
  const EVP_MD *	rv;
  rv = EVP_sha();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_sha1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA1
  const EVP_MD *	rv;
  rv = EVP_sha1();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_dss (ikpcb * pcb)
{
#ifdef HAVE_EVP_DSS
  const EVP_MD *	rv;
  rv = EVP_dss();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_dss1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DSS1
  const EVP_MD *	rv;
  rv = EVP_dss1();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_ecdsa (ikpcb * pcb)
{
#ifdef HAVE_EVP_ECDSA
  const EVP_MD *	rv;
  rv = EVP_ecdsa();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_sha224 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA224
  const EVP_MD *	rv;
  rv = EVP_sha224();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_sha256 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA256
  const EVP_MD *	rv;
  rv = EVP_sha256();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_sha384 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA384
  const EVP_MD *	rv;
  rv = EVP_sha384();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_sha512 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA512
  const EVP_MD *	rv;
  rv = EVP_sha512();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_mdc2 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MDC2
  const EVP_MD *	rv;
  rv = EVP_mdc2();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_ripemd160 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RIPEMD160
  const EVP_MD *	rv;
  rv = EVP_ripemd160();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_whirlpool (ikpcb * pcb)
{
#ifdef HAVE_EVP_WHIRLPOOL
  const EVP_MD *	rv;
  rv = EVP_whirlpool();
  return ika_pointer_alloc(pcb, (long)rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: algorithm inspection.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_md_size (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_SIZE
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  int			rv;
  rv = EVP_MD_size(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_block_size (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_BLOCK_SIZE
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  int			rv;
  rv = EVP_MD_block_size(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}

/* ------------------------------------------------------------------ */

ikptr
ikrt_openssl_evp_md_nid (ikptr s_algo, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_MD_NID) && HAVE_DECL_EVP_MD_NID)
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  int			rv;
  rv = EVP_MD_nid(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_type (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_TYPE
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  int			rv;
  rv = EVP_MD_type(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_name (ikptr s_algo, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_MD_NAME) && HAVE_DECL_EVP_MD_NAME)
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  const char *		rv;
  rv = EVP_MD_name(algo);
  return (rv)? ika_bytevector_from_cstring(pcb, rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_flags (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_FLAGS
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  unsigned long		rv;
  rv = EVP_MD_flags(algo);
  return ika_integer_from_ulong(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_md_pkey_type (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_PKEY_TYPE
  const EVP_MD *	algo = IK_EVP_MD(s_algo);
  int			rv;
  rv = EVP_MD_pkey_type(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP message digest functions C wrappers: miscellaneous functions.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_digest (ikptr s_buf, ikptr s_buf_len, ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGEST
  const void *		buf	= IK_GENERALISED_C_BUFFER(s_buf);
  size_t		buf_len	= ik_generalised_c_buffer_len(s_buf, s_buf_len);
  const EVP_MD *	algo	= IK_EVP_MD(s_algo);
  unsigned char		md_buf[EVP_MAX_MD_SIZE];
  unsigned int		md_len=EVP_MAX_MD_SIZE;
  int			rv;
  rv = EVP_Digest(buf, buf_len, md_buf, &md_len, algo, NULL);
  return (rv)? ika_bytevector_from_memory_block(pcb, md_buf, md_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_get_digestbyname (ikptr s_name_string, ikpcb * pcb)
{
#ifdef HAVE_EVP_GET_DIGESTBYNAME
  const char *		name = IK_GENERALISED_C_BUFFER(s_name_string);
  const EVP_MD *	rv;
  /* fprintf(stderr, "%s: %s\n", __func__, name); */
  rv = EVP_get_digestbyname(name);
  /* fprintf(stderr, "%s: %p\n", __func__, (void*)rv); */
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}

/* end of file */
