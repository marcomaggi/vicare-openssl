/*
  Part of: Vicare/OpenSSL
  Contents: Openssl for Vicare
  Date: Wed Mar 13, 2013

  Abstract

	EVP hash functions.

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
 ** EVP hash functions C wrappers.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_evp_md_type (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_TYPE
  /* rv = EVP_MD_type(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_nid (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_NID
  /* rv = EVP_MD_nid(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_name (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_NAME
  /* rv = EVP_MD_name(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_pkey_type (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_PKEY_TYPE
  /* rv = EVP_MD_pkey_type(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_SIZE
  /* rv = EVP_MD_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_block_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_BLOCK_SIZE
  /* rv = EVP_MD_block_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_FLAGS
  /* rv = EVP_MD_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_md (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_MD
  /* rv = EVP_MD_CTX_md(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_SIZE
  /* rv = EVP_MD_CTX_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_block_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_BLOCK_SIZE
  /* rv = EVP_MD_CTX_block_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_type (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_TYPE
  /* rv = EVP_MD_CTX_type(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_init (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_INIT
  /* rv = EVP_MD_CTX_init(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_cleanup (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_CLEANUP
  /* rv = EVP_MD_CTX_cleanup(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_create (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_CREATE
  /* rv = EVP_MD_CTX_create(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_destroy (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_DESTROY
  /* rv = EVP_MD_CTX_destroy(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_copy_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_COPY_EX
  /* rv = EVP_MD_CTX_copy_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_set_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_SET_FLAGS
  /* rv = EVP_MD_CTX_set_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_clear_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_CLEAR_FLAGS
  /* rv = EVP_MD_CTX_clear_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_test_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_TEST_FLAGS
  /* rv = EVP_MD_CTX_test_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_digestinit_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTINIT_EX
  /* rv = EVP_DigestInit_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_digestupdate (ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTUPDATE
  /* rv = EVP_DigestUpdate(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_digestfinal_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTFINAL_EX
  /* rv = EVP_DigestFinal_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_digest (ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGEST
  /* rv = EVP_Digest(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_ctx_copy (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_CTX_COPY
  /* rv = EVP_MD_CTX_copy(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_digestinit (ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTINIT
  /* rv = EVP_DigestInit(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_digestfinal (ikpcb * pcb)
{
#ifdef HAVE_EVP_DIGESTFINAL
  /* rv = EVP_DigestFinal(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md_null (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD_NULL
  /* rv = EVP_md_null(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md2 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD2
  /* rv = EVP_md2(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md4 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD4
  /* rv = EVP_md4(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_md5 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MD5
  /* rv = EVP_md5(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_sha (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA
  /* rv = EVP_sha(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_sha1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA1
  /* rv = EVP_sha1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_dss (ikpcb * pcb)
{
#ifdef HAVE_EVP_DSS
  /* rv = EVP_dss(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_dss1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DSS1
  /* rv = EVP_dss1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_ecdsa (ikpcb * pcb)
{
#ifdef HAVE_EVP_ECDSA
  /* rv = EVP_ecdsa(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_sha224 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA224
  /* rv = EVP_sha224(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_sha256 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA256
  /* rv = EVP_sha256(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_sha384 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA384
  /* rv = EVP_sha384(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_sha512 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SHA512
  /* rv = EVP_sha512(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_mdc2 (ikpcb * pcb)
{
#ifdef HAVE_EVP_MDC2
  /* rv = EVP_mdc2(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_ripemd160 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RIPEMD160
  /* rv = EVP_ripemd160(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_whirlpool (ikpcb * pcb)
{
#ifdef HAVE_EVP_WHIRLPOOL
  /* rv = EVP_whirlpool(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_get_digestbyname (ikpcb * pcb)
{
#ifdef HAVE_EVP_GET_DIGESTBYNAME
  /* rv = EVP_get_digestbyname(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}

/* end of file */
