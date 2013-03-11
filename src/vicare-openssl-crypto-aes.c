/*
  Part of: Vicare/OpenSSL
  Contents: wrapper functions for AES
  Date: Mon Mar 11, 2013

  Abstract



  Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>

  This program is  free software: you can redistribute  it and/or modify
  it under the  terms of the GNU General Public  License as published by
  the Free Software Foundation, either version  3 of the License, or (at
  your option) any later version.

  This program  is distributed in the  hope that it will  be useful, but
  WITHOUT   ANY  WARRANTY;   without  even   the  implied   warranty  of
  MERCHANTABILITY  or FITNESS  FOR A  PARTICULAR PURPOSE.   See the  GNU
  General Public License for more details.

  You should  have received  a copy  of the  GNU General  Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


/** --------------------------------------------------------------------
 ** Headers.
 ** ----------------------------------------------------------------- */

#include "vicare-openssl-internals.h"


/** --------------------------------------------------------------------
 ** Helpers.
 ** ----------------------------------------------------------------- */

static size_t
generalised_c_buffer_len (ikptr s_buffer, ikptr s_buffer_len)
{
  if (IK_IS_POINTER(s_buffer)) {
    return ik_integer_to_size_t(s_buffer_len);
  } else if (IK_IS_BYTEVECTOR(s_buffer)) {
    return IK_BYTEVECTOR_LENGTH(s_buffer);
  } else { /* it is a memory-block */
    return IK_MBLOCK_SIZE(s_buffer);
  }
}


/** --------------------------------------------------------------------
 ** AES C wrappers: miscellaneous functions.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_aes_options (ikpcb * pcb)
{
#ifdef HAVE_AES_OPTIONS
  const char *	rv;
  rv = AES_options();
  return (rv)? ika_bytevector_from_cstring(pcb, rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** AES C wrappers: encryption key.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_aes_set_encrypt_key (ikptr s_key, ikptr s_bits, ikpcb * pcb)
{
#ifdef HAVE_AES_SET_ENCRYPT_KEY
  const void *	key	= IK_GENERALISED_C_STRING(s_key);
  int		bits	= ik_integer_to_int(s_bits);
  AES_KEY *	ctx;
  int		rv;
  ctx = malloc(sizeof(MD4_CTX));
  if (ctx) {
    rv = AES_set_encrypt_key(key, bits, ctx);
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
ikrt_aes_set_decrypt_key (ikptr s_key, ikptr s_bits, ikpcb * pcb)
{
#ifdef HAVE_AES_SET_DECRYPT_KEY
  const void *	key	= IK_GENERALISED_C_STRING(s_key);
  int		bits	= ik_integer_to_int(s_bits);
  AES_KEY *	ctx;
  int		rv;
  ctx = malloc(sizeof(MD4_CTX));
  if (ctx) {
    rv = AES_set_decrypt_key(key, bits, ctx);
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

/* ------------------------------------------------------------------ */

ikptr
ikrt_aes_finalise (ikptr s_ctx, ikpcb * pcb)
/* This is not an OpenSSL function. */
{
  ikptr		s_pointer	= IK_AES_CTX_POINTER(s_ctx);
  AES_KEY *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  if (ctx) {
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return IK_VOID;
}


ikptr
ikrt_aes_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_ENCRYPT
  /* rv = AES_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_decrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_DECRYPT
  /* rv = AES_decrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_ecb_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_ECB_ENCRYPT
  /* rv = AES_ecb_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_cbc_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_CBC_ENCRYPT
  /* rv = AES_cbc_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_cfb128_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_CFB128_ENCRYPT
  /* rv = AES_cfb128_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_cfb1_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_CFB1_ENCRYPT
  /* rv = AES_cfb1_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_cfb8_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_CFB8_ENCRYPT
  /* rv = AES_cfb8_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_ofb128_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_OFB128_ENCRYPT
  /* rv = AES_ofb128_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_ctr128_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_CTR128_ENCRYPT
  /* rv = AES_ctr128_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_ige_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_IGE_ENCRYPT
  /* rv = AES_ige_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_bi_ige_encrypt (ikpcb * pcb)
{
#ifdef HAVE_AES_BI_IGE_ENCRYPT
  /* rv = AES_bi_ige_encrypt(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_wrap_key (ikpcb * pcb)
{
#ifdef HAVE_AES_WRAP_KEY
  /* rv = AES_wrap_key(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_unwrap_key (ikpcb * pcb)
{
#ifdef HAVE_AES_UNWRAP_KEY
  /* rv = AES_unwrap_key(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}




/* end of file */
