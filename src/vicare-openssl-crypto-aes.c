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
 ** AES C wrappers: encryption and decryption keys.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_aes_set_encrypt_key (ikptr s_key, ikptr s_key_len, ikpcb * pcb)
{
#ifdef HAVE_AES_SET_ENCRYPT_KEY
  const void *	key	= IK_GENERALISED_C_STRING(s_key);
  size_t	key_len	= ik_generalised_c_buffer_len(s_key, s_key_len);
  AES_KEY *	ctx;
  int		rv, bits;
  /* The  argument "bits"  requested  by the  OpenSSL  functions is  the
     length of  the key measured  in bits;  valid values are:  128, 192,
     256.  Measured in octets: 16, 24, 32. */
  switch (key_len) {
  case 16:	bits = 128;	break;
  case 24:	bits = 192;	break;
  case 32:	bits = 256;	break;
  default:
    return IK_FALSE;
  }
  ctx = malloc(sizeof(AES_KEY));
  if (ctx) {
    rv = AES_set_encrypt_key(key, bits, ctx);
    /* The return value "rv" is: 0 if  success, -1 if "key" or "ctx" are
       NULL pointers, -2 if "bits" is  not a correct key length measured
       in bits. */
    if (0 == rv)
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
ikrt_aes_set_decrypt_key (ikptr s_key, ikptr s_key_len, ikpcb * pcb)
{
#ifdef HAVE_AES_SET_DECRYPT_KEY
  const void *	key	= IK_GENERALISED_C_STRING(s_key);
  size_t	key_len	= ik_generalised_c_buffer_len(s_key, s_key_len);
  AES_KEY *	ctx;
  int		rv, bits;
  /* The  argument "bits"  requested  by the  OpenSSL  functions is  the
     length of  the key measured  in bits;  valid values are:  128, 192,
     256.  Measured in octets: 16, 24, 32. */
  switch (key_len) {
  case 16:	bits = 128;	break;
  case 24:	bits = 192;	break;
  case 32:	bits = 256;	break;
  default:
    return IK_FALSE;
  }
  ctx = malloc(sizeof(AES_KEY));
  if (ctx) {
    rv = AES_set_decrypt_key(key, bits, ctx);
    /* The return value "rv" is: 0 if  success, -1 if "key" or "ctx" are
       NULL pointers, -2 if "bits" is  not a correct key length measured
       in bits. */
    if (0 == rv)
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
/* This is not an OpenSSL  function.  It is introduced by Vicare/OpenSSL
   to allow clean finalisation of AES context structures. */
{
  ikptr		s_pointer	= IK_AES_KEY_POINTER(s_ctx);
  AES_KEY *	ctx		= IK_POINTER_DATA_VOIDP(s_pointer);
  if (ctx) {
    free(ctx);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return IK_VOID;
}


/** --------------------------------------------------------------------
 ** AES C wrappers: default encryption and decryption scheme.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_aes_encrypt (ikptr s_single_block_in, ikptr s_single_block_ou,
		  ikptr s_ctx, ikpcb * pcb)
/* Encrypt a single block of data using the default scheme. */
{
#ifdef HAVE_AES_ENCRYPT
  const unsigned char *	in  = IK_GENERALISED_C_BUFFER(s_single_block_in);
  unsigned char *	ou  = IK_GENERALISED_C_BUFFER(s_single_block_ou);
  const AES_KEY *	ctx = IK_AES_KEY(s_ctx);
  AES_encrypt(in, ou, ctx);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_decrypt (ikptr s_single_block_in, ikptr s_single_block_ou,
		  ikptr s_ctx, ikpcb * pcb)
/* Decrypt a single block of data using the default scheme. */
{
#ifdef HAVE_AES_DECRYPT
  const unsigned char *	in  = IK_GENERALISED_C_BUFFER(s_single_block_in);
  unsigned char *	ou  = IK_GENERALISED_C_BUFFER(s_single_block_ou);
  const AES_KEY *	ctx = IK_AES_KEY(s_ctx);
  AES_decrypt(in, ou, ctx);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** AES C wrappers: miscellaneous schemes.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_aes_ecb_encrypt (ikptr s_single_block_in, ikptr s_single_block_ou,
		      ikptr s_ctx, ikptr s_encrypt_or_decrypt, ikpcb * pcb)
/* Encrypt  or decrypt  a single  block of  data using  the ECB  scheme.
   S_ENCRYPT_OR_DECRYPT must be an exact integer representing one of the
   constants AES_ENCRYPT and AES_DECRYPT. */
{
#ifdef HAVE_AES_ECB_ENCRYPT
  const unsigned char *	in  = IK_GENERALISED_C_BUFFER(s_single_block_in);
  unsigned char *	ou  = IK_GENERALISED_C_BUFFER(s_single_block_ou);
  const AES_KEY *	ctx = IK_AES_KEY(s_ctx);
  int			enc = ik_integer_to_int(s_encrypt_or_decrypt);
  AES_ecb_encrypt(in, ou, ctx, enc);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_aes_cbc_encrypt (ikptr s_in, ikptr s_in_len,
		      ikptr s_ou, ikptr s_ou_len,
		      ikptr s_ctx,
		      ikptr s_iv, ikptr s_iv_len,
		      ikptr s_encrypt_or_decrypt, ikpcb * pcb)
/* Encrypt  or decrypt  multiple blocks  of data  using the  ECB scheme.
   S_ENCRYPT_OR_DECRYPT must be an exact integer representing one of the
   constants AES_ENCRYPT and AES_DECRYPT.

   S_IN is a generalised C buffer holding input data.  It length must be
   an exact multiple of AES_BLOCK_SIZE.

   S_OU is a generalised C buffer  to be filled with encrypted data; its
   length must equal the length of S_IN.

   S_IV is a generalised C  buffer holding the initialisation vector for
   the   CBC  encryption   scheme.   Its   length  must   be  equal   to
   AES_BLOCK_SIZE. */
{
#ifdef HAVE_AES_CBC_ENCRYPT
  const unsigned char *	in	= IK_GENERALISED_C_BUFFER(s_in);
  size_t		in_len	= ik_generalised_c_buffer_len(s_in, s_in_len);
  unsigned char *	ou	= IK_GENERALISED_C_BUFFER(s_ou);
  size_t		ou_len	= ik_generalised_c_buffer_len(s_ou, s_ou_len);
  const AES_KEY *	key	= IK_AES_KEY(s_ctx);
  unsigned char *	iv_ptr	= IK_GENERALISED_C_BUFFER(s_iv);
  size_t		iv_len	= ik_generalised_c_buffer_len(s_iv, s_iv_len);
  int			enc	= ik_integer_to_int(s_encrypt_or_decrypt);
  /* NOTE  The function  AES_cbc_encrypt() overwrites  the given  buffer
     holding  the initialisation  vector!!!  (Marco  Maggi; Tue  Mar 12,
     2013) */
  unsigned char		iv[AES_BLOCK_SIZE];
  assert(0 == (in_len % AES_BLOCK_SIZE));
  assert(in_len == ou_len);
  assert(AES_BLOCK_SIZE == iv_len);
  assert((AES_ENCRYPT == enc) || (AES_DECRYPT == enc));
  memcpy(iv, iv_ptr, AES_BLOCK_SIZE);
  AES_cbc_encrypt(in, ou, in_len, key, iv, enc);
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
