/*
  Part of: Vicare/OpenSSL
  Contents: C wrappers for cipher functions
  Date: Fri Mar 15, 2013

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
 ** EVP cipher algorithms C wrappers: makers for EVP_CIPHER references.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_enc_null (ikpcb * pcb)
{
#ifdef HAVE_EVP_ENC_NULL
  const EVP_CIPHER *	rv;
  rv = EVP_enc_null();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_des_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_des_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_DES_CFB) && HAVE_DECL_EVP_DES_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_des_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_DES_EDE3_CFB) && HAVE_DECL_EVP_DES_EDE3_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_des_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_des_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_des_ede3_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_des_ede3_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_desx_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DESX_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_desx_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc4 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC4
  const EVP_CIPHER *	rv;
  rv = EVP_rc4();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc4_40 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC4_40
  const EVP_CIPHER *	rv;
  rv = EVP_rc4_40();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc4_hmac_md5 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC4_HMAC_MD5
  const EVP_CIPHER *	rv;
  rv = EVP_rc4_hmac_md5();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_idea_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_idea_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_idea_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_idea_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_idea_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_IDEA_CFB) && HAVE_DECL_EVP_IDEA_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_idea_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_idea_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_idea_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_idea_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_idea_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_40_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_40_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_40_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_64_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_64_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_64_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_RC2_CFB) && HAVE_DECL_EVP_RC2_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc2_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_rc2_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_bf_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_bf_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_bf_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_bf_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_bf_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_bf_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_bf_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_BF_CFB) && HAVE_DECL_EVP_BF_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_bf_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_bf_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_bf_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cast5_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_cast5_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cast5_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_cast5_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cast5_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_cast5_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cast5_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CAST5_CFB) && HAVE_DECL_EVP_CAST5_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_cast5_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cast5_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_cast5_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc5_32_12_16_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_rc5_32_12_16_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc5_32_12_16_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_rc5_32_12_16_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc5_32_12_16_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_CFB64
  const EVP_CIPHER *	rv;
  rv = EVP_rc5_32_12_16_cfb64();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc5_32_12_16_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_RC5_32_12_16_CFB) && HAVE_DECL_EVP_RC5_32_12_16_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_rc5_32_12_16_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_rc5_32_12_16_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_rc5_32_12_16_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_AES_128_CFB) && HAVE_DECL_EVP_AES_128_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_ctr (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CTR
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_ctr();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_ccm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CCM
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_ccm();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_gcm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_GCM
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_gcm();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_xts (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_XTS
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_xts();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_AES_192_CFB) && HAVE_DECL_EVP_AES_192_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_ctr (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CTR
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_ctr();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_ccm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CCM
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_ccm();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_192_gcm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_GCM
  const EVP_CIPHER *	rv;
  rv = EVP_aes_192_gcm();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_AES_256_CFB) && HAVE_DECL_EVP_AES_256_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_ctr (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CTR
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_ctr();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_ccm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CCM
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_ccm();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_gcm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_GCM
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_gcm();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_xts (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_XTS
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_xts();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_128_cbc_hmac_sha1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CBC_HMAC_SHA1
  const EVP_CIPHER *	rv;
  rv = EVP_aes_128_cbc_hmac_sha1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_aes_256_cbc_hmac_sha1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CBC_HMAC_SHA1
  const EVP_CIPHER *	rv;
  rv = EVP_aes_256_cbc_hmac_sha1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CAMELLIA_128_CFB) && HAVE_DECL_EVP_CAMELLIA_128_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_128_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_128_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CAMELLIA_192_CFB) && HAVE_DECL_EVP_CAMELLIA_192_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_192_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_192_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB1
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_cfb1();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB8
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_cfb8();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CAMELLIA_256_CFB) && HAVE_DECL_EVP_CAMELLIA_256_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_camellia_256_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_camellia_256_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_seed_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_ECB
  const EVP_CIPHER *	rv;
  rv = EVP_seed_ecb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_seed_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_CBC
  const EVP_CIPHER *	rv;
  rv = EVP_seed_cbc();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_seed_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_CFB128
  const EVP_CIPHER *	rv;
  rv = EVP_seed_cfb128();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_seed_cfb (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_SEED_CFB) && HAVE_DECL_EVP_SEED_CFB)
  const EVP_CIPHER *	rv;
  rv = EVP_seed_cfb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_seed_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_OFB
  const EVP_CIPHER *	rv;
  rv = EVP_seed_ofb();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: special makers for EVP_CIPHER references.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_get_cipherbyname (ikptr s_name_string, ikpcb * pcb)
{
#ifdef HAVE_EVP_GET_CIPHERBYNAME
  const char *		name = IK_GENERALISED_C_BUFFER(s_name_string);
  const EVP_CIPHER *	rv;
  rv = EVP_get_cipherbyname(name);
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_get_cipherbynid (ikptr s_nid, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_GET_CIPHERBYNID) && HAVE_DECL_EVP_GET_CIPHERBYNID)
  int			nid = ik_integer_to_int(s_nid);
  const EVP_CIPHER *	rv;
  rv = EVP_get_cipherbynid(nid);
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_get_cipherbyobj (ikptr s_obj, ikpcb * pcb)
/* This converts an ASN.1 object to an EVP_CIPHER reference. */
{
#if ((defined HAVE_DECL_EVP_GET_CIPHERBYOBJ) && HAVE_EVP_GET_CIPHERBYOBJ)
  ASN1_OBJECT *		obj = IK_POINTER_DATA_VOIDP(s_obj);
  const EVP_CIPHER *	rv;
  rv = EVP_get_cipherbyobj(obj);
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: cipher algorithm inspection.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher_name (ikptr s_algo, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CIPHER_NAME) && HAVE_DECL_EVP_CIPHER_NAME)
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  const char *	rv;
  rv = EVP_CIPHER_name(algo);
  return (rv)? ika_bytevector_from_cstring(pcb, rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_type (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_TYPE
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_type(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_nid (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_NID
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_nid(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_block_size (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_BLOCK_SIZE
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_block_size(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_key_length (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_KEY_LENGTH
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_key_length(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_iv_length (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_IV_LENGTH
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_iv_length(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_mode (ikptr s_algo, ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CIPHER_MODE) && HAVE_DECL_EVP_CIPHER_MODE)
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_mode(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: cipher algorithm flags.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher_flags (ikptr s_algo, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_FLAGS
  EVP_CIPHER *	algo = IK_EVP_CIPHER(s_algo);
  int		rv;
  rv = EVP_CIPHER_flags(algo);
  return ika_integer_from_int(pcb, rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: context creation and destruction.
 ** ----------------------------------------------------------------- */

/* NOTE  We  prefer "EVP_CIPHER_CTX_new()"  and  "EVP_CIPHER_CTX_free()"
   over "EVP_CIPHER_CTX_init()" and "EVP_CIPHER_CTX_cleanup()".

   Internally  "EVP_CIPHER_CTX_new()" allocates  a new  "EVP_CIPHER_CTX"
   with "malloc()" and initialises it with "EVP_CIPHER_CTX_init()".

   Internally "EVP_CIPHER_CTX_free()" finalises  a "EVP_CIPHER_CTX" with
   "EVP_CIPHER_CTX_cleanup()" the releases the memory with "free()". */

ikptr
ikrt_openssl_evp_cipher_ctx_new (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_NEW
  EVP_CIPHER_CTX *	ctx;
  ctx = EVP_CIPHER_CTX_new();
  return (ctx)? ika_pointer_alloc(pcb, (long)ctx) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_free (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_FREE
  EVP_CIPHER_CTX *	ctx = IK_EVP_CIPHER_CTX(s_ctx);
  EVP_CIPHER_CTX_free(ctx);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_copy (ikptr s_dst_ctx, ikptr s_src_ctx, ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_COPY
  EVP_CIPHER_CTX *	dst = IK_EVP_CIPHER_CTX(s_dst_ctx);
  EVP_CIPHER_CTX *	src = IK_EVP_CIPHER_CTX(s_src_ctx);
  int			rv;
  rv = EVP_CIPHER_CTX_copy(dst, src);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: context init and final.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_minimum_output_length (ikptr s_ctx, ikptr s_in, ikptr s_in_len, ikpcb * pcb)
/* Compute the  minimum number  of bytes  needed to  hold the  result of
   encrypting or  decrypting the  given generalised C  buffer.

   Validate the input  to avoid overflow of integers:  OpenSSL wants the
   number of bytes to be stored in "int" locations; Vicare/OpenSSL wants
   both  the input  and output  data to  be containable  in bytevectors,
   which at most have GREATEST-FIXNUM bytes. */
{
  EVP_CIPHER_CTX *	ctx        = IK_EVP_CIPHER_CTX(s_ctx);
  size_t		in_len     = ik_generalised_c_buffer_len(s_in, s_in_len);
  int			block_size = EVP_CIPHER_CTX_block_size(ctx);
  if ((IK_GREATEST_FIXNUM - in_len < block_size) ||
      (INT_MAX            - in_len < block_size))
    return IK_FALSE;
  else
    return ika_integer_from_size_t(pcb, in_len + block_size);
}
static int
validate_output_buffer_length (EVP_CIPHER_CTX * ctx, size_t in_len, size_t ou_len)
/* Avoid  overflow of  integers and  "not enough  output space"  errors.
   Return true if there is an error in the arguments. */
{
  int		block_size = EVP_CIPHER_CTX_block_size(ctx);
  return ((IK_GREATEST_FIXNUM - in_len < block_size) ||
	  (INT_MAX            - in_len < block_size) ||
	  (ou_len                      < in_len + block_size));
}

/* ------------------------------------------------------------------ */

ikptr
ikrt_openssl_evp_encryptinit_ex (ikptr s_ctx, ikptr s_algo, ikptr s_key, ikptr s_iv,
				 ikpcb * pcb)
{
#ifdef HAVE_EVP_ENCRYPTINIT_EX
  EVP_CIPHER_CTX *	ctx    = IK_EVP_CIPHER_CTX(s_ctx);
  const EVP_CIPHER *	algo   = IK_EVP_CIPHER(s_algo);
  ENGINE *		engine = NULL;
  unsigned char *	key    = IK_GENERALISED_C_BUFFER_OR_FALSE(s_key);
  unsigned char *	iv     = IK_GENERALISED_C_BUFFER_OR_FALSE(s_iv);
  int			rv;
  rv = EVP_EncryptInit_ex(ctx, algo, engine, key, iv);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_encryptfinal_ex (ikptr s_ctx, ikpcb * pcb)
/* NOTE When finalising a context: the output data is at most equal to a
   cipher's block size.   Block sizes are "small", so we  put the output
   buffer on the stack.  (Marco Maggi; Wed Mar 20, 2013) */
{
#ifdef HAVE_EVP_ENCRYPTFINAL_EX
  EVP_CIPHER_CTX *	ctx = IK_EVP_CIPHER_CTX(s_ctx);
  unsigned char		ou[EVP_CIPHER_CTX_block_size(ctx)];
  int			ou_len;
  int			rv;
  rv = EVP_EncryptFinal_ex(ctx, ou, &ou_len);
  return (rv)? ika_bytevector_from_memory_block(pcb, ou, ou_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_encryptupdate (ikptr s_ctx,
				ikptr s_ou, ikptr s_ou_len,
				ikptr s_in, ikptr s_in_len,
				ikpcb * pcb)
{
#ifdef HAVE_EVP_ENCRYPTUPDATE
  EVP_CIPHER_CTX *	ctx	= IK_EVP_CIPHER_CTX(s_ctx);
  unsigned char *	ou	= IK_GENERALISED_C_BUFFER(s_ou);
  size_t		ou_len	= ik_generalised_c_buffer_len(s_ou, s_ou_len);
  unsigned char *	in	= IK_GENERALISED_C_BUFFER(s_in);
  size_t		in_len	= ik_generalised_c_buffer_len(s_in, s_in_len);
  int			rv;
  /* Avoid overflow of integers and "not enough output space" errors. */
  if (validate_output_buffer_length(ctx, in_len, ou_len))
    return IK_FALSE;
  rv = EVP_EncryptUpdate(ctx, ou, (int*)&ou_len, in, in_len);
  return (rv)? ika_integer_from_size_t(pcb, ou_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}

/* ------------------------------------------------------------------ */

ikptr
ikrt_openssl_evp_decryptinit_ex (ikptr s_ctx, ikptr s_algo, ikptr s_key, ikptr s_iv,
				 ikpcb * pcb)
{
#ifdef HAVE_EVP_DECRYPTINIT_EX
  EVP_CIPHER_CTX *	ctx    = IK_EVP_CIPHER_CTX(s_ctx);
  const EVP_CIPHER *	algo   = IK_EVP_CIPHER(s_algo);
  ENGINE *		engine = NULL;
  unsigned char *	key    = IK_GENERALISED_C_BUFFER_OR_FALSE(s_key);
  unsigned char *	iv     = IK_GENERALISED_C_BUFFER_OR_FALSE(s_iv);
  int			rv;
  rv = EVP_DecryptInit_ex(ctx, algo, engine, key, iv);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_decryptfinal_ex (ikptr s_ctx, ikpcb * pcb)
/* NOTE When finalising a context: the output data is at most equal to a
   cipher's block size.   Block sizes are "small", so we  put the output
   buffer on the stack.  (Marco Maggi; Wed Mar 20, 2013) */
{
#ifdef HAVE_EVP_DECRYPTFINAL_EX
  EVP_CIPHER_CTX *	ctx    = IK_EVP_CIPHER_CTX(s_ctx);
  unsigned char		ou[EVP_CIPHER_CTX_block_size(ctx)];
  int			ou_len;
  int			rv;
  rv = EVP_DecryptFinal_ex(ctx, ou, &ou_len);
  return (rv)? ika_bytevector_from_memory_block(pcb, ou, ou_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_decryptupdate (ikptr s_ctx,
				ikptr s_ou, ikptr s_ou_len,
				ikptr s_in, ikptr s_in_len,
				ikpcb * pcb)
{
#ifdef HAVE_EVP_DECRYPTUPDATE
  EVP_CIPHER_CTX *	ctx	= IK_EVP_CIPHER_CTX(s_ctx);
  unsigned char *	ou	= IK_GENERALISED_C_BUFFER(s_ou);
  size_t		ou_len	= ik_generalised_c_buffer_len(s_ou, s_ou_len);
  unsigned char *	in	= IK_GENERALISED_C_BUFFER(s_in);
  size_t		in_len	= ik_generalised_c_buffer_len(s_in, s_in_len);
  int			rv;
  /* Avoid overflow of integers and "not enough output space" errors. */
  if (validate_output_buffer_length(ctx, in_len, ou_len))
    return IK_FALSE;
  rv = EVP_DecryptUpdate(ctx, ou, (int*)&ou_len, in, in_len);
  return (rv)? ika_integer_from_size_t(pcb, ou_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}

/* ------------------------------------------------------------------ */

ikptr
ikrt_openssl_evp_cipherinit_ex (ikptr s_ctx, ikptr s_algo, ikptr s_key, ikptr s_iv,
				ikptr s_encrypt_or_decrypt, ikpcb * pcb)
/* Initialise    for   encryption    or   decryption.     The   argument
   S_ENCRYPT_OR_DECRYPT must  be an exact  integer: 1 for  encryption, 0
   for decryption, -1 to leave unchanged a previously set value. */
{
#ifdef HAVE_EVP_CIPHERINIT_EX
  EVP_CIPHER_CTX *	ctx    = IK_EVP_CIPHER_CTX(s_ctx);
  const EVP_CIPHER *	algo   = IK_EVP_CIPHER(s_algo);
  ENGINE *		engine = NULL;
  unsigned char *	key    = IK_GENERALISED_C_BUFFER_OR_FALSE(s_key);
  unsigned char *	iv     = IK_GENERALISED_C_BUFFER_OR_FALSE(s_iv);
  int			enc    = ik_integer_to_int(s_encrypt_or_decrypt);
  int			rv;
  rv = EVP_CipherInit_ex(ctx, algo, engine, key, iv, enc);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipherfinal_ex (ikptr s_ctx, ikpcb * pcb)
/* NOTE When finalising a context: the output data is at most equal to a
   cipher's block size.   Block sizes are "small", so we  put the output
   buffer on the stack.  (Marco Maggi; Wed Mar 20, 2013) */
{
#ifdef HAVE_EVP_CIPHERFINAL_EX
  EVP_CIPHER_CTX *	ctx    = IK_EVP_CIPHER_CTX(s_ctx);
  unsigned char		ou[EVP_CIPHER_CTX_block_size(ctx)];
  int			ou_len;
  int			rv;
  rv = EVP_CipherFinal_ex(ctx, ou, &ou_len);
  return (rv)? ika_bytevector_from_memory_block(pcb, ou, ou_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipherupdate (ikptr s_ctx,
			       ikptr s_ou, ikptr s_ou_len,
			       ikptr s_in, ikptr s_in_len,
			       ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHERUPDATE
  EVP_CIPHER_CTX *	ctx	= IK_EVP_CIPHER_CTX(s_ctx);
  unsigned char *	ou	= IK_GENERALISED_C_BUFFER(s_ou);
  size_t		ou_len	= ik_generalised_c_buffer_len(s_ou, s_ou_len);
  unsigned char *	in	= IK_GENERALISED_C_BUFFER(s_in);
  size_t		in_len	= ik_generalised_c_buffer_len(s_in, s_in_len);
  int			rv;
  /* Avoid overflow of integers and "not enough output space" errors. */
  if (validate_output_buffer_length(ctx, in_len, ou_len))
    return IK_FALSE;
  rv = EVP_CipherUpdate(ctx, ou, (int*)&ou_len, in, in_len);
  return (rv)? ika_integer_from_size_t(pcb, ou_len) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: context flags.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher_ctx_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_FLAGS
  /* rv = EVP_CIPHER_CTX_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_set_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_FLAGS
  /* rv = EVP_CIPHER_CTX_set_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_clear_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CLEAR_FLAGS
  /* rv = EVP_CIPHER_CTX_clear_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_test_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_TEST_FLAGS
  /* rv = EVP_CIPHER_CTX_test_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: context application data.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher_ctx_get_app_data (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_GET_APP_DATA
  /* rv = EVP_CIPHER_CTX_get_app_data(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_set_app_data (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_APP_DATA
  /* rv = EVP_CIPHER_CTX_set_app_data(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: context inspection.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher_ctx_set_key_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  /* rv = EVP_CIPHER_CTX_set_key_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_set_padding (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_PADDING
  /* rv = EVP_CIPHER_CTX_set_padding(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_ctrl (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CTRL
  /* rv = EVP_CIPHER_CTX_ctrl(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_cipher (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CIPHER
  /* rv = EVP_CIPHER_CTX_cipher(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_nid (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_NID
  /* rv = EVP_CIPHER_CTX_nid(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_block_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_BLOCK_SIZE
  /* rv = EVP_CIPHER_CTX_block_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_key_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_KEY_LENGTH
  /* rv = EVP_CIPHER_CTX_key_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_iv_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_IV_LENGTH
  /* rv = EVP_CIPHER_CTX_iv_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_type (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CIPHER_CTX_TYPE) && HAVE_DECL_EVP_CIPHER_CTX_TYPE)
  /* rv = EVP_CIPHER_CTX_type(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_mode (ikpcb * pcb)
{
#if ((defined HAVE_DECL_EVP_CIPHER_CTX_MODE) && HAVE_DECL_EVP_CIPHER_CTX_MODE)
  /* rv = EVP_CIPHER_CTX_mode(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_ctx_rand_key (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_RAND_KEY
  /* rv = EVP_CIPHER_CTX_rand_key(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: context to/from ASN.1 objects.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher_param_to_asn1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_PARAM_TO_ASN1
  /* rv = EVP_CIPHER_param_to_asn1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_evp_cipher_asn1_to_param (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_ASN1_TO_PARAM
  /* rv = EVP_CIPHER_asn1_to_param(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: one-step encription and decryption.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_evp_cipher (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER
  /* rv = EVP_Cipher(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}

/* end of file */
