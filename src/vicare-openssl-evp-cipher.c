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
ikrt_evp_enc_null (ikpcb * pcb)
{
#ifdef HAVE_EVP_ENC_NULL
  /* rv = EVP_enc_null(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_ECB
  /* rv = EVP_des_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE
  /* rv = EVP_des_ede(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3
  /* rv = EVP_des_ede3(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE_ECB
  /* rv = EVP_des_ede_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_ECB
  /* rv = EVP_des_ede3_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_CFB64
  /* rv = EVP_des_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_CFB
  /* rv = EVP_des_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB64
  /* rv = EVP_des_ede3_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB
  /* rv = EVP_des_ede3_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB1
  /* rv = EVP_des_ede3_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CFB8
  /* rv = EVP_des_ede3_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_OFB
  /* rv = EVP_des_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE_OFB
  /* rv = EVP_des_ede_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_OFB
  /* rv = EVP_des_ede3_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_CBC
  /* rv = EVP_des_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE_CBC
  /* rv = EVP_des_ede_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_des_ede3_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DES_EDE3_CBC
  /* rv = EVP_des_ede3_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_desx_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_DESX_CBC
  /* rv = EVP_desx_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc4 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC4
  /* rv = EVP_rc4(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc4_40 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC4_40
  /* rv = EVP_rc4_40(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc4_hmac_md5 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC4_HMAC_MD5
  /* rv = EVP_rc4_hmac_md5(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_idea_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_ECB
  /* rv = EVP_idea_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_idea_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_CFB64
  /* rv = EVP_idea_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_idea_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_CFB
  /* rv = EVP_idea_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_idea_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_OFB
  /* rv = EVP_idea_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_idea_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_IDEA_CBC
  /* rv = EVP_idea_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_ECB
  /* rv = EVP_rc2_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_CBC
  /* rv = EVP_rc2_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_40_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_40_CBC
  /* rv = EVP_rc2_40_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_64_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_64_CBC
  /* rv = EVP_rc2_64_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_CFB64
  /* rv = EVP_rc2_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_CFB
  /* rv = EVP_rc2_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc2_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC2_OFB
  /* rv = EVP_rc2_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_bf_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_ECB
  /* rv = EVP_bf_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_bf_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_CBC
  /* rv = EVP_bf_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_bf_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_CFB64
  /* rv = EVP_bf_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_bf_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_CFB
  /* rv = EVP_bf_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_bf_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_BF_OFB
  /* rv = EVP_bf_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cast5_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_ECB
  /* rv = EVP_cast5_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cast5_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_CBC
  /* rv = EVP_cast5_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cast5_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_CFB64
  /* rv = EVP_cast5_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cast5_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_CFB
  /* rv = EVP_cast5_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cast5_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAST5_OFB
  /* rv = EVP_cast5_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc5_32_12_16_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_CBC
  /* rv = EVP_rc5_32_12_16_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc5_32_12_16_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_ECB
  /* rv = EVP_rc5_32_12_16_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc5_32_12_16_cfb64 (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_CFB64
  /* rv = EVP_rc5_32_12_16_cfb64(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc5_32_12_16_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_CFB
  /* rv = EVP_rc5_32_12_16_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_rc5_32_12_16_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_RC5_32_12_16_OFB
  /* rv = EVP_rc5_32_12_16_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_ECB
  /* rv = EVP_aes_128_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CBC
  /* rv = EVP_aes_128_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB1
  /* rv = EVP_aes_128_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB8
  /* rv = EVP_aes_128_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB128
  /* rv = EVP_aes_128_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CFB
  /* rv = EVP_aes_128_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_OFB
  /* rv = EVP_aes_128_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_ctr (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CTR
  /* rv = EVP_aes_128_ctr(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_ccm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CCM
  /* rv = EVP_aes_128_ccm(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_gcm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_GCM
  /* rv = EVP_aes_128_gcm(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_xts (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_XTS
  /* rv = EVP_aes_128_xts(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_ECB
  /* rv = EVP_aes_192_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CBC
  /* rv = EVP_aes_192_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB1
  /* rv = EVP_aes_192_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB8
  /* rv = EVP_aes_192_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB128
  /* rv = EVP_aes_192_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CFB
  /* rv = EVP_aes_192_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_OFB
  /* rv = EVP_aes_192_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_ctr (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CTR
  /* rv = EVP_aes_192_ctr(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_ccm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_CCM
  /* rv = EVP_aes_192_ccm(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_192_gcm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_192_GCM
  /* rv = EVP_aes_192_gcm(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_ECB
  /* rv = EVP_aes_256_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CBC
  /* rv = EVP_aes_256_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB1
  /* rv = EVP_aes_256_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB8
  /* rv = EVP_aes_256_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB128
  /* rv = EVP_aes_256_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CFB
  /* rv = EVP_aes_256_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_OFB
  /* rv = EVP_aes_256_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_ctr (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CTR
  /* rv = EVP_aes_256_ctr(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_ccm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CCM
  /* rv = EVP_aes_256_ccm(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_gcm (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_GCM
  /* rv = EVP_aes_256_gcm(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_xts (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_XTS
  /* rv = EVP_aes_256_xts(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_128_cbc_hmac_sha1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_128_CBC_HMAC_SHA1
  /* rv = EVP_aes_128_cbc_hmac_sha1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_aes_256_cbc_hmac_sha1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_AES_256_CBC_HMAC_SHA1
  /* rv = EVP_aes_256_cbc_hmac_sha1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_ECB
  /* rv = EVP_camellia_128_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CBC
  /* rv = EVP_camellia_128_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB1
  /* rv = EVP_camellia_128_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB8
  /* rv = EVP_camellia_128_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB128
  /* rv = EVP_camellia_128_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_CFB
  /* rv = EVP_camellia_128_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_128_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_128_OFB
  /* rv = EVP_camellia_128_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_ECB
  /* rv = EVP_camellia_192_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CBC
  /* rv = EVP_camellia_192_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB1
  /* rv = EVP_camellia_192_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB8
  /* rv = EVP_camellia_192_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB128
  /* rv = EVP_camellia_192_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_CFB
  /* rv = EVP_camellia_192_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_192_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_192_OFB
  /* rv = EVP_camellia_192_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_ECB
  /* rv = EVP_camellia_256_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CBC
  /* rv = EVP_camellia_256_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_cfb1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB1
  /* rv = EVP_camellia_256_cfb1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_cfb8 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB8
  /* rv = EVP_camellia_256_cfb8(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB128
  /* rv = EVP_camellia_256_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_CFB
  /* rv = EVP_camellia_256_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_camellia_256_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_CAMELLIA_256_OFB
  /* rv = EVP_camellia_256_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_seed_ecb (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_ECB
  /* rv = EVP_seed_ecb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_seed_cbc (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_CBC
  /* rv = EVP_seed_cbc(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_seed_cfb128 (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_CFB128
  /* rv = EVP_seed_cfb128(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_seed_cfb (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_CFB
  /* rv = EVP_seed_cfb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_seed_ofb (ikpcb * pcb)
{
#ifdef HAVE_EVP_SEED_OFB
  /* rv = EVP_seed_ofb(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** EVP cipher algorithms C wrappers: unimplemented.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_evp_cipher_type (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_TYPE
  /* rv = EVP_CIPHER_type(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_get_cipherbyname (ikpcb * pcb)
{
#ifdef HAVE_EVP_GET_CIPHERBYNAME
  /* rv = EVP_get_cipherbyname(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_get_cipherbynid (ikpcb * pcb)
{
#ifdef HAVE_EVP_GET_CIPHERBYNID
  /* rv = EVP_get_cipherbynid(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_get_cipherbyobj (ikpcb * pcb)
{
#ifdef HAVE_EVP_GET_CIPHERBYOBJ
  /* rv = EVP_get_cipherbyobj(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_nid (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_NID
  /* rv = EVP_CIPHER_nid(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_name (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_NAME
  /* rv = EVP_CIPHER_name(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_block_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_BLOCK_SIZE
  /* rv = EVP_CIPHER_block_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_key_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_KEY_LENGTH
  /* rv = EVP_CIPHER_key_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_iv_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_IV_LENGTH
  /* rv = EVP_CIPHER_iv_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_FLAGS
  /* rv = EVP_CIPHER_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_mode (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_MODE
  /* rv = EVP_CIPHER_mode(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_init (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_INIT
  /* rv = EVP_CIPHER_CTX_init(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_cleanup (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CLEANUP
  /* rv = EVP_CIPHER_CTX_cleanup(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_new (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_NEW
  /* rv = EVP_CIPHER_CTX_new(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_free (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_FREE
  /* rv = EVP_CIPHER_CTX_free(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_encryptinit_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_ENCRYPTINIT_EX
  /* rv = EVP_EncryptInit_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_encryptfinal_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_ENCRYPTFINAL_EX
  /* rv = EVP_EncryptFinal_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_encryptupdate (ikpcb * pcb)
{
#ifdef HAVE_EVP_ENCRYPTUPDATE
  /* rv = EVP_EncryptUpdate(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_decryptinit_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_DECRYPTINIT_EX
  /* rv = EVP_DecryptInit_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_decryptupdate (ikpcb * pcb)
{
#ifdef HAVE_EVP_DECRYPTUPDATE
  /* rv = EVP_DecryptUpdate(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_decryptfinal_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_DECRYPTFINAL_EX
  /* rv = EVP_DecryptFinal_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipherinit_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHERINIT_EX
  /* rv = EVP_CipherInit_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipherupdate (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHERUPDATE
  /* rv = EVP_CipherUpdate(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipherfinal_ex (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHERFINAL_EX
  /* rv = EVP_CipherFinal_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_set_key_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  /* rv = EVP_CIPHER_CTX_set_key_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_set_padding (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_PADDING
  /* rv = EVP_CIPHER_CTX_set_padding(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_ctrl (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CTRL
  /* rv = EVP_CIPHER_CTX_ctrl(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_cipher (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CIPHER
  /* rv = EVP_CIPHER_CTX_cipher(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_nid (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_NID
  /* rv = EVP_CIPHER_CTX_nid(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_block_size (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_BLOCK_SIZE
  /* rv = EVP_CIPHER_CTX_block_size(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_key_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_KEY_LENGTH
  /* rv = EVP_CIPHER_CTX_key_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_iv_length (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_IV_LENGTH
  /* rv = EVP_CIPHER_CTX_iv_length(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_copy (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_COPY
  /* rv = EVP_CIPHER_CTX_copy(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_get_app_data (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_GET_APP_DATA
  /* rv = EVP_CIPHER_CTX_get_app_data(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_set_app_data (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_APP_DATA
  /* rv = EVP_CIPHER_CTX_set_app_data(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_type (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_TYPE
  /* rv = EVP_CIPHER_CTX_type(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_FLAGS
  /* rv = EVP_CIPHER_CTX_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_mode (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_MODE
  /* rv = EVP_CIPHER_CTX_mode(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_rand_key (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_RAND_KEY
  /* rv = EVP_CIPHER_CTX_rand_key(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_param_to_asn1 (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_PARAM_TO_ASN1
  /* rv = EVP_CIPHER_param_to_asn1(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_asn1_to_param (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_ASN1_TO_PARAM
  /* rv = EVP_CIPHER_asn1_to_param(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_set_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_SET_FLAGS
  /* rv = EVP_CIPHER_CTX_set_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_clear_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_CLEAR_FLAGS
  /* rv = EVP_CIPHER_CTX_clear_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher_ctx_test_flags (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER_CTX_TEST_FLAGS
  /* rv = EVP_CIPHER_CTX_test_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_evp_cipher (ikpcb * pcb)
{
#ifdef HAVE_EVP_CIPHER
  /* rv = EVP_Cipher(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/* end of file */