/*
  Part of: Vicare/OpenSSL
  Contents: print platform features library
  Date: Sat Mar  9, 2013

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


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>


int
main (int argc, const char *const argv[])
{
  printf(";;; -*- coding: utf-8-unix -*-\n\
;;;\n\
;;;Part of: Vicare/OpenSSL\n\
;;;Contents: static platform inspection\n\
;;;Date: Sat Mar  9, 2013\n\
;;;\n\
;;;Abstract\n\
;;;\n\
;;;\n\
;;;\n\
;;;Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>\n\
;;;\n\
;;;This program is free software:  you can redistribute it and/or modify\n\
;;;it under the terms of the  GNU General Public License as published by\n\
;;;the Free Software Foundation, either version 3 of the License, or (at\n\
;;;your option) any later version.\n\
;;;\n\
;;;This program is  distributed in the hope that it  will be useful, but\n\
;;;WITHOUT  ANY   WARRANTY;  without   even  the  implied   warranty  of\n\
;;;MERCHANTABILITY or  FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU\n\
;;;General Public License for more details.\n\
;;;\n\
;;;You should  have received a  copy of  the GNU General  Public License\n\
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\
;;;\n\
\n\
\n\
#!r6rs\n\
(library (vicare crypto openssl features)\n\
  (export\n\
    ;; Library initialisation features\n\
    HAVE_SSL_LIBRARY_INIT\n\
    HAVE_OPENSSL_ADD_ALL_ALGORITHMS_NOCONF\n\
    HAVE_OPENSSL_ADD_ALL_ALGORITHMS_CONF\n\
    HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS\n\
    HAVE_OPENSSL_ADD_ALL_CIPHERS\n\
    HAVE_OPENSSL_ADD_ALL_DIGESTS\n\
    HAVE_DECL_SSLEAY_ADD_ALL_ALGORITHMS\n\
    HAVE_DECL_SSLEAY_ADD_ALL_CIPHERS\n\
    HAVE_DECL_SSLEAY_ADD_ALL_DIGESTS\n\
    \n\
    HAVE_MD4_INIT\n\
    HAVE_MD4_UPDATE\n\
    HAVE_MD4_FINAL\n\
    HAVE_MD4\n\
    \n\
    HAVE_MD5_INIT\n\
    HAVE_MD5_UPDATE\n\
    HAVE_MD5_FINAL\n\
    HAVE_MD5\n\
    \n\
    ;; MDC2 features\n\
    HAVE_MDC2_INIT\n\
    HAVE_MDC2_UPDATE\n\
    HAVE_MDC2_FINAL\n\
    HAVE_MDC2\n\
    \n\
    ;; SHA 1 features\n\
    HAVE_SHA1_INIT\n\
    HAVE_SHA1_UPDATE\n\
    HAVE_SHA1_FINAL\n\
    HAVE_SHA1\n\
    \n\
    ;; SHA 224 features\n\
    HAVE_SHA224_INIT\n\
    HAVE_SHA224_UPDATE\n\
    HAVE_SHA224_FINAL\n\
    HAVE_SHA224\n\
    \n\
    ;; SHA 256 features\n\
    HAVE_SHA256_INIT\n\
    HAVE_SHA256_UPDATE\n\
    HAVE_SHA256_FINAL\n\
    HAVE_SHA256\n\
    \n\
    ;; SHA 384 features\n\
    HAVE_SHA384_INIT\n\
    HAVE_SHA384_UPDATE\n\
    HAVE_SHA384_FINAL\n\
    HAVE_SHA384\n\
    \n\
    ;; SHA 512 features\n\
    HAVE_SHA512_INIT\n\
    HAVE_SHA512_UPDATE\n\
    HAVE_SHA512_FINAL\n\
    HAVE_SHA512\n\
    \n\
    HAVE_RIPEMD160_INIT\n\
    HAVE_RIPEMD160_UPDATE\n\
    HAVE_RIPEMD160_FINAL\n\
    HAVE_RIPEMD160\n\
    \n\
    HAVE_WHIRLPOOL_INIT\n\
    HAVE_WHIRLPOOL_UPDATE\n\
    HAVE_WHIRLPOOL_FINAL\n\
    HAVE_WHIRLPOOL\n\
    \n\
    ;; HMAC features\n\
    HAVE_HMAC\n\
    HAVE_HMAC_CTX_INIT\n\
    HAVE_HMAC_CTX_CLEANUP\n\
    HAVE_HMAC_INIT\n\
    HAVE_HMAC_INIT_EX\n\
    HAVE_HMAC_UPDATE\n\
    HAVE_HMAC_FINAL\n\
    HAVE_HMAC_CTX_COPY\n\
    HAVE_HMAC_CTX_SET_FLAGS\n\
    \n\
    ;; EVP hash functions features\n\
    HAVE_EVP_MD_TYPE\n\
    HAVE_EVP_MD_NID\n\
    HAVE_EVP_MD_NAME\n\
    HAVE_EVP_MD_PKEY_TYPE\n\
    HAVE_EVP_MD_SIZE\n\
    HAVE_EVP_MD_BLOCK_SIZE\n\
    HAVE_EVP_MD_FLAGS\n\
    HAVE_EVP_MD_CTX_MD\n\
    HAVE_EVP_MD_CTX_SIZE\n\
    HAVE_EVP_MD_CTX_BLOCK_SIZE\n\
    HAVE_EVP_MD_CTX_TYPE\n\
    HAVE_EVP_MD_CTX_INIT\n\
    HAVE_EVP_MD_CTX_CLEANUP\n\
    HAVE_EVP_MD_CTX_CREATE\n\
    HAVE_EVP_MD_CTX_DESTROY\n\
    HAVE_EVP_MD_CTX_COPY_EX\n\
    HAVE_EVP_MD_CTX_SET_FLAGS\n\
    HAVE_EVP_MD_CTX_CLEAR_FLAGS\n\
    HAVE_EVP_MD_CTX_TEST_FLAGS\n\
    HAVE_EVP_DIGESTINIT_EX\n\
    HAVE_EVP_DIGESTUPDATE\n\
    HAVE_EVP_DIGESTFINAL_EX\n\
    HAVE_EVP_DIGEST\n\
    HAVE_EVP_MD_CTX_COPY\n\
    HAVE_EVP_DIGESTINIT\n\
    HAVE_EVP_DIGESTFINAL\n\
    HAVE_EVP_MD_NULL\n\
    HAVE_EVP_MD2\n\
    HAVE_EVP_MD4\n\
    HAVE_EVP_MD5\n\
    HAVE_EVP_SHA\n\
    HAVE_EVP_SHA1\n\
    HAVE_EVP_DSS\n\
    HAVE_EVP_DSS1\n\
    HAVE_EVP_ECDSA\n\
    HAVE_EVP_SHA224\n\
    HAVE_EVP_SHA256\n\
    HAVE_EVP_SHA384\n\
    HAVE_EVP_SHA512\n\
    HAVE_EVP_MDC2\n\
    HAVE_EVP_RIPEMD160\n\
    HAVE_EVP_WHIRLPOOL\n\
    HAVE_EVP_GET_DIGESTBYNAME\n\
    \n\
    ;; EVP cipher algorithms features\n\
    HAVE_EVP_ENC_NULL\n\
    HAVE_EVP_DES_ECB\n\
    HAVE_EVP_DES_EDE\n\
    HAVE_EVP_DES_EDE3\n\
    HAVE_EVP_DES_EDE_ECB\n\
    HAVE_EVP_DES_EDE3_ECB\n\
    HAVE_EVP_DES_CFB64\n\
    HAVE_DECL_EVP_DES_CFB\n\
    HAVE_EVP_DES_EDE3_CFB64\n\
    HAVE_DECL_EVP_DES_EDE3_CFB\n\
    HAVE_EVP_DES_EDE3_CFB1\n\
    HAVE_EVP_DES_EDE3_CFB8\n\
    HAVE_EVP_DES_OFB\n\
    HAVE_EVP_DES_EDE_OFB\n\
    HAVE_EVP_DES_EDE3_OFB\n\
    HAVE_EVP_DES_CBC\n\
    HAVE_EVP_DES_EDE_CBC\n\
    HAVE_EVP_DES_EDE3_CBC\n\
    HAVE_EVP_DESX_CBC\n\
    HAVE_EVP_RC4\n\
    HAVE_EVP_RC4_40\n\
    HAVE_EVP_RC4_HMAC_MD5\n\
    HAVE_EVP_IDEA_ECB\n\
    HAVE_EVP_IDEA_CFB64\n\
    HAVE_DECL_EVP_IDEA_CFB\n\
    HAVE_EVP_IDEA_OFB\n\
    HAVE_EVP_IDEA_CBC\n\
    HAVE_EVP_RC2_ECB\n\
    HAVE_EVP_RC2_CBC\n\
    HAVE_EVP_RC2_40_CBC\n\
    HAVE_EVP_RC2_64_CBC\n\
    HAVE_EVP_RC2_CFB64\n\
    HAVE_DECL_EVP_RC2_CFB\n\
    HAVE_EVP_RC2_OFB\n\
    HAVE_EVP_BF_ECB\n\
    HAVE_EVP_BF_CBC\n\
    HAVE_EVP_BF_CFB64\n\
    HAVE_DECL_EVP_BF_CFB\n\
    HAVE_EVP_BF_OFB\n\
    HAVE_EVP_CAST5_ECB\n\
    HAVE_EVP_CAST5_CBC\n\
    HAVE_EVP_CAST5_CFB64\n\
    HAVE_DECL_EVP_CAST5_CFB\n\
    HAVE_EVP_CAST5_OFB\n\
    HAVE_EVP_RC5_32_12_16_CBC\n\
    HAVE_EVP_RC5_32_12_16_ECB\n\
    HAVE_EVP_RC5_32_12_16_CFB64\n\
    HAVE_DECL_EVP_RC5_32_12_16_CFB\n\
    HAVE_EVP_RC5_32_12_16_OFB\n\
    HAVE_EVP_AES_128_ECB\n\
    HAVE_EVP_AES_128_CBC\n\
    HAVE_EVP_AES_128_CFB1\n\
    HAVE_EVP_AES_128_CFB8\n\
    HAVE_EVP_AES_128_CFB128\n\
    HAVE_DECL_EVP_AES_128_CFB\n\
    HAVE_EVP_AES_128_OFB\n\
    HAVE_EVP_AES_128_CTR\n\
    HAVE_EVP_AES_128_CCM\n\
    HAVE_EVP_AES_128_GCM\n\
    HAVE_EVP_AES_128_XTS\n\
    HAVE_EVP_AES_192_ECB\n\
    HAVE_EVP_AES_192_CBC\n\
    HAVE_EVP_AES_192_CFB1\n\
    HAVE_EVP_AES_192_CFB8\n\
    HAVE_EVP_AES_192_CFB128\n\
    HAVE_DECL_EVP_AES_192_CFB\n\
    HAVE_EVP_AES_192_OFB\n\
    HAVE_EVP_AES_192_CTR\n\
    HAVE_EVP_AES_192_CCM\n\
    HAVE_EVP_AES_192_GCM\n\
    HAVE_EVP_AES_256_ECB\n\
    HAVE_EVP_AES_256_CBC\n\
    HAVE_EVP_AES_256_CFB1\n\
    HAVE_EVP_AES_256_CFB8\n\
    HAVE_EVP_AES_256_CFB128\n\
    HAVE_DECL_EVP_AES_256_CFB\n\
    HAVE_EVP_AES_256_OFB\n\
    HAVE_EVP_AES_256_CTR\n\
    HAVE_EVP_AES_256_CCM\n\
    HAVE_EVP_AES_256_GCM\n\
    HAVE_EVP_AES_256_XTS\n\
    HAVE_EVP_AES_128_CBC_HMAC_SHA1\n\
    HAVE_EVP_AES_256_CBC_HMAC_SHA1\n\
    HAVE_EVP_CAMELLIA_128_ECB\n\
    HAVE_EVP_CAMELLIA_128_CBC\n\
    HAVE_EVP_CAMELLIA_128_CFB1\n\
    HAVE_EVP_CAMELLIA_128_CFB8\n\
    HAVE_EVP_CAMELLIA_128_CFB128\n\
    HAVE_DECL_EVP_CAMELLIA_128_CFB\n\
    HAVE_EVP_CAMELLIA_128_OFB\n\
    HAVE_EVP_CAMELLIA_192_ECB\n\
    HAVE_EVP_CAMELLIA_192_CBC\n\
    HAVE_EVP_CAMELLIA_192_CFB1\n\
    HAVE_EVP_CAMELLIA_192_CFB8\n\
    HAVE_EVP_CAMELLIA_192_CFB128\n\
    HAVE_DECL_EVP_CAMELLIA_192_CFB\n\
    HAVE_EVP_CAMELLIA_192_OFB\n\
    HAVE_EVP_CAMELLIA_256_ECB\n\
    HAVE_EVP_CAMELLIA_256_CBC\n\
    HAVE_EVP_CAMELLIA_256_CFB1\n\
    HAVE_EVP_CAMELLIA_256_CFB8\n\
    HAVE_EVP_CAMELLIA_256_CFB128\n\
    HAVE_DECL_EVP_CAMELLIA_256_CFB\n\
    HAVE_EVP_CAMELLIA_256_OFB\n\
    HAVE_EVP_SEED_ECB\n\
    HAVE_EVP_SEED_CBC\n\
    HAVE_EVP_SEED_CFB128\n\
    HAVE_DECL_EVP_SEED_CFB\n\
    HAVE_EVP_SEED_OFB\n\
    HAVE_EVP_CIPHER_TYPE\n\
    HAVE_EVP_GET_CIPHERBYNAME\n\
    HAVE_DECL_EVP_GET_CIPHERBYNID\n\
    HAVE_DECL_EVP_GET_CIPHERBYOBJ\n\
    HAVE_EVP_CIPHER_NID\n\
    HAVE_DECL_EVP_CIPHER_NAME\n\
    HAVE_EVP_CIPHER_BLOCK_SIZE\n\
    HAVE_EVP_CIPHER_KEY_LENGTH\n\
    HAVE_EVP_CIPHER_IV_LENGTH\n\
    HAVE_EVP_CIPHER_FLAGS\n\
    HAVE_DECL_EVP_CIPHER_MODE\n\
    HAVE_EVP_CIPHER_CTX_INIT\n\
    HAVE_EVP_CIPHER_CTX_CLEANUP\n\
    HAVE_EVP_CIPHER_CTX_NEW\n\
    HAVE_EVP_CIPHER_CTX_FREE\n\
    HAVE_EVP_ENCRYPTINIT_EX\n\
    HAVE_EVP_ENCRYPTFINAL_EX\n\
    HAVE_EVP_ENCRYPTUPDATE\n\
    HAVE_EVP_DECRYPTINIT_EX\n\
    HAVE_EVP_DECRYPTUPDATE\n\
    HAVE_EVP_DECRYPTFINAL_EX\n\
    HAVE_EVP_CIPHERINIT_EX\n\
    HAVE_EVP_CIPHERUPDATE\n\
    HAVE_EVP_CIPHERFINAL_EX\n\
    HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH\n\
    HAVE_EVP_CIPHER_CTX_SET_PADDING\n\
    HAVE_EVP_CIPHER_CTX_CTRL\n\
    HAVE_EVP_CIPHER_CTX_CIPHER\n\
    HAVE_EVP_CIPHER_CTX_NID\n\
    HAVE_EVP_CIPHER_CTX_BLOCK_SIZE\n\
    HAVE_EVP_CIPHER_CTX_KEY_LENGTH\n\
    HAVE_EVP_CIPHER_CTX_IV_LENGTH\n\
    HAVE_EVP_CIPHER_CTX_COPY\n\
    HAVE_EVP_CIPHER_CTX_GET_APP_DATA\n\
    HAVE_EVP_CIPHER_CTX_SET_APP_DATA\n\
    HAVE_DECL_EVP_CIPHER_CTX_TYPE\n\
    HAVE_EVP_CIPHER_CTX_FLAGS\n\
    HAVE_DECL_EVP_CIPHER_CTX_MODE\n\
    HAVE_EVP_CIPHER_CTX_RAND_KEY\n\
    HAVE_EVP_CIPHER_PARAM_TO_ASN1\n\
    HAVE_EVP_CIPHER_ASN1_TO_PARAM\n\
    HAVE_EVP_CIPHER_CTX_SET_FLAGS\n\
    HAVE_EVP_CIPHER_CTX_CLEAR_FLAGS\n\
    HAVE_EVP_CIPHER_CTX_TEST_FLAGS\n\
    HAVE_EVP_CIPHER\n\
    \n\
    ;; AES features\n\
    HAVE_AES_OPTIONS\n\
    HAVE_AES_SET_ENCRYPT_KEY\n\
    HAVE_AES_SET_DECRYPT_KEY\n\
    HAVE_AES_ENCRYPT\n\
    HAVE_AES_DECRYPT\n\
    HAVE_AES_ECB_ENCRYPT\n\
    HAVE_AES_CBC_ENCRYPT\n\
    HAVE_AES_CFB128_ENCRYPT\n\
    HAVE_AES_CFB1_ENCRYPT\n\
    HAVE_AES_CFB8_ENCRYPT\n\
    HAVE_AES_OFB128_ENCRYPT\n\
    HAVE_AES_CTR128_ENCRYPT\n\
    HAVE_AES_IGE_ENCRYPT\n\
    HAVE_AES_BI_IGE_ENCRYPT\n\
    HAVE_AES_WRAP_KEY\n\
    HAVE_AES_UNWRAP_KEY\n\
    \n\
    )\n\
  (import (rnrs))\n\
\n\
;;;; helpers\n\
\n\
(define-syntax define-inline-constant\n\
  (syntax-rules ()\n\
    ((_ ?name ?value)\n\
     (define-syntax ?name (identifier-syntax ?value)))))\n\
\n\
\n\
;;;; code\n\n");


/** --------------------------------------------------------------------
 ** Library initialisation features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SSL_LIBRARY_INIT %s)\n",
#ifdef HAVE_SSL_LIBRARY_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_OPENSSL_ADD_ALL_ALGORITHMS_NOCONF %s)\n",
#ifdef HAVE_OPENSSL_ADD_ALL_ALGORITHMS_NOCONF
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_OPENSSL_ADD_ALL_ALGORITHMS_CONF %s)\n",
#ifdef HAVE_OPENSSL_ADD_ALL_ALGORITHMS_CONF
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS %s)\n",
#if ((defined HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_OPENSSL_ADD_ALL_CIPHERS %s)\n",
#ifdef HAVE_OPENSSL_ADD_ALL_CIPHERS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_OPENSSL_ADD_ALL_DIGESTS %s)\n",
#ifdef HAVE_OPENSSL_ADD_ALL_DIGESTS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_SSLEAY_ADD_ALL_ALGORITHMS %s)\n",
#if ((defined HAVE_DECL_SSLEAY_ADD_ALL_ALGORITHMS) && HAVE_DECL_SSLEAY_ADD_ALL_ALGORITHMS)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_SSLEAY_ADD_ALL_CIPHERS %s)\n",
#if ((defined HAVE_DECL_SSLEAY_ADD_ALL_CIPHERS) && HAVE_DECL_SSLEAY_ADD_ALL_CIPHERS)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_SSLEAY_ADD_ALL_DIGESTS %s)\n",
#if ((defined HAVE_DECL_SSLEAY_ADD_ALL_DIGESTS) && HAVE_DECL_SSLEAY_ADD_ALL_DIGESTS)
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** MD4.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_MD4_INIT %s)\n",
#ifdef HAVE_MD4_INIT
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD4_UPDATE %s)\n",
#ifdef HAVE_MD4_UPDATE
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD4_FINAL %s)\n",
#ifdef HAVE_MD4_FINAL
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD4 %s)\n",
#ifdef HAVE_MD4
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** MD5.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_MD5_INIT %s)\n",
#ifdef HAVE_MD5_INIT
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD5_UPDATE %s)\n",
#ifdef HAVE_MD5_UPDATE
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD5_FINAL %s)\n",
#ifdef HAVE_MD5_FINAL
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD5 %s)\n",
#ifdef HAVE_MD5
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** MDC2 features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_MDC2_INIT %s)\n",
#ifdef HAVE_MDC2_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_MDC2_UPDATE %s)\n",
#ifdef HAVE_MDC2_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_MDC2_FINAL %s)\n",
#ifdef HAVE_MDC2_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_MDC2 %s)\n",
#ifdef HAVE_MDC2
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** SHA 1 features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SHA1_INIT %s)\n",
#ifdef HAVE_SHA1_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA1_UPDATE %s)\n",
#ifdef HAVE_SHA1_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA1_FINAL %s)\n",
#ifdef HAVE_SHA1_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA1 %s)\n",
#ifdef HAVE_SHA1
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** SHA 224 features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SHA224_INIT %s)\n",
#ifdef HAVE_SHA224_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA224_UPDATE %s)\n",
#ifdef HAVE_SHA224_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA224_FINAL %s)\n",
#ifdef HAVE_SHA224_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA224 %s)\n",
#ifdef HAVE_SHA224
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** SHA 256 features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SHA256_INIT %s)\n",
#ifdef HAVE_SHA256_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA256_UPDATE %s)\n",
#ifdef HAVE_SHA256_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA256_FINAL %s)\n",
#ifdef HAVE_SHA256_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA256 %s)\n",
#ifdef HAVE_SHA256
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** SHA 384 features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SHA384_INIT %s)\n",
#ifdef HAVE_SHA384_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA384_UPDATE %s)\n",
#ifdef HAVE_SHA384_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA384_FINAL %s)\n",
#ifdef HAVE_SHA384_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA384 %s)\n",
#ifdef HAVE_SHA384
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** SHA 512 features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SHA512_INIT %s)\n",
#ifdef HAVE_SHA512_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA512_UPDATE %s)\n",
#ifdef HAVE_SHA512_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA512_FINAL %s)\n",
#ifdef HAVE_SHA512_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_SHA512 %s)\n",
#ifdef HAVE_SHA512
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** RIPEMD160.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_RIPEMD160_INIT %s)\n",
#ifdef HAVE_RIPEMD160_INIT
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_RIPEMD160_UPDATE %s)\n",
#ifdef HAVE_RIPEMD160_UPDATE
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_RIPEMD160_FINAL %s)\n",
#ifdef HAVE_RIPEMD160_FINAL
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_RIPEMD160 %s)\n",
#ifdef HAVE_RIPEMD160
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** WHIRLPOOL.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_WHIRLPOOL_INIT %s)\n",
#ifdef HAVE_WHIRLPOOL_INIT
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_WHIRLPOOL_UPDATE %s)\n",
#ifdef HAVE_WHIRLPOOL_UPDATE
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_WHIRLPOOL_FINAL %s)\n",
#ifdef HAVE_WHIRLPOOL_FINAL
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_WHIRLPOOL %s)\n",
#ifdef HAVE_WHIRLPOOL
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** HMAC features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_HMAC %s)\n",
#ifdef HAVE_HMAC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_CTX_INIT %s)\n",
#ifdef HAVE_HMAC_CTX_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_CTX_CLEANUP %s)\n",
#ifdef HAVE_HMAC_CTX_CLEANUP
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_INIT %s)\n",
#ifdef HAVE_HMAC_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_INIT_EX %s)\n",
#ifdef HAVE_HMAC_INIT_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_UPDATE %s)\n",
#ifdef HAVE_HMAC_UPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_FINAL %s)\n",
#ifdef HAVE_HMAC_FINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_CTX_COPY %s)\n",
#ifdef HAVE_HMAC_CTX_COPY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_HMAC_CTX_SET_FLAGS %s)\n",
#ifdef HAVE_HMAC_CTX_SET_FLAGS
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** AES features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_AES_OPTIONS %s)\n",
#ifdef HAVE_AES_OPTIONS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_SET_ENCRYPT_KEY %s)\n",
#ifdef HAVE_AES_SET_ENCRYPT_KEY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_SET_DECRYPT_KEY %s)\n",
#ifdef HAVE_AES_SET_DECRYPT_KEY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_ENCRYPT %s)\n",
#ifdef HAVE_AES_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_DECRYPT %s)\n",
#ifdef HAVE_AES_DECRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_ECB_ENCRYPT %s)\n",
#ifdef HAVE_AES_ECB_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_CBC_ENCRYPT %s)\n",
#ifdef HAVE_AES_CBC_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_CFB128_ENCRYPT %s)\n",
#ifdef HAVE_AES_CFB128_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_CFB1_ENCRYPT %s)\n",
#ifdef HAVE_AES_CFB1_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_CFB8_ENCRYPT %s)\n",
#ifdef HAVE_AES_CFB8_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_OFB128_ENCRYPT %s)\n",
#ifdef HAVE_AES_OFB128_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_CTR128_ENCRYPT %s)\n",
#ifdef HAVE_AES_CTR128_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_IGE_ENCRYPT %s)\n",
#ifdef HAVE_AES_IGE_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_BI_IGE_ENCRYPT %s)\n",
#ifdef HAVE_AES_BI_IGE_ENCRYPT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_WRAP_KEY %s)\n",
#ifdef HAVE_AES_WRAP_KEY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_AES_UNWRAP_KEY %s)\n",
#ifdef HAVE_AES_UNWRAP_KEY
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** EVP hash functions features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_EVP_MD_TYPE %s)\n",
#ifdef HAVE_EVP_MD_TYPE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_NID %s)\n",
#ifdef HAVE_EVP_MD_NID
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_NAME %s)\n",
#ifdef HAVE_EVP_MD_NAME
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_PKEY_TYPE %s)\n",
#ifdef HAVE_EVP_MD_PKEY_TYPE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_SIZE %s)\n",
#ifdef HAVE_EVP_MD_SIZE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_BLOCK_SIZE %s)\n",
#ifdef HAVE_EVP_MD_BLOCK_SIZE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_FLAGS %s)\n",
#ifdef HAVE_EVP_MD_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_MD %s)\n",
#ifdef HAVE_EVP_MD_CTX_MD
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_SIZE %s)\n",
#ifdef HAVE_EVP_MD_CTX_SIZE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_BLOCK_SIZE %s)\n",
#ifdef HAVE_EVP_MD_CTX_BLOCK_SIZE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_TYPE %s)\n",
#ifdef HAVE_EVP_MD_CTX_TYPE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_INIT %s)\n",
#ifdef HAVE_EVP_MD_CTX_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_CLEANUP %s)\n",
#ifdef HAVE_EVP_MD_CTX_CLEANUP
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_CREATE %s)\n",
#ifdef HAVE_EVP_MD_CTX_CREATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_DESTROY %s)\n",
#ifdef HAVE_EVP_MD_CTX_DESTROY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_COPY_EX %s)\n",
#ifdef HAVE_EVP_MD_CTX_COPY_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_SET_FLAGS %s)\n",
#ifdef HAVE_EVP_MD_CTX_SET_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_CLEAR_FLAGS %s)\n",
#ifdef HAVE_EVP_MD_CTX_CLEAR_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_TEST_FLAGS %s)\n",
#ifdef HAVE_EVP_MD_CTX_TEST_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DIGESTINIT_EX %s)\n",
#ifdef HAVE_EVP_DIGESTINIT_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DIGESTUPDATE %s)\n",
#ifdef HAVE_EVP_DIGESTUPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DIGESTFINAL_EX %s)\n",
#ifdef HAVE_EVP_DIGESTFINAL_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DIGEST %s)\n",
#ifdef HAVE_EVP_DIGEST
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_CTX_COPY %s)\n",
#ifdef HAVE_EVP_MD_CTX_COPY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DIGESTINIT %s)\n",
#ifdef HAVE_EVP_DIGESTINIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DIGESTFINAL %s)\n",
#ifdef HAVE_EVP_DIGESTFINAL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD_NULL %s)\n",
#ifdef HAVE_EVP_MD_NULL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD2 %s)\n",
#ifdef HAVE_EVP_MD2
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD4 %s)\n",
#ifdef HAVE_EVP_MD4
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MD5 %s)\n",
#ifdef HAVE_EVP_MD5
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SHA %s)\n",
#ifdef HAVE_EVP_SHA
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SHA1 %s)\n",
#ifdef HAVE_EVP_SHA1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DSS %s)\n",
#ifdef HAVE_EVP_DSS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DSS1 %s)\n",
#ifdef HAVE_EVP_DSS1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_ECDSA %s)\n",
#ifdef HAVE_EVP_ECDSA
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SHA224 %s)\n",
#ifdef HAVE_EVP_SHA224
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SHA256 %s)\n",
#ifdef HAVE_EVP_SHA256
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SHA384 %s)\n",
#ifdef HAVE_EVP_SHA384
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SHA512 %s)\n",
#ifdef HAVE_EVP_SHA512
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_MDC2 %s)\n",
#ifdef HAVE_EVP_MDC2
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RIPEMD160 %s)\n",
#ifdef HAVE_EVP_RIPEMD160
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_WHIRLPOOL %s)\n",
#ifdef HAVE_EVP_WHIRLPOOL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_GET_DIGESTBYNAME %s)\n",
#ifdef HAVE_EVP_GET_DIGESTBYNAME
  "#t"
#else
  "#f"
#endif
  );


/** --------------------------------------------------------------------
 ** EVP cipher algorithms features.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_EVP_ENC_NULL %s)\n",
#ifdef HAVE_EVP_ENC_NULL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_ECB %s)\n",
#ifdef HAVE_EVP_DES_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE %s)\n",
#ifdef HAVE_EVP_DES_EDE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3 %s)\n",
#ifdef HAVE_EVP_DES_EDE3
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE_ECB %s)\n",
#ifdef HAVE_EVP_DES_EDE_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3_ECB %s)\n",
#ifdef HAVE_EVP_DES_EDE3_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_CFB64 %s)\n",
#ifdef HAVE_EVP_DES_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_DES_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_DES_CFB) && HAVE_DECL_EVP_DES_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3_CFB64 %s)\n",
#ifdef HAVE_EVP_DES_EDE3_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_DES_EDE3_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_DES_EDE3_CFB) && HAVE_DECL_EVP_DES_EDE3_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3_CFB1 %s)\n",
#ifdef HAVE_EVP_DES_EDE3_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3_CFB8 %s)\n",
#ifdef HAVE_EVP_DES_EDE3_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_OFB %s)\n",
#ifdef HAVE_EVP_DES_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE_OFB %s)\n",
#ifdef HAVE_EVP_DES_EDE_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3_OFB %s)\n",
#ifdef HAVE_EVP_DES_EDE3_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_CBC %s)\n",
#ifdef HAVE_EVP_DES_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE_CBC %s)\n",
#ifdef HAVE_EVP_DES_EDE_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DES_EDE3_CBC %s)\n",
#ifdef HAVE_EVP_DES_EDE3_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DESX_CBC %s)\n",
#ifdef HAVE_EVP_DESX_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC4 %s)\n",
#ifdef HAVE_EVP_RC4
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC4_40 %s)\n",
#ifdef HAVE_EVP_RC4_40
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC4_HMAC_MD5 %s)\n",
#ifdef HAVE_EVP_RC4_HMAC_MD5
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_IDEA_ECB %s)\n",
#ifdef HAVE_EVP_IDEA_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_IDEA_CFB64 %s)\n",
#ifdef HAVE_EVP_IDEA_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_IDEA_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_IDEA_CFB) && HAVE_DECL_EVP_IDEA_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_IDEA_OFB %s)\n",
#ifdef HAVE_EVP_IDEA_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_IDEA_CBC %s)\n",
#ifdef HAVE_EVP_IDEA_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC2_ECB %s)\n",
#ifdef HAVE_EVP_RC2_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC2_CBC %s)\n",
#ifdef HAVE_EVP_RC2_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC2_40_CBC %s)\n",
#ifdef HAVE_EVP_RC2_40_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC2_64_CBC %s)\n",
#ifdef HAVE_EVP_RC2_64_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC2_CFB64 %s)\n",
#ifdef HAVE_EVP_RC2_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_RC2_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_RC2_CFB) && HAVE_DECL_EVP_RC2_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC2_OFB %s)\n",
#ifdef HAVE_EVP_RC2_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_BF_ECB %s)\n",
#ifdef HAVE_EVP_BF_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_BF_CBC %s)\n",
#ifdef HAVE_EVP_BF_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_BF_CFB64 %s)\n",
#ifdef HAVE_EVP_BF_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_BF_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_BF_CFB) && HAVE_DECL_EVP_BF_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_BF_OFB %s)\n",
#ifdef HAVE_EVP_BF_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAST5_ECB %s)\n",
#ifdef HAVE_EVP_CAST5_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAST5_CBC %s)\n",
#ifdef HAVE_EVP_CAST5_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAST5_CFB64 %s)\n",
#ifdef HAVE_EVP_CAST5_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CAST5_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_CAST5_CFB) && HAVE_DECL_EVP_CAST5_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAST5_OFB %s)\n",
#ifdef HAVE_EVP_CAST5_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC5_32_12_16_CBC %s)\n",
#ifdef HAVE_EVP_RC5_32_12_16_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC5_32_12_16_ECB %s)\n",
#ifdef HAVE_EVP_RC5_32_12_16_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC5_32_12_16_CFB64 %s)\n",
#ifdef HAVE_EVP_RC5_32_12_16_CFB64
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_RC5_32_12_16_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_RC5_32_12_16_CFB) && HAVE_DECL_EVP_RC5_32_12_16_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_RC5_32_12_16_OFB %s)\n",
#ifdef HAVE_EVP_RC5_32_12_16_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_ECB %s)\n",
#ifdef HAVE_EVP_AES_128_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CBC %s)\n",
#ifdef HAVE_EVP_AES_128_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CFB1 %s)\n",
#ifdef HAVE_EVP_AES_128_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CFB8 %s)\n",
#ifdef HAVE_EVP_AES_128_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CFB128 %s)\n",
#ifdef HAVE_EVP_AES_128_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_AES_128_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_AES_128_CFB) && HAVE_DECL_EVP_AES_128_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_OFB %s)\n",
#ifdef HAVE_EVP_AES_128_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CTR %s)\n",
#ifdef HAVE_EVP_AES_128_CTR
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CCM %s)\n",
#ifdef HAVE_EVP_AES_128_CCM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_GCM %s)\n",
#ifdef HAVE_EVP_AES_128_GCM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_XTS %s)\n",
#ifdef HAVE_EVP_AES_128_XTS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_ECB %s)\n",
#ifdef HAVE_EVP_AES_192_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_CBC %s)\n",
#ifdef HAVE_EVP_AES_192_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_CFB1 %s)\n",
#ifdef HAVE_EVP_AES_192_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_CFB8 %s)\n",
#ifdef HAVE_EVP_AES_192_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_CFB128 %s)\n",
#ifdef HAVE_EVP_AES_192_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_AES_192_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_AES_192_CFB) && HAVE_DECL_EVP_AES_192_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_OFB %s)\n",
#ifdef HAVE_EVP_AES_192_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_CTR %s)\n",
#ifdef HAVE_EVP_AES_192_CTR
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_CCM %s)\n",
#ifdef HAVE_EVP_AES_192_CCM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_192_GCM %s)\n",
#ifdef HAVE_EVP_AES_192_GCM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_ECB %s)\n",
#ifdef HAVE_EVP_AES_256_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CBC %s)\n",
#ifdef HAVE_EVP_AES_256_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CFB1 %s)\n",
#ifdef HAVE_EVP_AES_256_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CFB8 %s)\n",
#ifdef HAVE_EVP_AES_256_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CFB128 %s)\n",
#ifdef HAVE_EVP_AES_256_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_AES_256_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_AES_256_CFB) && HAVE_DECL_EVP_AES_256_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_OFB %s)\n",
#ifdef HAVE_EVP_AES_256_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CTR %s)\n",
#ifdef HAVE_EVP_AES_256_CTR
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CCM %s)\n",
#ifdef HAVE_EVP_AES_256_CCM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_GCM %s)\n",
#ifdef HAVE_EVP_AES_256_GCM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_XTS %s)\n",
#ifdef HAVE_EVP_AES_256_XTS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_128_CBC_HMAC_SHA1 %s)\n",
#ifdef HAVE_EVP_AES_128_CBC_HMAC_SHA1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_AES_256_CBC_HMAC_SHA1 %s)\n",
#ifdef HAVE_EVP_AES_256_CBC_HMAC_SHA1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_128_ECB %s)\n",
#ifdef HAVE_EVP_CAMELLIA_128_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_128_CBC %s)\n",
#ifdef HAVE_EVP_CAMELLIA_128_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_128_CFB1 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_128_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_128_CFB8 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_128_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_128_CFB128 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_128_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CAMELLIA_128_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_CAMELLIA_128_CFB) && HAVE_DECL_EVP_CAMELLIA_128_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_128_OFB %s)\n",
#ifdef HAVE_EVP_CAMELLIA_128_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_192_ECB %s)\n",
#ifdef HAVE_EVP_CAMELLIA_192_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_192_CBC %s)\n",
#ifdef HAVE_EVP_CAMELLIA_192_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_192_CFB1 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_192_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_192_CFB8 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_192_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_192_CFB128 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_192_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CAMELLIA_192_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_CAMELLIA_192_CFB) && HAVE_DECL_EVP_CAMELLIA_192_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_192_OFB %s)\n",
#ifdef HAVE_EVP_CAMELLIA_192_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_256_ECB %s)\n",
#ifdef HAVE_EVP_CAMELLIA_256_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_256_CBC %s)\n",
#ifdef HAVE_EVP_CAMELLIA_256_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_256_CFB1 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_256_CFB1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_256_CFB8 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_256_CFB8
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_256_CFB128 %s)\n",
#ifdef HAVE_EVP_CAMELLIA_256_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CAMELLIA_256_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_CAMELLIA_256_CFB) && HAVE_DECL_EVP_CAMELLIA_256_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CAMELLIA_256_OFB %s)\n",
#ifdef HAVE_EVP_CAMELLIA_256_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SEED_ECB %s)\n",
#ifdef HAVE_EVP_SEED_ECB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SEED_CBC %s)\n",
#ifdef HAVE_EVP_SEED_CBC
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SEED_CFB128 %s)\n",
#ifdef HAVE_EVP_SEED_CFB128
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_SEED_CFB %s)\n",
#if ((defined HAVE_DECL_EVP_SEED_CFB) && HAVE_DECL_EVP_SEED_CFB)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_SEED_OFB %s)\n",
#ifdef HAVE_EVP_SEED_OFB
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_TYPE %s)\n",
#ifdef HAVE_EVP_CIPHER_TYPE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_GET_CIPHERBYNAME %s)\n",
#ifdef HAVE_EVP_GET_CIPHERBYNAME
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_GET_CIPHERBYNID %s)\n",
#if ((defined HAVE_DECL_EVP_GET_CIPHERBYNID) && HAVE_DECL_EVP_GET_CIPHERBYNID)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_GET_CIPHERBYOBJ %s)\n",
#if ((defined HAVE_DECL_EVP_GET_CIPHERBYOBJ) && HAVE_DECL_EVP_GET_CIPHERBYOBJ)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_NID %s)\n",
#ifdef HAVE_EVP_CIPHER_NID
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CIPHER_NAME %s)\n",
#if ((defined HAVE_DECL_EVP_CIPHER_NAME) && HAVE_DECL_EVP_CIPHER_NAME)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_BLOCK_SIZE %s)\n",
#ifdef HAVE_EVP_CIPHER_BLOCK_SIZE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_KEY_LENGTH %s)\n",
#ifdef HAVE_EVP_CIPHER_KEY_LENGTH
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_IV_LENGTH %s)\n",
#ifdef HAVE_EVP_CIPHER_IV_LENGTH
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_FLAGS %s)\n",
#ifdef HAVE_EVP_CIPHER_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CIPHER_MODE %s)\n",
#if ((defined HAVE_DECL_EVP_CIPHER_MODE) && HAVE_DECL_EVP_CIPHER_MODE)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_INIT %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_INIT
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_CLEANUP %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_CLEANUP
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_NEW %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_NEW
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_FREE %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_FREE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_ENCRYPTINIT_EX %s)\n",
#ifdef HAVE_EVP_ENCRYPTINIT_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_ENCRYPTFINAL_EX %s)\n",
#ifdef HAVE_EVP_ENCRYPTFINAL_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_ENCRYPTUPDATE %s)\n",
#ifdef HAVE_EVP_ENCRYPTUPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DECRYPTINIT_EX %s)\n",
#ifdef HAVE_EVP_DECRYPTINIT_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DECRYPTUPDATE %s)\n",
#ifdef HAVE_EVP_DECRYPTUPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_DECRYPTFINAL_EX %s)\n",
#ifdef HAVE_EVP_DECRYPTFINAL_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHERINIT_EX %s)\n",
#ifdef HAVE_EVP_CIPHERINIT_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHERUPDATE %s)\n",
#ifdef HAVE_EVP_CIPHERUPDATE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHERFINAL_EX %s)\n",
#ifdef HAVE_EVP_CIPHERFINAL_EX
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_SET_PADDING %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_SET_PADDING
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_CTRL %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_CTRL
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_CIPHER %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_CIPHER
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_NID %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_NID
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_BLOCK_SIZE %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_BLOCK_SIZE
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_KEY_LENGTH %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_KEY_LENGTH
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_IV_LENGTH %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_IV_LENGTH
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_COPY %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_COPY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_GET_APP_DATA %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_GET_APP_DATA
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_SET_APP_DATA %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_SET_APP_DATA
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CIPHER_CTX_TYPE %s)\n",
#if ((defined HAVE_DECL_EVP_CIPHER_CTX_TYPE) && HAVE_DECL_EVP_CIPHER_CTX_TYPE)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_FLAGS %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_DECL_EVP_CIPHER_CTX_MODE %s)\n",
#if ((defined HAVE_DECL_EVP_CIPHER_CTX_MODE) && HAVE_DECL_EVP_CIPHER_CTX_MODE)
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_RAND_KEY %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_RAND_KEY
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_PARAM_TO_ASN1 %s)\n",
#ifdef HAVE_EVP_CIPHER_PARAM_TO_ASN1
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_ASN1_TO_PARAM %s)\n",
#ifdef HAVE_EVP_CIPHER_ASN1_TO_PARAM
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_SET_FLAGS %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_SET_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_CLEAR_FLAGS %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_CLEAR_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER_CTX_TEST_FLAGS %s)\n",
#ifdef HAVE_EVP_CIPHER_CTX_TEST_FLAGS
  "#t"
#else
  "#f"
#endif
  );

printf("(define-inline-constant HAVE_EVP_CIPHER %s)\n",
#ifdef HAVE_EVP_CIPHER
  "#t"
#else
  "#f"
#endif
  );


  printf("\n\
;;;; done\n\
\n\
)\n\
\n\
;;; end of file\n");
  exit(EXIT_SUCCESS);
}

/* end of file */
