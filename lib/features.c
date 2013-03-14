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
    HAVE_SSL_LIBRARY_INIT\n\
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
 ** SSL.
 ** ----------------------------------------------------------------- */

printf("(define-inline-constant HAVE_SSL_LIBRARY_INIT %s)\n",
#ifdef HAVE_SSL_LIBRARY_INIT
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


  printf("\n\
;;;; done\n\
\n\
)\n\
\n\
;;; end of file\n");
  exit(EXIT_SUCCESS);
}

/* end of file */
