;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: feature-based conditional expansion
;;;Date: Sun Mar 17, 2013
;;;
;;;Abstract
;;;
;;;
;;;
;;;Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>
;;;
;;;This program is free software:  you can redistribute it and/or modify
;;;it under the terms of the  GNU General Public License as published by
;;;the Free Software Foundation, either version 3 of the License, or (at
;;;your option) any later version.
;;;
;;;This program is  distributed in the hope that it  will be useful, but
;;;WITHOUT  ANY   WARRANTY;  without   even  the  implied   warranty  of
;;;MERCHANTABILITY or  FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU
;;;General Public License for more details.
;;;
;;;You should  have received a  copy of  the GNU General  Public License
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;


#!r6rs
(library (vicare crypto openssl evp ciphers cond-expand)
  (export vicare-openssl-evp-ciphers-features)
  (import (only (vicare language-extensions cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl evp ciphers)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-evp-ciphers-features
  (evp-enc-null				HAVE_EVP_ENC_NULL)
  (evp-des-ecb				HAVE_EVP_DES_ECB)
  (evp-des-ede				HAVE_EVP_DES_EDE)
  (evp-des-ede3				HAVE_EVP_DES_EDE3)
  (evp-des-ede-ecb			HAVE_EVP_DES_EDE_ECB)
  (evp-des-ede3-ecb			HAVE_EVP_DES_EDE3_ECB)
  (evp-des-cfb64			HAVE_EVP_DES_CFB64)
  (evp-des-cfb				HAVE_DECL_EVP_DES_CFB)
  (evp-des-ede3-cfb64			HAVE_EVP_DES_EDE3_CFB64)
  (evp-des-ede3-cfb			HAVE_DECL_EVP_DES_EDE3_CFB)
  (evp-des-ede3-cfb1			HAVE_EVP_DES_EDE3_CFB1)
  (evp-des-ede3-cfb8			HAVE_EVP_DES_EDE3_CFB8)
  (evp-des-ofb				HAVE_EVP_DES_OFB)
  (evp-des-ede-ofb			HAVE_EVP_DES_EDE_OFB)
  (evp-des-ede3-ofb			HAVE_EVP_DES_EDE3_OFB)
  (evp-des-cbc				HAVE_EVP_DES_CBC)
  (evp-des-ede-cbc			HAVE_EVP_DES_EDE_CBC)
  (evp-des-ede3-cbc			HAVE_EVP_DES_EDE3_CBC)
  (evp-desx-cbc				HAVE_EVP_DESX_CBC)
  (evp-rc4				HAVE_EVP_RC4)
  (evp-rc4-40				HAVE_EVP_RC4_40)
  (evp-rc4-hmac-md5			HAVE_EVP_RC4_HMAC_MD5)
  (evp-idea-ecb				HAVE_EVP_IDEA_ECB)
  (evp-idea-cfb64			HAVE_EVP_IDEA_CFB64)
  (evp-idea-cfb				HAVE_DECL_EVP_IDEA_CFB)
  (evp-idea-ofb				HAVE_EVP_IDEA_OFB)
  (evp-idea-cbc				HAVE_EVP_IDEA_CBC)
  (evp-rc2-ecb				HAVE_EVP_RC2_ECB)
  (evp-rc2-cbc				HAVE_EVP_RC2_CBC)
  (evp-rc2-40-cbc			HAVE_EVP_RC2_40_CBC)
  (evp-rc2-64-cbc			HAVE_EVP_RC2_64_CBC)
  (evp-rc2-cfb64			HAVE_EVP_RC2_CFB64)
  (evp-rc2-cfb				HAVE_DECL_EVP_RC2_CFB)
  (evp-rc2-ofb				HAVE_EVP_RC2_OFB)
  (evp-bf-ecb				HAVE_EVP_BF_ECB)
  (evp-bf-cbc				HAVE_EVP_BF_CBC)
  (evp-bf-cfb64				HAVE_EVP_BF_CFB64)
  (evp-bf-cfb				HAVE_DECL_EVP_BF_CFB)
  (evp-bf-ofb				HAVE_EVP_BF_OFB)
  (evp-cast5-ecb			HAVE_EVP_CAST5_ECB)
  (evp-cast5-cbc			HAVE_EVP_CAST5_CBC)
  (evp-cast5-cfb64			HAVE_EVP_CAST5_CFB64)
  (evp-cast5-cfb			HAVE_DECL_EVP_CAST5_CFB)
  (evp-cast5-ofb			HAVE_EVP_CAST5_OFB)
  (evp-rc5-32-12-16-cbc			HAVE_EVP_RC5_32_12_16_CBC)
  (evp-rc5-32-12-16-ecb			HAVE_EVP_RC5_32_12_16_ECB)
  (evp-rc5-32-12-16-cfb64		HAVE_EVP_RC5_32_12_16_CFB64)
  (evp-rc5-32-12-16-cfb			HAVE_DECL_EVP_RC5_32_12_16_CFB)
  (evp-rc5-32-12-16-ofb			HAVE_EVP_RC5_32_12_16_OFB)
  (evp-aes-128-ecb			HAVE_EVP_AES_128_ECB)
  (evp-aes-128-cbc			HAVE_EVP_AES_128_CBC)
  (evp-aes-128-cfb1			HAVE_EVP_AES_128_CFB1)
  (evp-aes-128-cfb8			HAVE_EVP_AES_128_CFB8)
  (evp-aes-128-cfb128			HAVE_EVP_AES_128_CFB128)
  (evp-aes-128-cfb			HAVE_DECL_EVP_AES_128_CFB)
  (evp-aes-128-ofb			HAVE_EVP_AES_128_OFB)
  (evp-aes-128-ctr			HAVE_EVP_AES_128_CTR)
  (evp-aes-128-ccm			HAVE_EVP_AES_128_CCM)
  (evp-aes-128-gcm			HAVE_EVP_AES_128_GCM)
  (evp-aes-128-xts			HAVE_EVP_AES_128_XTS)
  (evp-aes-192-ecb			HAVE_EVP_AES_192_ECB)
  (evp-aes-192-cbc			HAVE_EVP_AES_192_CBC)
  (evp-aes-192-cfb1			HAVE_EVP_AES_192_CFB1)
  (evp-aes-192-cfb8			HAVE_EVP_AES_192_CFB8)
  (evp-aes-192-cfb128			HAVE_EVP_AES_192_CFB128)
  (evp-aes-192-cfb			HAVE_DECL_EVP_AES_192_CFB)
  (evp-aes-192-ofb			HAVE_EVP_AES_192_OFB)
  (evp-aes-192-ctr			HAVE_EVP_AES_192_CTR)
  (evp-aes-192-ccm			HAVE_EVP_AES_192_CCM)
  (evp-aes-192-gcm			HAVE_EVP_AES_192_GCM)
  (evp-aes-256-ecb			HAVE_EVP_AES_256_ECB)
  (evp-aes-256-cbc			HAVE_EVP_AES_256_CBC)
  (evp-aes-256-cfb1			HAVE_EVP_AES_256_CFB1)
  (evp-aes-256-cfb8			HAVE_EVP_AES_256_CFB8)
  (evp-aes-256-cfb128			HAVE_EVP_AES_256_CFB128)
  (evp-aes-256-cfb			HAVE_DECL_EVP_AES_256_CFB)
  (evp-aes-256-ofb			HAVE_EVP_AES_256_OFB)
  (evp-aes-256-ctr			HAVE_EVP_AES_256_CTR)
  (evp-aes-256-ccm			HAVE_EVP_AES_256_CCM)
  (evp-aes-256-gcm			HAVE_EVP_AES_256_GCM)
  (evp-aes-256-xts			HAVE_EVP_AES_256_XTS)
  (evp-aes-128-cbc-hmac-sha1		HAVE_EVP_AES_128_CBC_HMAC_SHA1)
  (evp-aes-256-cbc-hmac-sha1		HAVE_EVP_AES_256_CBC_HMAC_SHA1)
  (evp-camellia-128-ecb			HAVE_EVP_CAMELLIA_128_ECB)
  (evp-camellia-128-cbc			HAVE_EVP_CAMELLIA_128_CBC)
  (evp-camellia-128-cfb1		HAVE_EVP_CAMELLIA_128_CFB1)
  (evp-camellia-128-cfb8		HAVE_EVP_CAMELLIA_128_CFB8)
  (evp-camellia-128-cfb128		HAVE_EVP_CAMELLIA_128_CFB128)
  (evp-camellia-128-cfb			HAVE_DECL_EVP_CAMELLIA_128_CFB)
  (evp-camellia-128-ofb			HAVE_EVP_CAMELLIA_128_OFB)
  (evp-camellia-192-ecb			HAVE_EVP_CAMELLIA_192_ECB)
  (evp-camellia-192-cbc			HAVE_EVP_CAMELLIA_192_CBC)
  (evp-camellia-192-cfb1		HAVE_EVP_CAMELLIA_192_CFB1)
  (evp-camellia-192-cfb8		HAVE_EVP_CAMELLIA_192_CFB8)
  (evp-camellia-192-cfb128		HAVE_EVP_CAMELLIA_192_CFB128)
  (evp-camellia-192-cfb			HAVE_DECL_EVP_CAMELLIA_192_CFB)
  (evp-camellia-192-ofb			HAVE_EVP_CAMELLIA_192_OFB)
  (evp-camellia-256-ecb			HAVE_EVP_CAMELLIA_256_ECB)
  (evp-camellia-256-cbc			HAVE_EVP_CAMELLIA_256_CBC)
  (evp-camellia-256-cfb1		HAVE_EVP_CAMELLIA_256_CFB1)
  (evp-camellia-256-cfb8		HAVE_EVP_CAMELLIA_256_CFB8)
  (evp-camellia-256-cfb128		HAVE_EVP_CAMELLIA_256_CFB128)
  (evp-camellia-256-cfb			HAVE_DECL_EVP_CAMELLIA_256_CFB)
  (evp-camellia-256-ofb			HAVE_EVP_CAMELLIA_256_OFB)
  (evp-seed-ecb				HAVE_EVP_SEED_ECB)
  (evp-seed-cbc				HAVE_EVP_SEED_CBC)
  (evp-seed-cfb128			HAVE_EVP_SEED_CFB128)
  (evp-seed-cfb				HAVE_DECL_EVP_SEED_CFB)
  (evp-seed-ofb				HAVE_EVP_SEED_OFB)
  (evp-cipher-type			HAVE_EVP_CIPHER_TYPE)
  (evp-get-cipherbyname			HAVE_EVP_GET_CIPHERBYNAME)
  (evp-get-cipherbynid			HAVE_DECL_EVP_GET_CIPHERBYNID)
  (evp-get-cipherbyobj			HAVE_DECL_EVP_GET_CIPHERBYOBJ)
  (evp-cipher-nid			HAVE_EVP_CIPHER_NID)
  (evp-cipher-name			HAVE_DECL_EVP_CIPHER_NAME)
  (evp-cipher-block-size		HAVE_EVP_CIPHER_BLOCK_SIZE)
  (evp-cipher-key-length		HAVE_EVP_CIPHER_KEY_LENGTH)
  (evp-cipher-iv-length			HAVE_EVP_CIPHER_IV_LENGTH)
  (evp-cipher-flags			HAVE_EVP_CIPHER_FLAGS)
  (evp-cipher-mode			HAVE_DECL_EVP_CIPHER_MODE)

  (evp-cipher-ctx-init			HAVE_EVP_CIPHER_CTX_INIT)
  (evp-cipher-ctx-cleanup		HAVE_EVP_CIPHER_CTX_CLEANUP)
  (evp-cipher-ctx-new			HAVE_EVP_CIPHER_CTX_NEW)
  (evp-cipher-ctx-free			HAVE_EVP_CIPHER_CTX_FREE)
  (evp-encryptinit-ex			HAVE_EVP_ENCRYPTINIT_EX)
  (evp-encryptfinal-ex			HAVE_EVP_ENCRYPTFINAL_EX)
  (evp-encryptupdate			HAVE_EVP_ENCRYPTUPDATE)
  (evp-decryptinit-ex			HAVE_EVP_DECRYPTINIT_EX)
  (evp-decryptupdate			HAVE_EVP_DECRYPTUPDATE)
  (evp-decryptfinal-ex			HAVE_EVP_DECRYPTFINAL_EX)
  (evp-cipherinit-ex			HAVE_EVP_CIPHERINIT_EX)
  (evp-cipherupdate			HAVE_EVP_CIPHERUPDATE)
  (evp-cipherfinal-ex			HAVE_EVP_CIPHERFINAL_EX)
  (evp-cipher-ctx-set-key-length	HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH)
  (evp-cipher-ctx-set-padding		HAVE_EVP_CIPHER_CTX_SET_PADDING)
  (evp-cipher-ctx-ctrl			HAVE_EVP_CIPHER_CTX_CTRL)
  (evp-cipher-ctx-cipher		HAVE_EVP_CIPHER_CTX_CIPHER)
  (evp-cipher-ctx-nid			HAVE_EVP_CIPHER_CTX_NID)
  (evp-cipher-ctx-block-size		HAVE_EVP_CIPHER_CTX_BLOCK_SIZE)
  (evp-cipher-ctx-key-length		HAVE_EVP_CIPHER_CTX_KEY_LENGTH)
  (evp-cipher-ctx-iv-length		HAVE_EVP_CIPHER_CTX_IV_LENGTH)
  (evp-cipher-ctx-copy			HAVE_EVP_CIPHER_CTX_COPY)
  (evp-cipher-ctx-get-app-data		HAVE_EVP_CIPHER_CTX_GET_APP_DATA)
  (evp-cipher-ctx-set-app-data		HAVE_EVP_CIPHER_CTX_SET_APP_DATA)
  (evp-cipher-ctx-type			HAVE_DECL_EVP_CIPHER_CTX_TYPE)
  (evp-cipher-ctx-flags			HAVE_EVP_CIPHER_CTX_FLAGS)
  (evp-cipher-ctx-mode			HAVE_DECL_EVP_CIPHER_CTX_MODE)
  (evp-cipher-ctx-rand-key		HAVE_EVP_CIPHER_CTX_RAND_KEY)
  (evp-cipher-param-to-asn1		HAVE_EVP_CIPHER_PARAM_TO_ASN1)
  (evp-cipher-asn1-to-param		HAVE_EVP_CIPHER_ASN1_TO_PARAM)
  (evp-cipher-ctx-set-flags		HAVE_EVP_CIPHER_CTX_SET_FLAGS)
  (evp-cipher-ctx-clear-flags		HAVE_EVP_CIPHER_CTX_CLEAR_FLAGS)
  (evp-cipher-ctx-test-flags		HAVE_EVP_CIPHER_CTX_TEST_FLAGS)
  (evp-crypt				HAVE_EVP_CIPHER))


;;;; done

)

;;; end of file
