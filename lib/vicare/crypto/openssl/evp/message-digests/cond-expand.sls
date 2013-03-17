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
(library (vicare crypto openssl evp message-digests cond-expand)
  (export vicare-openssl-evp-message-digests-features)
  (import (only (vicare cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl evp message-digests)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-evp-message-digests-features
  (evp-md-ctx-create			HAVE_EVP_MD_CTX_CREATE)
  (evp-md-ctx-destroy			HAVE_EVP_MD_CTX_DESTROY)
  (evp-digest-init			HAVE_EVP_DIGESTINIT)
  (evp-digest-final			HAVE_EVP_DIGESTFINAL)
  (evp-digest-update			HAVE_EVP_DIGESTUPDATE)
  (evp-md-ctx-copy			HAVE_EVP_MD_CTX_COPY)
  (evp-md-ctx-size			HAVE_EVP_MD_CTX_SIZE)
  (evp-md-ctx-block-size		HAVE_EVP_MD_CTX_BLOCK_SIZE)

  (evp-md-null				HAVE_EVP_MD_NULL)
  (evp-md2				HAVE_EVP_MD2)
  (evp-md4				HAVE_EVP_MD4)
  (evp-md5				HAVE_EVP_MD5)
  (evp-sha				HAVE_EVP_SHA)
  (evp-sha1				HAVE_EVP_SHA1)
  (evp-dss				HAVE_EVP_DSS)
  (evp-dss1				HAVE_EVP_DSS1)
  (evp-ecdsa				HAVE_EVP_ECDSA)
  (evp-sha224				HAVE_EVP_SHA224)
  (evp-sha256				HAVE_EVP_SHA256)
  (evp-sha384				HAVE_EVP_SHA384)
  (evp-sha512				HAVE_EVP_SHA512)
  (evp-mdc2				HAVE_EVP_MDC2)
  (evp-ripemd160			HAVE_EVP_RIPEMD160)
  (evp-whirlpool			HAVE_EVP_WHIRLPOOL)

  (evp-md-name				HAVE_EVP_MD_NAME)
  (evp-md-type				HAVE_EVP_MD_TYPE)
  (evp-md-nid				HAVE_EVP_MD_NID)
  (evp-md-size				HAVE_EVP_MD_SIZE)
  (evp-md-block-size			HAVE_EVP_MD_BLOCK_SIZE)

  (evp-md-pkey-type			HAVE_EVP_MD_PKEY_TYPE)
  (evp-md-flags				HAVE_EVP_MD_FLAGS)
  (evp-md-ctx-md			HAVE_EVP_MD_CTX_MD)
  (evp-md-ctx-type			HAVE_EVP_MD_CTX_TYPE)
  (evp-md-ctx-set-flags			HAVE_EVP_MD_CTX_SET_FLAGS)
  (evp-md-ctx-clear-flags		HAVE_EVP_MD_CTX_CLEAR_FLAGS)
  (evp-md-ctx-test-flags		HAVE_EVP_MD_CTX_TEST_FLAGS)
  (evp-digest				HAVE_EVP_DIGEST)
  (evp-get-digestbyname			HAVE_EVP_GET_DIGESTBYNAME))


;;;; done

)

;;; end of file
