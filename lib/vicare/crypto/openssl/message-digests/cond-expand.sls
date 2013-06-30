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
(library (vicare crypto openssl message-digests cond-expand)
  (export vicare-openssl-message-digests-features)
  (import (only (vicare language-extensions cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl message-digests)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-message-digests-features
  (md4-init			HAVE_MD4_INIT)
  (md4-update			HAVE_MD4_UPDATE)
  (md4-final			HAVE_MD4_FINAL)
  (md4				HAVE_MD4)

  (md5-init			HAVE_MD5_INIT)
  (md5-update			HAVE_MD5_UPDATE)
  (md5-final			HAVE_MD5_FINAL)
  (md5				HAVE_MD5)

  (mdc2-init			HAVE_MDC2_INIT)
  (mdc2-update			HAVE_MDC2_UPDATE)
  (mdc2-final			HAVE_MDC2_FINAL)
  (mdc2				HAVE_MDC2)

  (sha1-init			HAVE_SHA1_INIT)
  (sha1-update			HAVE_SHA1_UPDATE)
  (sha1-final			HAVE_SHA1_FINAL)
  (sha1				HAVE_SHA1)

  (sha224-init			HAVE_SHA224_INIT)
  (sha224-update		HAVE_SHA224_UPDATE)
  (sha224-final			HAVE_SHA224_FINAL)
  (sha224			HAVE_SHA224)

  (sha256-init			HAVE_SHA256_INIT)
  (sha256-update		HAVE_SHA256_UPDATE)
  (sha256-final			HAVE_SHA256_FINAL)
  (sha256			HAVE_SHA256)

  (sha384-init			HAVE_SHA384_INIT)
  (sha384-update		HAVE_SHA384_UPDATE)
  (sha384-final			HAVE_SHA384_FINAL)
  (sha384			HAVE_SHA384)

  (sha512-init			HAVE_SHA512_INIT)
  (sha512-update		HAVE_SHA512_UPDATE)
  (sha512-final			HAVE_SHA512_FINAL)
  (sha512			HAVE_SHA512)

  (ripemd160-init		HAVE_RIPEMD160_INIT)
  (ripemd160-update		HAVE_RIPEMD160_UPDATE)
  (ripemd160-final		HAVE_RIPEMD160_FINAL)
  (ripemd160			HAVE_RIPEMD160)

  (whirlpool-update		HAVE_WHIRLPOOL_UPDATE)
  (whirlpool-final		HAVE_WHIRLPOOL_FINAL)
  (whirlpool			HAVE_WHIRLPOOL))


;;;; done

)

;;; end of file
