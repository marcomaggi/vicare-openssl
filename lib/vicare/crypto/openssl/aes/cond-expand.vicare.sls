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
(library (vicare crypto openssl aes cond-expand)
  (export vicare-openssl-aes-features)
  (import (only (vicare language-extensions cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl aes)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-aes-features
  (aes-options				HAVE_AES_OPTIONS)
  (aes-set-encrypt-key			HAVE_AES_SET_ENCRYPT_KEY)
  (aes-set-decrypt-key			HAVE_AES_SET_DECRYPT_KEY)
  (aes-encrypt				HAVE_AES_ENCRYPT)
  (aes-decrypt				HAVE_AES_DECRYPT)
  (aes-ecb-encrypt			HAVE_AES_ECB_ENCRYPT)
  (aes-ecb-decrypt			HAVE_AES_ECB_ENCRYPT)
  (aes-cbc-encrypt			HAVE_AES_CBC_ENCRYPT)
  (aes-cbc-decrypt			HAVE_AES_CBC_ENCRYPT)
  (aes-cfb128-encrypt			HAVE_AES_CFB128_ENCRYPT)
  (aes-cfb128-decrypt			HAVE_AES_CFB128_ENCRYPT)
  (aes-cfb1-encrypt			HAVE_AES_CFB1_ENCRYPT)
  (aes-cfb1-decrypt			HAVE_AES_CFB1_ENCRYPT)
  (aes-cfb8-encrypt			HAVE_AES_CFB8_ENCRYPT)
  (aes-cfb8-decrypt			HAVE_AES_CFB8_ENCRYPT)
  (aes-ofb128-encrypt			HAVE_AES_OFB128_ENCRYPT)
  (aes-ctr128-encrypt			HAVE_AES_CTR128_ENCRYPT)
  (aes-ige-encrypt			HAVE_AES_IGE_ENCRYPT)
  (aes-bi-ige-encrypt			HAVE_AES_BI_IGE_ENCRYPT)
  (aes-wrap-key				HAVE_AES_WRAP_KEY)
  (aes-unwrap-key			HAVE_AES_UNWRAP_KEY))


;;;; done

)

;;; end of file
