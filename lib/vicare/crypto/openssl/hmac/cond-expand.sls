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
(library (vicare crypto openssl hmac cond-expand)
  (export vicare-openssl-hmac-features)
  (import (only (vicare language-extensions cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl hmac)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-hmac-features
  (hmac				HAVE_HMAC)
  (hmac-ctx-init		HAVE_HMAC_CTX_INIT)
  (hmac-ctx-cleanup		HAVE_HMAC_CTX_CLEANUP)
  (hmac-init			HAVE_HMAC_INIT)
  (hmac-final			HAVE_HMAC_FINAL)
  (hmac-update			HAVE_HMAC_UPDATE)
  (hmac-ctx-copy		HAVE_HMAC_CTX_COPY)
  (hmac-ctx-set-flags		HAVE_HMAC_CTX_SET_FLAGS)
  (hmac-init-ex			HAVE_HMAC_INIT_EX))


;;;; done

)

;;; end of file
