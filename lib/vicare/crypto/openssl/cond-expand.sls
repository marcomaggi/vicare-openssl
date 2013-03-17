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
(library (vicare crypto openssl cond-expand)
  (export vicare-openssl-features)
  (import (only (vicare cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-features
  (ssl-library-init		HAVE_SSL_LIBRARY_INIT))


;;;; done

)

;;; end of file
