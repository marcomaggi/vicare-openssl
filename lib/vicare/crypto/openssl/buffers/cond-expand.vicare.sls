;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: feature-based conditional expansion
;;;Date: Fri Jul  5, 2013
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
(library (vicare crypto openssl buffers cond-expand)
  (export vicare-openssl-buffers-features)
  (import (only (vicare language-extensions cond-expand helpers)
		define-cond-expand-identifiers-helper)
    (vicare crypto openssl features)
    (for (vicare crypto openssl buffers)
	 (meta -1)))


(define-cond-expand-identifiers-helper vicare-openssl-buffers-features
  ;; cond-expand clauses buffer
  (buf-mem-new			HAVE_BUF_MEM_NEW)
  (buf-mem-free			HAVE_BUF_MEM_FREE)
  (buf-mem-grow			HAVE_BUF_MEM_GROW)
  (buf-mem-grow-clean		HAVE_BUF_MEM_GROW_CLEAN)
  ;; (buf-strdup			HAVE_BUF_STRDUP)
  ;; (buf-strndup			HAVE_BUF_STRNDUP)
  ;; (buf-memdup			HAVE_BUF_MEMDUP)
  ;; (buf-reverse			HAVE_BUF_REVERSE)
  ;; (buf-strlcpy			HAVE_BUF_STRLCPY)
  ;; (buf-strlcat			HAVE_BUF_STRLCAT)
  ;; (err-load-buf-strings		HAVE_ERR_LOAD_BUF_STRINGS)
  )


;;;; done

)

;;; end of file
