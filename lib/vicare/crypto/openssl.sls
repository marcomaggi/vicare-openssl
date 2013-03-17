;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: OpenSSL binding backend
;;;Date: Sat Mar  9, 2013
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
;;;MERCHANTABILITY  or FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU
;;;General Public License for more details.
;;;
;;;You should  have received  a copy of  the GNU General  Public License
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;


#!vicare
#!(load-shared-library "vicare-openssl")
(library (vicare crypto openssl)
  (export

    ;; version numbers and strings
    vicare-openssl-version-interface-current
    vicare-openssl-version-interface-revision
    vicare-openssl-version-interface-age
    vicare-openssl-version

    ;; initialisation functions
    ssl-library-init
    )
  (import (vicare)
    (prefix (vicare crypto openssl unsafe-capi)
	    capi.)
    (prefix (vicare ffi foreign-pointer-wrapper)
	    ffi.)
    (vicare syntactic-extensions)
    (vicare arguments validation))


;;;; version functions

(define (vicare-openssl-version-interface-current)
  (capi.vicare-openssl-version-interface-current))

(define (vicare-openssl-version-interface-revision)
  (capi.vicare-openssl-version-interface-revision))

(define (vicare-openssl-version-interface-age)
  (capi.vicare-openssl-version-interface-age))

(define (vicare-openssl-version)
  (ascii->string (capi.vicare-openssl-version)))


;;;; initialisation functions

(define (ssl-library-init)
  (capi.ssl-library-init))



;;;; done

)

;;; end of file
;; Local Variables:
;; eval: (put 'ffi.define-foreign-pointer-wrapper 'scheme-indent-function 1)
;; End:
