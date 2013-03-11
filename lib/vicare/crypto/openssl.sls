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

    ;; MD4
    md4-ctx
    md4-ctx?
    md4-ctx?/alive
    md4-ctx-custom-destructor
    set-md4-ctx-custom-destructor!
    md4-ctx.vicare-arguments-validation
    md4-ctx/alive.vicare-arguments-validation

    md4-init
    md4-update
    md4-final
    md4
    md4-transform

;;; --------------------------------------------------------------------
;;; still to be implemented

    )
  (import (vicare)
    (vicare crypto openssl constants)
    (prefix (vicare crypto openssl unsafe-capi)
	    capi.)
    (prefix (vicare ffi)
	    ffi.)
    (prefix (vicare ffi foreign-pointer-wrapper)
	    ffi.)
    (vicare syntactic-extensions)
    (vicare arguments validation)
    (vicare arguments general-c-buffers)
    #;(prefix (vicare words) words.))


;;;; arguments validation

#;(define-argument-validation (fixnum who obj)
  (fixnum? obj)
  (assertion-violation who "expected fixnum as argument" obj))


;;;; version functions

(define (vicare-openssl-version-interface-current)
  (capi.vicare-openssl-version-interface-current))

(define (vicare-openssl-version-interface-revision)
  (capi.vicare-openssl-version-interface-revision))

(define (vicare-openssl-version-interface-age)
  (capi.vicare-openssl-version-interface-age))

(define (vicare-openssl-version)
  (ascii->string (capi.vicare-openssl-version)))


;;;; MD4

(ffi.define-foreign-pointer-wrapper md4-ctx
  (ffi.foreign-destructor capi.md4-abort)
  (ffi.collector-struct-type #f))

(define (md4-init)
  (define who 'md4-init)
  (with-arguments-validation (who)
      ()
    (capi.md4-init)))

(define (md4-update)
  (define who 'md4-update)
  (with-arguments-validation (who)
      ()
    (capi.md4-update)))

(define (md4-final)
  (define who 'md4-final)
  (with-arguments-validation (who)
      ()
    (capi.md4-final)))

(define md4
  (case-lambda
   ((input)
    (md4 input #f))
   ((input input.len)
    (define who 'md4)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(capi.md4 input^ input.len))))))

(define (md4-transform)
  (define who 'md4-transform)
  (with-arguments-validation (who)
      ()
    (capi.md4-transform)))


;;;; done

)

;;; end of file
;; Local Variables:
;; eval: (put 'ffi.define-foreign-pointer-wrapper 'scheme-indent-function 1)
;; End:
