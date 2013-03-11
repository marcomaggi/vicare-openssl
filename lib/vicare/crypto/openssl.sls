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

    ;; MD5
    md5-ctx
    md5-ctx?
    md5-ctx?/alive
    md5-ctx-custom-destructor
    set-md5-ctx-custom-destructor!
    md5-ctx.vicare-arguments-validation
    md5-ctx/alive.vicare-arguments-validation

    md5-init
    md5-update
    md5-final
    md5

    ;; MDC2
    mdc2-ctx
    mdc2-ctx?
    mdc2-ctx?/alive
    mdc2-ctx-custom-destructor
    set-mdc2-ctx-custom-destructor!
    mdc2-ctx.vicare-arguments-validation
    mdc2-ctx/alive.vicare-arguments-validation

    mdc2-init
    mdc2-update
    mdc2-final
    mdc2

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
  (ffi.foreign-destructor capi.md4-final)
  (ffi.collector-struct-type #f))

(define (md4-init)
  (let ((rv (capi.md4-init)))
    (and rv (make-md4-ctx/owner rv))))

(define md4-update
  (case-lambda
   ((ctx input)
    (md4-update ctx input #f))
   ((ctx input input.len)
    (define who 'md4-update)
    (with-arguments-validation (who)
	((md4-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.md4-update ctx input^ input.len))))))

(define (md4-final ctx)
  (define who 'md4-final)
  (with-arguments-validation (who)
      ((md4-ctx		ctx))
    ($md4-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

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
	(string-to-bytevector string->utf8)
	(capi.md4 input^ input.len))))))


;;;; MD5

(ffi.define-foreign-pointer-wrapper md5-ctx
  (ffi.foreign-destructor capi.md5-final)
  (ffi.collector-struct-type #f))

(define (md5-init)
  (let ((rv (capi.md5-init)))
    (and rv (make-md5-ctx/owner rv))))

(define md5-update
  (case-lambda
   ((ctx input)
    (md5-update ctx input #f))
   ((ctx input input.len)
    (define who 'md5-update)
    (with-arguments-validation (who)
	((md5-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.md5-update ctx input^ input.len))))))

(define (md5-final ctx)
  (define who 'md5-final)
  (with-arguments-validation (who)
      ((md5-ctx		ctx))
    ($md5-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define md5
  (case-lambda
   ((input)
    (md5 input #f))
   ((input input.len)
    (define who 'md5)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.md5 input^ input.len))))))


;;;; MDC2

(ffi.define-foreign-pointer-wrapper mdc2-ctx
  (ffi.foreign-destructor capi.mdc2-final)
  (ffi.collector-struct-type #f))

(define (mdc2-init)
  (let ((rv (capi.mdc2-init)))
    (and rv (make-mdc2-ctx/owner rv))))

(define mdc2-update
  (case-lambda
   ((ctx input)
    (mdc2-update ctx input #f))
   ((ctx input input.len)
    (define who 'mdc2-update)
    (with-arguments-validation (who)
	((mdc2-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.mdc2-update ctx input^ input.len))))))

(define (mdc2-final ctx)
  (define who 'mdc2-final)
  (with-arguments-validation (who)
      ((mdc2-ctx		ctx))
    ($mdc2-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define mdc2
  (case-lambda
   ((input)
    (mdc2 input #f))
   ((input input.len)
    (define who 'mdc2)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.mdc2 input^ input.len))))))


;;;; done

)

;;; end of file
;; Local Variables:
;; eval: (put 'ffi.define-foreign-pointer-wrapper 'scheme-indent-function 1)
;; End:
