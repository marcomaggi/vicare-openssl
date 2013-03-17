;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: EVP message digests API
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


#!vicare
#!(load-shared-library "vicare-openssl")
(library (vicare crypto openssl evp message-digests)
  (export

    ;; EVP message digest context functions
    evp-md-ctx
    evp-md-ctx?
    evp-md-ctx?/alive
    evp-md-ctx?/running
    evp-md-ctx?/alive-not-running
    evp-md-ctx-custom-destructor
    set-evp-md-ctx-custom-destructor!
    evp-md-ctx.vicare-arguments-validation
    evp-md-ctx/alive.vicare-arguments-validation
    evp-md-ctx/running.vicare-arguments-validation
    evp-md-ctx/alive-not-running.vicare-arguments-validation

    evp-md-ctx-create		evp-md-ctx-destroy
    evp-digest-init		evp-digest-final
    evp-digest-update		evp-md-ctx-copy

    evp-md-ctx-size		evp-md-ctx-block-size

    ;; EVP message digest algorithms
    evp-md
    evp-md?
    evp-md.vicare-arguments-validation
    false-or-evp-md.vicare-arguments-validation

    evp-md-null
    evp-md2			evp-md4
    evp-md5			evp-sha
    evp-sha1			evp-dss
    evp-dss1			evp-ecdsa
    evp-sha224			evp-sha256
    evp-sha384			evp-sha512
    evp-mdc2			evp-ripemd160
    evp-whirlpool
    evp-md-name			evp-md-type
    evp-md-nid
    evp-md-size			evp-md-block-size

    evp-md-pkey-type
    evp-md-flags
    evp-md-ctx-md
    evp-md-ctx-type
    evp-md-ctx-set-flags
    evp-md-ctx-clear-flags
    evp-md-ctx-test-flags
    evp-digest
    evp-get-digestbyname)
  (import (vicare)
    (vicare crypto openssl constants)
    (vicare crypto openssl features)
    (prefix (vicare crypto openssl unsafe-capi)
	    capi.)
    (prefix (vicare crypto openssl helpers)
	    help.)
    #;(prefix (vicare ffi) ffi.)
    (prefix (vicare ffi foreign-pointer-wrapper)
	    ffi.)
    (vicare syntactic-extensions)
    (vicare arguments validation)
    (vicare arguments general-c-buffers))


;;;; arguments validation

(define-argument-validation (evp-md/symbol who obj)
  (or (evp-md? obj)
      (symbol? obj))
  (assertion-violation who
    "expected instance of \"evp-md\" or symbol as argument" obj))

(define-argument-validation (evp-md-ctx/running who obj)
  (evp-md-ctx?/running obj)
  (assertion-violation who "expected running EVP message digest context" obj))

(define-argument-validation (evp-md-ctx/alive-not-running who obj)
  (evp-md-ctx?/alive-not-running obj)
  (assertion-violation who
    "expected alive but not running EVP message digest context" obj))


;;;; EVP message digest context functions

(ffi.define-foreign-pointer-wrapper evp-md-ctx
  (ffi.fields running?)
  (ffi.foreign-destructor capi.evp-md-ctx-destroy)
  (ffi.collector-struct-type #f))

(define (evp-md-ctx?/running obj)
  (and (evp-md-ctx? obj)
       ($evp-md-ctx-running? obj)))

(define (evp-md-ctx?/alive-not-running obj)
  (and (evp-md-ctx?/alive obj)
       (not ($evp-md-ctx-running? obj))))

;;; --------------------------------------------------------------------

(define (evp-md-ctx-create)
  (let ((rv (capi.evp-md-ctx-create)))
    (and rv (make-evp-md-ctx/owner rv #f))))

(define (evp-md-ctx-destroy ctx)
  (define who 'evp-md-ctx-destroy)
  (with-arguments-validation (who)
      ((evp-md-ctx	ctx))
    ($set-evp-md-ctx-running?! ctx #f)
    ($evp-md-ctx-finalise ctx)))

(define (evp-md-ctx-copy dst src)
  (define who 'evp-md-ctx-copy)
  (with-arguments-validation (who)
      ((evp-md-ctx/alive-not-running	dst)
       (evp-md-ctx/running		src))
    (cond ((capi.evp-md-ctx-copy dst src)
	   => (lambda (rv)
		($set-evp-md-ctx-running?! dst #t)
		rv))
	  (else #f))))

;;; --------------------------------------------------------------------

(define (evp-digest-init ctx md)
  (define who 'evp-digest-init)
  (with-arguments-validation (who)
      ((evp-md-ctx/alive-not-running	ctx)
       (evp-md/symbol			md))
    (cond ((capi.evp-digest-init ctx (if (symbol? md)
					 (help.symbol->message-digest-index who md)
				       ($evp-md-pointer md)))
	   => (lambda (rv)
		($set-evp-md-ctx-running?! ctx #t)
		rv))
	  (else #f))))

(define (evp-digest-final ctx)
  (define who 'evp-digest-final)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx))
    (begin0
	(capi.evp-digest-final ctx)
      ($set-evp-md-ctx-running?! ctx #f))))

;;; --------------------------------------------------------------------

(define evp-digest-update
  (case-lambda
   ((ctx buf)
    (evp-digest-update ctx buf #f))
   ((ctx buf buf.len)
    (define who 'evp-digest-update)
    (with-arguments-validation (who)
	((evp-md-ctx/running	ctx)
	 (general-c-string*	buf buf.len))
      (with-general-c-strings
	  ((buf^	buf))
	(string-to-bytevector string->utf8)
	(capi.evp-digest-update ctx buf^ buf.len))))))

;;; --------------------------------------------------------------------

(define (evp-md-ctx-size ctx)
  (define who 'evp-md-ctx-size)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx))
    (capi.evp-md-ctx-size ctx)))

(define (evp-md-ctx-block-size ctx)
  (define who 'evp-md-ctx-block-size)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx))
    (capi.evp-md-ctx-block-size ctx)))

(define (evp-md-ctx-type ctx)
  (define who 'evp-md-ctx-type)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx))
    (capi.evp-md-ctx-type ctx)))

;;; --------------------------------------------------------------------

(define (evp-md-ctx-md ctx)
  (define who 'evp-md-ctx-md)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx))
    (cond ((capi.evp-md-ctx-md ctx)
	   => (lambda (rv)
		(make-evp-md rv)))
	  (else #f))))

;;; --------------------------------------------------------------------

(define (evp-md-ctx-set-flags ctx flags)
  (define who 'evp-md-ctx-set-flags)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx)
       (signed-int		flags))
    (capi.evp-md-ctx-set-flags ctx flags)))

(define (evp-md-ctx-clear-flags ctx flags)
  (define who 'evp-md-ctx-clear-flags)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx)
       (signed-int		flags))
    (capi.evp-md-ctx-clear-flags ctx flags)))

(define (evp-md-ctx-test-flags ctx flags)
  (define who 'evp-md-ctx-test-flags)
  (with-arguments-validation (who)
      ((evp-md-ctx/running	ctx)
       (signed-int		flags))
    (capi.evp-md-ctx-test-flags ctx flags)))


;;;; EVP message digest algorithms functions

(define-struct-extended evp-md
  (pointer)
  %evp-md-printer
  #f)

(define (%evp-md-printer S port sub-printer)
  (define (%display thing)
    (display thing port))
  (define (%write thing)
    (write thing port))
  (%display "#[evp-md")
  (%display " pointer=")	(%write ($evp-md-pointer S))
  (%display " algorithm=")	(%write (evp-md-name S))
  (%display " size=")		(%write (capi.evp-md-size S))
  (%display " block-size=")	(%write (capi.evp-md-block-size S))
  (%display "]"))

;;; --------------------------------------------------------------------

(let-syntax ((define-maker
	       (syntax-rules ()
		 ((_ ?who ?func)
		  (define (?who)
		    (make-evp-md (?func)))))))
  (define-maker evp-md-null	capi.evp-md-null)
  (define-maker evp-md2		capi.evp-md2)
  (define-maker evp-md4		capi.evp-md4)
  (define-maker evp-md5		capi.evp-md5)
  (define-maker evp-sha		capi.evp-sha)
  (define-maker evp-sha1	capi.evp-sha1)
  (define-maker evp-dss		capi.evp-dss)
  (define-maker evp-dss1	capi.evp-dss1)
  (define-maker evp-ecdsa	capi.evp-ecdsa)
  (define-maker evp-sha224	capi.evp-sha224)
  (define-maker evp-sha256	capi.evp-sha256)
  (define-maker evp-sha384	capi.evp-sha384)
  (define-maker evp-sha512	capi.evp-sha512)
  (define-maker evp-mdc2	capi.evp-mdc2)
  (define-maker evp-ripemd160	capi.evp-ripemd160)
  (define-maker evp-whirlpool	capi.evp-whirlpool))

;;; --------------------------------------------------------------------

(define (evp-md-size algo)
  (define who 'evp-md-size)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (capi.evp-md-size algo)))

(define (evp-md-block-size algo)
  (define who 'evp-md-block-size)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (capi.evp-md-block-size algo)))

(define (evp-md-name algo)
  (define who 'evp-md-name)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (cond ((capi.evp-md-name algo)
	   => (lambda (rv)
		(ascii->string rv)))
	  (else #f))))

(define (evp-md-type algo)
  (define who 'evp-md-type)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (capi.evp-md-type algo)))

(define (evp-md-nid algo)
  (define who 'evp-md-nid)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (capi.evp-md-nid algo)))

(define (evp-md-flags algo)
  (define who 'evp-md-flags)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (capi.evp-md-flags algo)))

(define (evp-md-pkey-type algo)
  (define who 'evp-md-pkey-type)
  (with-arguments-validation (who)
      ((evp-md		algo))
    (capi.evp-md-pkey-type algo)))

;;; --------------------------------------------------------------------

(define evp-digest
  (case-lambda
   ((buf algo)
    (evp-digest buf #f algo))
   ((buf buf.len algo)
    (define who 'evp-digest)
    (with-arguments-validation (who)
	((general-c-string*	buf buf.len)
	 (evp-md		algo))
      (with-general-c-strings
	  ((buf^	buf))
	(string-to-bytevector string->utf8)
	(capi.evp-digest buf^ buf.len algo))))))

(define (evp-get-digestbyname name)
  (define who 'evp-get-digestbyname)
  (with-arguments-validation (who)
      ((general-c-string	name))
    (with-general-c-strings
	((name^		name))
      (cond ((capi.evp-get-digestbyname name^)
	     => (lambda (rv)
		  (make-evp-md rv)))
	    (else #f)))))


;;;; done

)

;;; end of file
