;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: HMAC low-level API
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
(library (vicare crypto openssl hmac)
  (export

    hmac-ctx
    hmac-ctx?
    hmac-ctx?/alive
    hmac-ctx-custom-destructor
    set-hmac-ctx-custom-destructor!
    hmac-ctx.vicare-arguments-validation
    hmac-ctx/alive.vicare-arguments-validation

    hmac-ctx-putprop		hmac-ctx-getprop
    hmac-ctx-remprop		hmac-ctx-property-list

    hmac
    #;hmac-ctx-init
    #;hmac-ctx-cleanup
    hmac-init
    hmac-final
    hmac-update
    hmac-ctx-copy
    hmac-ctx-set-flags

;;; --------------------------------------------------------------------
;;; still to be implemented

    hmac-init-ex)
  (import (vicare)
    (vicare crypto openssl constants)
    (vicare crypto openssl features)
    (only (vicare crypto openssl evp message-digests)
	  evp-md?)
    (prefix (vicare crypto openssl unsafe-capi)
	    capi.)
    (prefix (vicare crypto openssl helpers)
	    help.)
    #;(prefix (vicare ffi) ffi.)
    (prefix (vicare ffi foreign-pointer-wrapper)
	    ffi.)
    (vicare language-extensions syntaxes)
    (vicare arguments validation)
    (vicare arguments general-c-buffers))


;;;; arguments validation

(define-argument-validation (evp-md/symbol who obj)
  (or (evp-md? obj)
      (symbol? obj))
  (assertion-violation who
    "expected instance of \"evp-md\" or symbol as argument" obj))


;;;; HMAC

(ffi.define-foreign-pointer-wrapper hmac-ctx
  (ffi.foreign-destructor capi.hmac-final)
  (ffi.collector-struct-type #f))

;;; --------------------------------------------------------------------

(define (hmac-init key key.len md)
  ;;This  version  performs  the  work  of  both  "HMAC_CTX_init()"  and
  ;;"HMAC_Init()".
  (define who 'hmac-init)
  (with-arguments-validation (who)
      ((general-c-string*	key key.len)
       (evp-md/symbol		md))
    (with-general-c-strings
	((key^	key))
      (string-to-bytevector string->utf8)
      (let ((rv (capi.hmac-init key^ key.len (if (symbol? md)
						 (help.symbol->message-digest-index who md)
					       md))))
	(and rv (make-hmac-ctx/owner rv))))))

;;These  old   versions  perform  the  work   of  "HMAC_CTX_init()"  and
;;"HMAC_Init()" separately.
;;
;; (define (hmac-ctx-init)
;;   (let ((rv (capi.hmac-ctx-init)))
;;     (and rv (make-hmac-ctx/owner rv))))
;;
;; (define hmac-init
;;   (case-lambda
;;    ((ctx key md)
;;     (hmac-init ctx key #f md))
;;    ((ctx key key.len md)
;;     (define who 'hmac-init)
;;     (with-arguments-validation (who)
;; 	((hmac-ctx/alive	ctx)
;; 	 (general-c-string*	key key.len)
;; 	 (symbol		md))
;;       (with-general-c-strings
;; 	  ((key^	key))
;; 	(string-to-bytevector string->utf8)
;; 	(capi.hmac-init ctx key^ key.len (help.symbol->message-digest-index who md)))))))

;;; --------------------------------------------------------------------

(define (hmac-final ctx)
  ;;These  version performs  the work  of both  "HMAC_CTX_cleanup()" and
  ;;"HMAC_Final()".
  ;;
  (define who 'hmac-final)
  (with-arguments-validation (who)
      ((hmac-ctx	ctx))
    ($hmac-ctx-finalise ctx)))

;;These  old  versions  perform  the work  of  "HMAC_CTX_cleanup()"  and
;;"HMAC_Final()" separately.
;;
;; (define (hmac-ctx-cleanup ctx)
;;   (define who 'hmac-ctx-cleanup)
;;   (with-arguments-validation (who)
;;       ((hmac-ctx	ctx))
;;     ($hmac-ctx-finalise ctx)))
;;
;; (define (hmac-final ctx)
;;   (define who 'hmac-final)
;;   (with-arguments-validation (who)
;;       ((hmac-ctx/alive	ctx))
;;     (capi.hmac-final ctx)))

;;; --------------------------------------------------------------------

(define hmac-update
  (case-lambda
   ((ctx input)
    (hmac-update ctx input #f))
   ((ctx input input.len)
    (define who 'hmac-update)
    (with-arguments-validation (who)
	((hmac-ctx/alive	ctx)
	 (general-c-string*	input input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.hmac-update ctx input^ input.len))))))

;;; --------------------------------------------------------------------

(define (hmac-ctx-copy dst-ctx src-ctx)
  (define who 'hmac-ctx-copy)
  (with-arguments-validation (who)
      ((hmac-ctx/alive	dst-ctx)
       (hmac-ctx/alive	src-ctx))
    (capi.hmac-ctx-copy dst-ctx src-ctx)))

(define (hmac-ctx-set-flags ctx flags)
  (define who 'hmac-ctx-set-flags)
  (with-arguments-validation (who)
      ((hmac-ctx/alive	ctx)
       (unsigned-long	flags))
    (capi.hmac-ctx-set-flags ctx flags)))

;;; --------------------------------------------------------------------

(define (hmac md key key.len input input.len)
  (define who 'hmac)
  (with-arguments-validation (who)
      ((evp-md/symbol		md)
       (general-c-string*	key key.len)
       (general-c-string*	input input.len))
    (with-general-c-strings
	((key^		key)
	 (input^	input))
      (string-to-bytevector string->utf8)
      (capi.hmac (if (symbol? md)
		     (help.symbol->message-digest-index who md)
		   md)
		 key^ key.len input^ input.len))))


;;;; still to be implemented

(define (hmac-init-ex ctx)
  (define who 'hmac-init-ex)
  (with-arguments-validation (who)
      ()
    (capi.hmac-init-ex)))


;;;; done

)

;;; end of file
