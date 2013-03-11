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

    ;; SHA1
    sha1-ctx
    sha1-ctx?
    sha1-ctx?/alive
    sha1-ctx-custom-destructor
    set-sha1-ctx-custom-destructor!
    sha1-ctx.vicare-arguments-validation
    sha1-ctx/alive.vicare-arguments-validation

    sha1-init
    sha1-update
    sha1-final
    sha1

    ;; SHA224
    sha224-ctx
    sha224-ctx?
    sha224-ctx?/alive
    sha224-ctx-custom-destructor
    set-sha224-ctx-custom-destructor!
    sha224-ctx.vicare-arguments-validation
    sha224-ctx/alive.vicare-arguments-validation

    sha224-init
    sha224-update
    sha224-final
    sha224

    ;; SHA256
    sha256-ctx
    sha256-ctx?
    sha256-ctx?/alive
    sha256-ctx-custom-destructor
    set-sha256-ctx-custom-destructor!
    sha256-ctx.vicare-arguments-validation
    sha256-ctx/alive.vicare-arguments-validation

    sha256-init
    sha256-update
    sha256-final
    sha256

    ;; SHA384
    sha384-ctx
    sha384-ctx?
    sha384-ctx?/alive
    sha384-ctx-custom-destructor
    set-sha384-ctx-custom-destructor!
    sha384-ctx.vicare-arguments-validation
    sha384-ctx/alive.vicare-arguments-validation

    sha384-init
    sha384-update
    sha384-final
    sha384

    ;; SHA512
    sha512-ctx
    sha512-ctx?
    sha512-ctx?/alive
    sha512-ctx-custom-destructor
    set-sha512-ctx-custom-destructor!
    sha512-ctx.vicare-arguments-validation
    sha512-ctx/alive.vicare-arguments-validation

    sha512-init
    sha512-update
    sha512-final
    sha512

    ;; RIPEMD160
    ripemd160-ctx
    ripemd160-ctx?
    ripemd160-ctx?/alive
    ripemd160-ctx-custom-destructor
    set-ripemd160-ctx-custom-destructor!
    ripemd160-ctx.vicare-arguments-validation
    ripemd160-ctx/alive.vicare-arguments-validation

    ripemd160-init
    ripemd160-update
    ripemd160-final
    ripemd160

    ;; HMAC
    hmac-ctx
    hmac-ctx?
    hmac-ctx?/alive
    hmac-ctx-custom-destructor
    set-hmac-ctx-custom-destructor!
    hmac-ctx.vicare-arguments-validation
    hmac-ctx/alive.vicare-arguments-validation

    hmac
    #;hmac-ctx-init
    #;hmac-ctx-cleanup
    hmac-init
    hmac-init-ex
    hmac-final
    hmac-update
    hmac-ctx-copy
    hmac-ctx-set-flags

    ;; AES
    aes-options
    aes-set-encrypt-key
    aes-set-decrypt-key
    aes-encrypt
    aes-decrypt
    aes-ecb-encrypt
    aes-cbc-encrypt
    aes-cfb128-encrypt
    aes-cfb1-encrypt
    aes-cfb8-encrypt
    aes-ofb128-encrypt
    aes-ctr128-encrypt
    aes-ige-encrypt
    aes-bi-ige-encrypt
    aes-wrap-key
    aes-unwrap-key


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


;;;; SHA1

(ffi.define-foreign-pointer-wrapper sha1-ctx
  (ffi.foreign-destructor capi.sha1-final)
  (ffi.collector-struct-type #f))

(define (sha1-init)
  (let ((rv (capi.sha1-init)))
    (and rv (make-sha1-ctx/owner rv))))

(define sha1-update
  (case-lambda
   ((ctx input)
    (sha1-update ctx input #f))
   ((ctx input input.len)
    (define who 'sha1-update)
    (with-arguments-validation (who)
	((sha1-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha1-update ctx input^ input.len))))))

(define (sha1-final ctx)
  (define who 'sha1-final)
  (with-arguments-validation (who)
      ((sha1-ctx		ctx))
    ($sha1-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define sha1
  (case-lambda
   ((input)
    (sha1 input #f))
   ((input input.len)
    (define who 'sha1)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha1 input^ input.len))))))


;;;; SHA224

(ffi.define-foreign-pointer-wrapper sha224-ctx
  (ffi.foreign-destructor capi.sha224-final)
  (ffi.collector-struct-type #f))

(define (sha224-init)
  (let ((rv (capi.sha224-init)))
    (and rv (make-sha224-ctx/owner rv))))

(define sha224-update
  (case-lambda
   ((ctx input)
    (sha224-update ctx input #f))
   ((ctx input input.len)
    (define who 'sha224-update)
    (with-arguments-validation (who)
	((sha224-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha224-update ctx input^ input.len))))))

(define (sha224-final ctx)
  (define who 'sha224-final)
  (with-arguments-validation (who)
      ((sha224-ctx		ctx))
    ($sha224-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define sha224
  (case-lambda
   ((input)
    (sha224 input #f))
   ((input input.len)
    (define who 'sha224)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha224 input^ input.len))))))


;;;; SHA256

(ffi.define-foreign-pointer-wrapper sha256-ctx
  (ffi.foreign-destructor capi.sha256-final)
  (ffi.collector-struct-type #f))

(define (sha256-init)
  (let ((rv (capi.sha256-init)))
    (and rv (make-sha256-ctx/owner rv))))

(define sha256-update
  (case-lambda
   ((ctx input)
    (sha256-update ctx input #f))
   ((ctx input input.len)
    (define who 'sha256-update)
    (with-arguments-validation (who)
	((sha256-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha256-update ctx input^ input.len))))))

(define (sha256-final ctx)
  (define who 'sha256-final)
  (with-arguments-validation (who)
      ((sha256-ctx		ctx))
    ($sha256-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define sha256
  (case-lambda
   ((input)
    (sha256 input #f))
   ((input input.len)
    (define who 'sha256)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha256 input^ input.len))))))


;;;; SHA384

(ffi.define-foreign-pointer-wrapper sha384-ctx
  (ffi.foreign-destructor capi.sha384-final)
  (ffi.collector-struct-type #f))

(define (sha384-init)
  (let ((rv (capi.sha384-init)))
    (and rv (make-sha384-ctx/owner rv))))

(define sha384-update
  (case-lambda
   ((ctx input)
    (sha384-update ctx input #f))
   ((ctx input input.len)
    (define who 'sha384-update)
    (with-arguments-validation (who)
	((sha384-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha384-update ctx input^ input.len))))))

(define (sha384-final ctx)
  (define who 'sha384-final)
  (with-arguments-validation (who)
      ((sha384-ctx		ctx))
    ($sha384-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define sha384
  (case-lambda
   ((input)
    (sha384 input #f))
   ((input input.len)
    (define who 'sha384)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha384 input^ input.len))))))


;;;; SHA512

(ffi.define-foreign-pointer-wrapper sha512-ctx
  (ffi.foreign-destructor capi.sha512-final)
  (ffi.collector-struct-type #f))

(define (sha512-init)
  (let ((rv (capi.sha512-init)))
    (and rv (make-sha512-ctx/owner rv))))

(define sha512-update
  (case-lambda
   ((ctx input)
    (sha512-update ctx input #f))
   ((ctx input input.len)
    (define who 'sha512-update)
    (with-arguments-validation (who)
	((sha512-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha512-update ctx input^ input.len))))))

(define (sha512-final ctx)
  (define who 'sha512-final)
  (with-arguments-validation (who)
      ((sha512-ctx		ctx))
    ($sha512-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define sha512
  (case-lambda
   ((input)
    (sha512 input #f))
   ((input input.len)
    (define who 'sha512)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.sha512 input^ input.len))))))


;;;; RIPEMD160

(ffi.define-foreign-pointer-wrapper ripemd160-ctx
  (ffi.foreign-destructor capi.ripemd160-final)
  (ffi.collector-struct-type #f))

(define (ripemd160-init)
  (let ((rv (capi.ripemd160-init)))
    (and rv (make-ripemd160-ctx/owner rv))))

(define ripemd160-update
  (case-lambda
   ((ctx input)
    (ripemd160-update ctx input #f))
   ((ctx input input.len)
    (define who 'ripemd160-update)
    (with-arguments-validation (who)
	((ripemd160-ctx/alive		ctx)
	 (general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.ripemd160-update ctx input^ input.len))))))

(define (ripemd160-final ctx)
  (define who 'ripemd160-final)
  (with-arguments-validation (who)
      ((ripemd160-ctx		ctx))
    ($ripemd160-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define ripemd160
  (case-lambda
   ((input)
    (ripemd160 input #f))
   ((input input.len)
    (define who 'ripemd160)
    (with-arguments-validation (who)
	((general-c-string	input)
	 (size_t/false		input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.ripemd160 input^ input.len))))))


;;;; HMAC

(ffi.define-foreign-pointer-wrapper hmac-ctx
  (ffi.foreign-destructor capi.hmac-final)
  (ffi.collector-struct-type #f))

;;; --------------------------------------------------------------------

(define (%symbol->md who md)
  (case md
    ;;This  mapping  must   be  kept  in  sync  with  the   one  in  the
    ;;implementation of the functions HMAC-INIT and HMAC.
    ((md4)		0)
    ((md5)		1)
    ((mdc2)		2)
    ((sha1)		3)
    ((sha224)		4)
    ((sha256)		5)
    ((sha384)		6)
    ((sha512)		7)
    ((ripemd160)	8)
    ((dss)		9)
    ((dss1)		10)
    (else
     (error who "unknown message digest" md))))

;;; --------------------------------------------------------------------

(define hmac-init
  ;;This  version  performs  the  work  of  both  "HMAC_CTX_init()"  and
  ;;"HMAC_Init()".
  (case-lambda
   ((key md)
    (hmac-init key #f md))
   ((key key.len md)
    (define who 'hmac-init)
    (with-arguments-validation (who)
	((general-c-string	key)
	 (size_t/false		key.len)
	 (symbol		md))
      (with-general-c-strings
	  ((key^	key))
	(string-to-bytevector string->utf8)
	(let ((rv (capi.hmac-init key^ key.len (%symbol->md who md))))
	  (and rv (make-hmac-ctx/owner rv))))))))

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
;; 	 (general-c-string	key)
;; 	 (size_t/false		key.len)
;; 	 (symbol		md))
;;       (with-general-c-strings
;; 	  ((key^	key))
;; 	(string-to-bytevector string->utf8)
;; 	(capi.hmac-init ctx key^ key.len (%symbol->md who md)))))))

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
	 (general-c-string	input)
	 (size_t/false		input.len))
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
      ((symbol			md)
       (general-c-string	key)
       (size_t/false		key.len)
       (general-c-string	input)
       (size_t/false		input.len))
    (with-general-c-strings
	((key^		key)
	 (input^	input))
      (string-to-bytevector string->utf8)
      (capi.hmac (%symbol->md who md) key^ key.len input^ input.len))))


;;;; AES

(define (aes-options ctx)
  (define who 'aes-options)
  (with-arguments-validation (who)
      ()
    (capi.aes-options)))

(define (aes-set-encrypt-key ctx)
  (define who 'aes-set-encrypt-key)
  (with-arguments-validation (who)
      ()
    (capi.aes-set-encrypt-key)))

(define (aes-set-decrypt-key ctx)
  (define who 'aes-set-decrypt-key)
  (with-arguments-validation (who)
      ()
    (capi.aes-set-decrypt-key)))

(define (aes-encrypt ctx)
  (define who 'aes-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-encrypt)))

(define (aes-decrypt ctx)
  (define who 'aes-decrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-decrypt)))

(define (aes-ecb-encrypt ctx)
  (define who 'aes-ecb-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-ecb-encrypt)))

(define (aes-cbc-encrypt ctx)
  (define who 'aes-cbc-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-cbc-encrypt)))

(define (aes-cfb128-encrypt ctx)
  (define who 'aes-cfb128-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-cfb128-encrypt)))

(define (aes-cfb1-encrypt ctx)
  (define who 'aes-cfb1-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-cfb1-encrypt)))

(define (aes-cfb8-encrypt ctx)
  (define who 'aes-cfb8-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-cfb8-encrypt)))

(define (aes-ofb128-encrypt ctx)
  (define who 'aes-ofb128-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-ofb128-encrypt)))

(define (aes-ctr128-encrypt ctx)
  (define who 'aes-ctr128-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-ctr128-encrypt)))

(define (aes-ige-encrypt ctx)
  (define who 'aes-ige-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-ige-encrypt)))

(define (aes-bi-ige-encrypt ctx)
  (define who 'aes-bi-ige-encrypt)
  (with-arguments-validation (who)
      ()
    (capi.aes-bi-ige-encrypt)))

(define (aes-wrap-key ctx)
  (define who 'aes-wrap-key)
  (with-arguments-validation (who)
      ()
    (capi.aes-wrap-key)))

(define (aes-unwrap-key ctx)
  (define who 'aes-unwrap-key)
  (with-arguments-validation (who)
      ()
    (capi.aes-unwrap-key)))


;;;; still to be implemented

(define (hmac-init-ex ctx)
  (define who 'hmac-init-ex)
  (with-arguments-validation (who)
      ()
    (capi.hmac-init-ex)))



;;;; done

)

;;; end of file
;; Local Variables:
;; eval: (put 'ffi.define-foreign-pointer-wrapper 'scheme-indent-function 1)
;; End:
