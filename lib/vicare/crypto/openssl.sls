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

    ;; SSL
    ssl-library-init

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

    ;; WHIRLPOOL
    whirlpool-ctx
    whirlpool-ctx?
    whirlpool-ctx?/alive
    whirlpool-ctx-custom-destructor
    set-whirlpool-ctx-custom-destructor!
    whirlpool-ctx.vicare-arguments-validation
    whirlpool-ctx/alive.vicare-arguments-validation

    whirlpool-init
    whirlpool-update
    whirlpool-final
    whirlpool

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
    hmac-final
    hmac-update
    hmac-ctx-copy
    hmac-ctx-set-flags

    ;; AES
    aes-key
    aes-key?
    aes-key?/alive
    aes-key-custom-destructor
    set-aes-key-custom-destructor!
    aes-key.vicare-arguments-validation
    aes-key/alive.vicare-arguments-validation

    aes-options
    aes-set-encrypt-key		aes-set-decrypt-key
    aes-encrypt			aes-decrypt
    aes-ecb-encrypt		aes-ecb-decrypt
    aes-cbc-encrypt		aes-cbc-decrypt
    ;; aes-cfb128-encrypt	aes-cfb128-decrypt
    ;; aes-cfb1-encrypt		aes-cfb1-decrypt
    ;; aes-cfb8-encrypt		aes-cfb8-decrypt
    aes-ofb128-encrypt
    aes-ctr128-encrypt
    aes-ige-encrypt
    aes-bi-ige-encrypt
    aes-wrap-key		aes-unwrap-key

    aes-block-len?
    aes-data-len?
    aes-key-len?
    aes-block-len.vicare-arguments-validation
    aes-data-len.vicare-arguments-validation
    aes-key-len.vicare-arguments-validation

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
    evp-get-digestbyname

;;; --------------------------------------------------------------------
;;; still to be implemented

    hmac-init-ex
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
    (prefix (vicare unsafe-operations)
	    $)
    #;(prefix (vicare words) words.))


;;;; arguments validation

(define-argument-validation (aes-block-len who buf buf.len)
  ;;BUF must  be a generalised  C buffer; BUF.LEN  must be false  or the
  ;;number of octets referenced by BUF, when BUF is a pointer object.
  ;;
  ;;Succeed if the length of the buffer equals the AES block size.
  ;;
  (= AES_BLOCK_SIZE (general-c-buffer-len buf buf.len))
  (assertion-violation who
    "invalid data block length for AES encryption" buf.len))

(define-argument-validation (aes-data-len who buf buf.len)
  ;;BUF must  be a generalised  C buffer; BUF.LEN  must be false  or the
  ;;number of octets referenced by BUF, when BUF is a pointer object.
  ;;
  ;;Succeed if the length of the buffer  is an exact multiple of the AES
  ;;block size.
  ;;
  (aes-data-len? (general-c-buffer-len buf buf.len))
  (assertion-violation who
    "invalid data block length for AES encryption" buf.len))

(define-argument-validation (aes-key-len who obj)
  ;;Succeed if OBJ is a finxum representing a valid AES key length.
  ;;
  (aes-key-len? obj)
  (assertion-violation who
    "invalid AES key length, expected fixnum 16, 24 or 32" obj))

;;; --------------------------------------------------------------------


;;;; helpers

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
    ((whirlpool)	9)
    ((dss)		10)
    ((dss1)		11)
    (else
     (error who "unknown message digest" md))))


;;;; version functions

(define (vicare-openssl-version-interface-current)
  (capi.vicare-openssl-version-interface-current))

(define (vicare-openssl-version-interface-revision)
  (capi.vicare-openssl-version-interface-revision))

(define (vicare-openssl-version-interface-age)
  (capi.vicare-openssl-version-interface-age))

(define (vicare-openssl-version)
  (ascii->string (capi.vicare-openssl-version)))


;;;; SSL

(define (ssl-library-init)
  (capi.ssl-library-init))


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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	((mdc2-ctx/alive	ctx)
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
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
	 (general-c-string*	input input.len))
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
	((general-c-string*	input input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.ripemd160 input^ input.len))))))


;;;; WHIRLPOOL

(ffi.define-foreign-pointer-wrapper whirlpool-ctx
  (ffi.foreign-destructor capi.whirlpool-final)
  (ffi.collector-struct-type #f))

(define (whirlpool-init)
  (let ((rv (capi.whirlpool-init)))
    (and rv (make-whirlpool-ctx/owner rv))))

(define whirlpool-update
  (case-lambda
   ((ctx input)
    (whirlpool-update ctx input #f))
   ((ctx input input.len)
    (define who 'whirlpool-update)
    (with-arguments-validation (who)
	((whirlpool-ctx/alive		ctx)
	 (general-c-string*	input input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.whirlpool-update ctx input^ input.len))))))

(define (whirlpool-final ctx)
  (define who 'whirlpool-final)
  (with-arguments-validation (who)
      ((whirlpool-ctx		ctx))
    ($whirlpool-ctx-finalise ctx)))

;;; --------------------------------------------------------------------

(define whirlpool
  (case-lambda
   ((input)
    (whirlpool input #f))
   ((input input.len)
    (define who 'whirlpool)
    (with-arguments-validation (who)
	((general-c-string*	input input.len))
      (with-general-c-strings
	  ((input^	input))
	(string-to-bytevector string->utf8)
	(capi.whirlpool input^ input.len))))))


;;;; HMAC

(ffi.define-foreign-pointer-wrapper hmac-ctx
  (ffi.foreign-destructor capi.hmac-final)
  (ffi.collector-struct-type #f))

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
	((general-c-string*	key key.len)
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
;; 	 (general-c-string*	key key.len)
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
      ((symbol			md)
       (general-c-string*	key key.len)
       (general-c-string*	input input.len))
    (with-general-c-strings
	((key^		key)
	 (input^	input))
      (string-to-bytevector string->utf8)
      (capi.hmac (%symbol->md who md) key^ key.len input^ input.len))))


;;;; AES

(ffi.define-foreign-pointer-wrapper aes-key
  (ffi.foreign-destructor capi.aes-finalise)
  (ffi.collector-struct-type #f))

;;; --------------------------------------------------------------------

(define (aes-block-len? obj)
  (and (fixnum? obj)
       (= AES_BLOCK_SIZE obj)))

(define (aes-data-len? obj)
  (and (fixnum? obj)
       (zero? (mod obj AES_BLOCK_SIZE))))

(define (aes-key-len? obj)
  (and (fixnum? obj)
       (or ($fx= obj 16)
	   ($fx= obj 24)
	   ($fx= obj 32))))

(define (aes-options)
  (define who 'aes-options)
  (cond ((capi.aes-options)
	 => (lambda (rv)
	      (ascii->string rv)))
	(else
	 (error who "error acquiring options string for AES"))))

;;; --------------------------------------------------------------------

(define aes-set-encrypt-key
  (case-lambda
   ((key)
    (aes-set-encrypt-key key #f))
   ((key key.len)
    (define who 'aes-set-encrypt-key)
    (with-arguments-validation (who)
	((general-c-string*	key key.len))
      (with-general-c-strings
	  ((key^	key))
	(let ((key.len (general-c-buffer-len key^ key.len)))
	  (with-arguments-validation (who)
	      ((aes-key-len	key.len))
	    (let ((rv (capi.aes-set-encrypt-key key^ key.len)))
	      (and rv (make-aes-key/owner rv))))))))))

(define aes-set-decrypt-key
  (case-lambda
   ((key)
    (aes-set-decrypt-key key #f))
   ((key key.len)
    (define who 'aes-set-decrypt-key)
    (with-arguments-validation (who)
	((general-c-string*	key key.len))
      (with-general-c-strings
	  ((key^	key))
	(let ((key.len (general-c-buffer-len key^ key.len)))
	  (with-arguments-validation (who)
	      ((aes-key-len	key.len))
	    (let ((rv (capi.aes-set-decrypt-key key^ key.len)))
	      (and rv (make-aes-key/owner rv))))))))))

;;; --------------------------------------------------------------------

(define (aes-encrypt in in.len ou ou.len ctx)
  (define who 'aes-encrypt)
  (with-arguments-validation (who)
      ((general-c-buffer	in)
       (size_t/false		in.len)
       (aes-block-len		ou in.len)
       (general-c-buffer	ou)
       (size_t/false		ou.len)
       (aes-block-len		ou ou.len)
       (aes-key/alive		ctx))
    (capi.aes-encrypt in ou ctx)))

(define (aes-decrypt in in.len ou ou.len ctx)
  (define who 'aes-decrypt)
  (with-arguments-validation (who)
      ((general-c-buffer	in)
       (size_t/false		in.len)
       (aes-block-len		ou in.len)
       (general-c-buffer	ou)
       (size_t/false		ou.len)
       (aes-block-len		ou ou.len)
       (aes-key/alive		ctx))
    (capi.aes-decrypt in ou ctx)))

;;; --------------------------------------------------------------------

(module (aes-ecb-encrypt aes-ecb-decrypt)

  (define (aes-ecb-encrypt in in.len ou ou.len ctx)
    (%aes-ecb-encrypt 'aes-ecb-encrypt in in.len ou ou.len ctx AES_ENCRYPT))

  (define (aes-ecb-decrypt in in.len ou ou.len ctx)
    (%aes-ecb-encrypt 'aes-ecb-decrypt in in.len ou ou.len ctx AES_DECRYPT))

  (define (%aes-ecb-encrypt who in in.len ou ou.len ctx mode)
    (with-arguments-validation (who)
	((general-c-buffer	in)
	 (size_t/false		in.len)
	 (aes-block-len		ou in.len)
	 (general-c-buffer	ou)
	 (size_t/false		ou.len)
	 (aes-block-len		ou ou.len)
	 (aes-key/alive		ctx))
      (capi.aes-ecb-encrypt in ou ctx mode)))

  #| end of module |# )

(module (aes-cbc-encrypt aes-cbc-decrypt)

  (define (aes-cbc-encrypt in in.len ou ou.len ctx iv iv.len)
    (%aes-cbc-encrypt 'aes-cbc-encrypt in in.len ou ou.len ctx iv iv.len AES_ENCRYPT))

  (define (aes-cbc-decrypt in in.len ou ou.len ctx iv iv.len)
    (%aes-cbc-encrypt 'aes-cbc-decrypt in in.len ou ou.len ctx iv iv.len AES_DECRYPT))

  (define (%aes-cbc-encrypt who in in.len ou ou.len ctx iv iv.len mode)
    (with-arguments-validation (who)
	((general-c-buffer	in)
	 (size_t/false		in.len)
	 (aes-data-len		ou in.len)
	 (general-c-buffer	ou)
	 (size_t/false		ou.len)
	 (aes-data-len		ou ou.len)
	 (aes-key/alive		ctx)
	 (general-c-buffer	iv)
	 (size_t/false		iv.len)
	 (aes-block-len		iv iv.len))
      (capi.aes-cbc-encrypt in in.len ou ou.len ctx iv iv.len mode)))

  #| end of module |# )

;; (module (aes-cfb128-encrypt aes-cfb128-decrypt)

;;   (define (aes-cfb128-encrypt in in.len ou ou.len ctx iv iv.len num)
;;     (%aes-cfb128-encrypt 'aes-cfb128-encrypt in in.len ou ou.len ctx iv iv.len num AES_ENCRYPT))

;;   (define (aes-cfb128-decrypt in in.len ou ou.len ctx iv iv.len num)
;;     (%aes-cfb128-encrypt 'aes-cfb128-decrypt in in.len ou ou.len ctx iv iv.len num AES_DECRYPT))

;;   (define (%aes-cfb128-encrypt who in in.len ou ou.len ctx iv iv.len num mode)
;;     (with-arguments-validation (who)
;; 	((general-c-buffer	in)
;; 	 (size_t/false		in.len)
;; 	 (aes-data-len		ou in.len)
;; 	 (general-c-buffer	ou)
;; 	 (size_t/false		ou.len)
;; 	 (aes-data-len		ou ou.len)
;; 	 (aes-key/alive		ctx)
;; 	 (general-c-buffer	iv)
;; 	 (size_t/false		iv.len)
;; 	 (aes-block-len		iv iv.len)
;; 	 (signed-int		num))
;;       (capi.aes-cfb128-encrypt in in.len ou ou.len ctx iv iv.len num mode)))

;;   #| end of module |# )

;; (module (aes-cfb1-encrypt aes-cfb1-decrypt)

;;   (define (aes-cfb1-encrypt in in.len ou ou.len ctx iv iv.len num)
;;     (%aes-cfb1-encrypt 'aes-cfb1-encrypt in in.len ou ou.len ctx iv iv.len num AES_ENCRYPT))

;;   (define (aes-cfb1-decrypt in in.len ou ou.len ctx iv iv.len num)
;;     (%aes-cfb1-encrypt 'aes-cfb1-decrypt in in.len ou ou.len ctx iv iv.len num AES_DECRYPT))

;;   (define (%aes-cfb1-encrypt who in in.len ou ou.len ctx iv iv.len num mode)
;;     (with-arguments-validation (who)
;; 	((general-c-buffer	in)
;; 	 (size_t/false		in.len)
;; 	 (aes-data-len		ou in.len)
;; 	 (general-c-buffer	ou)
;; 	 (size_t/false		ou.len)
;; 	 (aes-data-len		ou ou.len)
;; 	 (aes-key/alive		ctx)
;; 	 (general-c-buffer	iv)
;; 	 (size_t/false		iv.len)
;; 	 (aes-block-len		iv iv.len)
;; 	 (signed-int		num))
;;       (capi.aes-cfb1-encrypt in in.len ou ou.len ctx iv iv.len num mode)))

;;   #| end of module |# )

;; (module (aes-cfb8-encrypt aes-cfb8-decrypt)

;;   (define (aes-cfb8-encrypt in in.len ou ou.len ctx iv iv.len num)
;;     (%aes-cfb8-encrypt 'aes-cfb8-encrypt in in.len ou ou.len ctx iv iv.len num AES_ENCRYPT))

;;   (define (aes-cfb8-decrypt in in.len ou ou.len ctx iv iv.len num)
;;     (%aes-cfb8-encrypt 'aes-cfb8-decrypt in in.len ou ou.len ctx iv iv.len num AES_DECRYPT))

;;   (define (%aes-cfb8-encrypt who in in.len ou ou.len ctx iv iv.len num mode)
;;     (with-arguments-validation (who)
;; 	((general-c-buffer	in)
;; 	 (size_t/false		in.len)
;; 	 (aes-data-len		ou in.len)
;; 	 (general-c-buffer	ou)
;; 	 (size_t/false		ou.len)
;; 	 (aes-data-len		ou ou.len)
;; 	 (aes-key/alive		ctx)
;; 	 (general-c-buffer	iv)
;; 	 (size_t/false		iv.len)
;; 	 (aes-block-len		iv iv.len)
;; 	 (signed-int		num))
;;       (capi.aes-cfb8-encrypt in in.len ou ou.len ctx iv iv.len num mode)))

;;   #| end of module |# )

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

;;; --------------------------------------------------------------------

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


;;;; EVP message digest context functions

(ffi.define-foreign-pointer-wrapper evp-md-ctx
  (ffi.fields running?)
  (ffi.foreign-destructor capi.evp-md-ctx-destroy)
  (ffi.collector-struct-type #f))

(define-argument-validation (evp-md-ctx/running who obj)
  (evp-md-ctx?/running obj)
  (assertion-violation who "expected running EVP message digest context" obj))

(define-argument-validation (evp-md-ctx/alive-not-running who obj)
  (evp-md-ctx?/alive-not-running obj)
  (assertion-violation who
    "expected alive but not running EVP message digest context" obj))

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
       (symbol				md))
    (cond ((capi.evp-digest-init ctx (%symbol->md who md))
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

(define (evp-md-ctx-set-flags ctx)
  (define who 'evp-md-ctx-set-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-md-ctx-set-flags)))

(define (evp-md-ctx-clear-flags ctx)
  (define who 'evp-md-ctx-clear-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-md-ctx-clear-flags)))

(define (evp-md-ctx-test-flags ctx)
  (define who 'evp-md-ctx-test-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-md-ctx-test-flags)))

(define (evp-digest ctx)
  (define who 'evp-digest)
  (with-arguments-validation (who)
      ()
    (capi.evp-digest)))

(define (evp-get-digestbyname ctx)
  (define who 'evp-get-digestbyname)
  (with-arguments-validation (who)
      ()
    (capi.evp-get-digestbyname)))


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
