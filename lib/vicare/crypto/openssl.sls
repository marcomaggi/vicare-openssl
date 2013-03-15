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

    ;; EVP cipher algorithms
    evp-cipher
    evp-cipher?
    evp-cipher.vicare-arguments-validation
    false-or-evp-cipher.vicare-arguments-validation

    evp-enc-null
    evp-des-ecb
    evp-des-ede
    evp-des-ede3
    evp-des-ede-ecb
    evp-des-ede3-ecb
    evp-des-cfb64
    evp-des-cfb
    evp-des-ede3-cfb64
    evp-des-ede3-cfb
    evp-des-ede3-cfb1
    evp-des-ede3-cfb8
    evp-des-ofb
    evp-des-ede-ofb
    evp-des-ede3-ofb
    evp-des-cbc
    evp-des-ede-cbc
    evp-des-ede3-cbc
    evp-desx-cbc
    evp-rc4
    evp-rc4-40
    evp-rc4-hmac-md5
    evp-idea-ecb
    evp-idea-cfb64
    evp-idea-cfb
    evp-idea-ofb
    evp-idea-cbc
    evp-rc2-ecb
    evp-rc2-cbc
    evp-rc2-40-cbc
    evp-rc2-64-cbc
    evp-rc2-cfb64
    evp-rc2-cfb
    evp-rc2-ofb
    evp-bf-ecb
    evp-bf-cbc
    evp-bf-cfb64
    evp-bf-cfb
    evp-bf-ofb
    evp-cast5-ecb
    evp-cast5-cbc
    evp-cast5-cfb64
    evp-cast5-cfb
    evp-cast5-ofb
    evp-rc5-32-12-16-cbc
    evp-rc5-32-12-16-ecb
    evp-rc5-32-12-16-cfb64
    evp-rc5-32-12-16-cfb
    evp-rc5-32-12-16-ofb
    evp-aes-128-ecb
    evp-aes-128-cbc
    evp-aes-128-cfb1
    evp-aes-128-cfb8
    evp-aes-128-cfb128
    evp-aes-128-cfb
    evp-aes-128-ofb
    evp-aes-128-ctr
    evp-aes-128-ccm
    evp-aes-128-gcm
    evp-aes-128-xts
    evp-aes-192-ecb
    evp-aes-192-cbc
    evp-aes-192-cfb1
    evp-aes-192-cfb8
    evp-aes-192-cfb128
    evp-aes-192-cfb
    evp-aes-192-ofb
    evp-aes-192-ctr
    evp-aes-192-ccm
    evp-aes-192-gcm
    evp-aes-256-ecb
    evp-aes-256-cbc
    evp-aes-256-cfb1
    evp-aes-256-cfb8
    evp-aes-256-cfb128
    evp-aes-256-cfb
    evp-aes-256-ofb
    evp-aes-256-ctr
    evp-aes-256-ccm
    evp-aes-256-gcm
    evp-aes-256-xts
    evp-aes-128-cbc-hmac-sha1
    evp-aes-256-cbc-hmac-sha1
    evp-camellia-128-ecb
    evp-camellia-128-cbc
    evp-camellia-128-cfb1
    evp-camellia-128-cfb8
    evp-camellia-128-cfb128
    evp-camellia-128-cfb
    evp-camellia-128-ofb
    evp-camellia-192-ecb
    evp-camellia-192-cbc
    evp-camellia-192-cfb1
    evp-camellia-192-cfb8
    evp-camellia-192-cfb128
    evp-camellia-192-cfb
    evp-camellia-192-ofb
    evp-camellia-256-ecb
    evp-camellia-256-cbc
    evp-camellia-256-cfb1
    evp-camellia-256-cfb8
    evp-camellia-256-cfb128
    evp-camellia-256-cfb
    evp-camellia-256-ofb
    evp-seed-ecb
    evp-seed-cbc
    evp-seed-cfb128
    evp-seed-cfb
    evp-seed-ofb
    evp-cipher-type
    evp-get-cipherbyname
    evp-get-cipherbynid
    evp-get-cipherbyobj
    evp-cipher-nid
    evp-cipher-name
    evp-cipher-block-size
    evp-cipher-key-length
    evp-cipher-iv-length
    evp-cipher-flags
    evp-cipher-mode

    ;; EVP cipher algorithms, context API
    evp-cipher-ctx-init
    evp-cipher-ctx-cleanup
    evp-cipher-ctx-new
    evp-cipher-ctx-free
    evp-encryptinit-ex
    evp-encryptfinal-ex
    evp-encryptupdate
    evp-decryptinit-ex
    evp-decryptupdate
    evp-decryptfinal-ex
    evp-cipherinit-ex
    evp-cipherupdate
    evp-cipherfinal-ex
    evp-cipher-ctx-set-key-length
    evp-cipher-ctx-set-padding
    evp-cipher-ctx-ctrl
    evp-cipher-ctx-cipher
    evp-cipher-ctx-nid
    evp-cipher-ctx-block-size
    evp-cipher-ctx-key-length
    evp-cipher-ctx-iv-length
    evp-cipher-ctx-copy
    evp-cipher-ctx-get-app-data
    evp-cipher-ctx-set-app-data
    evp-cipher-ctx-type
    evp-cipher-ctx-flags
    evp-cipher-ctx-mode
    evp-cipher-ctx-rand-key
    evp-cipher-param-to-asn1
    evp-cipher-asn1-to-param
    evp-cipher-ctx-set-flags
    evp-cipher-ctx-clear-flags
    evp-cipher-ctx-test-flags
    evp-crypt

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

(define-argument-validation (evp-md/symbol who obj)
  (or (evp-md? obj)
      (symbol? obj))
  (assertion-violation who
    "expected instance of \"evp-md\" or symbol as argument" obj))

(define-argument-validation (evp-cipher/symbol who obj)
  (or (evp-cipher? obj)
      (symbol? obj))
  (assertion-violation who
    "expected instance of \"evp-cipher\" or symbol as argument" obj))


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
	 (evp-md/symbol	md))
      (with-general-c-strings
	  ((key^	key))
	(string-to-bytevector string->utf8)
	(let ((rv (capi.hmac-init key^ key.len (if (symbol? md)
						   (%symbol->md who md)
						 ($evp-md-pointer md)))))
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
      ((evp-md/symbol	md)
       (general-c-string*	key key.len)
       (general-c-string*	input input.len))
    (with-general-c-strings
	((key^		key)
	 (input^	input))
      (string-to-bytevector string->utf8)
      (capi.hmac (if (symbol? md)
		     (%symbol->md who md)
		   ($evp-md-pointer md))
		 key^ key.len input^ input.len))))


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
       (evp-md/symbol			md))
    (cond ((capi.evp-digest-init ctx (if (symbol? md)
					 (%symbol->md who md)
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


;;;; EVP cipher algorithms: algorithm functions

(define-struct-extended evp-cipher
  (pointer)
  %evp-cipher-printer
  #f)

(define (%evp-cipher-printer S port sub-printer)
  (define (%display thing)
    (display thing port))
  (define (%write thing)
    (write thing port))
  (%display "#[evp-cipher")
  (%display " pointer=")	(%write ($evp-cipher-pointer S))
  ;; (%display " algorithm=")	(%write (evp-cipher-name S))
  ;; (%display " size=")		(%write (capi.evp-cipher-size S))
  ;; (%display " block-size=")	(%write (capi.evp-cipher-block-size S))
  (%display "]"))

;;; --------------------------------------------------------------------

(define (evp-enc-null ctx)
  (define who 'evp-enc-null)
  (with-arguments-validation (who)
      ()
    (capi.evp-enc-null)))

(define (evp-des-ecb ctx)
  (define who 'evp-des-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ecb)))

(define (evp-des-ede ctx)
  (define who 'evp-des-ede)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede)))

(define (evp-des-ede3 ctx)
  (define who 'evp-des-ede3)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3)))

(define (evp-des-ede-ecb ctx)
  (define who 'evp-des-ede-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede-ecb)))

(define (evp-des-ede3-ecb ctx)
  (define who 'evp-des-ede3-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-ecb)))

(define (evp-des-cfb64 ctx)
  (define who 'evp-des-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-cfb64)))

(define (evp-des-cfb ctx)
  (define who 'evp-des-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-cfb)))

(define (evp-des-ede3-cfb64 ctx)
  (define who 'evp-des-ede3-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-cfb64)))

(define (evp-des-ede3-cfb ctx)
  (define who 'evp-des-ede3-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-cfb)))

(define (evp-des-ede3-cfb1 ctx)
  (define who 'evp-des-ede3-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-cfb1)))

(define (evp-des-ede3-cfb8 ctx)
  (define who 'evp-des-ede3-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-cfb8)))

(define (evp-des-ofb ctx)
  (define who 'evp-des-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ofb)))

(define (evp-des-ede-ofb ctx)
  (define who 'evp-des-ede-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede-ofb)))

(define (evp-des-ede3-ofb ctx)
  (define who 'evp-des-ede3-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-ofb)))

(define (evp-des-cbc ctx)
  (define who 'evp-des-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-cbc)))

(define (evp-des-ede-cbc ctx)
  (define who 'evp-des-ede-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede-cbc)))

(define (evp-des-ede3-cbc ctx)
  (define who 'evp-des-ede3-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-des-ede3-cbc)))

(define (evp-desx-cbc ctx)
  (define who 'evp-desx-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-desx-cbc)))

(define (evp-rc4 ctx)
  (define who 'evp-rc4)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc4)))

(define (evp-rc4-40 ctx)
  (define who 'evp-rc4-40)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc4-40)))

(define (evp-rc4-hmac-md5 ctx)
  (define who 'evp-rc4-hmac-md5)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc4-hmac-md5)))

(define (evp-idea-ecb ctx)
  (define who 'evp-idea-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-idea-ecb)))

(define (evp-idea-cfb64 ctx)
  (define who 'evp-idea-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-idea-cfb64)))

(define (evp-idea-cfb ctx)
  (define who 'evp-idea-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-idea-cfb)))

(define (evp-idea-ofb ctx)
  (define who 'evp-idea-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-idea-ofb)))

(define (evp-idea-cbc ctx)
  (define who 'evp-idea-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-idea-cbc)))

(define (evp-rc2-ecb ctx)
  (define who 'evp-rc2-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-ecb)))

(define (evp-rc2-cbc ctx)
  (define who 'evp-rc2-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-cbc)))

(define (evp-rc2-40-cbc ctx)
  (define who 'evp-rc2-40-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-40-cbc)))

(define (evp-rc2-64-cbc ctx)
  (define who 'evp-rc2-64-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-64-cbc)))

(define (evp-rc2-cfb64 ctx)
  (define who 'evp-rc2-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-cfb64)))

(define (evp-rc2-cfb ctx)
  (define who 'evp-rc2-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-cfb)))

(define (evp-rc2-ofb ctx)
  (define who 'evp-rc2-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc2-ofb)))

(define (evp-bf-ecb ctx)
  (define who 'evp-bf-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-bf-ecb)))

(define (evp-bf-cbc ctx)
  (define who 'evp-bf-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-bf-cbc)))

(define (evp-bf-cfb64 ctx)
  (define who 'evp-bf-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-bf-cfb64)))

(define (evp-bf-cfb ctx)
  (define who 'evp-bf-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-bf-cfb)))

(define (evp-bf-ofb ctx)
  (define who 'evp-bf-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-bf-ofb)))

(define (evp-cast5-ecb ctx)
  (define who 'evp-cast5-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-cast5-ecb)))

(define (evp-cast5-cbc ctx)
  (define who 'evp-cast5-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-cast5-cbc)))

(define (evp-cast5-cfb64 ctx)
  (define who 'evp-cast5-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-cast5-cfb64)))

(define (evp-cast5-cfb ctx)
  (define who 'evp-cast5-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-cast5-cfb)))

(define (evp-cast5-ofb ctx)
  (define who 'evp-cast5-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-cast5-ofb)))

(define (evp-rc5-32-12-16-cbc ctx)
  (define who 'evp-rc5-32-12-16-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc5-32-12-16-cbc)))

(define (evp-rc5-32-12-16-ecb ctx)
  (define who 'evp-rc5-32-12-16-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc5-32-12-16-ecb)))

(define (evp-rc5-32-12-16-cfb64 ctx)
  (define who 'evp-rc5-32-12-16-cfb64)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc5-32-12-16-cfb64)))

(define (evp-rc5-32-12-16-cfb ctx)
  (define who 'evp-rc5-32-12-16-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc5-32-12-16-cfb)))

(define (evp-rc5-32-12-16-ofb ctx)
  (define who 'evp-rc5-32-12-16-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-rc5-32-12-16-ofb)))

(define (evp-aes-128-ecb ctx)
  (define who 'evp-aes-128-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-ecb)))

(define (evp-aes-128-cbc ctx)
  (define who 'evp-aes-128-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-cbc)))

(define (evp-aes-128-cfb1 ctx)
  (define who 'evp-aes-128-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-cfb1)))

(define (evp-aes-128-cfb8 ctx)
  (define who 'evp-aes-128-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-cfb8)))

(define (evp-aes-128-cfb128 ctx)
  (define who 'evp-aes-128-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-cfb128)))

(define (evp-aes-128-cfb ctx)
  (define who 'evp-aes-128-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-cfb)))

(define (evp-aes-128-ofb ctx)
  (define who 'evp-aes-128-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-ofb)))

(define (evp-aes-128-ctr ctx)
  (define who 'evp-aes-128-ctr)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-ctr)))

(define (evp-aes-128-ccm ctx)
  (define who 'evp-aes-128-ccm)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-ccm)))

(define (evp-aes-128-gcm ctx)
  (define who 'evp-aes-128-gcm)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-gcm)))

(define (evp-aes-128-xts ctx)
  (define who 'evp-aes-128-xts)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-xts)))

(define (evp-aes-192-ecb ctx)
  (define who 'evp-aes-192-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-ecb)))

(define (evp-aes-192-cbc ctx)
  (define who 'evp-aes-192-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-cbc)))

(define (evp-aes-192-cfb1 ctx)
  (define who 'evp-aes-192-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-cfb1)))

(define (evp-aes-192-cfb8 ctx)
  (define who 'evp-aes-192-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-cfb8)))

(define (evp-aes-192-cfb128 ctx)
  (define who 'evp-aes-192-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-cfb128)))

(define (evp-aes-192-cfb ctx)
  (define who 'evp-aes-192-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-cfb)))

(define (evp-aes-192-ofb ctx)
  (define who 'evp-aes-192-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-ofb)))

(define (evp-aes-192-ctr ctx)
  (define who 'evp-aes-192-ctr)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-ctr)))

(define (evp-aes-192-ccm ctx)
  (define who 'evp-aes-192-ccm)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-ccm)))

(define (evp-aes-192-gcm ctx)
  (define who 'evp-aes-192-gcm)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-192-gcm)))

(define (evp-aes-256-ecb ctx)
  (define who 'evp-aes-256-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-ecb)))

(define (evp-aes-256-cbc ctx)
  (define who 'evp-aes-256-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-cbc)))

(define (evp-aes-256-cfb1 ctx)
  (define who 'evp-aes-256-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-cfb1)))

(define (evp-aes-256-cfb8 ctx)
  (define who 'evp-aes-256-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-cfb8)))

(define (evp-aes-256-cfb128 ctx)
  (define who 'evp-aes-256-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-cfb128)))

(define (evp-aes-256-cfb ctx)
  (define who 'evp-aes-256-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-cfb)))

(define (evp-aes-256-ofb ctx)
  (define who 'evp-aes-256-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-ofb)))

(define (evp-aes-256-ctr ctx)
  (define who 'evp-aes-256-ctr)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-ctr)))

(define (evp-aes-256-ccm ctx)
  (define who 'evp-aes-256-ccm)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-ccm)))

(define (evp-aes-256-gcm ctx)
  (define who 'evp-aes-256-gcm)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-gcm)))

(define (evp-aes-256-xts ctx)
  (define who 'evp-aes-256-xts)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-xts)))

(define (evp-aes-128-cbc-hmac-sha1 ctx)
  (define who 'evp-aes-128-cbc-hmac-sha1)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-128-cbc-hmac-sha1)))

(define (evp-aes-256-cbc-hmac-sha1 ctx)
  (define who 'evp-aes-256-cbc-hmac-sha1)
  (with-arguments-validation (who)
      ()
    (capi.evp-aes-256-cbc-hmac-sha1)))

(define (evp-camellia-128-ecb ctx)
  (define who 'evp-camellia-128-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-ecb)))

(define (evp-camellia-128-cbc ctx)
  (define who 'evp-camellia-128-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-cbc)))

(define (evp-camellia-128-cfb1 ctx)
  (define who 'evp-camellia-128-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-cfb1)))

(define (evp-camellia-128-cfb8 ctx)
  (define who 'evp-camellia-128-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-cfb8)))

(define (evp-camellia-128-cfb128 ctx)
  (define who 'evp-camellia-128-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-cfb128)))

(define (evp-camellia-128-cfb ctx)
  (define who 'evp-camellia-128-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-cfb)))

(define (evp-camellia-128-ofb ctx)
  (define who 'evp-camellia-128-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-128-ofb)))

(define (evp-camellia-192-ecb ctx)
  (define who 'evp-camellia-192-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-ecb)))

(define (evp-camellia-192-cbc ctx)
  (define who 'evp-camellia-192-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-cbc)))

(define (evp-camellia-192-cfb1 ctx)
  (define who 'evp-camellia-192-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-cfb1)))

(define (evp-camellia-192-cfb8 ctx)
  (define who 'evp-camellia-192-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-cfb8)))

(define (evp-camellia-192-cfb128 ctx)
  (define who 'evp-camellia-192-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-cfb128)))

(define (evp-camellia-192-cfb ctx)
  (define who 'evp-camellia-192-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-cfb)))

(define (evp-camellia-192-ofb ctx)
  (define who 'evp-camellia-192-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-192-ofb)))

(define (evp-camellia-256-ecb ctx)
  (define who 'evp-camellia-256-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-ecb)))

(define (evp-camellia-256-cbc ctx)
  (define who 'evp-camellia-256-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-cbc)))

(define (evp-camellia-256-cfb1 ctx)
  (define who 'evp-camellia-256-cfb1)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-cfb1)))

(define (evp-camellia-256-cfb8 ctx)
  (define who 'evp-camellia-256-cfb8)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-cfb8)))

(define (evp-camellia-256-cfb128 ctx)
  (define who 'evp-camellia-256-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-cfb128)))

(define (evp-camellia-256-cfb ctx)
  (define who 'evp-camellia-256-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-cfb)))

(define (evp-camellia-256-ofb ctx)
  (define who 'evp-camellia-256-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-camellia-256-ofb)))

(define (evp-seed-ecb ctx)
  (define who 'evp-seed-ecb)
  (with-arguments-validation (who)
      ()
    (capi.evp-seed-ecb)))

(define (evp-seed-cbc ctx)
  (define who 'evp-seed-cbc)
  (with-arguments-validation (who)
      ()
    (capi.evp-seed-cbc)))

(define (evp-seed-cfb128 ctx)
  (define who 'evp-seed-cfb128)
  (with-arguments-validation (who)
      ()
    (capi.evp-seed-cfb128)))

(define (evp-seed-cfb ctx)
  (define who 'evp-seed-cfb)
  (with-arguments-validation (who)
      ()
    (capi.evp-seed-cfb)))

(define (evp-seed-ofb ctx)
  (define who 'evp-seed-ofb)
  (with-arguments-validation (who)
      ()
    (capi.evp-seed-ofb)))

;;; --------------------------------------------------------------------

(define (evp-cipher-type ctx)
  (define who 'evp-cipher-type)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-type)))

(define (evp-get-cipherbyname ctx)
  (define who 'evp-get-cipherbyname)
  (with-arguments-validation (who)
      ()
    (capi.evp-get-cipherbyname)))

(define (evp-get-cipherbynid ctx)
  (define who 'evp-get-cipherbynid)
  (with-arguments-validation (who)
      ()
    (capi.evp-get-cipherbynid)))

(define (evp-get-cipherbyobj ctx)
  (define who 'evp-get-cipherbyobj)
  (with-arguments-validation (who)
      ()
    (capi.evp-get-cipherbyobj)))

(define (evp-cipher-nid ctx)
  (define who 'evp-cipher-nid)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-nid)))

(define (evp-cipher-name ctx)
  (define who 'evp-cipher-name)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-name)))

(define (evp-cipher-block-size ctx)
  (define who 'evp-cipher-block-size)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-block-size)))

(define (evp-cipher-key-length ctx)
  (define who 'evp-cipher-key-length)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-key-length)))

(define (evp-cipher-iv-length ctx)
  (define who 'evp-cipher-iv-length)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-iv-length)))

(define (evp-cipher-flags ctx)
  (define who 'evp-cipher-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-flags)))

(define (evp-cipher-mode ctx)
  (define who 'evp-cipher-mode)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-mode)))


;;;; EVP cipher algorithms: context functions

(define (evp-cipher-ctx-init ctx)
  (define who 'evp-cipher-ctx-init)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-init)))

(define (evp-cipher-ctx-cleanup ctx)
  (define who 'evp-cipher-ctx-cleanup)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-cleanup)))

(define (evp-cipher-ctx-new ctx)
  (define who 'evp-cipher-ctx-new)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-new)))

(define (evp-cipher-ctx-free ctx)
  (define who 'evp-cipher-ctx-free)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-free)))

(define (evp-encryptinit-ex ctx)
  (define who 'evp-encryptinit-ex)
  (with-arguments-validation (who)
      ()
    (capi.evp-encryptinit-ex)))

(define (evp-encryptfinal-ex ctx)
  (define who 'evp-encryptfinal-ex)
  (with-arguments-validation (who)
      ()
    (capi.evp-encryptfinal-ex)))

(define (evp-encryptupdate ctx)
  (define who 'evp-encryptupdate)
  (with-arguments-validation (who)
      ()
    (capi.evp-encryptupdate)))

(define (evp-decryptinit-ex ctx)
  (define who 'evp-decryptinit-ex)
  (with-arguments-validation (who)
      ()
    (capi.evp-decryptinit-ex)))

(define (evp-decryptupdate ctx)
  (define who 'evp-decryptupdate)
  (with-arguments-validation (who)
      ()
    (capi.evp-decryptupdate)))

(define (evp-decryptfinal-ex ctx)
  (define who 'evp-decryptfinal-ex)
  (with-arguments-validation (who)
      ()
    (capi.evp-decryptfinal-ex)))

(define (evp-cipherinit-ex ctx)
  (define who 'evp-cipherinit-ex)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipherinit-ex)))

(define (evp-cipherupdate ctx)
  (define who 'evp-cipherupdate)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipherupdate)))

(define (evp-cipherfinal-ex ctx)
  (define who 'evp-cipherfinal-ex)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipherfinal-ex)))

(define (evp-cipher-ctx-set-key-length ctx)
  (define who 'evp-cipher-ctx-set-key-length)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-set-key-length)))

(define (evp-cipher-ctx-set-padding ctx)
  (define who 'evp-cipher-ctx-set-padding)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-set-padding)))

(define (evp-cipher-ctx-ctrl ctx)
  (define who 'evp-cipher-ctx-ctrl)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-ctrl)))

(define (evp-cipher-ctx-cipher ctx)
  (define who 'evp-cipher-ctx-cipher)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-cipher)))

(define (evp-cipher-ctx-nid ctx)
  (define who 'evp-cipher-ctx-nid)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-nid)))

(define (evp-cipher-ctx-block-size ctx)
  (define who 'evp-cipher-ctx-block-size)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-block-size)))

(define (evp-cipher-ctx-key-length ctx)
  (define who 'evp-cipher-ctx-key-length)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-key-length)))

(define (evp-cipher-ctx-iv-length ctx)
  (define who 'evp-cipher-ctx-iv-length)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-iv-length)))

(define (evp-cipher-ctx-copy ctx)
  (define who 'evp-cipher-ctx-copy)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-copy)))

(define (evp-cipher-ctx-get-app-data ctx)
  (define who 'evp-cipher-ctx-get-app-data)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-get-app-data)))

(define (evp-cipher-ctx-set-app-data ctx)
  (define who 'evp-cipher-ctx-set-app-data)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-set-app-data)))

(define (evp-cipher-ctx-type ctx)
  (define who 'evp-cipher-ctx-type)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-type)))

(define (evp-cipher-ctx-flags ctx)
  (define who 'evp-cipher-ctx-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-flags)))

(define (evp-cipher-ctx-mode ctx)
  (define who 'evp-cipher-ctx-mode)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-mode)))

(define (evp-cipher-ctx-rand-key ctx)
  (define who 'evp-cipher-ctx-rand-key)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-rand-key)))

(define (evp-cipher-param-to-asn1 ctx)
  (define who 'evp-cipher-param-to-asn1)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-param-to-asn1)))

(define (evp-cipher-asn1-to-param ctx)
  (define who 'evp-cipher-asn1-to-param)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-asn1-to-param)))

(define (evp-cipher-ctx-set-flags ctx)
  (define who 'evp-cipher-ctx-set-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-set-flags)))

(define (evp-cipher-ctx-clear-flags ctx)
  (define who 'evp-cipher-ctx-clear-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-clear-flags)))

(define (evp-cipher-ctx-test-flags ctx)
  (define who 'evp-cipher-ctx-test-flags)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher-ctx-test-flags)))

(define (evp-crypt ctx)
  (define who 'evp-crypt)
  (with-arguments-validation (who)
      ()
    (capi.evp-cipher)))


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
