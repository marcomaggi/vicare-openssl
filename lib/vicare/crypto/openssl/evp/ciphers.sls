;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: EVP ciphers API
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
(library (vicare crypto openssl evp ciphers)
  (export

    ;; EVP cipher algorithms
    evp-cipher
    evp-cipher?
    evp-cipher.vicare-arguments-validation
    false-or-evp-cipher.vicare-arguments-validation

    ;; evp-cipher makers
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

    ;; evp-cipher special makers
    evp-get-cipherbyname
    evp-get-cipherbynid
    evp-get-cipherbyobj

    ;; evp-cipher inspection
    evp-cipher-type
    evp-cipher-nid
    evp-cipher-name
    evp-cipher-block-size
    evp-cipher-key-length
    evp-cipher-iv-length
    evp-cipher-flags
    evp-cipher-mode

    ;; EVP cipher context
    evp-cipher-ctx
    evp-cipher-ctx?
    evp-cipher-ctx?/alive
    evp-cipher-ctx?/running
    evp-cipher-ctx?/alive-not-running
    evp-cipher-ctx-custom-destructor
    set-evp-cipher-ctx-custom-destructor!
    evp-cipher-ctx.vicare-arguments-validation
    evp-cipher-ctx/alive.vicare-arguments-validation
    evp-cipher-ctx/running.vicare-arguments-validation
    evp-cipher-ctx/alive-not-running.vicare-arguments-validation

    ;; EVP cipher context: init, update, final
    evp-cipher-ctx-new		evp-cipher-ctx-free
    evp-cipher-ctx-copy

    evp-encrypt-init		evp-encrypt-final	evp-encrypt-update
    evp-decrypt-init		evp-decrypt-final	evp-decrypt-update
    evp-cipher-init		evp-cipher-final	evp-cipher-update
    evp-minimum-output-length

    ;; EVP cipher context: inspection
    evp-cipher-ctx-set-key-length
    evp-cipher-ctx-set-padding
    evp-cipher-ctx-ctrl
    evp-cipher-ctx-cipher
    evp-cipher-ctx-nid
    evp-cipher-ctx-block-size
    evp-cipher-ctx-key-length
    evp-cipher-ctx-iv-length
    evp-cipher-ctx-type
    evp-cipher-ctx-mode
    evp-cipher-ctx-rand-key

    ;; EVP cipher context: flags
    evp-cipher-ctx-flags		evp-cipher-ctx-set-flags
    evp-cipher-ctx-clear-flags		evp-cipher-ctx-test-flags

    ;; EVP cipher context: misc
    evp-cipher-ctx-get-app-data		evp-cipher-ctx-set-app-data
    evp-cipher-param-to-asn1		evp-cipher-asn1-to-param

    ;; single-step encryption and decryption
    evp-crypt

    ;; constants to symbols
    evp-ciph-mode->symbol
    )
  (import (vicare)
    (vicare crypto openssl constants)
    #;(vicare crypto openssl features)
    (prefix (vicare crypto openssl unsafe-capi)
	    capi.)
    (prefix (vicare crypto openssl helpers)
	    help.)
    #;(prefix (vicare ffi) ffi.)
    (prefix (vicare unsafe-operations)
	    $)
    (prefix (vicare ffi foreign-pointer-wrapper)
	    ffi.)
    (vicare syntactic-extensions)
    (vicare arguments validation)
    (vicare arguments general-c-buffers))


;;;; arguments validation

(define-argument-validation (evp-cipher/symbol who obj)
  (or (evp-cipher? obj)
      (symbol? obj))
  (assertion-violation who
    "expected instance of \"evp-cipher\" or symbol as argument" obj))

(define-argument-validation (evp-cipher-ctx/running who obj)
  (evp-cipher-ctx?/running obj)
  (assertion-violation who "expected running EVP cipher context" obj))

(define-argument-validation (evp-cipher-ctx/alive-not-running who obj)
  (evp-cipher-ctx?/alive-not-running obj)
  (assertion-violation who
    "expected alive but not running EVP cipher context" obj))

;;; --------------------------------------------------------------------

(define-argument-validation (evp-cipher-enc who obj)
  (and (fixnum? obj)
       (or ($fx= +1 obj)
	   ($fxzero? obj)
	   ($fx= -1 obj)))
  (assertion-violation who
    "expected EVP cipher encryption or descryption selection" obj))


;;;; EVP cipher algorithms: makers for EVP_CIPHER references

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
  (%display " algorithm=")	(%write (evp-cipher-name S))
  (%display " block-size=")	(%write (evp-cipher-block-size S))
  (%display " key-length=")	(%write (evp-cipher-key-length S))
  (%display " iv-length=")	(%write (evp-cipher-iv-length S))
  (%display " mode=")		(%display (evp-ciph-mode->symbol (evp-cipher-mode S)))
  (%display "]"))

;;; --------------------------------------------------------------------

(let-syntax ((define-maker
	       (syntax-rules ()
		 ((_ ?who ?func)
		  (define (?who)
		    (make-evp-cipher (?func)))))))
  (define-maker evp-enc-null			capi.evp-enc-null)
  (define-maker evp-des-ecb			capi.evp-des-ecb)
  (define-maker evp-des-ede			capi.evp-des-ede)
  (define-maker evp-des-ede3			capi.evp-des-ede3)
  (define-maker evp-des-ede-ecb			capi.evp-des-ede-ecb)
  (define-maker evp-des-ede3-ecb		capi.evp-des-ede3-ecb)
  (define-maker evp-des-cfb64			capi.evp-des-cfb64)
  (define-maker evp-des-cfb			capi.evp-des-cfb)
  (define-maker evp-des-ede3-cfb64		capi.evp-des-ede3-cfb64)
  (define-maker evp-des-ede3-cfb		capi.evp-des-ede3-cfb)
  (define-maker evp-des-ede3-cfb1		capi.evp-des-ede3-cfb1)
  (define-maker evp-des-ede3-cfb8		capi.evp-des-ede3-cfb8)
  (define-maker evp-des-ofb			capi.evp-des-ofb)
  (define-maker evp-des-ede-ofb			capi.evp-des-ede-ofb)
  (define-maker evp-des-ede3-ofb		capi.evp-des-ede3-ofb)
  (define-maker evp-des-cbc			capi.evp-des-cbc)
  (define-maker evp-des-ede-cbc			capi.evp-des-ede-cbc)
  (define-maker evp-des-ede3-cbc		capi.evp-des-ede3-cbc)
  (define-maker evp-desx-cbc			capi.evp-desx-cbc)
  (define-maker evp-rc4				capi.evp-rc4)
  (define-maker evp-rc4-40			capi.evp-rc4-40)
  (define-maker evp-rc4-hmac-md5		capi.evp-rc4-hmac-md5)
  (define-maker evp-idea-ecb			capi.evp-idea-ecb)
  (define-maker evp-idea-cfb64			capi.evp-idea-cfb64)
  (define-maker evp-idea-cfb			capi.evp-idea-cfb)
  (define-maker evp-idea-ofb			capi.evp-idea-ofb)
  (define-maker evp-idea-cbc			capi.evp-idea-cbc)
  (define-maker evp-rc2-ecb			capi.evp-rc2-ecb)
  (define-maker evp-rc2-cbc			capi.evp-rc2-cbc)
  (define-maker evp-rc2-40-cbc			capi.evp-rc2-40-cbc)
  (define-maker evp-rc2-64-cbc			capi.evp-rc2-64-cbc)
  (define-maker evp-rc2-cfb64			capi.evp-rc2-cfb64)
  (define-maker evp-rc2-cfb			capi.evp-rc2-cfb)
  (define-maker evp-rc2-ofb			capi.evp-rc2-ofb)
  (define-maker evp-bf-ecb			capi.evp-bf-ecb)
  (define-maker evp-bf-cbc			capi.evp-bf-cbc)
  (define-maker evp-bf-cfb64			capi.evp-bf-cfb64)
  (define-maker evp-bf-cfb			capi.evp-bf-cfb)
  (define-maker evp-bf-ofb			capi.evp-bf-ofb)
  (define-maker evp-cast5-ecb			capi.evp-cast5-ecb)
  (define-maker evp-cast5-cbc			capi.evp-cast5-cbc)
  (define-maker evp-cast5-cfb64			capi.evp-cast5-cfb64)
  (define-maker evp-cast5-cfb			capi.evp-cast5-cfb)
  (define-maker evp-cast5-ofb			capi.evp-cast5-ofb)
  (define-maker evp-rc5-32-12-16-cbc		capi.evp-rc5-32-12-16-cbc)
  (define-maker evp-rc5-32-12-16-ecb		capi.evp-rc5-32-12-16-ecb)
  (define-maker evp-rc5-32-12-16-cfb64		capi.evp-rc5-32-12-16-cfb64)
  (define-maker evp-rc5-32-12-16-cfb		capi.evp-rc5-32-12-16-cfb)
  (define-maker evp-rc5-32-12-16-ofb		capi.evp-rc5-32-12-16-ofb)
  (define-maker evp-aes-128-ecb			capi.evp-aes-128-ecb)
  (define-maker evp-aes-128-cbc			capi.evp-aes-128-cbc)
  (define-maker evp-aes-128-cfb1		capi.evp-aes-128-cfb1)
  (define-maker evp-aes-128-cfb8		capi.evp-aes-128-cfb8)
  (define-maker evp-aes-128-cfb128		capi.evp-aes-128-cfb128)
  (define-maker evp-aes-128-cfb			capi.evp-aes-128-cfb)
  (define-maker evp-aes-128-ofb			capi.evp-aes-128-ofb)
  (define-maker evp-aes-128-ctr			capi.evp-aes-128-ctr)
  (define-maker evp-aes-128-ccm			capi.evp-aes-128-ccm)
  (define-maker evp-aes-128-gcm			capi.evp-aes-128-gcm)
  (define-maker evp-aes-128-xts			capi.evp-aes-128-xts)
  (define-maker evp-aes-192-ecb			capi.evp-aes-192-ecb)
  (define-maker evp-aes-192-cbc			capi.evp-aes-192-cbc)
  (define-maker evp-aes-192-cfb1		capi.evp-aes-192-cfb1)
  (define-maker evp-aes-192-cfb8		capi.evp-aes-192-cfb8)
  (define-maker evp-aes-192-cfb128		capi.evp-aes-192-cfb128)
  (define-maker evp-aes-192-cfb			capi.evp-aes-192-cfb)
  (define-maker evp-aes-192-ofb			capi.evp-aes-192-ofb)
  (define-maker evp-aes-192-ctr			capi.evp-aes-192-ctr)
  (define-maker evp-aes-192-ccm			capi.evp-aes-192-ccm)
  (define-maker evp-aes-192-gcm			capi.evp-aes-192-gcm)
  (define-maker evp-aes-256-ecb			capi.evp-aes-256-ecb)
  (define-maker evp-aes-256-cbc			capi.evp-aes-256-cbc)
  (define-maker evp-aes-256-cfb1		capi.evp-aes-256-cfb1)
  (define-maker evp-aes-256-cfb8		capi.evp-aes-256-cfb8)
  (define-maker evp-aes-256-cfb128		capi.evp-aes-256-cfb128)
  (define-maker evp-aes-256-cfb			capi.evp-aes-256-cfb)
  (define-maker evp-aes-256-ofb			capi.evp-aes-256-ofb)
  (define-maker evp-aes-256-ctr			capi.evp-aes-256-ctr)
  (define-maker evp-aes-256-ccm			capi.evp-aes-256-ccm)
  (define-maker evp-aes-256-gcm			capi.evp-aes-256-gcm)
  (define-maker evp-aes-256-xts			capi.evp-aes-256-xts)
  (define-maker evp-aes-128-cbc-hmac-sha1	capi.evp-aes-128-cbc-hmac-sha1)
  (define-maker evp-aes-256-cbc-hmac-sha1	capi.evp-aes-256-cbc-hmac-sha1)
  (define-maker evp-camellia-128-ecb		capi.evp-camellia-128-ecb)
  (define-maker evp-camellia-128-cbc		capi.evp-camellia-128-cbc)
  (define-maker evp-camellia-128-cfb1		capi.evp-camellia-128-cfb1)
  (define-maker evp-camellia-128-cfb8		capi.evp-camellia-128-cfb8)
  (define-maker evp-camellia-128-cfb128		capi.evp-camellia-128-cfb128)
  (define-maker evp-camellia-128-cfb		capi.evp-camellia-128-cfb)
  (define-maker evp-camellia-128-ofb		capi.evp-camellia-128-ofb)
  (define-maker evp-camellia-192-ecb		capi.evp-camellia-192-ecb)
  (define-maker evp-camellia-192-cbc		capi.evp-camellia-192-cbc)
  (define-maker evp-camellia-192-cfb1		capi.evp-camellia-192-cfb1)
  (define-maker evp-camellia-192-cfb8		capi.evp-camellia-192-cfb8)
  (define-maker evp-camellia-192-cfb128		capi.evp-camellia-192-cfb128)
  (define-maker evp-camellia-192-cfb		capi.evp-camellia-192-cfb)
  (define-maker evp-camellia-192-ofb		capi.evp-camellia-192-ofb)
  (define-maker evp-camellia-256-ecb		capi.evp-camellia-256-ecb)
  (define-maker evp-camellia-256-cbc		capi.evp-camellia-256-cbc)
  (define-maker evp-camellia-256-cfb1		capi.evp-camellia-256-cfb1)
  (define-maker evp-camellia-256-cfb8		capi.evp-camellia-256-cfb8)
  (define-maker evp-camellia-256-cfb128		capi.evp-camellia-256-cfb128)
  (define-maker evp-camellia-256-cfb		capi.evp-camellia-256-cfb)
  (define-maker evp-camellia-256-ofb		capi.evp-camellia-256-ofb)
  (define-maker evp-seed-ecb			capi.evp-seed-ecb)
  (define-maker evp-seed-cbc			capi.evp-seed-cbc)
  (define-maker evp-seed-cfb128			capi.evp-seed-cfb128)
  (define-maker evp-seed-cfb			capi.evp-seed-cfb)
  (define-maker evp-seed-ofb			capi.evp-seed-ofb))


;;;; EVP cipher algorithms: special makers for EVP_CIPHER references

(define (evp-get-cipherbyname name)
  (define who 'evp-get-cipherbyname)
  (with-arguments-validation (who)
      ((general-c-string	name))
    (with-general-c-strings
	((name^		name))
      (let ((rv (capi.evp-get-cipherbyname name^)))
	(and rv (make-evp-cipher rv))))))

(define (evp-get-cipherbynid nid)
  (define who 'evp-get-cipherbynid)
  (with-arguments-validation (who)
      ((signed-int	nid))
    (let ((rv (capi.evp-get-cipherbynid nid)))
      (and rv (make-evp-cipher rv)))))

;;; --------------------------------------------------------------------
;;; still unimplemented

(define (evp-get-cipherbyobj ctx)
  ;;Convert an ASN.1 object to an EVP_CIPHER.
  ;;
  (define who 'evp-get-cipherbyobj)
  (with-arguments-validation (who)
      ()
    (make-evp-cipher (capi.evp-get-cipherbyobj))))


;;;; EVP cipher algorithms: algorithm inspection

(define (evp-cipher-name algo)
  (define who 'evp-cipher-name)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (let ((rv (capi.evp-cipher-name algo)))
      (and rv (ascii->string rv)))))

(define (evp-cipher-type algo)
  (define who 'evp-cipher-type)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-type algo)))

(define (evp-cipher-nid algo)
  (define who 'evp-cipher-nid)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-nid algo)))

(define (evp-cipher-block-size algo)
  (define who 'evp-cipher-block-size)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-block-size algo)))

(define (evp-cipher-key-length algo)
  (define who 'evp-cipher-key-length)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-key-length algo)))

(define (evp-cipher-iv-length algo)
  (define who 'evp-cipher-iv-length)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-iv-length algo)))

(define (evp-cipher-flags algo)
  (define who 'evp-cipher-flags)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-flags algo)))

(define (evp-cipher-mode algo)
  (define who 'evp-cipher-mode)
  (with-arguments-validation (who)
      ((evp-cipher	algo))
    (capi.evp-cipher-mode algo)))


;;;; EVP cipher algorithms: context initialisation and finalisation

(ffi.define-foreign-pointer-wrapper evp-cipher-ctx
  (ffi.fields running?)
  (ffi.foreign-destructor capi.evp-cipher-ctx-free)
  (ffi.collector-struct-type #f))

(define (evp-cipher-ctx?/running obj)
  (and (evp-cipher-ctx? obj)
       ($evp-cipher-ctx-running? obj)))

(define (evp-cipher-ctx?/alive-not-running obj)
  (and (evp-cipher-ctx?/alive obj)
       (not ($evp-cipher-ctx-running? obj))))

;;; --------------------------------------------------------------------

(define (evp-cipher-ctx-new)
  (let ((rv (capi.evp-cipher-ctx-new)))
    (and rv (make-evp-cipher-ctx/owner rv #f))))

(define (evp-cipher-ctx-free ctx)
  (define who 'evp-cipher-ctx-free)
  (with-arguments-validation (who)
      ((evp-cipher-ctx	ctx))
    ($set-evp-cipher-ctx-running?! ctx #f)
    ($evp-cipher-ctx-finalise ctx)))

(define (evp-cipher-ctx-copy dst src)
  (define who 'evp-cipher-ctx-copy)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	dst)
       (evp-cipher-ctx/running	src))
    (capi.evp-cipher-ctx-copy dst src)))

;;; --------------------------------------------------------------------

(define (evp-minimum-output-length ctx in in.len)
  (define who 'evp-encryp-tinit)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (general-c-string*	in in.len))
    (with-general-c-strings
	((in^	in))
      (string-to-bytevector string->utf8)
      (evp-minimum-output-length ctx in^ in.len))))

;;; --------------------------------------------------------------------

(define (evp-encrypt-init ctx algo key iv)
  (define who 'evp-encryp-tinit)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/alive-not-running	ctx)
       (evp-cipher				algo)
       (general-c-string/false			key)
       (general-c-string/false			iv))
    (with-general-c-strings/false
	((key^		key)
	 (iv^		iv))
      (string-to-bytevector string->utf8)
      (cond ((capi.evp-encrypt-init ctx algo key^ iv^)
	     => (lambda (rv)
		  ($set-evp-cipher-ctx-running?! ctx #t)
		  rv))
	    (else #f)))))

(define (evp-encrypt-final ctx)
  (define who 'evp-encrypt-final)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (begin0
	(capi.evp-encrypt-final ctx)
      ($set-evp-cipher-ctx-running?! ctx #f))))

(define (evp-encrypt-update ctx ou ou.len in in.len)
  (define who 'evp-encrypt-update)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (general-c-buffer*	ou ou.len)
       (general-c-string*	in in.len))
    (with-general-c-strings
	((in^	in))
      (string-to-bytevector string->utf8)
      (capi.evp-encrypt-update ctx ou ou.len in^ in.len))))

;;; --------------------------------------------------------------------

(define (evp-decrypt-init ctx algo key iv)
  (define who 'evp-decrypt-init)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/alive-not-running	ctx)
       (evp-cipher				algo)
       (general-c-string/false			key)
       (general-c-string/false			iv))
    (with-general-c-strings/false
	((key^		key)
	 (iv^		iv))
      (string-to-bytevector string->utf8)
      (cond ((capi.evp-decrypt-init ctx algo key^ iv^)
	     => (lambda (rv)
		  ($set-evp-cipher-ctx-running?! ctx #t)
		  rv))
	    (else #f)))))

(define (evp-decrypt-final ctx)
  (define who 'evp-decrypt-final)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (begin0
	(capi.evp-decrypt-final ctx)
      ($set-evp-cipher-ctx-running?! ctx #f))))

(define (evp-decrypt-update ctx ou ou.len in in.len)
  (define who 'evp-decrypt-update)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (general-c-buffer*	ou ou.len)
       (general-c-buffer*	in in.len))
    (capi.evp-decrypt-update ctx ou ou.len in in.len)))

;;; --------------------------------------------------------------------

(define (evp-cipher-init ctx algo key iv enc)
  (define who 'evp-cipher-init)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/alive-not-running	ctx)
       (evp-cipher				algo)
       (general-c-string/false			key)
       (general-c-string/false			iv)
       (evp-cipher-enc				enc))
    (with-general-c-strings/false
	((key^		key)
	 (iv^		iv))
      (string-to-bytevector string->utf8)
      (cond ((capi.evp-cipher-init ctx algo key^ iv^ enc)
	     => (lambda (rv)
		  ($set-evp-cipher-ctx-running?! ctx #t)
		  rv))
	    (else #f)))))

(define (evp-cipher-final ctx)
  (define who 'evp-cipher-final)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (begin0
	(capi.evp-cipher-final ctx)
      ($set-evp-cipher-ctx-running?! ctx #f))))

(define (evp-cipher-update ctx ou ou.len in in.len)
  (define who 'evp-cipher-update)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (general-c-buffer*	ou ou.len)
       (general-c-string*	in in.len))
    (with-general-c-strings
	((in^	in))
      (string-to-bytevector string->utf8)
      (capi.evp-cipher-update ctx ou ou.len in^ in.len))))


;;;; EVP cipher algorithms: context inspection

(define (evp-cipher-ctx-cipher ctx)
  (define who 'evp-cipher-ctx-cipher)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (let ((rv (capi.evp-cipher-ctx-cipher ctx)))
      (and rv (make-evp-cipher rv)))))

(define (evp-cipher-ctx-type ctx)
  (define who 'evp-cipher-ctx-type)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-type ctx)))

(define (evp-cipher-ctx-nid ctx)
  (define who 'evp-cipher-ctx-nid)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-nid ctx)))

(define (evp-cipher-ctx-block-size ctx)
  (define who 'evp-cipher-ctx-block-size)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-block-size ctx)))

(define (evp-cipher-ctx-key-length ctx)
  (define who 'evp-cipher-ctx-key-length)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-key-length ctx)))

(define (evp-cipher-ctx-iv-length ctx)
  (define who 'evp-cipher-ctx-iv-length)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-iv-length ctx)))

(define (evp-cipher-ctx-mode ctx)
  (define who 'evp-cipher-ctx-mode)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-mode ctx)))


;;;; EVP cipher algorithms: context configuration

(define (evp-cipher-ctx-rand-key ctx key)
  (define who 'evp-cipher-ctx-rand-key)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (general-c-string	key))
    (with-general-c-strings
	((key^		key))
      (string-to-bytevector string->utf8)
      (capi.evp-cipher-ctx-rand-key ctx key^))))

(define (evp-cipher-ctx-set-key-length ctx key.len)
  (define who 'evp-cipher-ctx-set-key-length)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (signed-int		key.len))
    (capi.evp-cipher-ctx-set-key-length ctx key.len)))

(define (evp-cipher-ctx-set-padding ctx pad?)
  (define who 'evp-cipher-ctx-set-padding)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-set-padding ctx pad?)))

(define evp-cipher-ctx-ctrl
  (case-lambda
   ((ctx type)
    (define who 'evp-cipher-ctx-ctrl)
    (with-arguments-validation (who)
	((evp-cipher-ctx/running	ctx)
	 (signed-int			type))
      (capi.evp-cipher-ctx-ctrl ctx type #f)))
   ((ctx type arg)
    (define who 'evp-cipher-ctx-ctrl)
    (with-arguments-validation (who)
	((evp-cipher-ctx/running	ctx)
	 (signed-int			type)
	 (signed-int			arg))
      (capi.evp-cipher-ctx-ctrl ctx type arg)))
   ))


;;;; EVP cipher algorithms: context flags

(define (evp-cipher-ctx-flags ctx)
  (define who 'evp-cipher-ctx-flags)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx))
    (capi.evp-cipher-ctx-flags ctx)))

(define (evp-cipher-ctx-set-flags ctx flags)
  (define who 'evp-cipher-ctx-set-flags)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (signed-int		flags))
    (capi.evp-cipher-ctx-set-flags ctx flags)))

(define (evp-cipher-ctx-clear-flags ctx flags)
  (define who 'evp-cipher-ctx-clear-flags)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (signed-int		flags))
    (capi.evp-cipher-ctx-clear-flags ctx flags)))

(define (evp-cipher-ctx-test-flags ctx flags)
  (define who 'evp-cipher-ctx-test-flags)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (signed-int		flags))
    (capi.evp-cipher-ctx-test-flags ctx flags)))


;;;; EVP cipher algorithms: context misc functions

(define (evp-cipher-ctx-get-app-data ctx)
  (define who 'evp-cipher-ctx-get-app-data)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/alive	ctx))
    (capi.evp-cipher-ctx-get-app-data ctx)))

(define (evp-cipher-ctx-set-app-data ctx data)
  (define who 'evp-cipher-ctx-set-app-data)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/alive	ctx)
       (pointer/false		data))
    (capi.evp-cipher-ctx-set-app-data ctx data)))

;;; --------------------------------------------------------------------
;;; still not implemented

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


;;;; EVP cipher algorithms: context single-step encryption and decryption

(define (evp-crypt ctx ou ou.len in in.len)
  (define who 'evp-crypt)
  (with-arguments-validation (who)
      ((evp-cipher-ctx/running	ctx)
       (general-c-buffer*	ou ou.len)
       (general-c-string*	in in.len))
    (with-general-c-strings
	((in^	in))
      (string-to-bytevector string->utf8)
      (capi.evp-cipher ctx ou ou.len in^ in.len))))


;;;; constants to symbols

(define-exact-integer->symbol-function evp-ciph-mode->symbol
  (EVP_CIPH_STREAM_CIPHER
   EVP_CIPH_ECB_MODE
   EVP_CIPH_CBC_MODE
   EVP_CIPH_CFB_MODE
   EVP_CIPH_OFB_MODE
   EVP_CIPH_CTR_MODE
   EVP_CIPH_GCM_MODE
   EVP_CIPH_CCM_MODE
   EVP_CIPH_XTS_MODE
   EVP_CIPH_MODE))


;;;; done

)

;;; end of file
