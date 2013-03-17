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
    )
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

(define-argument-validation (evp-cipher/symbol who obj)
  (or (evp-cipher? obj)
      (symbol? obj))
  (assertion-violation who
    "expected instance of \"evp-cipher\" or symbol as argument" obj))


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


;;;; done

)

;;; end of file