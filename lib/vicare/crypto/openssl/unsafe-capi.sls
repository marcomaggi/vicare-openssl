;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: unsafe interface to the C language API
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
;;;MERCHANTABILITY or  FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU
;;;General Public License for more details.
;;;
;;;You should  have received a  copy of  the GNU General  Public License
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;


#!r6rs
(library (vicare crypto openssl unsafe-capi)
  (export

    ;; version functions
    vicare-openssl-version-interface-current
    vicare-openssl-version-interface-revision
    vicare-openssl-version-interface-age
    vicare-openssl-version

    ;; MD4
    md4-init
    md4-update
    md4-final
    md4

    ;; MD5
    md5-init
    md5-update
    md5-final
    md5

    ;; MDC2
    mdc2-init
    mdc2-update
    mdc2-final
    mdc2

    ;; SHA1
    sha1-init
    sha1-update
    sha1-final
    sha1

    ;; SHA224
    sha224-init
    sha224-update
    sha224-final
    sha224

    ;; SHA256
    sha256-init
    sha256-update
    sha256-final
    sha256

    ;; SHA384
    sha384-init
    sha384-update
    sha384-final
    sha384

    ;; SHA512
    sha512-init
    sha512-update
    sha512-final
    sha512

    ;; RIPEMD160
    ripemd160-init
    ripemd160-update
    ripemd160-final
    ripemd160

    ;; HMAC unsafe C API
    hmac
    #;hmac-ctx-init
    #;hmac-ctx-cleanup
    hmac-init
    hmac-update
    hmac-final
    hmac-ctx-copy
    hmac-ctx-set-flags

    ;; AES unsafe C API
    aes-options
    aes-finalise
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

    hmac-init-ex
    )
  (import (vicare))


;;;; helpers

(define-syntax define-inline
  (syntax-rules ()
    ((_ (?name ?arg ... . ?rest) ?form0 ?form ...)
     (define-syntax ?name
       (syntax-rules ()
	 ((_ ?arg ... . ?rest)
	  (begin ?form0 ?form ...)))))))


;;;; version functions

(define-inline (vicare-openssl-version-interface-current)
  (foreign-call "ikrt_openssl_version_interface_current"))

(define-inline (vicare-openssl-version-interface-revision)
  (foreign-call "ikrt_openssl_version_interface_revision"))

(define-inline (vicare-openssl-version-interface-age)
  (foreign-call "ikrt_openssl_version_interface_age"))

(define-inline (vicare-openssl-version)
  (foreign-call "ikrt_openssl_version"))


;;;; MD4

(define-inline (md4-init)
  (foreign-call "ikrt_md4_init"))

(define-inline (md4-update ctx input input.len)
  (foreign-call "ikrt_md4_update" ctx input input.len))

(define-inline (md4-final ctx)
  (foreign-call "ikrt_md4_final" ctx))

(define-inline (md4 input input.len)
  (foreign-call "ikrt_md4" input input.len))


;;;; MD5

(define-inline (md5-init)
  (foreign-call "ikrt_md5_init"))

(define-inline (md5-update ctx input input.len)
  (foreign-call "ikrt_md5_update" ctx input input.len))

(define-inline (md5-final ctx)
  (foreign-call "ikrt_md5_final" ctx))

(define-inline (md5 input input.len)
  (foreign-call "ikrt_md5" input input.len))


;;;; MDC2

(define-inline (mdc2-init)
  (foreign-call "ikrt_mdc2_init"))

(define-inline (mdc2-update ctx input input.len)
  (foreign-call "ikrt_mdc2_update" ctx input input.len))

(define-inline (mdc2-final ctx)
  (foreign-call "ikrt_mdc2_final" ctx))

(define-inline (mdc2 input input.len)
  (foreign-call "ikrt_mdc2" input input.len))


;;;; SHA

(define-inline (sha1-init)
  (foreign-call "ikrt_sha1_init"))

(define-inline (sha1-update ctx input input.len)
  (foreign-call "ikrt_sha1_update" ctx input input.len))

(define-inline (sha1-final ctx)
  (foreign-call "ikrt_sha1_final" ctx))

(define-inline (sha1 input input.len)
  (foreign-call "ikrt_sha1" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha224-init)
  (foreign-call "ikrt_sha224_init"))

(define-inline (sha224-update ctx input input.len)
  (foreign-call "ikrt_sha224_update" ctx input input.len))

(define-inline (sha224-final ctx)
  (foreign-call "ikrt_sha224_final" ctx))

(define-inline (sha224 input input.len)
  (foreign-call "ikrt_sha224" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha256-init)
  (foreign-call "ikrt_sha256_init"))

(define-inline (sha256-update ctx input input.len)
  (foreign-call "ikrt_sha256_update" ctx input input.len))

(define-inline (sha256-final ctx)
  (foreign-call "ikrt_sha256_final" ctx))

(define-inline (sha256 input input.len)
  (foreign-call "ikrt_sha256" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha384-init)
  (foreign-call "ikrt_sha384_init"))

(define-inline (sha384-update ctx input input.len)
  (foreign-call "ikrt_sha384_update" ctx input input.len))

(define-inline (sha384-final ctx)
  (foreign-call "ikrt_sha384_final" ctx))

(define-inline (sha384 input input.len)
  (foreign-call "ikrt_sha384" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha512-init)
  (foreign-call "ikrt_sha512_init"))

(define-inline (sha512-update ctx input input.len)
  (foreign-call "ikrt_sha512_update" ctx input input.len))

(define-inline (sha512-final ctx)
  (foreign-call "ikrt_sha512_final" ctx))

(define-inline (sha512 input input.len)
  (foreign-call "ikrt_sha512" input input.len))


;;;; RIPEMD160

(define-inline (ripemd160-init)
  (foreign-call "ikrt_ripemd160_init"))

(define-inline (ripemd160-update ctx input input.len)
  (foreign-call "ikrt_ripemd160_update" ctx input input.len))

(define-inline (ripemd160-final ctx)
  (foreign-call "ikrt_ripemd160_final" ctx))

(define-inline (ripemd160 input input.len)
  (foreign-call "ikrt_ripemd160" input input.len))


;;;; HMAC

(define-inline (hmac md key key.len input input.len)
  (foreign-call "ikrt_hmac" md key key.len input input.len))

;;; --------------------------------------------------------------------

(define-inline (hmac-init input input.len md)
  (foreign-call "ikrt_hmac_init" input input.len md))
;; (define-inline (hmac-ctx-init)
;;   (foreign-call "ikrt_hmac_ctx_init"))
;; (define-inline (hmac-init ctx input input.len md)
;;   (foreign-call "ikrt_hmac_init" ctx input input.len md))

(define-inline (hmac-final ctx)
  (foreign-call "ikrt_hmac_final" ctx))
;; (define-inline (hmac-ctx-cleanup ctx)
;;   (foreign-call "ikrt_hmac_ctx_cleanup" ctx))

(define-inline (hmac-update ctx input input.len)
  (foreign-call "ikrt_hmac_update" ctx input input.len))

(define-inline (hmac-ctx-copy dst-ctx src-ctx)
  (foreign-call "ikrt_hmac_ctx_copy" dst-ctx src-ctx))

(define-inline (hmac-ctx-set-flags ctx flags)
  (foreign-call "ikrt_hmac_ctx_set_flags" ctx flags))


;;;; AES unsafe C API

(define-inline (aes-options)
  (foreign-call "ikrt_aes_options"))

;;; --------------------------------------------------------------------

(define-inline (aes-finalise ctx)
  ;;This is not an OpenSSL function.
  ;;
  (foreign-call "ikrt_aes_finalise" ctx))

(define-inline (aes-set-encrypt-key key key.len)
  (foreign-call "ikrt_aes_set_encrypt_key" key key.len))

(define-inline (aes-set-decrypt-key key key.len)
  (foreign-call "ikrt_aes_set_decrypt_key" key key.len))

;;; --------------------------------------------------------------------

(define-inline (aes-encrypt in ou ctx)
  (foreign-call "ikrt_aes_encrypt" in ou ctx))

(define-inline (aes-decrypt in ou ctx)
  (foreign-call "ikrt_aes_decrypt" in ou ctx))

;;; --------------------------------------------------------------------

(define-inline (aes-ecb-encrypt in ou ctx mode)
  (foreign-call "ikrt_aes_ecb_encrypt" in ou ctx mode))

(define-inline (aes-cbc-encrypt in in.len ou ou.len ctx iv iv.len mode)
  (foreign-call "ikrt_aes_cbc_encrypt" in in.len ou ou.len ctx iv iv.len mode))

(define-inline (aes-cfb128-encrypt)
  (foreign-call "ikrt_aes_cfb128_encrypt"))

(define-inline (aes-cfb1-encrypt)
  (foreign-call "ikrt_aes_cfb1_encrypt"))

(define-inline (aes-cfb8-encrypt)
  (foreign-call "ikrt_aes_cfb8_encrypt"))

(define-inline (aes-ofb128-encrypt)
  (foreign-call "ikrt_aes_ofb128_encrypt"))

(define-inline (aes-ctr128-encrypt)
  (foreign-call "ikrt_aes_ctr128_encrypt"))

(define-inline (aes-ige-encrypt)
  (foreign-call "ikrt_aes_ige_encrypt"))

(define-inline (aes-bi-ige-encrypt)
  (foreign-call "ikrt_aes_bi_ige_encrypt"))

;;; --------------------------------------------------------------------

(define-inline (aes-wrap-key)
  (foreign-call "ikrt_aes_wrap_key"))

(define-inline (aes-unwrap-key)
  (foreign-call "ikrt_aes_unwrap_key"))


;;;; still to be implemented

(define-inline (hmac-init-ex)
  (foreign-call "ikrt_hmac_init_ex"))


;;;; done

)

;;; end of file
