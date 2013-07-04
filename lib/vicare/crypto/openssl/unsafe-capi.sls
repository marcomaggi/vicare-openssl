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

    ;; Library initialisation unsafe C API
    ssl-library-init
    openssl-add-all-algorithms-noconf
    openssl-add-all-algorithms-conf
    openssl-add-all-algorithms
    openssl-add-all-ciphers
    openssl-add-all-digests
    ssleay-add-all-algorithms
    ssleay-add-all-ciphers
    ssleay-add-all-digests

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

    ;; WHIRLPOOL
    whirlpool-init
    whirlpool-update
    whirlpool-final
    whirlpool

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
    ;; aes-cfb128-encrypt
    ;; aes-cfb1-encrypt
    ;; aes-cfb8-encrypt
    aes-ofb128-encrypt
    aes-ctr128-encrypt
    aes-ige-encrypt
    aes-bi-ige-encrypt
    aes-wrap-key
    aes-unwrap-key

    ;; EVP hash functions unsafe C API
    evp-md-ctx-create		evp-md-ctx-destroy
    evp-digest-init		evp-digest-final
    evp-digest-update

    evp-md-type
    evp-md-nid
    evp-md-name
    evp-md-pkey-type
    evp-md-size
    evp-md-block-size
    evp-md-flags
    evp-md-ctx-md
    evp-md-ctx-size
    evp-md-ctx-block-size
    evp-md-ctx-type
    evp-md-ctx-copy
    evp-md-ctx-set-flags
    evp-md-ctx-clear-flags
    evp-md-ctx-test-flags
    evp-digest
    evp-md-null
    evp-md2
    evp-md4
    evp-md5
    evp-sha
    evp-sha1
    evp-dss
    evp-dss1
    evp-ecdsa
    evp-sha224
    evp-sha256
    evp-sha384
    evp-sha512
    evp-mdc2
    evp-ripemd160
    evp-whirlpool
    evp-get-digestbyname

    ;; EVP cipher algorithms unsafe C API
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

    evp-get-cipherbyname	evp-get-cipherbynid		evp-get-cipherbyobj

    evp-cipher-type		evp-cipher-nid
    evp-cipher-name		evp-cipher-block-size
    evp-cipher-key-length	evp-cipher-iv-length
    evp-cipher-flags		evp-cipher-mode

    ;; EVP cipher context
    evp-cipher-ctx-new		evp-cipher-ctx-free		evp-cipher-ctx-copy
    evp-encrypt-init		evp-encrypt-final		evp-encrypt-update
    evp-decrypt-init		evp-decrypt-final		evp-decrypt-update
    evp-cipher-init		evp-cipher-final		evp-cipher-update
    evp-minimum-output-length

    evp-cipher-ctx-set-key-length	evp-cipher-ctx-set-padding
    evp-cipher-ctx-ctrl			evp-cipher-ctx-cipher
    evp-cipher-ctx-nid			evp-cipher-ctx-block-size
    evp-cipher-ctx-key-length		evp-cipher-ctx-iv-length
    evp-cipher-ctx-type			evp-cipher-ctx-mode
    evp-cipher-ctx-rand-key

    evp-cipher-ctx-get-app-data		evp-cipher-ctx-set-app-data
    evp-cipher-param-to-asn1		evp-cipher-asn1-to-param
    evp-cipher-ctx-flags		evp-cipher-ctx-set-flags
    evp-cipher-ctx-clear-flags		evp-cipher-ctx-test-flags
    evp-cipher

;;; --------------------------------------------------------------------
;;; still to be implemented

    hmac-init-ex
    )
  (import (vicare))


;;;; version functions

(define-inline (vicare-openssl-version-interface-current)
  (foreign-call "ikrt_openssl_version_interface_current"))

(define-inline (vicare-openssl-version-interface-revision)
  (foreign-call "ikrt_openssl_version_interface_revision"))

(define-inline (vicare-openssl-version-interface-age)
  (foreign-call "ikrt_openssl_version_interface_age"))

(define-inline (vicare-openssl-version)
  (foreign-call "ikrt_openssl_version"))


;;;; Library initialisation unsafe C API

(define-inline (ssl-library-init)
  (foreign-call "ikrt_openssl_ssl_library_init"))

(define-inline (openssl-add-all-algorithms-noconf)
  (foreign-call "ikrt_openssl_add_all_algorithms_noconf"))

(define-inline (openssl-add-all-algorithms-conf)
  (foreign-call "ikrt_openssl_add_all_algorithms_conf"))

(define-inline (openssl-add-all-algorithms)
  (foreign-call "ikrt_openssl_add_all_algorithms"))

(define-inline (openssl-add-all-ciphers)
  (foreign-call "ikrt_openssl_add_all_ciphers"))

(define-inline (openssl-add-all-digests)
  (foreign-call "ikrt_openssl_add_all_digests"))

(define-inline (ssleay-add-all-algorithms)
  (foreign-call "ikrt_ssleay_add_all_algorithms"))

(define-inline (ssleay-add-all-ciphers)
  (foreign-call "ikrt_ssleay_add_all_ciphers"))

(define-inline (ssleay-add-all-digests)
  (foreign-call "ikrt_ssleay_add_all_digests"))


;;;; MD4

(define-inline (md4-init)
  (foreign-call "ikrt_openssl_md4_init"))

(define-inline (md4-update ctx input input.len)
  (foreign-call "ikrt_openssl_md4_update" ctx input input.len))

(define-inline (md4-final ctx)
  (foreign-call "ikrt_openssl_md4_final" ctx))

(define-inline (md4 input input.len)
  (foreign-call "ikrt_openssl_md4" input input.len))


;;;; MD5

(define-inline (md5-init)
  (foreign-call "ikrt_openssl_md5_init"))

(define-inline (md5-update ctx input input.len)
  (foreign-call "ikrt_openssl_md5_update" ctx input input.len))

(define-inline (md5-final ctx)
  (foreign-call "ikrt_openssl_md5_final" ctx))

(define-inline (md5 input input.len)
  (foreign-call "ikrt_openssl_md5" input input.len))


;;;; MDC2

(define-inline (mdc2-init)
  (foreign-call "ikrt_openssl_mdc2_init"))

(define-inline (mdc2-update ctx input input.len)
  (foreign-call "ikrt_openssl_mdc2_update" ctx input input.len))

(define-inline (mdc2-final ctx)
  (foreign-call "ikrt_openssl_mdc2_final" ctx))

(define-inline (mdc2 input input.len)
  (foreign-call "ikrt_openssl_mdc2" input input.len))


;;;; SHA

(define-inline (sha1-init)
  (foreign-call "ikrt_openssl_sha1_init"))

(define-inline (sha1-update ctx input input.len)
  (foreign-call "ikrt_openssl_sha1_update" ctx input input.len))

(define-inline (sha1-final ctx)
  (foreign-call "ikrt_openssl_sha1_final" ctx))

(define-inline (sha1 input input.len)
  (foreign-call "ikrt_openssl_sha1" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha224-init)
  (foreign-call "ikrt_openssl_sha224_init"))

(define-inline (sha224-update ctx input input.len)
  (foreign-call "ikrt_openssl_sha224_update" ctx input input.len))

(define-inline (sha224-final ctx)
  (foreign-call "ikrt_openssl_sha224_final" ctx))

(define-inline (sha224 input input.len)
  (foreign-call "ikrt_openssl_sha224" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha256-init)
  (foreign-call "ikrt_openssl_sha256_init"))

(define-inline (sha256-update ctx input input.len)
  (foreign-call "ikrt_openssl_sha256_update" ctx input input.len))

(define-inline (sha256-final ctx)
  (foreign-call "ikrt_openssl_sha256_final" ctx))

(define-inline (sha256 input input.len)
  (foreign-call "ikrt_openssl_sha256" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha384-init)
  (foreign-call "ikrt_openssl_sha384_init"))

(define-inline (sha384-update ctx input input.len)
  (foreign-call "ikrt_openssl_sha384_update" ctx input input.len))

(define-inline (sha384-final ctx)
  (foreign-call "ikrt_openssl_sha384_final" ctx))

(define-inline (sha384 input input.len)
  (foreign-call "ikrt_openssl_sha384" input input.len))

;;; --------------------------------------------------------------------

(define-inline (sha512-init)
  (foreign-call "ikrt_openssl_sha512_init"))

(define-inline (sha512-update ctx input input.len)
  (foreign-call "ikrt_openssl_sha512_update" ctx input input.len))

(define-inline (sha512-final ctx)
  (foreign-call "ikrt_openssl_sha512_final" ctx))

(define-inline (sha512 input input.len)
  (foreign-call "ikrt_openssl_sha512" input input.len))


;;;; RIPEMD160

(define-inline (ripemd160-init)
  (foreign-call "ikrt_openssl_ripemd160_init"))

(define-inline (ripemd160-update ctx input input.len)
  (foreign-call "ikrt_openssl_ripemd160_update" ctx input input.len))

(define-inline (ripemd160-final ctx)
  (foreign-call "ikrt_openssl_ripemd160_final" ctx))

(define-inline (ripemd160 input input.len)
  (foreign-call "ikrt_openssl_ripemd160" input input.len))


;;;; WHIRLPOOL

(define-inline (whirlpool-init)
  (foreign-call "ikrt_openssl_whirlpool_init"))

(define-inline (whirlpool-update ctx input input.len)
  (foreign-call "ikrt_openssl_whirlpool_update" ctx input input.len))

(define-inline (whirlpool-final ctx)
  (foreign-call "ikrt_openssl_whirlpool_final" ctx))

(define-inline (whirlpool input input.len)
  (foreign-call "ikrt_openssl_whirlpool" input input.len))


;;;; HMAC

(define-inline (hmac md key key.len input input.len)
  (foreign-call "ikrt_openssl_hmac" md key key.len input input.len))

;;; --------------------------------------------------------------------

(define-inline (hmac-init input input.len md)
  (foreign-call "ikrt_openssl_hmac_init" input input.len md))
;; (define-inline (hmac-ctx-init)
;;   (foreign-call "ikrt_openssl_hmac_ctx_init"))
;; (define-inline (hmac-init ctx input input.len md)
;;   (foreign-call "ikrt_openssl_hmac_init" ctx input input.len md))

(define-inline (hmac-final ctx)
  (foreign-call "ikrt_openssl_hmac_final" ctx))
;; (define-inline (hmac-ctx-cleanup ctx)
;;   (foreign-call "ikrt_openssl_hmac_ctx_cleanup" ctx))

(define-inline (hmac-update ctx input input.len)
  (foreign-call "ikrt_openssl_hmac_update" ctx input input.len))

(define-inline (hmac-ctx-copy dst-ctx src-ctx)
  (foreign-call "ikrt_openssl_hmac_ctx_copy" dst-ctx src-ctx))

(define-inline (hmac-ctx-set-flags ctx flags)
  (foreign-call "ikrt_openssl_hmac_ctx_set_flags" ctx flags))


;;;; AES unsafe C API

(define-inline (aes-options)
  (foreign-call "ikrt_openssl_aes_options"))

;;; --------------------------------------------------------------------

(define-inline (aes-finalise ctx)
  ;;This is not an OpenSSL function.
  ;;
  (foreign-call "ikrt_openssl_aes_finalise" ctx))

(define-inline (aes-set-encrypt-key key key.len)
  (foreign-call "ikrt_openssl_aes_set_encrypt_key" key key.len))

(define-inline (aes-set-decrypt-key key key.len)
  (foreign-call "ikrt_openssl_aes_set_decrypt_key" key key.len))

;;; --------------------------------------------------------------------

(define-inline (aes-encrypt in ou ctx)
  (foreign-call "ikrt_openssl_aes_encrypt" in ou ctx))

(define-inline (aes-decrypt in ou ctx)
  (foreign-call "ikrt_openssl_aes_decrypt" in ou ctx))

;;; --------------------------------------------------------------------

(define-inline (aes-ecb-encrypt in ou ctx mode)
  (foreign-call "ikrt_openssl_aes_ecb_encrypt" in ou ctx mode))

(define-inline (aes-cbc-encrypt in in.len ou ou.len ctx iv iv.len mode)
  (foreign-call "ikrt_openssl_aes_cbc_encrypt" in in.len ou ou.len ctx iv iv.len mode))

;; (define-inline (aes-cfb128-encrypt in in.len ou ou.len ctx iv iv.len num mode)
;;   (foreign-call "ikrt_openssl_aes_cfb128_encrypt" in in.len ou ou.len ctx iv iv.len num mode))

;; (define-inline (aes-cfb1-encrypt in in.len ou ou.len ctx iv iv.len num mode)
;;   (foreign-call "ikrt_openssl_aes_cfb1_encrypt" in in.len ou ou.len ctx iv iv.len num mode))

;; (define-inline (aes-cfb8-encrypt in in.len ou ou.len ctx iv iv.len num mode)
;;   (foreign-call "ikrt_openssl_aes_cfb8_encrypt" in in.len ou ou.len ctx iv iv.len num mode))

(define-inline (aes-ofb128-encrypt)
  (foreign-call "ikrt_openssl_aes_ofb128_encrypt"))

(define-inline (aes-ctr128-encrypt)
  (foreign-call "ikrt_openssl_aes_ctr128_encrypt"))

(define-inline (aes-ige-encrypt)
  (foreign-call "ikrt_openssl_aes_ige_encrypt"))

(define-inline (aes-bi-ige-encrypt)
  (foreign-call "ikrt_openssl_aes_bi_ige_encrypt"))

;;; --------------------------------------------------------------------

(define-inline (aes-wrap-key)
  (foreign-call "ikrt_openssl_aes_wrap_key"))

(define-inline (aes-unwrap-key)
  (foreign-call "ikrt_openssl_aes_unwrap_key"))


;;;; EVP hash functions unsafe C API

(define-inline (evp-md-ctx-create)
  (foreign-call "ikrt_openssl_evp_md_ctx_create"))

(define-inline (evp-md-ctx-destroy ctx)
  (foreign-call "ikrt_openssl_evp_md_ctx_destroy" ctx))

(define-inline (evp-md-ctx-copy ou in)
  (foreign-call "ikrt_openssl_evp_md_ctx_copy_ex" ou in))

;;; --------------------------------------------------------------------

(define-inline (evp-digest-init ctx md)
  (foreign-call "ikrt_openssl_evp_digestinit_ex" ctx md))

(define-inline (evp-digest-final ctx)
  (foreign-call "ikrt_openssl_evp_digestfinal_ex" ctx))

;;; --------------------------------------------------------------------

(define-inline (evp-digest-update ctx buf buf.len)
  (foreign-call "ikrt_openssl_evp_digestupdate" ctx buf buf.len))

;;; --------------------------------------------------------------------

(define-inline (evp-md-ctx-size ctx)
  (foreign-call "ikrt_openssl_evp_md_ctx_size" ctx))

(define-inline (evp-md-ctx-block-size ctx)
  (foreign-call "ikrt_openssl_evp_md_ctx_block_size" ctx))

(define-inline (evp-md-ctx-md ctx)
  (foreign-call "ikrt_openssl_evp_md_ctx_md" ctx))

(define-inline (evp-md-ctx-type ctx)
  (foreign-call "ikrt_openssl_evp_md_ctx_type" ctx))

;;; --------------------------------------------------------------------

(define-inline (evp-md-ctx-set-flags ctx flags)
  (foreign-call "ikrt_openssl_evp_md_ctx_set_flags" ctx flags))

(define-inline (evp-md-ctx-clear-flags ctx flags)
  (foreign-call "ikrt_openssl_evp_md_ctx_clear_flags" ctx flags))

(define-inline (evp-md-ctx-test-flags ctx flags)
  (foreign-call "ikrt_openssl_evp_md_ctx_test_flags" ctx flags))

;;; --------------------------------------------------------------------

(define-inline (evp-md-null)
  (foreign-call "ikrt_openssl_evp_md_null"))

(define-inline (evp-md2)
  (foreign-call "ikrt_openssl_evp_md2"))

(define-inline (evp-md4)
  (foreign-call "ikrt_openssl_evp_md4"))

(define-inline (evp-md5)
  (foreign-call "ikrt_openssl_evp_md5"))

(define-inline (evp-sha)
  (foreign-call "ikrt_openssl_evp_sha"))

(define-inline (evp-sha1)
  (foreign-call "ikrt_openssl_evp_sha1"))

(define-inline (evp-dss)
  (foreign-call "ikrt_openssl_evp_dss"))

(define-inline (evp-dss1)
  (foreign-call "ikrt_openssl_evp_dss1"))

(define-inline (evp-ecdsa)
  (foreign-call "ikrt_openssl_evp_ecdsa"))

(define-inline (evp-sha224)
  (foreign-call "ikrt_openssl_evp_sha224"))

(define-inline (evp-sha256)
  (foreign-call "ikrt_openssl_evp_sha256"))

(define-inline (evp-sha384)
  (foreign-call "ikrt_openssl_evp_sha384"))

(define-inline (evp-sha512)
  (foreign-call "ikrt_openssl_evp_sha512"))

(define-inline (evp-mdc2)
  (foreign-call "ikrt_openssl_evp_mdc2"))

(define-inline (evp-ripemd160)
  (foreign-call "ikrt_openssl_evp_ripemd160"))

(define-inline (evp-whirlpool)
  (foreign-call "ikrt_openssl_evp_whirlpool"))

;;; --------------------------------------------------------------------

(define-inline (evp-md-size algo)
  (foreign-call "ikrt_openssl_evp_md_size" algo))

(define-inline (evp-md-block-size algo)
  (foreign-call "ikrt_openssl_evp_md_block_size" algo))

(define-inline (evp-md-name algo)
  (foreign-call "ikrt_openssl_evp_md_name" algo))

(define-inline (evp-md-type algo)
  (foreign-call "ikrt_openssl_evp_md_type" algo))

(define-inline (evp-md-nid algo)
  (foreign-call "ikrt_openssl_evp_md_nid" algo))

(define-inline (evp-md-flags algo)
  (foreign-call "ikrt_openssl_evp_md_flags" algo))

(define-inline (evp-md-pkey-type algo)
  (foreign-call "ikrt_openssl_evp_md_pkey_type" algo))

;;; --------------------------------------------------------------------

(define-inline (evp-digest buf buf.len algo)
  (foreign-call "ikrt_openssl_evp_digest" buf buf.len algo))

(define-inline (evp-get-digestbyname name)
  (foreign-call "ikrt_openssl_evp_get_digestbyname" name))


;;;; EVP cipher algorithms unsafe C API

(define-inline (evp-enc-null)
  (foreign-call "ikrt_openssl_evp_enc_null"))

(define-inline (evp-des-ecb)
  (foreign-call "ikrt_openssl_evp_des_ecb"))

(define-inline (evp-des-ede)
  (foreign-call "ikrt_openssl_evp_des_ede"))

(define-inline (evp-des-ede3)
  (foreign-call "ikrt_openssl_evp_des_ede3"))

(define-inline (evp-des-ede-ecb)
  (foreign-call "ikrt_openssl_evp_des_ede_ecb"))

(define-inline (evp-des-ede3-ecb)
  (foreign-call "ikrt_openssl_evp_des_ede3_ecb"))

(define-inline (evp-des-cfb64)
  (foreign-call "ikrt_openssl_evp_des_cfb64"))

(define-inline (evp-des-cfb)
  (foreign-call "ikrt_openssl_evp_des_cfb"))

(define-inline (evp-des-ede3-cfb64)
  (foreign-call "ikrt_openssl_evp_des_ede3_cfb64"))

(define-inline (evp-des-ede3-cfb)
  (foreign-call "ikrt_openssl_evp_des_ede3_cfb"))

(define-inline (evp-des-ede3-cfb1)
  (foreign-call "ikrt_openssl_evp_des_ede3_cfb1"))

(define-inline (evp-des-ede3-cfb8)
  (foreign-call "ikrt_openssl_evp_des_ede3_cfb8"))

(define-inline (evp-des-ofb)
  (foreign-call "ikrt_openssl_evp_des_ofb"))

(define-inline (evp-des-ede-ofb)
  (foreign-call "ikrt_openssl_evp_des_ede_ofb"))

(define-inline (evp-des-ede3-ofb)
  (foreign-call "ikrt_openssl_evp_des_ede3_ofb"))

(define-inline (evp-des-cbc)
  (foreign-call "ikrt_openssl_evp_des_cbc"))

(define-inline (evp-des-ede-cbc)
  (foreign-call "ikrt_openssl_evp_des_ede_cbc"))

(define-inline (evp-des-ede3-cbc)
  (foreign-call "ikrt_openssl_evp_des_ede3_cbc"))

(define-inline (evp-desx-cbc)
  (foreign-call "ikrt_openssl_evp_desx_cbc"))

(define-inline (evp-rc4)
  (foreign-call "ikrt_openssl_evp_rc4"))

(define-inline (evp-rc4-40)
  (foreign-call "ikrt_openssl_evp_rc4_40"))

(define-inline (evp-rc4-hmac-md5)
  (foreign-call "ikrt_openssl_evp_rc4_hmac_md5"))

(define-inline (evp-idea-ecb)
  (foreign-call "ikrt_openssl_evp_idea_ecb"))

(define-inline (evp-idea-cfb64)
  (foreign-call "ikrt_openssl_evp_idea_cfb64"))

(define-inline (evp-idea-cfb)
  (foreign-call "ikrt_openssl_evp_idea_cfb"))

(define-inline (evp-idea-ofb)
  (foreign-call "ikrt_openssl_evp_idea_ofb"))

(define-inline (evp-idea-cbc)
  (foreign-call "ikrt_openssl_evp_idea_cbc"))

(define-inline (evp-rc2-ecb)
  (foreign-call "ikrt_openssl_evp_rc2_ecb"))

(define-inline (evp-rc2-cbc)
  (foreign-call "ikrt_openssl_evp_rc2_cbc"))

(define-inline (evp-rc2-40-cbc)
  (foreign-call "ikrt_openssl_evp_rc2_40_cbc"))

(define-inline (evp-rc2-64-cbc)
  (foreign-call "ikrt_openssl_evp_rc2_64_cbc"))

(define-inline (evp-rc2-cfb64)
  (foreign-call "ikrt_openssl_evp_rc2_cfb64"))

(define-inline (evp-rc2-cfb)
  (foreign-call "ikrt_openssl_evp_rc2_cfb"))

(define-inline (evp-rc2-ofb)
  (foreign-call "ikrt_openssl_evp_rc2_ofb"))

(define-inline (evp-bf-ecb)
  (foreign-call "ikrt_openssl_evp_bf_ecb"))

(define-inline (evp-bf-cbc)
  (foreign-call "ikrt_openssl_evp_bf_cbc"))

(define-inline (evp-bf-cfb64)
  (foreign-call "ikrt_openssl_evp_bf_cfb64"))

(define-inline (evp-bf-cfb)
  (foreign-call "ikrt_openssl_evp_bf_cfb"))

(define-inline (evp-bf-ofb)
  (foreign-call "ikrt_openssl_evp_bf_ofb"))

(define-inline (evp-cast5-ecb)
  (foreign-call "ikrt_openssl_evp_cast5_ecb"))

(define-inline (evp-cast5-cbc)
  (foreign-call "ikrt_openssl_evp_cast5_cbc"))

(define-inline (evp-cast5-cfb64)
  (foreign-call "ikrt_openssl_evp_cast5_cfb64"))

(define-inline (evp-cast5-cfb)
  (foreign-call "ikrt_openssl_evp_cast5_cfb"))

(define-inline (evp-cast5-ofb)
  (foreign-call "ikrt_openssl_evp_cast5_ofb"))

(define-inline (evp-rc5-32-12-16-cbc)
  (foreign-call "ikrt_openssl_evp_rc5_32_12_16_cbc"))

(define-inline (evp-rc5-32-12-16-ecb)
  (foreign-call "ikrt_openssl_evp_rc5_32_12_16_ecb"))

(define-inline (evp-rc5-32-12-16-cfb64)
  (foreign-call "ikrt_openssl_evp_rc5_32_12_16_cfb64"))

(define-inline (evp-rc5-32-12-16-cfb)
  (foreign-call "ikrt_openssl_evp_rc5_32_12_16_cfb"))

(define-inline (evp-rc5-32-12-16-ofb)
  (foreign-call "ikrt_openssl_evp_rc5_32_12_16_ofb"))

(define-inline (evp-aes-128-ecb)
  (foreign-call "ikrt_openssl_evp_aes_128_ecb"))

(define-inline (evp-aes-128-cbc)
  (foreign-call "ikrt_openssl_evp_aes_128_cbc"))

(define-inline (evp-aes-128-cfb1)
  (foreign-call "ikrt_openssl_evp_aes_128_cfb1"))

(define-inline (evp-aes-128-cfb8)
  (foreign-call "ikrt_openssl_evp_aes_128_cfb8"))

(define-inline (evp-aes-128-cfb128)
  (foreign-call "ikrt_openssl_evp_aes_128_cfb128"))

(define-inline (evp-aes-128-cfb)
  (foreign-call "ikrt_openssl_evp_aes_128_cfb"))

(define-inline (evp-aes-128-ofb)
  (foreign-call "ikrt_openssl_evp_aes_128_ofb"))

(define-inline (evp-aes-128-ctr)
  (foreign-call "ikrt_openssl_evp_aes_128_ctr"))

(define-inline (evp-aes-128-ccm)
  (foreign-call "ikrt_openssl_evp_aes_128_ccm"))

(define-inline (evp-aes-128-gcm)
  (foreign-call "ikrt_openssl_evp_aes_128_gcm"))

(define-inline (evp-aes-128-xts)
  (foreign-call "ikrt_openssl_evp_aes_128_xts"))

(define-inline (evp-aes-192-ecb)
  (foreign-call "ikrt_openssl_evp_aes_192_ecb"))

(define-inline (evp-aes-192-cbc)
  (foreign-call "ikrt_openssl_evp_aes_192_cbc"))

(define-inline (evp-aes-192-cfb1)
  (foreign-call "ikrt_openssl_evp_aes_192_cfb1"))

(define-inline (evp-aes-192-cfb8)
  (foreign-call "ikrt_openssl_evp_aes_192_cfb8"))

(define-inline (evp-aes-192-cfb128)
  (foreign-call "ikrt_openssl_evp_aes_192_cfb128"))

(define-inline (evp-aes-192-cfb)
  (foreign-call "ikrt_openssl_evp_aes_192_cfb"))

(define-inline (evp-aes-192-ofb)
  (foreign-call "ikrt_openssl_evp_aes_192_ofb"))

(define-inline (evp-aes-192-ctr)
  (foreign-call "ikrt_openssl_evp_aes_192_ctr"))

(define-inline (evp-aes-192-ccm)
  (foreign-call "ikrt_openssl_evp_aes_192_ccm"))

(define-inline (evp-aes-192-gcm)
  (foreign-call "ikrt_openssl_evp_aes_192_gcm"))

(define-inline (evp-aes-256-ecb)
  (foreign-call "ikrt_openssl_evp_aes_256_ecb"))

(define-inline (evp-aes-256-cbc)
  (foreign-call "ikrt_openssl_evp_aes_256_cbc"))

(define-inline (evp-aes-256-cfb1)
  (foreign-call "ikrt_openssl_evp_aes_256_cfb1"))

(define-inline (evp-aes-256-cfb8)
  (foreign-call "ikrt_openssl_evp_aes_256_cfb8"))

(define-inline (evp-aes-256-cfb128)
  (foreign-call "ikrt_openssl_evp_aes_256_cfb128"))

(define-inline (evp-aes-256-cfb)
  (foreign-call "ikrt_openssl_evp_aes_256_cfb"))

(define-inline (evp-aes-256-ofb)
  (foreign-call "ikrt_openssl_evp_aes_256_ofb"))

(define-inline (evp-aes-256-ctr)
  (foreign-call "ikrt_openssl_evp_aes_256_ctr"))

(define-inline (evp-aes-256-ccm)
  (foreign-call "ikrt_openssl_evp_aes_256_ccm"))

(define-inline (evp-aes-256-gcm)
  (foreign-call "ikrt_openssl_evp_aes_256_gcm"))

(define-inline (evp-aes-256-xts)
  (foreign-call "ikrt_openssl_evp_aes_256_xts"))

(define-inline (evp-aes-128-cbc-hmac-sha1)
  (foreign-call "ikrt_openssl_evp_aes_128_cbc_hmac_sha1"))

(define-inline (evp-aes-256-cbc-hmac-sha1)
  (foreign-call "ikrt_openssl_evp_aes_256_cbc_hmac_sha1"))

(define-inline (evp-camellia-128-ecb)
  (foreign-call "ikrt_openssl_evp_camellia_128_ecb"))

(define-inline (evp-camellia-128-cbc)
  (foreign-call "ikrt_openssl_evp_camellia_128_cbc"))

(define-inline (evp-camellia-128-cfb1)
  (foreign-call "ikrt_openssl_evp_camellia_128_cfb1"))

(define-inline (evp-camellia-128-cfb8)
  (foreign-call "ikrt_openssl_evp_camellia_128_cfb8"))

(define-inline (evp-camellia-128-cfb128)
  (foreign-call "ikrt_openssl_evp_camellia_128_cfb128"))

(define-inline (evp-camellia-128-cfb)
  (foreign-call "ikrt_openssl_evp_camellia_128_cfb"))

(define-inline (evp-camellia-128-ofb)
  (foreign-call "ikrt_openssl_evp_camellia_128_ofb"))

(define-inline (evp-camellia-192-ecb)
  (foreign-call "ikrt_openssl_evp_camellia_192_ecb"))

(define-inline (evp-camellia-192-cbc)
  (foreign-call "ikrt_openssl_evp_camellia_192_cbc"))

(define-inline (evp-camellia-192-cfb1)
  (foreign-call "ikrt_openssl_evp_camellia_192_cfb1"))

(define-inline (evp-camellia-192-cfb8)
  (foreign-call "ikrt_openssl_evp_camellia_192_cfb8"))

(define-inline (evp-camellia-192-cfb128)
  (foreign-call "ikrt_openssl_evp_camellia_192_cfb128"))

(define-inline (evp-camellia-192-cfb)
  (foreign-call "ikrt_openssl_evp_camellia_192_cfb"))

(define-inline (evp-camellia-192-ofb)
  (foreign-call "ikrt_openssl_evp_camellia_192_ofb"))

(define-inline (evp-camellia-256-ecb)
  (foreign-call "ikrt_openssl_evp_camellia_256_ecb"))

(define-inline (evp-camellia-256-cbc)
  (foreign-call "ikrt_openssl_evp_camellia_256_cbc"))

(define-inline (evp-camellia-256-cfb1)
  (foreign-call "ikrt_openssl_evp_camellia_256_cfb1"))

(define-inline (evp-camellia-256-cfb8)
  (foreign-call "ikrt_openssl_evp_camellia_256_cfb8"))

(define-inline (evp-camellia-256-cfb128)
  (foreign-call "ikrt_openssl_evp_camellia_256_cfb128"))

(define-inline (evp-camellia-256-cfb)
  (foreign-call "ikrt_openssl_evp_camellia_256_cfb"))

(define-inline (evp-camellia-256-ofb)
  (foreign-call "ikrt_openssl_evp_camellia_256_ofb"))

(define-inline (evp-seed-ecb)
  (foreign-call "ikrt_openssl_evp_seed_ecb"))

(define-inline (evp-seed-cbc)
  (foreign-call "ikrt_openssl_evp_seed_cbc"))

(define-inline (evp-seed-cfb128)
  (foreign-call "ikrt_openssl_evp_seed_cfb128"))

(define-inline (evp-seed-cfb)
  (foreign-call "ikrt_openssl_evp_seed_cfb"))

(define-inline (evp-seed-ofb)
  (foreign-call "ikrt_openssl_evp_seed_ofb"))


;;;; EVP cipher algorithms unsafe C API: special makers for EVP_CIPHER references

(define-inline (evp-get-cipherbyname name)
  (foreign-call "ikrt_openssl_evp_get_cipherbyname" name))

(define-inline (evp-get-cipherbynid nid)
  (foreign-call "ikrt_openssl_evp_get_cipherbynid" nid))

(define-inline (evp-get-cipherbyobj)
  ;;Retrieve an EVP_CIPHER from an ASN.1 object.
  (foreign-call "ikrt_openssl_evp_get_cipherbyobj"))


;;;; EVP cipher algorithms unsafe C API: algorithm inspection

(define-inline (evp-cipher-type algo)
  (foreign-call "ikrt_openssl_evp_cipher_type" algo))

(define-inline (evp-cipher-nid algo)
  (foreign-call "ikrt_openssl_evp_cipher_nid" algo))

(define-inline (evp-cipher-name algo)
  (foreign-call "ikrt_openssl_evp_cipher_name" algo))

(define-inline (evp-cipher-block-size algo)
  (foreign-call "ikrt_openssl_evp_cipher_block_size" algo))

(define-inline (evp-cipher-key-length algo)
  (foreign-call "ikrt_openssl_evp_cipher_key_length" algo))

(define-inline (evp-cipher-iv-length algo)
  (foreign-call "ikrt_openssl_evp_cipher_iv_length" algo))

(define-inline (evp-cipher-flags algo)
  (foreign-call "ikrt_openssl_evp_cipher_flags" algo))

(define-inline (evp-cipher-mode algo)
  (foreign-call "ikrt_openssl_evp_cipher_mode" algo))


;;;; EVP cipher context unsafe C API:

(define-inline (evp-cipher-ctx-new)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_new"))

(define-inline (evp-cipher-ctx-free ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_free" ctx))

(define-inline (evp-cipher-ctx-copy dst src)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_copy" dst src))

;;; --------------------------------------------------------------------

(define-inline (evp-minimum-output-length ctx in in.len)
  ;;This  function  is  not  defined  by  OpenSSL,  it  is  specific  of
  ;;Vicare/OpenSSL.
  (foreign-call "ikrt_openssl_evp_minimum_output_length" ctx in in.len))

;;; --------------------------------------------------------------------

(define-inline (evp-encrypt-init ctx algo key key.len iv iv.len)
  (foreign-call "ikrt_openssl_evp_encryptinit_ex" ctx algo key key.len iv iv.len))

(define-inline (evp-encrypt-final ctx)
  (foreign-call "ikrt_openssl_evp_encryptfinal_ex" ctx))

(define-inline (evp-encrypt-update ctx ou ou.len in in.len)
  (foreign-call "ikrt_openssl_evp_encryptupdate" ctx ou ou.len in in.len))

;;; --------------------------------------------------------------------

(define-inline (evp-decrypt-init ctx algo key key.len iv iv.len)
  (foreign-call "ikrt_openssl_evp_decryptinit_ex" ctx algo key key.len iv iv.len))

(define-inline (evp-decrypt-update ctx ou ou.len in in.len)
  (foreign-call "ikrt_openssl_evp_decryptupdate" ctx ou ou.len in in.len))

(define-inline (evp-decrypt-final ctx)
  (foreign-call "ikrt_openssl_evp_decryptfinal_ex" ctx))

;;; --------------------------------------------------------------------

(define-inline (evp-cipher-init ctx algo key key.len iv iv.len enc)
  (foreign-call "ikrt_openssl_evp_cipherinit_ex" ctx algo key key.len iv iv.len enc))

(define-inline (evp-cipher-update ctx ou ou.len in in.len)
  (foreign-call "ikrt_openssl_evp_cipherupdate" ctx ou ou.len in in.len))

(define-inline (evp-cipher-final ctx)
  (foreign-call "ikrt_openssl_evp_cipherfinal_ex" ctx))

;;; --------------------------------------------------------------------

(define-inline (evp-cipher-ctx-cipher ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_cipher" ctx))

(define-inline (evp-cipher-ctx-nid ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_nid" ctx))

(define-inline (evp-cipher-ctx-type ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_type" ctx))

(define-inline (evp-cipher-ctx-mode ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_mode" ctx))

(define-inline (evp-cipher-ctx-block-size ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_block_size" ctx))

(define-inline (evp-cipher-ctx-key-length ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_key_length" ctx))

(define-inline (evp-cipher-ctx-iv-length ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_iv_length" ctx))

;;; --------------------------------------------------------------------

(define-inline (evp-cipher-ctx-set-key-length ctx key.len)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_set_key_length" ctx key.len))

(define-inline (evp-cipher-ctx-set-padding ctx pad?)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_set_padding" ctx pad?))

(define-inline (evp-cipher-ctx-ctrl ctx type arg)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_ctrl" ctx type arg))

(define-inline (evp-cipher-ctx-rand-key ctx rand-key)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_rand_key" ctx rand-key))

;;; --------------------------------------------------------------------

(define-inline (evp-cipher-ctx-get-app-data ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_get_app_data" ctx))

(define-inline (evp-cipher-ctx-set-app-data ctx data)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_set_app_data" ctx data))

;;; --------------------------------------------------------------------

(define-inline (evp-cipher-param-to-asn1)
  (foreign-call "ikrt_openssl_evp_cipher_param_to_asn1"))

(define-inline (evp-cipher-asn1-to-param)
  (foreign-call "ikrt_openssl_evp_cipher_asn1_to_param"))

;;; --------------------------------------------------------------------

(define-inline (evp-cipher-ctx-flags ctx)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_flags" ctx))

(define-inline (evp-cipher-ctx-set-flags ctx flags)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_set_flags" ctx flags))

(define-inline (evp-cipher-ctx-clear-flags ctx flags)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_clear_flags" ctx flags))

(define-inline (evp-cipher-ctx-test-flags ctx flags)
  (foreign-call "ikrt_openssl_evp_cipher_ctx_test_flags" ctx flags))


;;;; EVP cipher context unsafe C API: single-step encryption and decryption

(define-inline (evp-cipher ctx ou ou.len in in.len)
  (foreign-call "ikrt_openssl_evp_cipher" ctx ou ou.len in in.len))


;;;; still to be implemented

(define-inline (hmac-init-ex)
  (foreign-call "ikrt_openssl_hmac_init_ex"))


;;;; done

)

;;; end of file
