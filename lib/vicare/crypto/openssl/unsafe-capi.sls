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

;;; --------------------------------------------------------------------
;;; still to be implemented

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


;;;; done

)

;;; end of file
