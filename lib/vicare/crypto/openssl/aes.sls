;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: low-level AES API
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
(library (vicare crypto openssl aes)
  (export

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

    aes-block-len?		aes-block-len.vicare-arguments-validation
    aes-data-len?		aes-data-len.vicare-arguments-validation
    aes-key-len?		aes-key-len.vicare-arguments-validation
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
    (vicare language-extensions syntaxes)
    (vicare arguments validation)
    (vicare arguments general-c-buffers)
    (vicare unsafe operations))


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


;;;; done

)

;;; end of file
