;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: buffer functions
;;;Date: Fri Jul  5, 2013
;;;
;;;Abstract
;;;
;;;
;;;
;;;Copyright (C) 2013, 2017 Marco Maggi <marco.maggi-ipsu@poste.it>
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
(library (vicare crypto openssl buffers)
  (options typed-language)
  (foreign-library "vicare-openssl")
  (export

    buf-mem
    buf-mem?
    buf-mem?/alive
    buf-mem-custom-destructor
    set-buf-mem-custom-destructor!
    buf-mem.vicare-arguments-validation
    buf-mem/alive.vicare-arguments-validation

    buf-mem-putprop		buf-mem-getprop
    buf-mem-remprop		buf-mem-property-list

    ;; buffer
    buf-mem-new
    buf-mem-free
    buf-mem-grow
    buf-mem-grow-clean
    ;; buf-strdup
    ;; buf-strndup
    ;; buf-memdup
    ;; buf-reverse
    ;; buf-strlcpy
    ;; buf-strlcat
    ;; err-load-buf-strings
    )
  (import (vicare)
    (prefix (vicare crypto openssl unsafe-capi)
	    capi.)
    (prefix (vicare ffi foreign-pointer-wrapper)
	    ffi.)
    #;(vicare language-extensions syntaxes)
    (vicare arguments validation))


;;;; struct type definition

(ffi.define-foreign-pointer-wrapper buf-mem
  (ffi.foreign-destructor capi.buf-mem-free)
  (ffi.collector-struct-type #f))


;;;; buffer

(define (buf-mem-new)
  (let ((rv (capi.buf-mem-new)))
    (and rv (make-buf-mem/owner rv))))

(define (buf-mem-free buf)
  (define who 'buf-mem-free)
  (with-arguments-validation (who)
      ((buf-mem		buf))
    ($buf-mem-finalise buf)))

(define (buf-mem-grow buf len)
  (define who 'buf-mem-grow)
  (with-arguments-validation (who)
      ((buf-mem/alive	buf)
       (signed-int	len))
    (capi.buf-mem-grow buf len)))

(define (buf-mem-grow-clean buf len)
  (define who 'buf-mem-grow-clean)
  (with-arguments-validation (who)
      ((buf-mem/alive	buf)
       (signed-int	len))
    (capi.buf-mem-grow-clean buf len)))

;; (define (buf-strdup buf)
;;   (define who 'buf-strdup)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.buf-strdup)))

;; (define (buf-strndup ctx)
;;   (define who 'buf-strndup)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.buf-strndup)))

;; (define (buf-memdup ctx)
;;   (define who 'buf-memdup)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.buf-memdup)))

;; (define (buf-reverse ctx)
;;   (define who 'buf-reverse)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.buf-reverse)))

;; (define (buf-strlcpy ctx)
;;   (define who 'buf-strlcpy)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.buf-strlcpy)))

;; (define (buf-strlcat ctx)
;;   (define who 'buf-strlcat)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.buf-strlcat)))

;; (define (err-load-buf-strings ctx)
;;   (define who 'err-load-buf-strings)
;;   (with-arguments-validation (who)
;;       ()
;;     (capi.err-load-buf-strings)))


;;;; done

)

;;; end of file
