;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, raw AES API
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


#!r6rs
(import (vicare)
  (vicare cond-expand)
  (for (prefix (vicare crypto openssl aes cond-expand) ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl aes) ssl.)
;;;  (prefix (vicare ffi) ffi.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: raw AES API\n")

(ssl.openssl-add-all-algorithms)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-aes-features)


(parametrise ((check-test-name	'features))

  (check
      (ssl.cond-expand
       (ssl.aes-set-encrypt-key
	#t)
       (else #f))
    => #t)

  #t)


(parametrise ((check-test-name	'misc))

  (when #f
    (check-pretty-print (ssl.aes-options)))

  (check
      (string? (ssl.aes-options))
    => #t)

  #f)


(parametrise ((check-test-name	'key))

  (check
      (let ((ctx (ssl.aes-set-encrypt-key "0123456789012345")))
	(ssl.aes-key? ctx))
    => #t)

  (check
      (let ((ctx (ssl.aes-set-encrypt-key "0123456789012345")))
	(ssl.aes-key?/alive ctx))
    => #t)

;;; --------------------------------------------------------------------

  (check
      (let ((ctx (ssl.aes-set-decrypt-key "0123456789012345")))
	(ssl.aes-key? ctx))
    => #t)

  (check
      (let ((ctx (ssl.aes-set-decrypt-key "0123456789012345")))
	(ssl.aes-key?/alive ctx))
    => #t)

  (collect))


(parametrise ((check-test-name	'default))

;;; crypt with the default scheme

  (check
      (let ((key.en	(ssl.aes-set-encrypt-key "0123456789012345"))
	    (key.de	(ssl.aes-set-decrypt-key "0123456789012345"))
	    (data.in	(make-bytevector ssl.AES_BLOCK_SIZE 123))
	    (data.en	(make-bytevector ssl.AES_BLOCK_SIZE 0))
	    (data.de	(make-bytevector ssl.AES_BLOCK_SIZE 0)))
	(ssl.aes-encrypt data.in #f data.en #f key.en)
	(ssl.aes-decrypt data.en #f data.de #f key.de)
	(bytevector=? data.in data.de))
    => #t)

  (collect))


(parametrise ((check-test-name	'ecb))

;;; crypt with the ECB scheme

  (check
      (let ((key.en	(ssl.aes-set-encrypt-key "0123456789012345"))
	    (key.de	(ssl.aes-set-decrypt-key "0123456789012345"))
	    (data.in	(make-bytevector ssl.AES_BLOCK_SIZE 123))
	    (data.en	(make-bytevector ssl.AES_BLOCK_SIZE 0))
	    (data.de	(make-bytevector ssl.AES_BLOCK_SIZE 0)))
	(ssl.aes-ecb-encrypt data.in #f data.en #f key.en)
	(ssl.aes-ecb-decrypt data.en #f data.de #f key.de)
	(bytevector=? data.in data.de))
    => #t)

  (collect))


(parametrise ((check-test-name	'cbc))

;;; crypt with the ECB scheme

  (check
      (let ()
	(define key.en
	  (ssl.aes-set-encrypt-key "0123456789012345"))
	(define key.de
	  (ssl.aes-set-decrypt-key "0123456789012345"))
	(define iv
	  (make-bytevector ssl.AES_BLOCK_SIZE 99))
	(define data.len
	  (* 5 ssl.AES_BLOCK_SIZE))
	(define data.in
	  (make-bytevector data.len 123))
	(define data.en
	  (make-bytevector data.len 0))
	(define data.de
	  (make-bytevector data.len 0))
	(ssl.aes-cbc-encrypt data.in #f data.en #f key.en iv #f)
	(ssl.aes-cbc-decrypt data.en #f data.de #f key.de iv #f)
	(bytevector=? data.in data.de))
    => #t)

  (collect))


#;(parametrise ((check-test-name	'cfb))

;;; crypt with the ECB scheme

  (check	;cfb128
      (let ()
	(define key.en
	  (ssl.aes-set-encrypt-key "0123456789012345"))
	(define key.de
	  (ssl.aes-set-decrypt-key "0123456789012345"))
	(define iv
	  (make-bytevector ssl.AES_BLOCK_SIZE 99))
	(define data.len
	  (* 5 ssl.AES_BLOCK_SIZE))
	(define data.in
	  (make-bytevector data.len 123))
	(define data.en
	  (make-bytevector data.len 0))
	(define data.de
	  (make-bytevector data.len 0))
	(check-pretty-print (ssl.aes-cfb128-encrypt data.in #f data.en #f key.en iv #f 0))
	(check-pretty-print (ssl.aes-cfb128-decrypt data.en #f data.de #f key.de iv #f 0))
;;;	(check-pretty-print (list data.in data.en data.de))
	(bytevector=? data.in data.de))
    => #t)

  (check	;cfb1
      (let ()
	(define key.en
	  (ssl.aes-set-encrypt-key "0123456789012345"))
	(define key.de
	  (ssl.aes-set-decrypt-key "0123456789012345"))
	(define iv
	  (make-bytevector ssl.AES_BLOCK_SIZE 99))
	(define data.len
	  (* 5 ssl.AES_BLOCK_SIZE))
	(define data.in
	  (make-bytevector data.len 123))
	(define data.en
	  (make-bytevector data.len 0))
	(define data.de
	  (make-bytevector data.len 0))
	(check-pretty-print (ssl.aes-cfb1-encrypt data.in #f data.en #f key.en iv #f 0))
	(check-pretty-print (ssl.aes-cfb1-decrypt data.en #f data.de #f key.de iv #f 0))
;;;	(check-pretty-print (list data.in data.en data.de))
	(bytevector=? data.in data.de))
    => #t)

  (check	;cfb8
      (let ()
	(define key.en
	  (ssl.aes-set-encrypt-key "0123456789012345"))
	(define key.de
	  (ssl.aes-set-decrypt-key "0123456789012345"))
	(define iv
	  (make-bytevector ssl.AES_BLOCK_SIZE 99))
	(define data.len
	  (* 5 ssl.AES_BLOCK_SIZE))
	(define data.in
	  (make-bytevector data.len 123))
	(define data.en
	  (make-bytevector data.len 0))
	(define data.de
	  (make-bytevector data.len 0))
	(check-pretty-print (ssl.aes-cfb8-encrypt data.in #f data.en #f key.en iv #f 0))
	(check-pretty-print (ssl.aes-cfb8-decrypt data.en #f data.de #f key.de iv #f 0))
;;;	(check-pretty-print (list data.in data.en data.de))
	(bytevector=? data.in data.de))
    => #t)

  (collect))


;;;; done

(check-report)

;;; end of file
