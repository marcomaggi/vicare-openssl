;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for OpenSSL bindings: EVP cipher API
;;;Date: Sat Mar 16, 2013
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
(import (vicare)
  (vicare cond-expand)
  (for (prefix (vicare crypto openssl evp ciphers cond-expand)
	       ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl evp ciphers) ssl.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: EVP cipher API\n")


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-evp-ciphers-features)


(parametrise ((check-test-name	'algo))

  (define-syntax check-single-maker
    (syntax-rules ()
      ((_ ?maker)
       (check
	   (ssl.evp-cipher? (?maker))
	 => #t))))

  (define-syntax check-makers
    (syntax-rules ()
      ((_)
       (void))
      ((_ ?maker0 ?maker ...)
       (begin
	 (ssl.cond-expand
	  (?maker0
	   (check-single-maker ?maker0))
	  (else
	   (void)))
	 (check-makers ?maker ...)))))

;;; --------------------------------------------------------------------

  (check-makers
   ssl.evp-enc-null
   ssl.evp-des-ecb
   ssl.evp-des-ede
   ssl.evp-des-ede3
   ssl.evp-des-ede-ecb
   ssl.evp-des-ede3-ecb
   ssl.evp-des-cfb64
   ssl.evp-des-cfb
   ssl.evp-des-ede3-cfb64
   ssl.evp-des-ede3-cfb
   ssl.evp-des-ede3-cfb1
   ssl.evp-des-ede3-cfb8
   ssl.evp-des-ofb
   ssl.evp-des-ede-ofb
   ssl.evp-des-ede3-ofb
   ssl.evp-des-cbc
   ssl.evp-des-ede-cbc
   ssl.evp-des-ede3-cbc
   ssl.evp-desx-cbc
   ssl.evp-rc4
   ssl.evp-rc4-40
   ssl.evp-rc4-hmac-md5
   ssl.evp-idea-ecb
   ssl.evp-idea-cfb64
   ssl.evp-idea-cfb
   ssl.evp-idea-ofb
   ssl.evp-idea-cbc
   ssl.evp-rc2-ecb
   ssl.evp-rc2-cbc
   ssl.evp-rc2-40-cbc
   ssl.evp-rc2-64-cbc
   ssl.evp-rc2-cfb64
   ssl.evp-rc2-cfb
   ssl.evp-rc2-ofb
   ssl.evp-bf-ecb
   ssl.evp-bf-cbc
   ssl.evp-bf-cfb64
   ssl.evp-bf-cfb
   ssl.evp-bf-ofb
   ssl.evp-cast5-ecb
   ssl.evp-cast5-cbc
   ssl.evp-cast5-cfb64
   ssl.evp-cast5-cfb
   ssl.evp-cast5-ofb
   ssl.evp-rc5-32-12-16-cbc
   ssl.evp-rc5-32-12-16-ecb
   ssl.evp-rc5-32-12-16-cfb64
   ssl.evp-rc5-32-12-16-cfb
   ssl.evp-rc5-32-12-16-ofb
   ssl.evp-aes-128-ecb
   ssl.evp-aes-128-cbc
   ssl.evp-aes-128-cfb1
   ssl.evp-aes-128-cfb8
   ssl.evp-aes-128-cfb128
   ssl.evp-aes-128-cfb
   ssl.evp-aes-128-ofb
   ssl.evp-aes-128-ctr
   ssl.evp-aes-128-ccm
   ssl.evp-aes-128-gcm
   ssl.evp-aes-128-xts
   ssl.evp-aes-192-ecb
   ssl.evp-aes-192-cbc
   ssl.evp-aes-192-cfb1
   ssl.evp-aes-192-cfb8
   ssl.evp-aes-192-cfb128
   ssl.evp-aes-192-cfb
   ssl.evp-aes-192-ofb
   ssl.evp-aes-192-ctr
   ssl.evp-aes-192-ccm
   ssl.evp-aes-192-gcm
   ssl.evp-aes-256-ecb
   ssl.evp-aes-256-cbc
   ssl.evp-aes-256-cfb1
   ssl.evp-aes-256-cfb8
   ssl.evp-aes-256-cfb128
   ssl.evp-aes-256-cfb
   ssl.evp-aes-256-ofb
   ssl.evp-aes-256-ctr
   ssl.evp-aes-256-ccm
   ssl.evp-aes-256-gcm
   ssl.evp-aes-256-xts
   ssl.evp-aes-128-cbc-hmac-sha1
   ssl.evp-aes-256-cbc-hmac-sha1
   ssl.evp-camellia-128-ecb
   ssl.evp-camellia-128-cbc
   ssl.evp-camellia-128-cfb1
   ssl.evp-camellia-128-cfb8
   ssl.evp-camellia-128-cfb128
   ssl.evp-camellia-128-cfb
   ssl.evp-camellia-128-ofb
   ssl.evp-camellia-192-ecb
   ssl.evp-camellia-192-cbc
   ssl.evp-camellia-192-cfb1
   ssl.evp-camellia-192-cfb8
   ssl.evp-camellia-192-cfb128
   ssl.evp-camellia-192-cfb
   ssl.evp-camellia-192-ofb
   ssl.evp-camellia-256-ecb
   ssl.evp-camellia-256-cbc
   ssl.evp-camellia-256-cfb1
   ssl.evp-camellia-256-cfb8
   ssl.evp-camellia-256-cfb128
   ssl.evp-camellia-256-cfb
   ssl.evp-camellia-256-ofb
   ssl.evp-seed-ecb
   ssl.evp-seed-cbc
   ssl.evp-seed-cfb128
   ssl.evp-seed-cfb
   ssl.evp-seed-ofb
   )

#t)


;;;; done

(check-report)

;;; end of file
