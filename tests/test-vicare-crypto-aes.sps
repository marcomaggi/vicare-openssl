;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, AES functions
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
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
;;;  (prefix (vicare ffi) ffi.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: AES functions\n")


;;;; helpers



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


;;;; done

(check-report)

;;; end of file
