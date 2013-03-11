;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, hash checksums
;;;Date: Mon Mar 11, 2013
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
  (prefix (vicare crypto openssl)
	  ssl.)
  (prefix (vicare crypto openssl constants)
	  ssl.)
;;;  (prefix (vicare ffi) ffi.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: hash checksums\n")


;;;; helpers



(parametrise ((check-test-name		'md4)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.md4-init)))

  (check
      (let ((ctx (ssl.md4-init)))
	(ssl.md4-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.md4-init)))
	(ssl.md4-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.md4-init)))
	(ssl.md4-final ctx)
	(ssl.md4-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.md4-init)))
	(ssl.md4-final ctx)
	(ssl.md4-final ctx)
	(ssl.md4-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; md4-update

  (check
      (let ((ctx (ssl.md4-init)))
	(assert (ssl.md4-update ctx "ciao"))
	(ssl.md4-final ctx))
    => '#vu8(229 95 235 57 89 152 65 126 80 152 248 176 252 4 127 16))

;;; --------------------------------------------------------------------
;;; md4

  (check
      (ssl.md4 "ciao")
    => '#vu8(229 95 235 57 89 152 65 126 80 152 248 176 252 4 127 16))

  (collect))


;;;; done

(check-report)

;;; end of file
