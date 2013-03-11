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


(parametrise ((check-test-name		'md5)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.md5-init)))

  (check
      (let ((ctx (ssl.md5-init)))
	(ssl.md5-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.md5-init)))
	(ssl.md5-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.md5-init)))
	(ssl.md5-final ctx)
	(ssl.md5-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.md5-init)))
	(ssl.md5-final ctx)
	(ssl.md5-final ctx)
	(ssl.md5-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; md5-update

  (check
      (let ((ctx (ssl.md5-init)))
	(assert (ssl.md5-update ctx "ciao"))
	(ssl.md5-final ctx))
    => '#vu8(110 107 196 228 157 212 119 235 201 142 244 4 108 6 123 95))

;;; --------------------------------------------------------------------
;;; md5

  (check
      (ssl.md5 "ciao")
    => '#vu8(110 107 196 228 157 212 119 235 201 142 244 4 108 6 123 95))

  (collect))


(parametrise ((check-test-name		'mdc2)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.mdc2-init)))

  (check
      (let ((ctx (ssl.mdc2-init)))
	(ssl.mdc2-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.mdc2-init)))
	(ssl.mdc2-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.mdc2-init)))
	(ssl.mdc2-final ctx)
	(ssl.mdc2-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.mdc2-init)))
	(ssl.mdc2-final ctx)
	(ssl.mdc2-final ctx)
	(ssl.mdc2-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; mdc2-update

  (check
      (let ((ctx (ssl.mdc2-init)))
	(assert (ssl.mdc2-update ctx "ciao"))
	(ssl.mdc2-final ctx))
    => '#vu8(7 135 111 85 63 136 98 189 26 91 47 77 36 135 251 237))

;;; --------------------------------------------------------------------
;;; mdc2

  (check
      (ssl.mdc2 "ciao")
    => '#vu8(7 135 111 85 63 136 98 189 26 91 47 77 36 135 251 237))

  (collect))


;;;; done

(check-report)

;;; end of file
