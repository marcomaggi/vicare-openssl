;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, hmac
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
  (only (vicare syntactic-extensions)
	begin0)
;;;  (prefix (vicare ffi) ffi.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: HMAC\n")


;;;; helpers



(parametrise ((check-test-name		'hmac)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.hmac-ctx-init)))

  (check
      (let ((ctx (ssl.hmac-ctx-init)))
	(ssl.hmac-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.hmac-ctx-init)))
	(ssl.hmac-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.hmac-ctx-init)))
	(ssl.hmac-ctx-cleanup ctx)
	(ssl.hmac-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.hmac-ctx-init)))
	(ssl.hmac-ctx-cleanup ctx)
	(ssl.hmac-ctx-cleanup ctx)
	(ssl.hmac-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; hmac-update

  (check
      (let ((ctx (ssl.hmac-ctx-init)))
	(assert (ssl.hmac-init ctx "key" 'md5))
	(assert (ssl.hmac-update ctx "ciao"))
	(begin0
	    (ssl.hmac-final ctx)
	  (ssl.hmac-ctx-cleanup ctx)))
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

;;; --------------------------------------------------------------------
;;; hmac

  (check
      (ssl.hmac 'md5 "key" #f "ciao" #f)
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

  (collect))


;;;; done

(check-report)

;;; end of file
