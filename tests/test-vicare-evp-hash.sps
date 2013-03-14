;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for OpenSSL bindings, EVP hash functions
;;;Date: Thu Mar 14, 2013
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
(check-display "*** testing Vicare OpenSSL bindings: EVP hash functions\n")

(ssl.ssl-library-init)


;;;; helpers



(parametrise ((check-test-name		'context)
	      (struct-guardian-logger	#t))

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-md-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-md-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-md-ctx-destroy ctx)
	(ssl.evp-md-ctx?/alive ctx))
    => #f)

  (check	;destroy twice
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-md-ctx-destroy ctx)
	(ssl.evp-md-ctx-destroy ctx)
	(ssl.evp-md-ctx?/alive ctx))
    => #f)

  (collect))


;;;; done

(check-report)

;;; end of file
