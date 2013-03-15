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



(parametrise ((check-test-name		'algo))

  (when #f
    (check-pretty-print (ssl.evp-sha256)))

  (check
      (let ((algo (ssl.evp-md-null)))
	(ssl.evp-md? algo))
    => #t)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md? algo))
    => #t)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-size algo))
    => 16)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-block-size algo))
    => 64)

  #t)


(parametrise ((check-test-name		'context)
	      (struct-guardian-logger	#f))

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


(parametrise ((check-test-name		'running)
	      (struct-guardian-logger	#f))

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(assert (ssl.evp-digest-init ctx 'md5))
	(assert (ssl.evp-digest-update ctx "ciao"))
	(ssl.evp-digest-final ctx))
    => '#vu8(110 107 196 228 157 212 119 235 201 142 244 4 108 6 123 95))

  (check	;context copy
      (let ((ctx1 (ssl.evp-md-ctx-create)))
	(assert (ssl.evp-digest-init ctx1 'md5))
	(assert (ssl.evp-digest-update ctx1 "ciao"))
	(let ((ctx2 (ssl.evp-md-ctx-create)))
	  (ssl.evp-md-ctx-copy ctx2 ctx1)
	  (ssl.evp-digest-final ctx2)))
    => '#vu8(110 107 196 228 157 212 119 235 201 142 244 4 108 6 123 95))

  (check	;running predicate
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-md-ctx?/running ctx))
    => #t)

  (check	;running predicate
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-digest-final ctx)
	(ssl.evp-md-ctx?/running ctx))
    => #f)

  (collect))


(parametrise ((check-test-name		'inspect)
	      (struct-guardian-logger	#f))

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-md-ctx-size ctx))
    => 16)

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-md-ctx-block-size ctx))
    => 64)

  (collect))


;;;; done

(check-report)

;;; end of file
