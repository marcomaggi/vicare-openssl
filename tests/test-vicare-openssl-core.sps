;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, core functions
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
  (vicare language-extensions cond-expand)
  (for (prefix (vicare crypto openssl cond-expand) ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: version functions\n")

(ssl.ssl-library-init)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-features)


;;;; initialisation

(let-syntax ((doit (syntax-rules ()
		     ((_ ?fun)
		      (ssl.cond-expand
		       (?fun (?fun))
		       (else (void)))))))
  (doit ssl.openssl-add-all-algorithms-noconf)
  (doit ssl.openssl-add-all-algorithms-conf)
  (doit ssl.openssl-add-all-algorithms)
  (doit ssl.openssl-add-all-ciphers)
  (doit ssl.openssl-add-all-digests)
  (doit ssl.ssleay-add-all-algorithms)
  (doit ssl.ssleay-add-all-ciphers)
  (doit ssl.ssleay-add-all-digests))



(parametrise ((check-test-name	'version))

  (check
      (fixnum? (ssl.vicare-openssl-version-interface-current))
    => #t)

  (check
      (fixnum? (ssl.vicare-openssl-version-interface-revision))
    => #t)

  (check
      (fixnum? (ssl.vicare-openssl-version-interface-age))
    => #t)

  (check
      (string? (ssl.vicare-openssl-version))
    => #t)

  #t)


;;;; done

(check-report)

;;; end of file
