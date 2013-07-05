;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, memory buffers
;;;Date: Fri Jul  5, 2013
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
  (for (prefix (vicare crypto openssl buffers cond-expand) ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  #;(prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl buffers) ssl.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: memory buffers API\n")

#;(ssl.openssl-add-all-digests)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-buffers-features)


(parametrise ((check-test-name	'features))

  (check
      (ssl.cond-expand
       (ssl.buf-mem-new	#t)
       (else		#f))
    => #t)

  #t)


(parametrise ((check-test-name		'struct)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.buf-mem-new)))

  (check
      (let ((buf (ssl.buf-mem-new)))
	(ssl.buf-mem? buf))
    => #t)

  (check
      (let ((buf (ssl.buf-mem-new)))
	(ssl.buf-mem?/alive buf))
    => #t)

  (check
      (let ((buf (ssl.buf-mem-new)))
	(ssl.buf-mem-free buf)
	(ssl.buf-mem?/alive buf))
    => #f)

  (check
      (let ((buf (ssl.buf-mem-new)))
	(ssl.buf-mem-free buf)
	(ssl.buf-mem-free buf)
	(ssl.buf-mem?/alive buf))
    => #f)

  (collect))


;;;; done

(check-report)

;;; end of file
