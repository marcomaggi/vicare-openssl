;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, raw HMAC API
;;;Date: Mon Mar 11, 2013
;;;
;;;Abstract
;;;
;;;
;;;
;;;Copyright (C) 2013, 2017 Marco Maggi <marco.maggi-ipsu@poste.it>
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
  (prefix (vicare system structs) structs::)
  (vicare language-extensions cond-expand)
  (for (prefix (vicare crypto openssl hmac cond-expand) ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl hmac) ssl.)
  (prefix (vicare crypto openssl evp message-digests) ssl.)
;;;  (prefix (vicare ffi) ffi.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: raw HMAC API\n")

(ssl.openssl-add-all-digests)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-hmac-features)


(parametrise ((check-test-name	'features))

  (check
      (ssl.cond-expand
       (ssl.hmac	#t)
       (else		#f))
    => #t)

  #t)


(parametrise ((check-test-name		'md5)
	      (structs::struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.hmac-init "key" #f 'md5)))

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'md5)))
	(ssl.hmac-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'md5)))
	(ssl.hmac-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'md5)))
	(ssl.hmac-final ctx)
	(ssl.hmac-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'md5)))
	(ssl.hmac-final ctx)
	(ssl.hmac-final ctx)
	(ssl.hmac-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; hmac-update

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'md5)))
	(assert (ssl.hmac-update ctx "ciao"))
	(ssl.hmac-final ctx))
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

  (check
      (let ((ctx (ssl.hmac-init "key" #f (ssl.evp-md5))))
	(assert (ssl.hmac-update ctx "ciao"))
	(ssl.hmac-final ctx))
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

;;; --------------------------------------------------------------------
;;; hmac-copy

  (check
      (let ((ctx1 (ssl.hmac-init "key"   #f 'md5))
	    (ctx2 (ssl.hmac-init "hello" #f 'md5)))
	(ssl.hmac-ctx-copy ctx2 ctx1)
	(assert (ssl.hmac-update ctx2 "ciao"))
	(ssl.hmac-final ctx2))
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

;;; --------------------------------------------------------------------
;;; hmac-ctx-set-flags

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'md5)))
	(void-object? (ssl.hmac-ctx-set-flags ctx 0)))
    => #t)

  (collect))


(parametrise ((check-test-name		'whirlpool)
	      (structs::struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.hmac-init "key" #f 'whirlpool)))

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'whirlpool)))
	(ssl.hmac-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'whirlpool)))
	(ssl.hmac-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'whirlpool)))
	(ssl.hmac-final ctx)
	(ssl.hmac-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'whirlpool)))
	(ssl.hmac-final ctx)
	(ssl.hmac-final ctx)
	(ssl.hmac-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; hmac-update

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'whirlpool)))
	(assert (ssl.hmac-update ctx "ciao"))
	(ssl.hmac-final ctx))
    => '#vu8(6 37 67 106 243 81 149 29 182 191 33 8 18 103 188 135
	       134 65 71 203 81 86 233 36 195 143 61 76 203 89 169 6
	       233 160 156 247 147 113 225 219 191 178 126 211 40 107
	       128 96 165 130 225 249 85 52 185 211 42 97 183 182 183
	       253 53 7))

;;; --------------------------------------------------------------------
;;; hmac-update

  (check
      (let ((ctx1 (ssl.hmac-init "key" #f 'whirlpool))
	    (ctx2 (ssl.hmac-init "hello" #f 'whirlpool)))
	(ssl.hmac-ctx-copy ctx2 ctx1)
	(assert (ssl.hmac-update ctx2 "ciao"))
	(ssl.hmac-final ctx2))
    => '#vu8(6 37 67 106 243 81 149 29 182 191 33 8 18 103 188 135
	       134 65 71 203 81 86 233 36 195 143 61 76 203 89 169 6
	       233 160 156 247 147 113 225 219 191 178 126 211 40 107
	       128 96 165 130 225 249 85 52 185 211 42 97 183 182 183
	       253 53 7))

;;; --------------------------------------------------------------------
;;; hmac-ctx-set-flags

  (check
      (let ((ctx (ssl.hmac-init "key" #f 'whirlpool)))
	(void-object? (ssl.hmac-ctx-set-flags ctx 0)))
    => #t)

  (collect))


(parametrise ((check-test-name		'hmac))

  (check
      (ssl.hmac 'md5 "key" #f "ciao" #f)
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

  (check
      (ssl.hmac 'dss "key" #f "ciao" #f)
    => '#vu8(114 204 128 122 15 129 253 87 142 129 131 117 4 88 3 220 87 22 179 154))

  (check
      (ssl.hmac 'dss1 "key" #f "ciao" #f)
    => '#vu8(114 204 128 122 15 129 253 87 142 129 131 117 4 88 3 220 87 22 179 154))

;;; --------------------------------------------------------------------

  (check
      (ssl.hmac (ssl.evp-md5) "key" #f "ciao" #f)
    => '#vu8(104 95 146 126 133 66 104 215 19 225 230 101 126 75 39 188))

  #f)


;;;; done

(check-report)

;;; end of file
