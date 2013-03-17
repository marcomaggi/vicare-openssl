;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for Openssl bindings, raw message digest API
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
  (vicare cond-expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl message-digests) ssl.)
;;;  (prefix (vicare ffi) ffi.)
  (for (prefix (vicare crypto openssl message-digests cond-expand)
	       ssl.)
       expand)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: raw message digest API\n")

(ssl.ssl-library-init)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-message-digests-features)


(parametrise ((check-test-name		'cond-expand))

  (check
      (ssl.cond-expand
       (ssl.md5	#t)
       (else	#f))
    => #t)

  #t)


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


(parametrise ((check-test-name		'sha1)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.sha1-init)))

  (check
      (let ((ctx (ssl.sha1-init)))
	(ssl.sha1-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha1-init)))
	(ssl.sha1-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha1-init)))
	(ssl.sha1-final ctx)
	(ssl.sha1-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.sha1-init)))
	(ssl.sha1-final ctx)
	(ssl.sha1-final ctx)
	(ssl.sha1-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; sha1-update

  (check
      (let ((ctx (ssl.sha1-init)))
	(assert (ssl.sha1-update ctx "ciao"))
	(ssl.sha1-final ctx))
    => '#vu8(30 78 136 138 198 111 141 212 30 0 197 167 172 54 163
		42 153 80 210 113))

;;; --------------------------------------------------------------------
;;; sha1

  (check
      (ssl.sha1 "ciao")
    => '#vu8(30 78 136 138 198 111 141 212 30 0 197 167 172 54 163
		42 153 80 210 113))

  (collect))


(parametrise ((check-test-name		'sha224)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.sha224-init)))

  (check
      (let ((ctx (ssl.sha224-init)))
	(ssl.sha224-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha224-init)))
	(ssl.sha224-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha224-init)))
	(ssl.sha224-final ctx)
	(ssl.sha224-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.sha224-init)))
	(ssl.sha224-final ctx)
	(ssl.sha224-final ctx)
	(ssl.sha224-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; sha224-update

  (check
      (let ((ctx (ssl.sha224-init)))
	(assert (ssl.sha224-update ctx "ciao"))
	(ssl.sha224-final ctx))
    => '#vu8(241 177 161 48 51 237 220 63 222 236 192 237 3 189 192
		 25 194 88 144 186 144 102 88 173 218 217 254 254))

;;; --------------------------------------------------------------------
;;; sha224

  (check
      (ssl.sha224 "ciao")
    => '#vu8(241 177 161 48 51 237 220 63 222 236 192 237 3 189 192
		 25 194 88 144 186 144 102 88 173 218 217 254 254))

  (collect))


(parametrise ((check-test-name		'sha256)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.sha256-init)))

  (check
      (let ((ctx (ssl.sha256-init)))
	(ssl.sha256-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha256-init)))
	(ssl.sha256-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha256-init)))
	(ssl.sha256-final ctx)
	(ssl.sha256-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.sha256-init)))
	(ssl.sha256-final ctx)
	(ssl.sha256-final ctx)
	(ssl.sha256-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; sha256-update

  (check
      (let ((ctx (ssl.sha256-init)))
	(assert (ssl.sha256-update ctx "ciao"))
	(ssl.sha256-final ctx))
    => '#vu8(177 51 160 192 233 190 227 190 32 22 61 42 211 29 98 72
		 219 41 42 166 220 177 238 8 122 42 165 14 15 199 90 226))

;;; --------------------------------------------------------------------
;;; sha256

  (check
      (ssl.sha256 "ciao")
    => '#vu8(177 51 160 192 233 190 227 190 32 22 61 42 211 29 98 72
		 219 41 42 166 220 177 238 8 122 42 165 14 15 199 90 226))

  (collect))


(parametrise ((check-test-name		'sha384)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.sha384-init)))

  (check
      (let ((ctx (ssl.sha384-init)))
	(ssl.sha384-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha384-init)))
	(ssl.sha384-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha384-init)))
	(ssl.sha384-final ctx)
	(ssl.sha384-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.sha384-init)))
	(ssl.sha384-final ctx)
	(ssl.sha384-final ctx)
	(ssl.sha384-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; sha384-update

  (check
      (let ((ctx (ssl.sha384-init)))
	(assert (ssl.sha384-update ctx "ciao"))
	(ssl.sha384-final ctx))
    => '#vu8(110 218 79 204 118 133 171 186 67 69 181 195 13 193 56
		 133 175 247 53 154 81 209 135 124 124 85 207 48 93 213
		 47 198 34 188 209 168 24 58 194 231 199 253 193 252 20
		 195 246 133))

;;; --------------------------------------------------------------------
;;; sha384

  (check
      (ssl.sha384 "ciao")
    => '#vu8(110 218 79 204 118 133 171 186 67 69 181 195 13 193 56
		 133 175 247 53 154 81 209 135 124 124 85 207 48 93 213
		 47 198 34 188 209 168 24 58 194 231 199 253 193 252 20
		 195 246 133))

  (collect))


(parametrise ((check-test-name		'sha512)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.sha512-init)))

  (check
      (let ((ctx (ssl.sha512-init)))
	(ssl.sha512-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha512-init)))
	(ssl.sha512-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.sha512-init)))
	(ssl.sha512-final ctx)
	(ssl.sha512-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.sha512-init)))
	(ssl.sha512-final ctx)
	(ssl.sha512-final ctx)
	(ssl.sha512-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; sha512-update

  (check
      (let ((ctx (ssl.sha512-init)))
	(assert (ssl.sha512-update ctx "ciao"))
	(ssl.sha512-final ctx))
    => '#vu8(160 194 153 183 26 158 89 213 235 176 121 23 231 6 1
		 163 87 10 161 3 233 154 123 182 90 88 231 128 236 144
		 119 177 144 45 29 237 179 27 20 87 190 218 89 95 228
		 215 29 119 155 108 169 202 212 118 38 108 192 117 144
		 227 29 132 178 6))

;;; --------------------------------------------------------------------
;;; sha512

  (check
      (ssl.sha512 "ciao")
    => '#vu8(160 194 153 183 26 158 89 213 235 176 121 23 231 6 1
		 163 87 10 161 3 233 154 123 182 90 88 231 128 236 144
		 119 177 144 45 29 237 179 27 20 87 190 218 89 95 228
		 215 29 119 155 108 169 202 212 118 38 108 192 117 144
		 227 29 132 178 6))

  (collect))


(parametrise ((check-test-name		'ripemd160)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.ripemd160-init)))

  (check
      (let ((ctx (ssl.ripemd160-init)))
	(ssl.ripemd160-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.ripemd160-init)))
	(ssl.ripemd160-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.ripemd160-init)))
	(ssl.ripemd160-final ctx)
	(ssl.ripemd160-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.ripemd160-init)))
	(ssl.ripemd160-final ctx)
	(ssl.ripemd160-final ctx)
	(ssl.ripemd160-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; ripemd160-update

  (check
      (let ((ctx (ssl.ripemd160-init)))
	(assert (ssl.ripemd160-update ctx "ciao"))
	(ssl.ripemd160-final ctx))
    => '#vu8(73 78 219 37 115 168 139 92 233 100 122 73 155 77 18 242 144 169 250 190))

;;; --------------------------------------------------------------------
;;; ripemd160

  (check
      (ssl.ripemd160 "ciao")
    => '#vu8(73 78 219 37 115 168 139 92 233 100 122 73 155 77 18 242 144 169 250 190))

  (collect))


(parametrise ((check-test-name		'whirlpool)
	      (struct-guardian-logger	#f))

  (when #f
    (check-pretty-print (ssl.whirlpool-init)))

  (check
      (let ((ctx (ssl.whirlpool-init)))
	(ssl.whirlpool-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.whirlpool-init)))
	(ssl.whirlpool-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.whirlpool-init)))
	(ssl.whirlpool-final ctx)
	(ssl.whirlpool-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.whirlpool-init)))
	(ssl.whirlpool-final ctx)
	(ssl.whirlpool-final ctx)
	(ssl.whirlpool-ctx?/alive ctx))
    => #f)

;;; --------------------------------------------------------------------
;;; whirlpool-update

  (check
      (let ((ctx (ssl.whirlpool-init)))
	(assert (ssl.whirlpool-update ctx "ciao"))
	(ssl.whirlpool-final ctx))
    => '#vu8(152 106 126 88 185 42 0 166 63 74 143 200 89 163 3 73
		 252 24 173 157 214 90 15 140 193 41 96 233 221 94 42
		 180 241 235 84 108 60 85 85 110 6 1 84 141 34 68 60 230
		 208 104 203 49 17 139 135 81 125 206 42 25 173 36 243
		 237))

;;; --------------------------------------------------------------------
;;; whirlpool

  (check
      (ssl.whirlpool "ciao")
    => '#vu8(152 106 126 88 185 42 0 166 63 74 143 200 89 163 3 73
		 252 24 173 157 214 90 15 140 193 41 96 233 221 94 42
		 180 241 235 84 108 60 85 85 110 6 1 84 141 34 68 60 230
		 208 104 203 49 17 139 135 81 125 206 42 25 173 36 243
		 237))

  (collect))


;;;; done

(check-report)

;;; end of file
