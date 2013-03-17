;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for OpenSSL bindings, EVP message digest functions
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
  (vicare cond-expand)
  (for (prefix (vicare crypto openssl evp message-digests cond-expand)
	       ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl evp message-digests) ssl.)
;;;  (prefix (vicare ffi) ffi.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: EVP message digest API\n")

(ssl.ssl-library-init)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-evp-message-digests-features)


(parametrise ((check-test-name		'features))

  (check
      (ssl.cond-expand
       (ssl.evp-digest-init
	#t)
       (else #f))
    => #t)

  #t)


(parametrise ((check-test-name		'algo))

  (when #f
    (check-pretty-print (ssl.evp-sha256))
    (check-pretty-print (ssl.evp-md-null)))

  (check
      (let ((algo (ssl.evp-md-null)))
	(ssl.evp-md? algo))
    => #t)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md? algo))
    => #t)

;;; --------------------------------------------------------------------
;;; sizes

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-size algo))
    => 16)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-block-size algo))
    => 64)

;;; --------------------------------------------------------------------

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-name algo))
    => "MD5")

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-nid algo))
    => 4)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-type algo))
    => 4)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-flags algo))
    => 0)

  (check
      (let ((algo (ssl.evp-md5)))
	(ssl.evp-md-pkey-type algo))
    => 8)

;;; --------------------------------------------------------------------

  (check
      (let ((algo (ssl.evp-get-digestbyname "MD5")))
	(and (ssl.evp-md? algo)
	     (ssl.evp-md-name algo)))
    => "MD5")

  (check
      (let ((algo (ssl.evp-get-digestbyname "SHA1")))
	(and (ssl.evp-md? algo)
	     (ssl.evp-md-name algo)))
    => "SHA1")

  (check
      (let ((algo (ssl.evp-get-digestbyname "SHA224")))
	(and (ssl.evp-md? algo)
	     (ssl.evp-md-name algo)))
    => "SHA224")

  (check
      (let ((algo (ssl.evp-get-digestbyname "SHA256")))
	(and (ssl.evp-md? algo)
	     (ssl.evp-md-name algo)))
    => "SHA256")

  (check
      (let ((algo (ssl.evp-get-digestbyname "SHA384")))
	(and (ssl.evp-md? algo)
	     (ssl.evp-md-name algo)))
    => "SHA384")

  (check
      (let ((algo (ssl.evp-get-digestbyname "SHA512")))
	(and (ssl.evp-md? algo)
	     (ssl.evp-md-name algo)))
    => "SHA512")

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

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(assert (ssl.evp-digest-init ctx (ssl.evp-md5)))
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

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-md-ctx-type ctx))
    => 4)

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(let ((algo (ssl.evp-md-ctx-md ctx)))
	  (and (ssl.evp-md? algo)
	       (ssl.evp-md-name algo))))
    => "MD5")

  (collect))


(parametrise ((check-test-name		'flags)
	      (struct-guardian-logger	#f))

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-md-ctx-set-flags ctx ssl.EVP_MD_FLAG_DIGALGID_NULL)
	(ssl.evp-md-ctx-test-flags ctx ssl.EVP_MD_FLAG_DIGALGID_NULL))
    => 0)

  (check
      (let ((ctx (ssl.evp-md-ctx-create)))
	(ssl.evp-digest-init ctx 'md5)
	(ssl.evp-md-ctx-set-flags ctx ssl.EVP_MD_FLAG_DIGALGID_NULL)
	(ssl.evp-md-ctx-clear-flags ctx ssl.EVP_MD_FLAG_DIGALGID_NULL)
	(ssl.evp-md-ctx-test-flags ctx ssl.EVP_MD_FLAG_DIGALGID_NULL))
    => 0)


  (collect))


(parametrise ((check-test-name		'digest))

  (check
      (ssl.evp-digest "ciao" (ssl.evp-md5))
    => '#vu8(110 107 196 228 157 212 119 235 201 142 244 4 108 6 123 95))

  (check
      (ssl.evp-digest "ciao" (ssl.evp-md-null))
    => '#vu8())

  #t)


;;;; done

(check-report)

;;; end of file
