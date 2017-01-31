;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: tests for OpenSSL bindings: EVP cipher API
;;;Date: Sat Mar 16, 2013
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
;;;MERCHANTABILITY or  FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU
;;;General Public License for more details.
;;;
;;;You should  have received a  copy of  the GNU General  Public License
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;


#!vicare
(import (vicare)
  (prefix (vicare system structs) structs::)
  (vicare language-extensions cond-expand)
  (for (prefix (vicare crypto openssl evp ciphers cond-expand)
	       ssl.)
       expand)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl constants) ssl.)
  (prefix (vicare crypto openssl evp ciphers) ssl.)
  (vicare checks))

(check-set-mode! 'report-failed)
(check-display "*** testing Vicare OpenSSL bindings: EVP cipher API\n")

(ssl.openssl-add-all-ciphers)


;;;; helpers

(define-cond-expand ssl.cond-expand
  ssl.vicare-openssl-evp-ciphers-features)


(parametrise ((check-test-name	'algo-makers))

  (define-syntax check-single-maker
    (syntax-rules ()
      ((_ ?maker)
       (check
	   (ssl.evp-cipher? (?maker))
	 => #t))))

  (define-syntax check-makers
    (syntax-rules ()
      ((_)
       (void))
      ((_ ?maker0 ?maker ...)
       (begin
	 (ssl.cond-expand
	  (?maker0
	   (check-single-maker ?maker0))
	  (else
	   (void)))
	 (check-makers ?maker ...)))))

;;; --------------------------------------------------------------------

  (when #f
    (check-pretty-print (ssl.evp-cast5-ecb)))

  (check-makers
   ssl.evp-enc-null
   ssl.evp-des-ecb
   ssl.evp-des-ede
   ssl.evp-des-ede3
   ssl.evp-des-ede-ecb
   ssl.evp-des-ede3-ecb
   ssl.evp-des-cfb64
   ssl.evp-des-cfb
   ssl.evp-des-ede3-cfb64
   ssl.evp-des-ede3-cfb
   ssl.evp-des-ede3-cfb1
   ssl.evp-des-ede3-cfb8
   ssl.evp-des-ofb
   ssl.evp-des-ede-ofb
   ssl.evp-des-ede3-ofb
   ssl.evp-des-cbc
   ssl.evp-des-ede-cbc
   ssl.evp-des-ede3-cbc
   ssl.evp-desx-cbc
   ssl.evp-rc4
   ssl.evp-rc4-40
   ssl.evp-rc4-hmac-md5
   ssl.evp-idea-ecb
   ssl.evp-idea-cfb64
   ssl.evp-idea-cfb
   ssl.evp-idea-ofb
   ssl.evp-idea-cbc
   ssl.evp-rc2-ecb
   ssl.evp-rc2-cbc
   ssl.evp-rc2-40-cbc
   ssl.evp-rc2-64-cbc
   ssl.evp-rc2-cfb64
   ssl.evp-rc2-cfb
   ssl.evp-rc2-ofb
   ssl.evp-bf-ecb
   ssl.evp-bf-cbc
   ssl.evp-bf-cfb64
   ssl.evp-bf-cfb
   ssl.evp-bf-ofb
   ssl.evp-cast5-ecb
   ssl.evp-cast5-cbc
   ssl.evp-cast5-cfb64
   ssl.evp-cast5-cfb
   ssl.evp-cast5-ofb
   ssl.evp-rc5-32-12-16-cbc
   ssl.evp-rc5-32-12-16-ecb
   ssl.evp-rc5-32-12-16-cfb64
   ssl.evp-rc5-32-12-16-cfb
   ssl.evp-rc5-32-12-16-ofb
   ssl.evp-aes-128-ecb
   ssl.evp-aes-128-cbc
   ssl.evp-aes-128-cfb1
   ssl.evp-aes-128-cfb8
   ssl.evp-aes-128-cfb128
   ssl.evp-aes-128-cfb
   ssl.evp-aes-128-ofb
   ssl.evp-aes-128-ctr
   ssl.evp-aes-128-ccm
   ssl.evp-aes-128-gcm
   ssl.evp-aes-128-xts
   ssl.evp-aes-192-ecb
   ssl.evp-aes-192-cbc
   ssl.evp-aes-192-cfb1
   ssl.evp-aes-192-cfb8
   ssl.evp-aes-192-cfb128
   ssl.evp-aes-192-cfb
   ssl.evp-aes-192-ofb
   ssl.evp-aes-192-ctr
   ssl.evp-aes-192-ccm
   ssl.evp-aes-192-gcm
   ssl.evp-aes-256-ecb
   ssl.evp-aes-256-cbc
   ssl.evp-aes-256-cfb1
   ssl.evp-aes-256-cfb8
   ssl.evp-aes-256-cfb128
   ssl.evp-aes-256-cfb
   ssl.evp-aes-256-ofb
   ssl.evp-aes-256-ctr
   ssl.evp-aes-256-ccm
   ssl.evp-aes-256-gcm
   ssl.evp-aes-256-xts
   ssl.evp-aes-128-cbc-hmac-sha1
   ssl.evp-aes-256-cbc-hmac-sha1
   ssl.evp-camellia-128-ecb
   ssl.evp-camellia-128-cbc
   ssl.evp-camellia-128-cfb1
   ssl.evp-camellia-128-cfb8
   ssl.evp-camellia-128-cfb128
   ssl.evp-camellia-128-cfb
   ssl.evp-camellia-128-ofb
   ssl.evp-camellia-192-ecb
   ssl.evp-camellia-192-cbc
   ssl.evp-camellia-192-cfb1
   ssl.evp-camellia-192-cfb8
   ssl.evp-camellia-192-cfb128
   ssl.evp-camellia-192-cfb
   ssl.evp-camellia-192-ofb
   ssl.evp-camellia-256-ecb
   ssl.evp-camellia-256-cbc
   ssl.evp-camellia-256-cfb1
   ssl.evp-camellia-256-cfb8
   ssl.evp-camellia-256-cfb128
   ssl.evp-camellia-256-cfb
   ssl.evp-camellia-256-ofb
   ssl.evp-seed-ecb
   ssl.evp-seed-cbc
   ssl.evp-seed-cfb128
   ssl.evp-seed-cfb
   ssl.evp-seed-ofb)

  #t)


(parametrise ((check-test-name	'algo-inspect))

  (check
      (let ((algo (ssl.evp-enc-null)))
	(ssl.evp-cipher-name algo))
    => "UNDEF")

  (check
      (let ((algo (ssl.evp-des-ecb)))
	(ssl.evp-cipher-name algo))
    => "DES-ECB")

  (ssl.cond-expand
   (ssl.evp-idea-ecb
    (check
	(let ((algo (ssl.evp-idea-ecb)))
	  (ssl.evp-cipher-name algo))
      => "IDEA"))
   (else
    (void)))

  (check
      (let ((algo (ssl.evp-rc4)))
	(ssl.evp-cipher-name algo))
    => "RC4")

  (check
      (let ((algo (ssl.evp-rc2-ecb)))
	(ssl.evp-cipher-name algo))
    => "RC2-ECB")

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-name algo))
    => "CAST5-ECB")

  (check
      (let ((algo (ssl.evp-camellia-128-ecb)))
	(ssl.evp-cipher-name algo))
    => "CAMELLIA-128-ECB")

;;; --------------------------------------------------------------------
;;; NID

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-nid algo))
    => 109)

;;; --------------------------------------------------------------------
;;; type

  (check
      (let ((algo (ssl.evp-enc-null)))
	(ssl.evp-cipher-type algo))
    => 0)

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-type algo))
    => 0)

;;; --------------------------------------------------------------------
;;; block size

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-block-size algo))
    => 8)

  (check
      (let ((algo (ssl.evp-rc4)))
	(ssl.evp-cipher-block-size algo))
    => 1)

;;; --------------------------------------------------------------------
;;; key length

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-key-length algo))
    => 16)

;;; --------------------------------------------------------------------
;;; initialisation vector length

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-iv-length algo))
    => 0)


;;; --------------------------------------------------------------------
;;; mode

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-mode algo))
    => ssl.EVP_CIPH_ECB_MODE)

;;; --------------------------------------------------------------------
;;; flags

  (check
      (let ((algo (ssl.evp-cast5-ecb)))
	(ssl.evp-cipher-flags algo))
    => 9)

  #t)


(parametrise ((check-test-name	'algo-special-makers))

  (check
      (let ((algo (ssl.evp-get-cipherbyname "DES-ECB")))
	(ssl.evp-cipher? algo))
    => #t)

  (check
      (let ((algo (ssl.evp-get-cipherbyname "RC4")))
	(ssl.evp-cipher? algo))
    => #t)

;;; --------------------------------------------------------------------

  (check
      (let ((algo (ssl.evp-get-cipherbynid 109)))
	(ssl.evp-cipher? algo))
    => #t)

  #t)


(parametrise ((check-test-name		'ctx)
	      (structs::struct-guardian-logger	#f))

  (check
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx? ctx))
    => #t)

  (check
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx?/alive ctx))
    => #t)

  (check
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx?/alive-not-running ctx))
    => #t)

  (check
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx?/running ctx))
    => #f)

  (check	;free
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx-free ctx)
	(ssl.evp-cipher-ctx?/alive ctx))
    => #f)

  (check	;free twice
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx-free ctx)
	(ssl.evp-cipher-ctx-free ctx)
	(ssl.evp-cipher-ctx?/alive ctx))
    => #f)

  (check
      (let ((ctx (ssl.evp-cipher-ctx-new)))
	(ssl.evp-cipher-ctx-free ctx)
	(ssl.evp-cipher-ctx?/running ctx))
    => #f)

  (collect))


(parametrise ((check-test-name		'ctx-inspect)
	      (structs::struct-guardian-logger	#f))

;;; cipher

  (check	;RC4 has no init vector
      (let* ((algo	(ssl.evp-rc4))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	'#vu8()))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(let ((algo (ssl.evp-cipher-ctx-cipher ctx)))
	  (and algo (ssl.evp-cipher-name algo))))
    => "RC4")

;;; --------------------------------------------------------------------
;;; NID

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-nid ctx))
    => 109)

;;; --------------------------------------------------------------------
;;; type

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-type ctx))
    => 0)

;;; --------------------------------------------------------------------
;;; block size

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-block-size ctx))
    => 8)

;;; --------------------------------------------------------------------
;;; key length

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-key-length ctx))
    => 16)

;;; --------------------------------------------------------------------
;;; iv length

  (check	;ECB mode has no IV
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-iv-length ctx))
    => 0)

  (check
      (let* ((algo	(ssl.evp-cast5-cbc))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-iv-length ctx))
    => 8)

;;; --------------------------------------------------------------------
;;; mode

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-mode ctx))
    => ssl.EVP_CIPH_ECB_MODE)

  (collect))


(parametrise ((check-test-name		'ctx-config)
	      (structs::struct-guardian-logger	#f))

;;; key length

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-set-key-length ctx key.len))
    => #t)

;;; --------------------------------------------------------------------
;;; padding

  (check	;disable
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-set-padding ctx #f))
    => #t)

  (check	;enable
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-set-padding ctx 'fuck-yes))
    => #t)

;;; --------------------------------------------------------------------
;;; ctrl

  (check	;get RC2 key bits
      (let* ((algo	(ssl.evp-rc2-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-ctrl ctx ssl.EVP_CTRL_GET_RC2_KEY_BITS))
    => 128)

  (check	;set RC2 key bits
      (let* ((algo	(ssl.evp-rc2-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-ctrl ctx ssl.EVP_CTRL_SET_RC2_KEY_BITS 128))
    => #t)

;;; --------------------------------------------------------------------
;;; rand key

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-rand-key ctx (make-bytevector key.len)))
    => #t)

  (collect))


(parametrise ((check-test-name		'ctx-flags)
	      (structs::struct-guardian-logger	#f))

;;; get

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-flags ctx))
    => 9)

;;; --------------------------------------------------------------------
;;; set

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(void-object? (ssl.evp-cipher-ctx-set-flags ctx 0)))
    => #t)

;;; --------------------------------------------------------------------
;;; clear

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(void-object? (ssl.evp-cipher-ctx-clear-flags ctx 0)))
    => #t)

;;; --------------------------------------------------------------------
;;; test

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-test-flags ctx 0))
    => 0)

  (collect))


(parametrise ((check-test-name		'ctx-app-data)
	      (structs::struct-guardian-logger	#f))

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key.len	(ssl.evp-cipher-key-length algo))
	     (key	(make-bytevector key.len))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-cipher-ctx-set-app-data ctx (integer->pointer 123))
	(ssl.evp-cipher-ctx-get-app-data ctx))
    => (integer->pointer 123))

  (collect))


(parametrise ((check-test-name		'ctx-output-length))

  (check
      (let* ((algo	(ssl.evp-cast5-ecb))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	#;(debug-print (ssl.evp-cipher-name algo)
		     'key-len (ssl.evp-cipher-key-length algo)
		     'block-len (ssl.evp-cipher-block-size algo))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-minimum-output-length ctx (make-bytevector 10) #f))
    => 24)

  (check
      (let* ((algo	(ssl.evp-cast5-cbc))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	#;(debug-print (ssl.evp-cipher-name algo)
		     'key-len (ssl.evp-cipher-key-length algo)
		     'block-len (ssl.evp-cipher-block-size algo))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-minimum-output-length ctx (make-bytevector 10) #f))
    => 24)

  (check
      (let* ((algo	(ssl.evp-rc4))
	     (ctx	(ssl.evp-cipher-ctx-new))
	     (key	(make-bytevector (ssl.evp-cipher-key-length algo)))
	     (iv	(make-bytevector (ssl.evp-cipher-block-size algo))))
	#;(debug-print (ssl.evp-cipher-name algo)
		     'key-len (ssl.evp-cipher-key-length algo)
		     'block-len (ssl.evp-cipher-block-size algo))
	(ssl.evp-encrypt-init ctx algo key #f iv #f)
	(ssl.evp-minimum-output-length ctx (make-bytevector 10) #f))
    => 12)

  (collect))


(parametrise ((check-test-name		'encrypt-rc4)
	      (structs::struct-guardian-logger	#f))

  (check
      (let ()
	(define algo (ssl.evp-rc4))
	(define key
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv '#vu8())

	(define (encrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-encrypt-init ctx algo key #f iv #f)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-encrypt-update ctx ou #f in #f))
		   (ou.final (ssl.evp-encrypt-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(define (decrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-decrypt-init ctx algo key #f iv #f)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-decrypt-update ctx ou #f in #f))
		   (ou.final (ssl.evp-decrypt-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))


	(decrypt (encrypt "mamma")))
    => '#ve(ascii "mamma"))

;;; --------------------------------------------------------------------

  (check
      (let ()
	(define (make-chunked-bytevector-input-port bv)
	  (let ((port (open-bytevector-input-port bv)))
	    (values port (lambda ()
			   (get-bytevector-n port 4096)))))

	(define (make-chunked-bytevector-output-port)
	  (receive (port getter)
	      (open-bytevector-output-port)
	    (values port getter (lambda (data)
				  (put-bytevector port data)))))

	(define algo (ssl.evp-rc4))
	(define key
	  ;;A random key.
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv '#vu8())

	(define (encrypt input output)
	  (define ctx
	    (ssl.evp-cipher-ctx-new))
	  (ssl.evp-encrypt-init ctx algo key #f iv #f)
	  (let loop ((in.data (input)))
	    (if (eof-object? in.data)
		(cond ((ssl.evp-decrypt-final ctx)
		       => output)
		      (else
		       (error #f "error finalising encryption")))
	      (let* ((ou.len  (ssl.evp-minimum-output-length ctx in.data #f))
		     (ou.data (make-bytevector ou.len)))
		(cond ((ssl.evp-decrypt-update ctx ou.data #f in.data #f)
		       => (lambda (ou.len)
			    (output (subbytevector-u8 ou.data 0 ou.len))
			    (loop (input))))
		      (else
		       (error #f "error encrypting data")))))))

	(define (decrypt input output)
	  (define ctx
	    (ssl.evp-cipher-ctx-new))
	  (ssl.evp-decrypt-init ctx algo key #f iv #f)
	  (let loop ((in.data (input)))
	    (if (eof-object? in.data)
		(cond ((ssl.evp-decrypt-final ctx)
		       => output)
		      (else
		       (error #f "error finalising decryption")))
	      (let* ((ou.len  (ssl.evp-minimum-output-length ctx in.data #f))
		     (ou.data (make-bytevector ou.len)))
		(cond ((ssl.evp-decrypt-update ctx ou.data #f in.data #f)
		       => (lambda (ou.len)
			    (output (subbytevector-u8 ou.data 0 ou.len))
			    (loop (input))))
		      (else
		       (error #f "error decrypting data")))))))

	(define clear-text
	  (make-bytevector 123456))

	(define-values (clear-port clear-reader)
	  (make-chunked-bytevector-input-port clear-text))

	(define-values (encrypted-port encrypted-getter encrypted-writer)
	  (make-chunked-bytevector-output-port))

	(encrypt clear-reader encrypted-writer)

	(let ((encrypted-text (encrypted-getter)))
	  (define-values (encrypted-port encrypted-reader)
	    (make-chunked-bytevector-input-port encrypted-text))
	  (define-values (decrypted-port decrypted-getter decrypted-writer)
	    (make-chunked-bytevector-output-port))
	  (decrypt encrypted-reader decrypted-writer)
	  (bytevector=? clear-text (decrypted-getter))))
    => #t)

;;; --------------------------------------------------------------------
;;; copying contexts

  (check
      (let ()
	(define algo (ssl.evp-rc4))
	(define key
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv '#vu8())

	(define (encrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-encrypt-init ctx algo key #f iv #f)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-encrypt-update ctx ou #f in #f))
		   (ou.final (ssl.evp-encrypt-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(define (decrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-decrypt-init ctx algo key #f iv #f)
	      (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		     (ou.len   (ssl.evp-decrypt-update ctx ou #f in #f)))
		(let ((ctx^ (ssl.evp-cipher-ctx-new)))
		  (ssl.evp-decrypt-init ctx^ algo key #f iv #f)
		  (assert (ssl.evp-cipher-ctx-copy ctx^ ctx))
		  (let ((ou.final (ssl.evp-decrypt-final ctx^)))
		    (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))))

	(decrypt (encrypt "mamma")))
    => '#ve(ascii "mamma"))

  (collect))


(parametrise ((check-test-name		'encrypt-cast5)
	      (structs::struct-guardian-logger	#f))

  (check
      (let ()
	(define algo (ssl.evp-cast5-cbc))
	(define key
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv
	  (make-bytevector (ssl.evp-cipher-iv-length algo)))

	(define (encrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-encrypt-init ctx algo key #f iv #f)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-encrypt-update ctx ou #f in #f))
		   (ou.final (ssl.evp-encrypt-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(define (decrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-decrypt-init ctx algo key #f iv #f)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-decrypt-update ctx ou #f in #f))
		   (ou.final (ssl.evp-decrypt-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))


	(decrypt (encrypt "mamma")))
    => '#ve(ascii "mamma"))

;;; --------------------------------------------------------------------

  (check
      (let ()
	(define (make-chunked-bytevector-input-port bv)
	  (let ((port (open-bytevector-input-port bv)))
	    (values port (lambda ()
			   (get-bytevector-n port 4096)))))

	(define (make-chunked-bytevector-output-port)
	  (receive (port getter)
	      (open-bytevector-output-port)
	    (values port getter (lambda (data)
				  (put-bytevector port data)))))

	;;FIXME This fails  with CBC mode, but works with  all the other
	;;modes.  Why?  (Marco Maggi; Fri Jul 5, 2013)
	(define algo (ssl.evp-cast5-ofb) #;(ssl.evp-cast5-ofb))
	(define key
	  ;;A random key.
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv
	  (make-bytevector (ssl.evp-cipher-iv-length algo)))

	(define (encrypt input output)
	  (define ctx
	    (ssl.evp-cipher-ctx-new))
	  (ssl.evp-encrypt-init ctx algo key #f iv #f)
	  (let loop ((in.data (input)))
	    (if (eof-object? in.data)
		(cond ((ssl.evp-decrypt-final ctx)
		       => output)
		      (else
		       (error #f "error finalising encryption")))
	      (let* ((ou.len  (ssl.evp-minimum-output-length ctx in.data #f))
		     (ou.data (make-bytevector ou.len)))
		(cond ((ssl.evp-decrypt-update ctx ou.data #f in.data #f)
		       => (lambda (ou.len)
			    (output (subbytevector-u8 ou.data 0 ou.len))
			    (loop (input))))
		      (else
		       (error #f "error encrypting data")))))))

	(define (decrypt input output)
	  (define ctx
	    (ssl.evp-cipher-ctx-new))
	  (ssl.evp-decrypt-init ctx algo key #f iv #f)
	  (let loop ((in.data (input)))
	    (if (eof-object? in.data)
		(cond ((ssl.evp-decrypt-final ctx)
		       => output)
		      (else
		       (error #f "error finalising decryption")))
	      (let* ((ou.len  (ssl.evp-minimum-output-length ctx in.data #f))
		     (ou.data (make-bytevector ou.len)))
		(cond ((ssl.evp-decrypt-update ctx ou.data #f in.data #f)
		       => (lambda (ou.len)
			    (output (subbytevector-u8 ou.data 0 ou.len))
			    (loop (input))))
		      (else
		       (error #f "error decrypting data")))))))

	(define clear-text
	  (make-bytevector 123456))

	(define-values (clear-port clear-reader)
	  (make-chunked-bytevector-input-port clear-text))

	(define-values (encrypted-port encrypted-getter encrypted-writer)
	  (make-chunked-bytevector-output-port))

	(encrypt clear-reader encrypted-writer)

	(let ((encrypted-text (encrypted-getter)))
	  (define-values (encrypted-port encrypted-reader)
	    (make-chunked-bytevector-input-port encrypted-text))
	  (define-values (decrypted-port decrypted-getter decrypted-writer)
	    (make-chunked-bytevector-output-port))
	  (decrypt encrypted-reader decrypted-writer)
	  (bytevector=? clear-text (decrypted-getter))))
    => #t)

  (collect))


(parametrise ((check-test-name		'cipher-rc4)
	      (structs::struct-guardian-logger	#f))

  (check
      (let ()
	(define algo (ssl.evp-rc4))
	(define key
	  (make-bytevector (ssl.evp-cipher-key-length algo)))

	(define (encrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-cipher-init ctx algo key #f '#vu8() #f ssl.EVP_CIPHER_ENCRYPT)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-cipher-update ctx ou #f in #f))
		   (ou.final (ssl.evp-cipher-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(define (decrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-cipher-init ctx algo key #f '#vu8() #f ssl.EVP_CIPHER_DECRYPT)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-cipher-update ctx ou #f in #f))
		   (ou.final (ssl.evp-cipher-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(decrypt (encrypt "mamma")))
    => '#ve(ascii "mamma"))

;;; --------------------------------------------------------------------

  (check
      (let ()
	(define (make-chunked-bytevector-input-port bv)
	  (let ((port (open-bytevector-input-port bv)))
	    (values port (lambda ()
			   (get-bytevector-n port 4096)))))

	(define (make-chunked-bytevector-output-port)
	  (receive (port getter)
	      (open-bytevector-output-port)
	    (values port getter (lambda (data)
				  (put-bytevector port data)))))

	(define algo (ssl.evp-rc4))
	(define key
	  ;;A random key.
	  (make-bytevector (ssl.evp-cipher-key-length algo)))

	(define (cipher ctx input output)
	  (let loop ((in.data (input)))
	    (if (eof-object? in.data)
		(cond ((ssl.evp-decrypt-final ctx)
		       => output)
		      (else
		       (error #f "error finalising cipher")))
	      (let* ((ou.len  (ssl.evp-minimum-output-length ctx in.data #f))
		     (ou.data (make-bytevector ou.len)))
		(cond ((ssl.evp-decrypt-update ctx ou.data #f in.data #f)
		       => (lambda (ou.len)
			    (output (subbytevector-u8 ou.data 0 ou.len))
			    (loop (input))))
		      (else
		       (error #f "error enciphering data")))))))

	(define clear-text
	  (make-bytevector 123456))

	(define-values (clear-port clear-reader)
	  (make-chunked-bytevector-input-port clear-text))

	(define-values (encrypted-port encrypted-getter encrypted-writer)
	  (make-chunked-bytevector-output-port))

	(let ((ctx (ssl.evp-cipher-ctx-new)))
	  (ssl.evp-cipher-init ctx algo key #f '#vu8() #f ssl.EVP_CIPHER_ENCRYPT)
	  (cipher ctx clear-reader encrypted-writer))

	(let ((encrypted-text (encrypted-getter)))
	  (define-values (encrypted-port encrypted-reader)
	    (make-chunked-bytevector-input-port encrypted-text))
	  (define-values (ciphered-port ciphered-getter ciphered-writer)
	    (make-chunked-bytevector-output-port))
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-cipher-init ctx algo key #f '#vu8() #f ssl.EVP_CIPHER_DECRYPT)
	    (cipher ctx encrypted-reader ciphered-writer))
	  (bytevector=? clear-text (ciphered-getter))))
    => #t)

  (collect))


(parametrise ((check-test-name		'cipher-cast5)
	      (structs::struct-guardian-logger	#f))

  (check
      (let ()
	(define algo (ssl.evp-cast5-cbc))
	(define key
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv
	  (make-bytevector (ssl.evp-cipher-iv-length algo)))

	(define (encrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-cipher-init ctx algo key #f iv #f ssl.EVP_CIPHER_ENCRYPT)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-cipher-update ctx ou #f in #f))
		   (ou.final (ssl.evp-cipher-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(define (decrypt in)
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-cipher-init ctx algo key #f iv #f ssl.EVP_CIPHER_DECRYPT)
	    (let* ((ou       (make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		   (ou.len   (ssl.evp-cipher-update ctx ou #f in #f))
		   (ou.final (ssl.evp-cipher-final ctx)))
	      (bytevector-append (subbytevector-u8 ou 0 ou.len) ou.final))))

	(decrypt (encrypt "mamma")))
    => '#ve(ascii "mamma"))

;;; --------------------------------------------------------------------

  (check
      (let ()
	(define (make-chunked-bytevector-input-port bv)
	  (let ((port (open-bytevector-input-port bv)))
	    (values port (lambda ()
			   (get-bytevector-n port 4096)))))

	(define (make-chunked-bytevector-output-port)
	  (receive (port getter)
	      (open-bytevector-output-port)
	    (values port getter (lambda (data)
				  (put-bytevector port data)))))

	(define algo (ssl.evp-cast5-ofb))
	(define key
	  ;;A random key.
	  (make-bytevector (ssl.evp-cipher-key-length algo)))
	(define iv
	  (make-bytevector (ssl.evp-cipher-iv-length algo)))

	(define (cipher ctx input output)
	  (let loop ((in.data (input)))
	    (if (eof-object? in.data)
		(cond ((ssl.evp-decrypt-final ctx)
		       => output)
		      (else
		       (error #f "error finalising cipher")))
	      (let* ((ou.len  (ssl.evp-minimum-output-length ctx in.data #f))
		     (ou.data (make-bytevector ou.len)))
		(cond ((ssl.evp-decrypt-update ctx ou.data #f in.data #f)
		       => (lambda (ou.len)
			    (output (subbytevector-u8 ou.data 0 ou.len))
			    (loop (input))))
		      (else
		       (error #f "error enciphering data")))))))

	(define clear-text
	  (make-bytevector 123456))

	(define-values (clear-port clear-reader)
	  (make-chunked-bytevector-input-port clear-text))

	(define-values (encrypted-port encrypted-getter encrypted-writer)
	  (make-chunked-bytevector-output-port))

	(let ((ctx (ssl.evp-cipher-ctx-new)))
	  (ssl.evp-cipher-init ctx algo key #f iv #f ssl.EVP_CIPHER_ENCRYPT)
	  (cipher ctx clear-reader encrypted-writer))

	(let ((encrypted-text (encrypted-getter)))
	  (define-values (encrypted-port encrypted-reader)
	    (make-chunked-bytevector-input-port encrypted-text))
	  (define-values (ciphered-port ciphered-getter ciphered-writer)
	    (make-chunked-bytevector-output-port))
	  (let ((ctx (ssl.evp-cipher-ctx-new)))
	    (ssl.evp-cipher-init ctx algo key #f iv #f ssl.EVP_CIPHER_DECRYPT)
	    (cipher ctx encrypted-reader ciphered-writer))
	  (bytevector=? clear-text (ciphered-getter))))
    => #t)

  (collect))


(parametrise ((check-test-name		'step)
	      (structs::struct-guardian-logger	#f))

  (let ((key '#vu8(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)))
    #;(debug-print (ssl.evp-cipher-key-length (ssl.evp-rc4)))

    (check
	(let* ((algo	(ssl.evp-rc4))
	       (ctx	(ssl.evp-cipher-ctx-new))
	       (iv	'#vu8()) ;RC4 has no IV
	       (in	'#ve(ascii "mamma")))
	  (ssl.evp-encrypt-init ctx algo key #f iv #f)
	  (let* ((ou	(make-bytevector (ssl.evp-minimum-output-length ctx in #f) 0))
		 (ou.len	(ssl.evp-crypt ctx ou #f in #f)))
	    #;(debug-print ou.len)
	    (subbytevector-u8 ou 0 5)))
      => '#vu8(132 253 45 148 38))

    (check
	(let* ((algo	(ssl.evp-rc4))
	       (ctx	(ssl.evp-cipher-ctx-new))
	       (iv	'#vu8()) ;RC4 has no IV
	       (in	'#vu8(132 253 45 148 38)))
	  (void)
	  (ssl.evp-decrypt-init ctx algo key #f iv #f)
	  (let* ((ou		(make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		 (ou.len	(ssl.evp-crypt ctx ou #f in #f)))
	    (subbytevector-u8 ou 0 5)))
      => '#ve(ascii "mamma"))

    #f)

;;; --------------------------------------------------------------------

  (let ((key '#vu8(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
	(iv  '#vu8(0 1 2 3 4 5 6 7)))
    #;(debug-print (ssl.evp-cipher-key-length (ssl.evp-cast5-cbc))
    		 (ssl.evp-cipher-iv-length (ssl.evp-cast5-cbc)))

    (check
	(let* ((algo	(ssl.evp-cast5-cbc))
	       (ctx	(ssl.evp-cipher-ctx-new))
	       (in	'#ve(ascii "mamma")))
	  (ssl.evp-encrypt-init ctx algo key #f iv #f)
	  (let* ((ou	(make-bytevector (ssl.evp-minimum-output-length ctx in #f) 0))
		 (ou.len	(ssl.evp-crypt ctx ou #f in #f)))
	    #;(debug-print ou.len)
	    (subbytevector-u8 ou 0 8)))
      => '#vu8(205 32 197 38 33 9 237 126))

    (check
	(let* ((algo	(ssl.evp-cast5-cbc))
	       (ctx	(ssl.evp-cipher-ctx-new))
	       (in	'#vu8(205 32 197 38 33 9 237 126)))
	  (void)
	  (ssl.evp-decrypt-init ctx algo key #f iv #f)
	  (let* ((ou		(make-bytevector (ssl.evp-minimum-output-length ctx in #f)))
		 (ou.len	(ssl.evp-crypt ctx ou #f in #f)))
	    (subbytevector-u8 ou 0 5)))
      => '#ve(ascii "mamma"))

    #f)

  (collect))


;;;; done

(check-report)

;;; end of file
