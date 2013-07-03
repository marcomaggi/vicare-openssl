;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: demonstration script for Vicare/OpenSSL
;;;Date: Tue Jul  2, 2013
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
;;;MERCHANTABILITY or  FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU
;;;General Public License for more details.
;;;
;;;You should  have received a  copy of  the GNU General  Public License
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;


#!r6rs
(import (vicare)
  (prefix (vicare crypto openssl) ssl.)
  (prefix (vicare crypto openssl hmac) ssl.)
  (prefix (vicare crypto openssl evp message-digests) ssl.))

(ssl.openssl-add-all-algorithms)


;;;; main

(module (main)

  (define (main argv)
    (define in-port
      (standard-input-port))
    (define ou-port
      (standard-output-port))
    (with-compensations
      (message-digest (ssl.evp-md5)
		      (lambda ()
			(get-bytevector-n in-port 4096))
		      (lambda (binary-data)
			(put-bytevector ou-port (bytevector->hex binary-data))
			(put-u8 ou-port (char->integer #\newline))
			(flush-output-port ou-port))))
    (exit 0))

  #| end of module: main |# )


;;;; command line arguments

;;We parse  all the command line  arguments and store the  results in an
;;instance of this record; then we inspect the values
;;
(define-record-type <command-line-arguments>
  (nongenerative vicare-openssl:<command-line-arguments>)
  (fields (mutable message-digest-algorithm)))


;;;; message digests

(define (message-digest algo input-chunk process-output)
  ;;Initialise a message digest context with the algorithm specification
  ;;ALGO;  read bytevectors  calling the  thunk INPUT-CHUNK,  until EOF,
  ;;digest them and finally hand the resulting checksum to the procedure
  ;;PROCESS-OUTPUT.
  ;;
  (define ctx
    (compensate
	(ssl.evp-md-ctx-create)
      (with
       (ssl.evp-md-ctx-destroy ctx))))
  (unless (ssl.evp-digest-init ctx algo)
    (error "cannot initialise message digest context" algo))
  (let loop ((chunk (input-chunk)))
    (cond ((eof-object? chunk)
	   (cond ((ssl.evp-digest-final ctx)
		  => process-output)
		 (else
		  (error "error generating message digest checksum"))))
	  ((ssl.evp-digest-update ctx chunk #f)
	   (loop (input-chunk)))
	  (else
	   (error "error processing data for message digest")))))

(define (hmac algo key input-chunk process-output)
  ;;Initialise a HMAC context with  the algorithm specification ALGO and
  ;;KEY;  read bytevectors  calling  the thunk  INPUT-CHUNK, until  EOF,
  ;;digest them and finally hand the resulting checksum to the procedure
  ;;PROCESS-OUTPUT.
  ;;
  (define ctx
    (ssl.hmac-init key #f algo))
  (unless ctx
    (error "cannot initialise HMAC context" algo))
  (let loop ((chunk (input-chunk)))
    (cond ((eof-object? chunk)
	   (cond ((ssl.hmac-final ctx)
		  => process-output)
		 (else
		  (error "error generating HMAC"))))
	  ((ssl.hmac-update ctx chunk #f)
	   (loop (input-chunk)))
	  (else
	   (error "error processing data for HMAC")))))


;;;; let's go

(main (command-line))

;;; end of file
