;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: helper functions
;;;Date: Sun Mar 17, 2013
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
(library (vicare crypto openssl helpers)
  (export
    symbol->message-digest-index)
  (import (vicare))


;;;; helpers

(define (symbol->message-digest-index who md)
  (case md
    ;;This  mapping  must   be  kept  in  sync  with  the   one  in  the
    ;;implementation of the functions HMAC-INIT and HMAC.
    ((md4)		0)
    ((md5)		1)
    ((mdc2)		2)
    ((sha1)		3)
    ((sha224)		4)
    ((sha256)		5)
    ((sha384)		6)
    ((sha512)		7)
    ((ripemd160)	8)
    ((whirlpool)	9)
    ((dss)		10)
    ((dss1)		11)
    (else
     (error who "unknown message digest" md))))


;;;; done

)

;;; end of file
