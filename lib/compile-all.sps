;;; -*- coding: utf-8-unix -*-
;;;
;;;Part of: Vicare/OpenSSL
;;;Contents: compile script
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
(import (only (vicare crypto openssl))
  (only (vicare crypto openssl features))
  (only (vicare crypto openssl constants))
  (only (vicare crypto openssl evp message-digests))
  (only (vicare crypto openssl evp ciphers))
  (only (vicare crypto openssl message-digests))
  (only (vicare crypto openssl hmac))
  (only (vicare crypto openssl aes))

  (only (vicare crypto openssl cond-expand))
  (only (vicare crypto openssl evp message-digests cond-expand))
  (only (vicare crypto openssl evp ciphers cond-expand))
  (only (vicare crypto openssl message-digests cond-expand))
  (only (vicare crypto openssl hmac cond-expand))
  (only (vicare crypto openssl aes cond-expand))

  (only (vicare crypto openssl buffers))
  (only (vicare crypto openssl buffers cond-expand))
  )

;;; end of file
