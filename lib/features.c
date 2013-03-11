/*
  Part of: Vicare/OpenSSL
  Contents: print platform features library
  Date: Sat Mar  9, 2013

  Abstract



  Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>

  This program is  free software: you can redistribute  it and/or modify
  it under the  terms of the GNU General Public  License as published by
  the Free Software Foundation, either version  3 of the License, or (at
  your option) any later version.

  This program  is distributed in the  hope that it will  be useful, but
  WITHOUT   ANY  WARRANTY;   without  even   the  implied   warranty  of
  MERCHANTABILITY  or FITNESS  FOR A  PARTICULAR PURPOSE.   See the  GNU
  General Public License for more details.

  You should  have received  a copy  of the  GNU General  Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>


int
main (int argc, const char *const argv[])
{
  printf(";;; -*- coding: utf-8-unix -*-\n\
;;;\n\
;;;Part of: Vicare/OpenSSL\n\
;;;Contents: static platform inspection\n\
;;;Date: Sat Mar  9, 2013\n\
;;;\n\
;;;Abstract\n\
;;;\n\
;;;\n\
;;;\n\
;;;Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>\n\
;;;\n\
;;;This program is free software:  you can redistribute it and/or modify\n\
;;;it under the terms of the  GNU General Public License as published by\n\
;;;the Free Software Foundation, either version 3 of the License, or (at\n\
;;;your option) any later version.\n\
;;;\n\
;;;This program is  distributed in the hope that it  will be useful, but\n\
;;;WITHOUT  ANY   WARRANTY;  without   even  the  implied   warranty  of\n\
;;;MERCHANTABILITY or  FITNESS FOR  A PARTICULAR  PURPOSE.  See  the GNU\n\
;;;General Public License for more details.\n\
;;;\n\
;;;You should  have received a  copy of  the GNU General  Public License\n\
;;;along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\
;;;\n\
\n\
\n\
#!r6rs\n\
(library (vicare crypto openssl features)\n\
  (export\n\
    HAVE_MD4_INIT\n\
    HAVE_MD4_UPDATE\n\
    HAVE_MD4_FINAL\n\
    HAVE_MD4\n\
    HAVE_MD4_TRANSFORM\n\
    )\n\
  (import (rnrs))\n\
\n\
;;;; helpers\n\
\n\
(define-syntax define-inline-constant\n\
  (syntax-rules ()\n\
    ((_ ?name ?value)\n\
     (define-syntax ?name (identifier-syntax ?value)))))\n\
\n\
\n\
;;;; code\n\n");


printf("(define-inline-constant HAVE_MD4_INIT %s)\n",
#ifdef HAVE_MD4_INIT
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD4_UPDATE %s)\n",
#ifdef HAVE_MD4_UPDATE
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD4_FINAL %s)\n",
#ifdef HAVE_MD4_FINAL
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant HAVE_MD4 %s)\n",
#ifdef HAVE_MD4
  "#t"
#else
  "#f"
#endif
  );
printf("(define-inline-constant  HAVE_MD4_TRANSFORM %s)\n",
#ifdef HAVE_MD4_TRANSFORM
  "#t"
#else
  "#f"
#endif
  );


  printf("\n\
;;;; done\n\
\n\
)\n\
\n\
;;; end of file\n");
  exit(EXIT_SUCCESS);
}

/* end of file */
