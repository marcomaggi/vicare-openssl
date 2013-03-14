/*
  Part of: Vicare/OpenSSL
  Contents: helper functions
  Date: Thu Mar 14, 2013

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


/** --------------------------------------------------------------------
 ** Headers.
 ** ----------------------------------------------------------------- */

#include "vicare-openssl-internals.h"


const EVP_MD *
ik_openssl_integer_to_evp_md (ikptr s_md)
{
  /* This mapping must  be kept in sync with the  Scheme function in the
     public library. */
  switch (ik_integer_to_int(s_md)) {
  case 0:	return EVP_md4();
  case 1:	return EVP_md5();
  case 2:	return EVP_mdc2();
  case 3:	return EVP_sha1();
  case 4:	return EVP_sha224();
  case 5:	return EVP_sha256();
  case 6:	return EVP_sha384();
  case 7:	return EVP_sha512();
  case 8:	return EVP_ripemd160();
  case 9:	return EVP_whirlpool();
  case 10:	return EVP_dss();
  case 11:	return EVP_dss1();
  default:
    return NULL;
  }
}





/* end of file */
