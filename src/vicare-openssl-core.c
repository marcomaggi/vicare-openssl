/*
  Part of: Vicare/OpenSSL
  Contents: Openssl for Vicare
  Date: Wed Mar 13, 2013

  Abstract

	Core functions.

  Copyright (C) 2013 Marco Maggi <marco.maggi-ipsu@poste.it>

  This program is  free software: you can redistribute  it and/or modify
  it under the  terms of the GNU General Public  License as published by
  the Free Software Foundation, either  version 3 of the License, or (at
  your option) any later version.

  This program  is distributed in the  hope that it will  be useful, but
  WITHOUT   ANY  WARRANTY;   without  even   the  implied   warranty  of
  MERCHANTABILITY  or FITNESS  FOR A  PARTICULAR PURPOSE.   See  the GNU
  General Public License for more details.

  You  should have received  a copy  of the  GNU General  Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


/** --------------------------------------------------------------------
 ** Headers.
 ** ----------------------------------------------------------------- */

#include "vicare-openssl-internals.h"


/** --------------------------------------------------------------------
 ** Global initialisation functions.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_ssl_library_init (ikpcb * pcb)
{
#ifdef HAVE_SSL_LIBRARY_INIT
  SSL_library_init();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}

/* end of file */
