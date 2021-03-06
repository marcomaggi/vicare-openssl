/*
  Part of: Vicare/OpenSSL
  Contents: Openssl for Vicare
  Date: Sat Mar  9, 2013

  Abstract

	Version functions.

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
 ** Version functions.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_openssl_version_interface_current (void)
{
  return IK_FIX(vicare_openssl_VERSION_INTERFACE_CURRENT);
}
ikptr
ikrt_openssl_version_interface_revision (void)
{
  return IK_FIX(vicare_openssl_VERSION_INTERFACE_REVISION);
}
ikptr
ikrt_openssl_version_interface_age (void)
{
  return IK_FIX(vicare_openssl_VERSION_INTERFACE_AGE);
}
ikptr
ikrt_openssl_version (ikpcb * pcb)
{
  return ika_bytevector_from_cstring(pcb, vicare_openssl_VERSION_INTERFACE_STRING);
}

/* end of file */
