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
ikrt_openssl_ssl_library_init (ikpcb * pcb)
{
#ifdef HAVE_SSL_LIBRARY_INIT
  SSL_library_init();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_add_all_algorithms_noconf (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_ADD_ALL_ALGORITHMS_NOCONF
  OPENSSL_add_all_algorithms_noconf();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_add_all_algorithms_conf (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_ADD_ALL_ALGORITHMS_CONF
  OPENSSL_add_all_algorithms_conf();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_add_all_algorithms (ikpcb * pcb)
{
#if ((defined HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS)
  OpenSSL_add_all_algorithms();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_add_all_ciphers (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_ADD_ALL_CIPHERS
  OpenSSL_add_all_ciphers();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_openssl_add_all_digests (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_ADD_ALL_DIGESTS
  OpenSSL_add_all_digests();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_ssleay_add_all_algorithms (ikpcb * pcb)
{
#if ((defined HAVE_DECL_SSLEAY_ADD_ALL_ALGORITHMS) && HAVE_DECL_SSLEAY_ADD_ALL_ALGORITHMS)
  SSLeay_add_all_algorithms();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_ssleay_add_all_ciphers (ikpcb * pcb)
{
#if ((defined HAVE_DECL_SSLEAY_ADD_ALL_CIPHERS) && HAVE_DECL_SSLEAY_ADD_ALL_CIPHERS)
  SSLeay_add_all_ciphers();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_ssleay_add_all_digests (ikpcb * pcb)
{
#if ((defined HAVE_DECL_SSLEAY_ADD_ALL_DIGESTS) && HAVE_DECL_SSLEAY_ADD_ALL_DIGESTS)
  SSLeay_add_all_digests();
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}

/* end of file */
