/*
  Part of: Vicare/OpenSSL
  Contents: OpenSSL for Vicare
  Date: Mon Mar 11, 2013

  Abstract

	HMAC functions.

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
 ** Helpers.
 ** ----------------------------------------------------------------- */

static size_t
generalised_c_buffer_len (ikptr s_buffer, ikptr s_buffer_len)
{
  if (IK_IS_POINTER(s_buffer)) {
    return ik_integer_to_size_t(s_buffer_len);
  } else if (IK_IS_BYTEVECTOR(s_buffer)) {
    return IK_BYTEVECTOR_LENGTH(s_buffer);
  } else { /* it is a memory-block */
    return IK_MBLOCK_SIZE(s_buffer);
  }
}


/** --------------------------------------------------------------------
 ** Initialisation and finalisation.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_hmac (ikpcb * pcb)
{
#ifdef HAVE_HMAC
  /* rv = HMAC(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_ctx_init (ikpcb * pcb)
{
#ifdef HAVE_HMAC_CTX_INIT
  /* rv = HMAC_CTX_init(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_ctx_cleanup (ikpcb * pcb)
{
#ifdef HAVE_HMAC_CTX_CLEANUP
  /* rv = HMAC_CTX_cleanup(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_init (ikpcb * pcb)
{
#ifdef HAVE_HMAC_INIT
  /* rv = HMAC_Init(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_init_ex (ikpcb * pcb)
{
#ifdef HAVE_HMAC_INIT_EX
  /* rv = HMAC_Init_ex(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_update (ikpcb * pcb)
{
#ifdef HAVE_HMAC_UPDATE
  /* rv = HMAC_Update(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_final (ikpcb * pcb)
{
#ifdef HAVE_HMAC_FINAL
  /* rv = HMAC_Final(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_ctx_copy (ikpcb * pcb)
{
#ifdef HAVE_HMAC_CTX_COPY
  /* rv = HMAC_CTX_copy(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_hmac_ctx_set_flags (ikpcb * pcb)
{
#ifdef HAVE_HMAC_CTX_SET_FLAGS
  /* rv = HMAC_CTX_set_flags(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}


/** --------------------------------------------------------------------
 ** Still to be implemented.
 ** ----------------------------------------------------------------- */

#if 0
ikptr
ikrt_openssl_doit (ikpcb * pcb)
{
#ifdef HAVE_OPENSSL_DOIT
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
#endif

/* end of file */
