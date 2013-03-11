/*
  Part of: Vicare/OpenSSL
  Contents: OpenSSL for Vicare
  Date: Sat Mar  9, 2013

  Abstract

	Hash checksum functions.

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

typedef const unsigned char		ik_ssl_cuchar;


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
 ** MD4.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_md4_init (ikpcb * pcb)
{
#ifdef HAVE_MD4_INIT
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4_update (ikpcb * pcb)
{
#ifdef HAVE_MD4_UPDATE
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4_final (ikpcb * pcb)
{
#ifdef HAVE_MD4_FINAL
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4_abort (ikptr s_ctx, ikpcb * pcb)
{
#ifdef HAVE_MD4_FINAL
  MD4_CTX *	ctx	= IK_MD4_CTX(s_ctx);
  unsigned char	dummy[MD4_DIGEST_LENGTH];
  MD4_Final(dummy, ctx);
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4 (ikptr s_input, ikptr s_input_len, ikpcb * pcb)
{
#ifdef HAVE_MD4
  ik_ssl_cuchar *	in     = (ik_ssl_cuchar *)IK_GENERALISED_C_STRING(s_input);
  ik_ulong		in_len = (ik_ulong)generalised_c_buffer_len(s_input, s_input_len);
  ikptr			rv;
  pcb->root0 = &s_input;
  {
    unsigned char *	ou;
    rv = ika_bytevector_alloc(pcb, MD4_DIGEST_LENGTH);
    ou = IK_BYTEVECTOR_DATA_VOIDP(rv);
    MD4(in, in_len, ou);
  }
  pcb->root0 = NULL;
  return rv;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_md4_transform (ikpcb * pcb)
{
#ifdef HAVE_MD4_TRANSFORM
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
