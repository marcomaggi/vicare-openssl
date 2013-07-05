/*
  Part of: Vicare/OpenSSL
  Contents: Openssl for Vicare
  Date: Fri Jul  5, 2013

  Abstract

	Buffer functions.

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
 ** buffer C wrappers.
 ** ----------------------------------------------------------------- */

ikptr
ikrt_buf_mem_new (ikpcb * pcb)
{
#ifdef HAVE_BUF_MEM_NEW
  BUF_MEM *	rv;
  rv = BUF_MEM_new();
  return (rv)? ika_pointer_alloc(pcb, (long)rv) : IK_FALSE;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_mem_free (ikptr s_buffer, ikpcb * pcb)
{
#ifdef HAVE_BUF_MEM_FREE
  ikptr		s_pointer = IK_BUF_MEM_POINTER(s_buffer);
  BUF_MEM *	buf       = IK_POINTER_DATA_VOIDP(s_pointer);
  if (buf) {
    BUF_MEM_free(buf);
    IK_POINTER_SET_NULL(s_pointer);
  }
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_mem_grow (ikptr s_buffer, ikptr s_len, ikpcb * pcb)
{
#ifdef HAVE_BUF_MEM_GROW
  BUF_MEM *	buf = IK_BUF_MEM(s_buffer);
  int		len = ik_integer_to_int(s_len);
  int		rv;
  rv = BUF_MEM_grow(buf, len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_mem_grow_clean (ikptr s_buffer, ikptr s_len, ikpcb * pcb)
{
#ifdef HAVE_BUF_MEM_GROW_CLEAN
  BUF_MEM *	buf = IK_BUF_MEM(s_buffer);
  int		len = ik_integer_to_int(s_len);
  int		rv;
  rv = BUF_MEM_grow_clean(buf, len);
  return IK_BOOLEAN_FROM_INT(rv);
#else
  feature_failure(__func__);
#endif
}

/* ------------------------------------------------------------------ */

#if 0
ikptr
ikrt_buf_strdup (ikpcb * pcb)
{
#ifdef HAVE_BUF_STRDUP
  /* rv = BUF_strdup(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_strndup (ikpcb * pcb)
{
#ifdef HAVE_BUF_STRNDUP
  /* rv = BUF_strndup(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_memdup (ikpcb * pcb)
{
#ifdef HAVE_BUF_MEMDUP
  /* rv = BUF_memdup(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_reverse (ikpcb * pcb)
{
#ifdef HAVE_BUF_REVERSE
  /* rv = BUF_reverse(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_strlcpy (ikpcb * pcb)
{
#ifdef HAVE_BUF_STRLCPY
  /* rv = BUF_strlcpy(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_buf_strlcat (ikpcb * pcb)
{
#ifdef HAVE_BUF_STRLCAT
  /* rv = BUF_strlcat(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}
ikptr
ikrt_err_load_buf_strings (ikpcb * pcb)
{
#ifdef HAVE_ERR_LOAD_BUF_STRINGS
  /* rv = ERR_load_BUF_strings(); */
  return IK_VOID;
#else
  feature_failure(__func__);
#endif
}

#endif

/* end of file */
