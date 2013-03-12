/*
  Part of: Vicare/OpenSSL
  Contents: internal header file
  Date: Sat Mar  9, 2013

  Abstract

	Internal header file.

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

#ifndef VICARE_OPENSSL_INTERNALS_H
#define VICARE_OPENSSL_INTERNALS_H 1


/** --------------------------------------------------------------------
 ** Headers.
 ** ----------------------------------------------------------------- */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <assert.h>
#include <vicare.h>

/* It is better if this comes first. */
#ifdef HAVE_OPENSSL_SSL_H
#  include <openssl/ssl.h>
#endif

/* Message digests. */
#ifdef HAVE_OPENSSL_MD4_H
#  include <openssl/md4.h>
#endif
#ifdef HAVE_OPENSSL_MD5_H
#  include <openssl/md5.h>
#endif
#ifdef HAVE_OPENSSL_MDC2_H
#  include <openssl/mdc2.h>
#endif
#ifdef HAVE_OPENSSL_SHA_H
#  include <openssl/sha.h>
#endif
#ifdef HAVE_OPENSSL_RIPEMD_H
#  include <openssl/ripemd.h>
#endif

#ifdef HAVE_OPENSSL_HMAC_H
#  include <openssl/hmac.h>
#endif

/* Encrypting and decrypting. */
#ifdef HAVE_OPENSSL_AES_H
#  include <openssl/aes.h>
#endif



/** --------------------------------------------------------------------
 ** Handling of Scheme objects: hash checksums and HMAC.
 ** ----------------------------------------------------------------- */

/* Accessors for the fields of the Scheme structure "md4-ctx". */
#define IK_MD4_CTX_POINTER(CTX)		IK_FIELD((CTX),0)
#define IK_MD4_CTX(CTX)			IK_POINTER_DATA_VOIDP(IK_MD4_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "md5-ctx". */
#define IK_MD5_CTX_POINTER(CTX)		IK_FIELD((CTX),0)
#define IK_MD5_CTX(CTX)			IK_POINTER_DATA_VOIDP(IK_MD5_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "mdc2-ctx". */
#define IK_MDC2_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_MDC2_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_MDC2_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "sha-ctx". */
#define IK_SHA_CTX_POINTER(CTX)		IK_FIELD((CTX),0)
#define IK_SHA_CTX(CTX)			IK_POINTER_DATA_VOIDP(IK_SHA_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "sha224-ctx". */
#define IK_SHA224_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_SHA224_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_SHA224_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "sha256-ctx". */
#define IK_SHA256_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_SHA256_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_SHA256_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "sha384-ctx". */
#define IK_SHA384_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_SHA384_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_SHA384_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "sha512-ctx". */
#define IK_SHA512_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_SHA512_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_SHA512_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "ripemd160-ctx". */
#define IK_RIPEMD160_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_RIPEMD160_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_RIPEMD160_CTX_POINTER(CTX))

/* Accessors for the fields of the Scheme structure "hmac-ctx". */
#define IK_HMAC_CTX_POINTER(CTX)	IK_FIELD((CTX),0)
#define IK_HMAC_CTX(CTX)		IK_POINTER_DATA_VOIDP(IK_HMAC_CTX_POINTER(CTX))


/** --------------------------------------------------------------------
 ** Handling of Scheme objects: encrypting and decripting.
 ** ----------------------------------------------------------------- */

/* Accessors for the fields of the Scheme structure "aes-key". */
#define IK_AES_KEY_POINTER(CTX)		IK_FIELD((CTX),0)
#define IK_AES_KEY(CTX)			IK_POINTER_DATA_VOIDP(IK_AES_KEY_POINTER(CTX))


/** --------------------------------------------------------------------
 ** Support for missing functions.
 ** ----------------------------------------------------------------- */

static IK_UNUSED void
feature_failure_ (const char * funcname)
{
  ik_abort("called unavailable OpenSSL specific function, %s\n", funcname);
}

#define feature_failure(FN)     { feature_failure_(FN); return IK_VOID; }


/** --------------------------------------------------------------------
 ** Done.
 ** ----------------------------------------------------------------- */


#endif /* VICARE_OPENSSL_INTERNALS_H */

/* end of file */
