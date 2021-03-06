dnl @configure_input@
dnl

AC_PREREQ([2.68])
AC_INIT([Vicare/OpenSSL],[0.4d1],[marco.maggi-ipsu@poste.it],
  [vicare-openssl],[http://marcomaggi.github.io/vicare.html])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([meta/autotools])
AC_CONFIG_AUX_DIR([meta/autotools])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz no-dist-gzip])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CC_C_O
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
LT_PREREQ([2.4])
LT_INIT([shared disable-static])
AC_LANG([C])
AC_DEFINE([_GNU_SOURCE],[1],[enable everything GNU])

VICARE_SCHEME
VICARE_CHECK_LIBRARY([VICARE],[(vicare (0 4 2017 1 (>= 10)))])
AS_IF([test "$vicare_cv_schemelib_VICARE" = no],
  [AC_MSG_ERROR([wrong Vicare version],1)])

VICARE_CHECK_LIBRARY([VICARE_FFI],
  [(vicare ffi (or (0 4 2015 5 (>= 27))
                   (0 4 2015 (>= 6))
                   (0 4 (>= 2016))))])

AS_IF([test "$vicare_cv_schemelib_VICARE_FFI" = no],
  [AC_MSG_ERROR([wrong Vicare FFI library version],1)])

# Command  line  options  for  the executable  "vicare".   The  variable
# AX_VFLAGS is  for options preselected by  the building infrastructure.
# The variable VFLAGS  is for user options selected on  the command line
# of "configure" and "make", for example:
#
#    $ make VFLAGS="-g --option print-loaded-libraries"
#
AS_VAR_SET(AX_VFLAGS,["-O2 --verbose"])
AS_VAR_SET_IF(VFLAGS,,[AS_VAR_SET(VFLAGS)])

VICARE_OPTION_DEBUGGING_MODE

AM_CONDITIONAL([WANT_VICARE_DEBUG],[test x$VICARE_DEBUG = xyes])
AM_COND_IF([WANT_VICARE_DEBUG],[AS_VAR_SET(VFLAGS,"$VFLAGS -g")])

VICARE_ENABLE_OPTION([INSTALL_SOURCES],[sources-installation],[no],
  [whether to install source Scheme libraries],
  [enable installation of source Scheme libraries])
AM_CONDITIONAL([WANT_INSTALL_SOURCES],
  [test "x$vicare_enable_INSTALL_SOURCES" = xyes])

VICARE_ENABLE_OPTION([TIME_TESTS],[time-tests],[no],
  [whether to enable timing of tests],
  [enable timing of tests])
AM_CONDITIONAL([WANT_TIME_TESTS],[test "x$vicare_enable_TIME_TESTS" = xyes])

AM_COND_IF([WANT_TIME_TESTS],
  [AC_PATH_PROG([TIME_PROGRAM],[time])])

#page
#### openssl configuration

VICARE_EXTENSION_LIBRARY_VERSION([openssl],[0],[0],[0])

AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl],[the path to the OpenSSL files])],
  [OPENSSL_DIR=${withval}],
  [OPENSSL_DIR=])

AS_IF([test "z$OPENSSL_DIR" != z],
  [CFLAGS="$CFLAGS -I $OPENSSL_DIR/include"
   CPPFLAGS="$CPPFLAGS -I $OPENSSL_DIR/include"
   LIBS="$LIBS -L$OPENSSL_DIR/lib"])

dnl This must come first.
AC_CHECK_HEADERS([openssl/ssl.h],,
  [AC_MSG_FAILURE([missing openssl/ssl.h header],[2])])

dnl Message digests.
AC_CHECK_HEADERS([openssl/md4.h],,
  [AC_MSG_FAILURE([missing openssl/md4.h header],[2])])
AC_CHECK_HEADERS([openssl/md5.h],,
  [AC_MSG_FAILURE([missing openssl/md5.h header],[2])])
dnl This header is not available in more recent OpenSSL releases.
AC_CHECK_HEADERS([openssl/mdc2.h],,
  [AC_MSG_WARN([missing openssl/mdc2.h header],[2])])
AC_CHECK_HEADERS([openssl/sha.h],,
  [AC_MSG_FAILURE([missing openssl/sha.h header],[2])])
AC_CHECK_HEADERS([openssl/ripemd.h],,
  [AC_MSG_FAILURE([missing openssl/ripemd.h header],[2])])
AC_CHECK_HEADERS([openssl/whrlpool.h],,
  [AC_MSG_FAILURE([missing openssl/whrlpool.h header],[2])])
AC_CHECK_HEADERS([openssl/hmac.h],,
  [AC_MSG_FAILURE([missing openssl/hmac.h header],[2])])

AC_CHECK_HEADERS([openssl/evp.h],,
  [AC_MSG_FAILURE([missing openssl/evp.h header],[2])])

dnl Encrypting and decrypting
AC_CHECK_HEADERS([openssl/aes.h],,
  [AC_MSG_FAILURE([missing openssl/aes.h header],[2])])

dnl Miscellaneous features
AC_CHECK_HEADERS([openssl/buffer.h],,
  [AC_MSG_FAILURE([missing openssl/buffer.h header],[2])])

dnl --------------------------------------------------------------------

AC_CHECK_LIB([crypto],[MD5_Init],,
  [AC_MSG_FAILURE([missing OpenSSL crypto library],[2])])
AC_CHECK_LIB([ssl],[SSL_library_init],,
  [AC_MSG_FAILURE([missing OpenSSL ssl library],[2])])

dnl --------------------------------------------------------------------

m4_define([VICARE_INCLUDES],[
AC_INCLUDES_DEFAULT
#ifdef HAVE_VICARE_H
#  include <vicare.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H
#  include <openssl/ssl.h>
#endif

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
#ifdef HAVE_OPENSSL_WHRLPOOL_H
#  include <openssl/whrlpool.h>
#endif

#ifdef HAVE_OPENSSL_HMAC_H
#  include <openssl/hmac.h>
#endif

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#ifdef HAVE_OPENSSL_AES_H
#  include <openssl/aes.h>
#endif

#ifdef HAVE_OPENSSL_BUFFER_H
#  include <openssl/buffer.h>
#endif

])

#page
#### C language stuff from the files "openssl/ssl.h".

dnl Library initialisation functions checking
AC_CHECK_FUNCS([SSL_library_init OPENSSL_add_all_algorithms_noconf OPENSSL_add_all_algorithms_conf OpenSSL_add_all_ciphers OpenSSL_add_all_digests])

dnl Library initialisation declarations checking
AC_CHECK_DECLS([OpenSSL_add_all_algorithms, SSLeay_add_all_algorithms, SSLeay_add_all_ciphers, SSLeay_add_all_digests],,,[VICARE_INCLUDES])

#page
#### C language stuff from the files "openssl/md4.h", "openssl/md5.h", etc.

dnl Message Digest 4
VICARE_CONSTANT_TESTS([MD4_DIGEST_LENGTH])
AC_CHECK_FUNCS([MD4_Init MD4_Update MD4_Final MD4])

dnl Message Digest 5
VICARE_CONSTANT_TESTS([MD5_DIGEST_LENGTH])
AC_CHECK_FUNCS([MD5_Init MD5_Update MD5_Final MD5])

dnl MDC2
VICARE_CONSTANT_TESTS([MDC2_DIGEST_LENGTH])
AC_CHECK_FUNCS([MDC2_Init MDC2_Update MDC2_Final MDC2])

dnl SHA1
VICARE_CONSTANT_TESTS([SHA_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA1_Init SHA1_Update SHA1_Final SHA1])

dnl SHA224
VICARE_CONSTANT_TESTS([SHA224_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA224_Init SHA224_Update SHA224_Final SHA224])

dnl SHA256
VICARE_CONSTANT_TESTS([SHA256_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA256_Init SHA256_Update SHA256_Final SHA256])

dnl SHA384
VICARE_CONSTANT_TESTS([SHA384_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA384_Init SHA384_Update SHA384_Final SHA384])

dnl SHA512
VICARE_CONSTANT_TESTS([SHA512_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA512_Init SHA512_Update SHA512_Final SHA512])

dnl RIPEMD 160
VICARE_CONSTANT_TESTS([RIPEMD160_DIGEST_LENGTH])
AC_CHECK_FUNCS([RIPEMD160_Init RIPEMD160_Update RIPEMD160_Final RIPEMD160])

dnl WHIRLPOOL
VICARE_CONSTANT_TESTS([WHIRLPOOL_DIGEST_LENGTH])
AC_CHECK_FUNCS([WHIRLPOOL_Init WHIRLPOOL_Update WHIRLPOOL_Final WHIRLPOOL])

#page
#### C language stuff from the files "openssl/hmac.h"

dnl HMAC
VICARE_CONSTANT_TESTS([HMAC_MAX_MD_CBLOCK])

dnl HMAC functions checking
AC_CHECK_FUNCS([HMAC HMAC_CTX_init HMAC_CTX_cleanup HMAC_Init HMAC_Init_ex HMAC_Update HMAC_Final HMAC_CTX_copy HMAC_CTX_set_flags ])

#page
#### C language stuff from the files "openssl/evp.h"

dnl EVP hash functions functions checking
AC_CHECK_FUNCS([EVP_MD_type EVP_MD_pkey_type EVP_MD_size EVP_MD_block_size EVP_MD_flags EVP_MD_CTX_md EVP_MD_CTX_init EVP_MD_CTX_cleanup EVP_MD_CTX_create EVP_MD_CTX_destroy EVP_MD_CTX_copy_ex EVP_MD_CTX_set_flags EVP_MD_CTX_clear_flags EVP_MD_CTX_test_flags EVP_DigestInit_ex EVP_DigestUpdate EVP_DigestFinal_ex EVP_Digest EVP_MD_CTX_copy EVP_DigestInit EVP_DigestFinal EVP_md_null EVP_md2 EVP_md4 EVP_md5 EVP_sha EVP_sha1 EVP_dss EVP_dss1 EVP_ecdsa EVP_sha224 EVP_sha256 EVP_sha384 EVP_sha512 EVP_mdc2 EVP_ripemd160 EVP_whirlpool EVP_get_digestbyname ])

AC_CHECK_DECLS([EVP_MD_name, EVP_MD_nid],,,[VICARE_INCLUDES])
AC_CHECK_DECLS([EVP_MD_CTX_size, EVP_MD_CTX_block_size, EVP_MD_CTX_type],,,[VICARE_INCLUDES])

dnl EVP cipher algorithms functions checking
AC_CHECK_FUNCS([EVP_enc_null EVP_des_ecb EVP_des_ede EVP_des_ede3 EVP_des_ede_ecb EVP_des_ede3_ecb EVP_des_cfb64 EVP_des_ede3_cfb64 EVP_des_ede3_cfb1 EVP_des_ede3_cfb8 EVP_des_ofb EVP_des_ede_ofb EVP_des_ede3_ofb EVP_des_cbc EVP_des_ede_cbc EVP_des_ede3_cbc EVP_desx_cbc EVP_rc4 EVP_rc4_40 EVP_rc4_hmac_md5 EVP_idea_ecb EVP_idea_cfb64 EVP_idea_ofb EVP_idea_cbc EVP_rc2_ecb EVP_rc2_cbc EVP_rc2_40_cbc EVP_rc2_64_cbc EVP_rc2_cfb64 EVP_rc2_ofb EVP_bf_ecb EVP_bf_cbc EVP_bf_cfb64 EVP_bf_ofb EVP_cast5_ecb EVP_cast5_cbc EVP_cast5_cfb64 EVP_cast5_ofb EVP_rc5_32_12_16_cbc EVP_rc5_32_12_16_ecb EVP_rc5_32_12_16_cfb64 EVP_rc5_32_12_16_ofb EVP_aes_128_ecb EVP_aes_128_cbc EVP_aes_128_cfb1 EVP_aes_128_cfb8 EVP_aes_128_cfb128 EVP_aes_128_ofb EVP_aes_128_ctr EVP_aes_128_ccm EVP_aes_128_gcm EVP_aes_128_xts EVP_aes_192_ecb EVP_aes_192_cbc EVP_aes_192_cfb1 EVP_aes_192_cfb8 EVP_aes_192_cfb128 EVP_aes_192_ofb EVP_aes_192_ctr EVP_aes_192_ccm EVP_aes_192_gcm EVP_aes_256_ecb EVP_aes_256_cbc EVP_aes_256_cfb1 EVP_aes_256_cfb8 EVP_aes_256_cfb128 EVP_aes_256_ofb EVP_aes_256_ctr EVP_aes_256_ccm EVP_aes_256_gcm EVP_aes_256_xts EVP_aes_128_cbc_hmac_sha1 EVP_aes_256_cbc_hmac_sha1 EVP_camellia_128_ecb EVP_camellia_128_cbc EVP_camellia_128_cfb1 EVP_camellia_128_cfb8 EVP_camellia_128_cfb128 EVP_camellia_128_ofb EVP_camellia_192_ecb EVP_camellia_192_cbc EVP_camellia_192_cfb1 EVP_camellia_192_cfb8 EVP_camellia_192_cfb128 EVP_camellia_192_ofb EVP_camellia_256_ecb EVP_camellia_256_cbc EVP_camellia_256_cfb1 EVP_camellia_256_cfb8 EVP_camellia_256_cfb128 EVP_camellia_256_ofb EVP_seed_ecb EVP_seed_cbc EVP_seed_cfb128 EVP_seed_ofb EVP_CIPHER_type EVP_get_cipherbyname EVP_CIPHER_nid EVP_CIPHER_block_size EVP_CIPHER_key_length EVP_CIPHER_iv_length EVP_CIPHER_flags EVP_CIPHER_CTX_init EVP_CIPHER_CTX_cleanup EVP_CIPHER_CTX_new EVP_CIPHER_CTX_free EVP_EncryptInit_ex EVP_EncryptFinal_ex EVP_EncryptUpdate EVP_DecryptInit_ex EVP_DecryptUpdate EVP_DecryptFinal_ex EVP_CipherInit_ex EVP_CipherUpdate EVP_CipherFinal_ex EVP_CIPHER_CTX_set_key_length EVP_CIPHER_CTX_set_padding EVP_CIPHER_CTX_ctrl EVP_CIPHER_CTX_cipher EVP_CIPHER_CTX_nid EVP_CIPHER_CTX_block_size EVP_CIPHER_CTX_key_length EVP_CIPHER_CTX_iv_length EVP_CIPHER_CTX_copy EVP_CIPHER_CTX_get_app_data EVP_CIPHER_CTX_set_app_data EVP_CIPHER_CTX_flags EVP_CIPHER_CTX_rand_key EVP_CIPHER_param_to_asn1 EVP_CIPHER_asn1_to_param EVP_CIPHER_CTX_set_flags EVP_CIPHER_CTX_clear_flags EVP_CIPHER_CTX_test_flags EVP_Cipher ])

AC_CHECK_DECLS([EVP_get_cipherbynid, EVP_get_cipherbyobj, EVP_CIPHER_name, EVP_CIPHER_mode, EVP_CIPHER_CTX_type, EVP_CIPHER_CTX_mode, EVP_des_cfb, EVP_des_ede3_cfb, EVP_idea_cfb, EVP_rc2_cfb, EVP_bf_cfb, EVP_cast5_cfb, EVP_rc5_32_12_16_cfb, EVP_aes_128_cfb, EVP_aes_192_cfb, EVP_aes_256_cfb, EVP_camellia_128_cfb, EVP_camellia_192_cfb, EVP_camellia_256_cfb, EVP_seed_cfb],,,[VICARE_INCLUDES])

VICARE_CONSTANT_TESTS([
 EVP_MAX_MD_SIZE
 EVP_MAX_KEY_LENGTH
 EVP_MAX_IV_LENGTH
 EVP_MAX_BLOCK_LENGTH])

VICARE_CONSTANT_TESTS([
 PKCS5_SALT_LEN
 PKCS5_DEFAULT_ITER])

VICARE_CONSTANT_TESTS([
 EVP_PK_RSA
 EVP_PK_DSA
 EVP_PK_DH
 EVP_PK_EC
 EVP_PKT_SIGN
 EVP_PKT_ENC
 EVP_PKT_EXCH
 EVP_PKS_RSA
 EVP_PKS_DSA
 EVP_PKS_EC
 EVP_PKT_EXP])

VICARE_CONSTANT_TESTS([
 EVP_PKEY_NONE
 EVP_PKEY_RSA
 EVP_PKEY_RSA2
 EVP_PKEY_DSA
 EVP_PKEY_DSA1
 EVP_PKEY_DSA2
 EVP_PKEY_DSA3
 EVP_PKEY_DSA4
 EVP_PKEY_DH
 EVP_PKEY_EC
 EVP_PKEY_HMAC
 EVP_PKEY_CMAC])

VICARE_CONSTANT_TESTS([
 EVP_PKEY_MO_SIGN
 EVP_PKEY_MO_VERIFY
 EVP_PKEY_MO_ENCRYPT
 EVP_PKEY_MO_DECRYPT])

VICARE_CONSTANT_TESTS([
 EVP_MD_FLAG_ONESHOT
 EVP_MD_FLAG_PKEY_DIGEST
 EVP_MD_FLAG_PKEY_METHOD_SIGNATURE
 EVP_MD_FLAG_DIGALGID_MASK
 EVP_MD_FLAG_DIGALGID_NULL
 EVP_MD_FLAG_DIGALGID_ABSENT
 EVP_MD_FLAG_DIGALGID_CUSTOM
 EVP_MD_FLAG_FIPS
 EVP_MD_CTRL_DIGALGID
 EVP_MD_CTRL_MICALG
 EVP_MD_CTRL_ALG_CTRL])

VICARE_CONSTANT_TESTS([
 EVP_MD_CTX_FLAG_ONESHOT
 EVP_MD_CTX_FLAG_CLEANED
 EVP_MD_CTX_FLAG_REUSE
 EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
 EVP_MD_CTX_FLAG_PAD_MASK
 EVP_MD_CTX_FLAG_PAD_PKCS1
 EVP_MD_CTX_FLAG_PAD_X931
 EVP_MD_CTX_FLAG_PAD_PSS
 EVP_MD_CTX_FLAG_NO_INIT])

VICARE_CONSTANT_TESTS([
 EVP_CIPH_STREAM_CIPHER
 EVP_CIPH_ECB_MODE
 EVP_CIPH_CBC_MODE
 EVP_CIPH_CFB_MODE
 EVP_CIPH_OFB_MODE
 EVP_CIPH_CTR_MODE
 EVP_CIPH_GCM_MODE
 EVP_CIPH_CCM_MODE
 EVP_CIPH_XTS_MODE
 EVP_CIPH_MODE
 EVP_CIPH_VARIABLE_LENGTH
 EVP_CIPH_CUSTOM_IV
 EVP_CIPH_ALWAYS_CALL_INIT
 EVP_CIPH_CTRL_INIT
 EVP_CIPH_CUSTOM_KEY_LENGTH
 EVP_CIPH_NO_PADDING
 EVP_CIPH_RAND_KEY
 EVP_CIPH_CUSTOM_COPY
 EVP_CIPH_FLAG_DEFAULT_ASN1
 EVP_CIPH_FLAG_LENGTH_BITS
 EVP_CIPH_FLAG_FIPS
 EVP_CIPH_FLAG_NON_FIPS_ALLOW
 EVP_CIPH_FLAG_CUSTOM_CIPHER
 EVP_CIPH_FLAG_AEAD_CIPHER])

VICARE_CONSTANT_TESTS([
 EVP_CTRL_INIT
 EVP_CTRL_SET_KEY_LENGTH
 EVP_CTRL_GET_RC2_KEY_BITS
 EVP_CTRL_SET_RC2_KEY_BITS
 EVP_CTRL_GET_RC5_ROUNDS
 EVP_CTRL_SET_RC5_ROUNDS
 EVP_CTRL_RAND_KEY
 EVP_CTRL_PBE_PRF_NID
 EVP_CTRL_COPY
 EVP_CTRL_GCM_SET_IVLEN
 EVP_CTRL_GCM_GET_TAG
 EVP_CTRL_GCM_SET_TAG
 EVP_CTRL_GCM_SET_IV_FIXED
 EVP_CTRL_GCM_IV_GEN
 EVP_CTRL_CCM_SET_IVLEN
 EVP_CTRL_CCM_GET_TAG
 EVP_CTRL_CCM_SET_TAG
 EVP_CTRL_CCM_SET_L
 EVP_CTRL_CCM_SET_MSGLEN
 EVP_CTRL_AEAD_TLS1_AAD
 EVP_CTRL_AEAD_SET_MAC_KEY
 EVP_CTRL_GCM_SET_IV_INV])

VICARE_CONSTANT_TESTS([
 EVP_GCM_TLS_FIXED_IV_LEN
 EVP_GCM_TLS_EXPLICIT_IV_LEN
 EVP_GCM_TLS_TAG_LEN])

VICARE_CONSTANT_TESTS([
 EVP_PBE_TYPE_OUTER
 EVP_PBE_TYPE_PRF])

VICARE_CONSTANT_TESTS([
 ASN1_PKEY_ALIAS
 ASN1_PKEY_DYNAMIC
 ASN1_PKEY_SIGPARAM_NULL
 ASN1_PKEY_CTRL_PKCS7_SIGN
 ASN1_PKEY_CTRL_PKCS7_ENCRYPT
 ASN1_PKEY_CTRL_DEFAULT_MD_NID
 ASN1_PKEY_CTRL_CMS_SIGN
 ASN1_PKEY_CTRL_CMS_ENVELOPE])

VICARE_CONSTANT_TESTS([
 EVP_PKEY_OP_UNDEFINED
 EVP_PKEY_OP_PARAMGEN
 EVP_PKEY_OP_KEYGEN
 EVP_PKEY_OP_SIGN
 EVP_PKEY_OP_VERIFY
 EVP_PKEY_OP_VERIFYRECOVER
 EVP_PKEY_OP_SIGNCTX
 EVP_PKEY_OP_VERIFYCTX
 EVP_PKEY_OP_ENCRYPT
 EVP_PKEY_OP_DECRYPT
 EVP_PKEY_OP_DERIVE
 EVP_PKEY_OP_TYPE_SIG
 EVP_PKEY_OP_TYPE_CRYPT
 EVP_PKEY_OP_TYPE_NOGEN
 EVP_PKEY_OP_TYPE_GEN])

VICARE_CONSTANT_TESTS([
 EVP_PKEY_CTRL_MD
 EVP_PKEY_CTRL_PEER_KEY
 EVP_PKEY_CTRL_PKCS7_ENCRYPT
 EVP_PKEY_CTRL_PKCS7_DECRYPT
 EVP_PKEY_CTRL_PKCS7_SIGN
 EVP_PKEY_CTRL_SET_MAC_KEY
 EVP_PKEY_CTRL_DIGESTINIT
 EVP_PKEY_CTRL_SET_IV
 EVP_PKEY_CTRL_CMS_ENCRYPT
 EVP_PKEY_CTRL_CMS_DECRYPT
 EVP_PKEY_CTRL_CMS_SIGN
 EVP_PKEY_CTRL_CIPHER
 EVP_PKEY_ALG_CTRL
 EVP_PKEY_FLAG_AUTOARGLEN
 EVP_PKEY_FLAG_SIGCTX_CUSTOM])

VICARE_CONSTANT_TESTS([
 EVP_F_AESNI_INIT_KEY
 EVP_F_AESNI_XTS_CIPHER
 EVP_F_AES_INIT_KEY
 EVP_F_AES_XTS
 EVP_F_AES_XTS_CIPHER
 EVP_F_ALG_MODULE_INIT
 EVP_F_CAMELLIA_INIT_KEY
 EVP_F_CMAC_INIT
 EVP_F_D2I_PKEY
 EVP_F_DO_SIGVER_INIT
 EVP_F_DSAPKEY2PKCS8
 EVP_F_DSA_PKEY2PKCS8
 EVP_F_ECDSA_PKEY2PKCS8
 EVP_F_ECKEY_PKEY2PKCS8
 EVP_F_EVP_CIPHERINIT_EX
 EVP_F_EVP_CIPHER_CTX_COPY
 EVP_F_EVP_CIPHER_CTX_CTRL
 EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH
 EVP_F_EVP_DECRYPTFINAL_EX
 EVP_F_EVP_DIGESTINIT_EX
 EVP_F_EVP_ENCRYPTFINAL_EX
 EVP_F_EVP_MD_CTX_COPY_EX
 EVP_F_EVP_MD_SIZE
 EVP_F_EVP_OPENINIT
 EVP_F_EVP_PBE_ALG_ADD
 EVP_F_EVP_PBE_ALG_ADD_TYPE
 EVP_F_EVP_PBE_CIPHERINIT
 EVP_F_EVP_PKCS82PKEY
 EVP_F_EVP_PKCS82PKEY_BROKEN
 EVP_F_EVP_PKEY2PKCS8_BROKEN
 EVP_F_EVP_PKEY_COPY_PARAMETERS
 EVP_F_EVP_PKEY_CTX_CTRL
 EVP_F_EVP_PKEY_CTX_CTRL_STR
 EVP_F_EVP_PKEY_CTX_DUP
 EVP_F_EVP_PKEY_DECRYPT
 EVP_F_EVP_PKEY_DECRYPT_INIT
 EVP_F_EVP_PKEY_DECRYPT_OLD
 EVP_F_EVP_PKEY_DERIVE
 EVP_F_EVP_PKEY_DERIVE_INIT
 EVP_F_EVP_PKEY_DERIVE_SET_PEER
 EVP_F_EVP_PKEY_ENCRYPT
 EVP_F_EVP_PKEY_ENCRYPT_INIT
 EVP_F_EVP_PKEY_ENCRYPT_OLD
 EVP_F_EVP_PKEY_GET1_DH
 EVP_F_EVP_PKEY_GET1_DSA
 EVP_F_EVP_PKEY_GET1_ECDSA
 EVP_F_EVP_PKEY_GET1_EC_KEY
 EVP_F_EVP_PKEY_GET1_RSA
 EVP_F_EVP_PKEY_KEYGEN
 EVP_F_EVP_PKEY_KEYGEN_INIT
 EVP_F_EVP_PKEY_NEW
 EVP_F_EVP_PKEY_PARAMGEN
 EVP_F_EVP_PKEY_PARAMGEN_INIT
 EVP_F_EVP_PKEY_SIGN
 EVP_F_EVP_PKEY_SIGN_INIT
 EVP_F_EVP_PKEY_VERIFY
 EVP_F_EVP_PKEY_VERIFY_INIT
 EVP_F_EVP_PKEY_VERIFY_RECOVER
 EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT
 EVP_F_EVP_RIJNDAEL
 EVP_F_EVP_SIGNFINAL
 EVP_F_EVP_VERIFYFINAL
 EVP_F_FIPS_CIPHERINIT
 EVP_F_FIPS_CIPHER_CTX_COPY
 EVP_F_FIPS_CIPHER_CTX_CTRL
 EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH
 EVP_F_FIPS_DIGESTINIT
 EVP_F_FIPS_MD_CTX_COPY
 EVP_F_HMAC_INIT_EX
 EVP_F_INT_CTX_NEW
 EVP_F_PKCS5_PBE_KEYIVGEN
 EVP_F_PKCS5_V2_PBE_KEYIVGEN
 EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN
 EVP_F_PKCS8_SET_BROKEN
 EVP_F_PKEY_SET_TYPE
 EVP_F_RC2_MAGIC_TO_METH
 EVP_F_RC5_CTRL])

VICARE_CONSTANT_TESTS([
 EVP_R_AES_IV_SETUP_FAILED
 EVP_R_AES_KEY_SETUP_FAILED
 EVP_R_ASN1_LIB
 EVP_R_BAD_BLOCK_LENGTH
 EVP_R_BAD_DECRYPT
 EVP_R_BAD_KEY_LENGTH
 EVP_R_BN_DECODE_ERROR
 EVP_R_BN_PUBKEY_ERROR
 EVP_R_BUFFER_TOO_SMALL
 EVP_R_CAMELLIA_KEY_SETUP_FAILED
 EVP_R_CIPHER_PARAMETER_ERROR
 EVP_R_COMMAND_NOT_SUPPORTED
 EVP_R_CTRL_NOT_IMPLEMENTED
 EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED
 EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
 EVP_R_DECODE_ERROR
 EVP_R_DIFFERENT_KEY_TYPES
 EVP_R_DIFFERENT_PARAMETERS
 EVP_R_DISABLED_FOR_FIPS
 EVP_R_ENCODE_ERROR
 EVP_R_ERROR_LOADING_SECTION
 EVP_R_ERROR_SETTING_FIPS_MODE
 EVP_R_EVP_PBE_CIPHERINIT_ERROR
 EVP_R_EXPECTING_AN_RSA_KEY
 EVP_R_EXPECTING_A_DH_KEY
 EVP_R_EXPECTING_A_DSA_KEY
 EVP_R_EXPECTING_A_ECDSA_KEY
 EVP_R_EXPECTING_A_EC_KEY
 EVP_R_FIPS_MODE_NOT_SUPPORTED
 EVP_R_INITIALIZATION_ERROR
 EVP_R_INPUT_NOT_INITIALIZED
 EVP_R_INVALID_DIGEST
 EVP_R_INVALID_FIPS_MODE
 EVP_R_INVALID_KEY_LENGTH
 EVP_R_INVALID_OPERATION
 EVP_R_IV_TOO_LARGE
 EVP_R_KEYGEN_FAILURE
 EVP_R_MESSAGE_DIGEST_IS_NULL
 EVP_R_METHOD_NOT_SUPPORTED
 EVP_R_MISSING_PARAMETERS
 EVP_R_NO_CIPHER_SET
 EVP_R_NO_DEFAULT_DIGEST
 EVP_R_NO_DIGEST_SET
 EVP_R_NO_DSA_PARAMETERS
 EVP_R_NO_KEY_SET
 EVP_R_NO_OPERATION_SET
 EVP_R_NO_SIGN_FUNCTION_CONFIGURED
 EVP_R_NO_VERIFY_FUNCTION_CONFIGURED
 EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE
 EVP_R_OPERATON_NOT_INITIALIZED
 EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE
 EVP_R_PRIVATE_KEY_DECODE_ERROR
 EVP_R_PRIVATE_KEY_ENCODE_ERROR
 EVP_R_PUBLIC_KEY_NOT_RSA
 EVP_R_TOO_LARGE
 EVP_R_UNKNOWN_CIPHER
 EVP_R_UNKNOWN_DIGEST
 EVP_R_UNKNOWN_OPTION
 EVP_R_UNKNOWN_PBE_ALGORITHM
 EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS
 EVP_R_UNSUPPORTED_ALGORITHM
 EVP_R_UNSUPPORTED_CIPHER
 EVP_R_UNSUPPORTED_KEYLENGTH
 EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION
 EVP_R_UNSUPPORTED_KEY_SIZE
 EVP_R_UNSUPPORTED_PRF
 EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM
 EVP_R_UNSUPPORTED_SALT_TYPE
 EVP_R_WRONG_FINAL_BLOCK_LENGTH
 EVP_R_WRONG_PUBLIC_KEY_TYPE])

#page
#### C language stuff from the files "openssl/aes.h"

dnl AES
VICARE_CONSTANT_TESTS([AES_ENCRYPT AES_DECRYPT AES_BLOCK_SIZE])

dnl AES functions checking
AC_CHECK_FUNCS([AES_options AES_set_encrypt_key AES_set_decrypt_key AES_encrypt AES_decrypt AES_ecb_encrypt AES_cbc_encrypt AES_cfb128_encrypt AES_cfb1_encrypt AES_cfb8_encrypt AES_ofb128_encrypt AES_ctr128_encrypt AES_ige_encrypt AES_bi_ige_encrypt AES_wrap_key AES_unwrap_key ])

#page
#### miscellaneous features

dnl buffer functions checking
AC_CHECK_FUNCS([BUF_MEM_new BUF_MEM_free BUF_MEM_grow BUF_MEM_grow_clean BUF_strdup BUF_strndup BUF_memdup BUF_reverse BUF_strlcpy BUF_strlcat ERR_load_BUF_strings])

VICARE_CONSTANT_TESTS([
 BUF_F_BUF_MEMDUP
 BUF_F_BUF_MEM_GROW
 BUF_F_BUF_MEM_GROW_CLEAN
 BUF_F_BUF_MEM_NEW
 BUF_F_BUF_STRDUP
 BUF_F_BUF_STRNDUP])

#page
#### finish

VICARE_OUTPUT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile]
   [lib/vicare/crypto/openssl/constants.vicare.sls])
AC_OUTPUT

### end of file
# Local Variables:
# mode: autoconf
# page-delimiter: "^#page"
# End:
