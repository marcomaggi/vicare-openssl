## Process this file with automake to produce Makefile.in

EXTRA_DIST	= \
	vicare/crypto/openssl/constants.sls.in

# These files are hand-written.
nobase_dist_libvicare_DATA = \
	vicare/crypto/openssl.sls				\
	vicare/crypto/openssl/unsafe-capi.sls			\
	vicare/crypto/openssl/helpers.sls			\
	\
	vicare/crypto/openssl/evp/ciphers.sls			\
	vicare/crypto/openssl/evp/message-digests.sls		\
	vicare/crypto/openssl/evp/message-digests/cond-expand.sls	\
	\
	vicare/crypto/openssl/message-digests.sls		\
	vicare/crypto/openssl/message-digests/cond-expand.sls	\
	vicare/crypto/openssl/hmac.sls				\
	vicare/crypto/openssl/hmac/cond-expand.sls		\
	vicare/crypto/openssl/aes.sls				\
	vicare/crypto/openssl/aes/cond-expand.sls

# These files are created at configuration or make time.
nobase_nodist_libvicare2_DATA = \
	vicare/crypto/openssl/constants.sls		\
	vicare/crypto/openssl/features.sls

# if WANT_NAUSICAA
# nobase_dist_libvicare_DATA	+= nausicaa/crypto/openssl.vicare.sls
# endif

VICARE_LIB_INFIX	= crypto/openssl

include $(top_srcdir)/meta/makefiles/lib.am

### end of file
