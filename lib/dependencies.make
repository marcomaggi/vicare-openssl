## dependencies.make --
#
# Automatically built.

EXTRA_DIST +=  \
	lib/vicare/crypto/openssl/constants.vicare.sls.in

lib/vicare/crypto/openssl.fasl: \
		lib/vicare/crypto/openssl.vicare.sls \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_fasldir = $(bundledlibsdir)/vicare/crypto
lib_vicare_crypto_openssl_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto
nodist_lib_vicare_crypto_openssl_fasl_DATA = lib/vicare/crypto/openssl.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_vicare_sls_DATA = lib/vicare/crypto/openssl.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl.fasl

lib/vicare/crypto/openssl/unsafe-capi.fasl: \
		lib/vicare/crypto/openssl/unsafe-capi.vicare.sls \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_unsafe_capi_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_unsafe_capi_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_unsafe_capi_fasl_DATA = lib/vicare/crypto/openssl/unsafe-capi.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_unsafe_capi_vicare_sls_DATA = lib/vicare/crypto/openssl/unsafe-capi.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/unsafe-capi.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/unsafe-capi.fasl

lib/vicare/crypto/openssl/buffers/cond-expand.fasl: \
		lib/vicare/crypto/openssl/buffers/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/buffers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_buffers_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/buffers
lib_vicare_crypto_openssl_buffers_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/buffers
nodist_lib_vicare_crypto_openssl_buffers_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/buffers/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_buffers_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/buffers/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/buffers/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/buffers/cond-expand.fasl

lib/vicare/crypto/openssl/features.fasl: \
		lib/vicare/crypto/openssl/features.vicare.sls \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_features_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_features_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_features_fasl_DATA = lib/vicare/crypto/openssl/features.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_features_vicare_sls_DATA = lib/vicare/crypto/openssl/features.vicare.sls
endif
CLEANFILES += lib/vicare/crypto/openssl/features.fasl

lib/vicare/crypto/openssl/buffers.fasl: \
		lib/vicare/crypto/openssl/buffers.vicare.sls \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_buffers_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_buffers_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_buffers_fasl_DATA = lib/vicare/crypto/openssl/buffers.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_buffers_vicare_sls_DATA = lib/vicare/crypto/openssl/buffers.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/buffers.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/buffers.fasl

lib/vicare/crypto/openssl/constants.fasl: \
		lib/vicare/crypto/openssl/constants.vicare.sls \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_constants_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_constants_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_constants_fasl_DATA = lib/vicare/crypto/openssl/constants.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_constants_vicare_sls_DATA = lib/vicare/crypto/openssl/constants.vicare.sls
endif
CLEANFILES += lib/vicare/crypto/openssl/constants.fasl

lib/vicare/crypto/openssl/aes/cond-expand.fasl: \
		lib/vicare/crypto/openssl/aes/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/aes.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_aes_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/aes
lib_vicare_crypto_openssl_aes_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/aes
nodist_lib_vicare_crypto_openssl_aes_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/aes/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_aes_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/aes/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/aes/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/aes/cond-expand.fasl

lib/vicare/crypto/openssl/aes.fasl: \
		lib/vicare/crypto/openssl/aes.vicare.sls \
		lib/vicare/crypto/openssl/constants.fasl \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		lib/vicare/crypto/openssl/helpers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_aes_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_aes_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_aes_fasl_DATA = lib/vicare/crypto/openssl/aes.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_aes_vicare_sls_DATA = lib/vicare/crypto/openssl/aes.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/aes.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/aes.fasl

lib/vicare/crypto/openssl/helpers.fasl: \
		lib/vicare/crypto/openssl/helpers.vicare.sls \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_helpers_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_helpers_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_helpers_fasl_DATA = lib/vicare/crypto/openssl/helpers.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_helpers_vicare_sls_DATA = lib/vicare/crypto/openssl/helpers.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/helpers.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/helpers.fasl

lib/vicare/crypto/openssl/hmac/cond-expand.fasl: \
		lib/vicare/crypto/openssl/hmac/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/hmac.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_hmac_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/hmac
lib_vicare_crypto_openssl_hmac_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/hmac
nodist_lib_vicare_crypto_openssl_hmac_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/hmac/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_hmac_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/hmac/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/hmac/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/hmac/cond-expand.fasl

lib/vicare/crypto/openssl/hmac.fasl: \
		lib/vicare/crypto/openssl/hmac.vicare.sls \
		lib/vicare/crypto/openssl/constants.fasl \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/evp/message-digests.fasl \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		lib/vicare/crypto/openssl/helpers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_hmac_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_hmac_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_hmac_fasl_DATA = lib/vicare/crypto/openssl/hmac.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_hmac_vicare_sls_DATA = lib/vicare/crypto/openssl/hmac.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/hmac.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/hmac.fasl

lib/vicare/crypto/openssl/evp/message-digests.fasl: \
		lib/vicare/crypto/openssl/evp/message-digests.vicare.sls \
		lib/vicare/crypto/openssl/constants.fasl \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		lib/vicare/crypto/openssl/helpers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_evp_message_digests_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/evp
lib_vicare_crypto_openssl_evp_message_digests_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/evp
nodist_lib_vicare_crypto_openssl_evp_message_digests_fasl_DATA = lib/vicare/crypto/openssl/evp/message-digests.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_evp_message_digests_vicare_sls_DATA = lib/vicare/crypto/openssl/evp/message-digests.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/evp/message-digests.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/evp/message-digests.fasl

lib/vicare/crypto/openssl/message-digests.fasl: \
		lib/vicare/crypto/openssl/message-digests.vicare.sls \
		lib/vicare/crypto/openssl/constants.fasl \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		lib/vicare/crypto/openssl/helpers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_message_digests_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_message_digests_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_message_digests_fasl_DATA = lib/vicare/crypto/openssl/message-digests.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_message_digests_vicare_sls_DATA = lib/vicare/crypto/openssl/message-digests.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/message-digests.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/message-digests.fasl

lib/vicare/crypto/openssl/message-digests/cond-expand.fasl: \
		lib/vicare/crypto/openssl/message-digests/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/message-digests.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_message_digests_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/message-digests
lib_vicare_crypto_openssl_message_digests_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/message-digests
nodist_lib_vicare_crypto_openssl_message_digests_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/message-digests/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_message_digests_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/message-digests/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/message-digests/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/message-digests/cond-expand.fasl

lib/vicare/crypto/openssl/cond-expand.fasl: \
		lib/vicare/crypto/openssl/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl
lib_vicare_crypto_openssl_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl
nodist_lib_vicare_crypto_openssl_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/cond-expand.fasl

lib/vicare/crypto/openssl/evp/ciphers.fasl: \
		lib/vicare/crypto/openssl/evp/ciphers.vicare.sls \
		lib/vicare/crypto/openssl/constants.fasl \
		lib/vicare/crypto/openssl/unsafe-capi.fasl \
		lib/vicare/crypto/openssl/helpers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_evp_ciphers_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/evp
lib_vicare_crypto_openssl_evp_ciphers_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/evp
nodist_lib_vicare_crypto_openssl_evp_ciphers_fasl_DATA = lib/vicare/crypto/openssl/evp/ciphers.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_evp_ciphers_vicare_sls_DATA = lib/vicare/crypto/openssl/evp/ciphers.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/evp/ciphers.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/evp/ciphers.fasl

lib/vicare/crypto/openssl/evp/ciphers/cond-expand.fasl: \
		lib/vicare/crypto/openssl/evp/ciphers/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/evp/ciphers.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_evp_ciphers_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/evp/ciphers
lib_vicare_crypto_openssl_evp_ciphers_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/evp/ciphers
nodist_lib_vicare_crypto_openssl_evp_ciphers_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/evp/ciphers/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_evp_ciphers_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/evp/ciphers/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/evp/ciphers/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/evp/ciphers/cond-expand.fasl

lib/vicare/crypto/openssl/evp/message-digests/cond-expand.fasl: \
		lib/vicare/crypto/openssl/evp/message-digests/cond-expand.vicare.sls \
		lib/vicare/crypto/openssl/features.fasl \
		lib/vicare/crypto/openssl/evp/message-digests.fasl \
		$(FASL_PREREQUISITES)
	$(VICARE_COMPILE_RUN) --output $@ --compile-library $<

lib_vicare_crypto_openssl_evp_message_digests_cond_expand_fasldir = $(bundledlibsdir)/vicare/crypto/openssl/evp/message-digests
lib_vicare_crypto_openssl_evp_message_digests_cond_expand_vicare_slsdir  = $(bundledlibsdir)/vicare/crypto/openssl/evp/message-digests
nodist_lib_vicare_crypto_openssl_evp_message_digests_cond_expand_fasl_DATA = lib/vicare/crypto/openssl/evp/message-digests/cond-expand.fasl
if WANT_INSTALL_SOURCES
dist_lib_vicare_crypto_openssl_evp_message_digests_cond_expand_vicare_sls_DATA = lib/vicare/crypto/openssl/evp/message-digests/cond-expand.vicare.sls
endif
EXTRA_DIST += lib/vicare/crypto/openssl/evp/message-digests/cond-expand.vicare.sls
CLEANFILES += lib/vicare/crypto/openssl/evp/message-digests/cond-expand.fasl


### end of file
# Local Variables:
# mode: makefile-automake
# End:
