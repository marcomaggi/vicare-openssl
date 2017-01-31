;; libraries.scm --
;;
;;This file is meant  to be included by the build dependencies script,  so it must be
;;in the sources search path.

(define-constant INCLUDE-LIBRARY-BUILD-HIERARCHIES
  '((vicare crypto openssl)))

(define-constant INCLUDE-LIBRARY-DEPENDENCIES-HIERARCHIES
  '())

(define-constant INCLUDE-INSTALL-RULES
  #t)

;;These are the library files generated by the "configure" script starting from ".in"
;;models.
;;
(define-constant FROM-MODELS-SOURCE-FILES
  '("lib/vicare/crypto/openssl/constants.vicare.sls"))

;;These are the  library files generated by some automated  process; for example, the
;;"features"  program  that inspects  the  availability  of host  facilities  through
;;preprocessor constant generated by the GNU Autoconf infrastructure.
;;
(define-constant BUILT-SOURCE-FILES
  '("lib/vicare/crypto/openssl/features.vicare.sls"))

;;This is the table of libraries to compile.  The table is a list of entries:
;;
;;   (?entry ...)
;;
;;each ?ENTRY having one of the formats:
;;
;;   ((?want-feature ...) ?library-name ...)
;;
;;where: each ?WANT-FEATURE is a symbol  defined in the "configure.ac" model using
;;AM_CONDITIONAL  from the  GNU  Automake infrastructure;  ?LIBRARY-NAME  is an  R6RS
;;library name specification.   If no ?WANT-FEATURE is present: the  libraries are to
;;be always processed.
;;
(define-constant LIBRARIES-SPECS
  '((()
     (vicare crypto openssl)
     (vicare crypto openssl buffers cond-expand)
     (vicare crypto openssl unsafe-capi)
     (vicare crypto openssl constants)
     (vicare crypto openssl features)
     (vicare crypto openssl aes cond-expand)
     (vicare crypto openssl hmac cond-expand)
     (vicare crypto openssl message-digests)
     (vicare crypto openssl aes)
     (vicare crypto openssl message-digests cond-expand)
     (vicare crypto openssl cond-expand)
     (vicare crypto openssl hmac)
     (vicare crypto openssl helpers)
     (vicare crypto openssl buffers)
     (vicare crypto openssl evp ciphers)
     (vicare crypto openssl evp ciphers cond-expand)
     (vicare crypto openssl evp message-digests)
     (vicare crypto openssl evp message-digests cond-expand)
     )))

;;; end of file
;; Local Variables:
;; mode: vicare
;; End: