VERSION = 1:1:0
VERSION_STR = 1.1.0

lib_LTLIBRARIES=ibmca-provider.la

ibmca_provider_la_SOURCES=p_ibmca.c p_key.c p_context.c \
			rsa_keymgmt.c rsa_asym_cipher.c rsa_padding.c \
			rsa_signature.c ec_keymgmt.c ec_signature.c

ibmca_provider_la_CFLAGS=-DIBMCA_VERSION=\"${VERSION_STR}\" -DIBMCA_LOGDIR=\"$(logdir)\"

if PROVIDER_FULL_LIBICA
ibmca_provider_la_LIBADD=-ldl -lica
else
ibmca_provider_la_LIBADD=-ldl -lica-cex
endif
ibmca_provider_la_LDFLAGS=-module -version-number ${VERSION} -shared -no-undefined \
		  -avoid-version -Wl,--version-script=${srcdir}/ibmca-provider.map

EXTRA_DIST = openssl.cnf.provider.sample ibmca-provider-opensslconfig

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc

noinst_SCRIPTS = ibmca-provider-opensslconfig

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(logdir)
	$(CHMOD) 0777 $(DESTDIR)$(logdir)
