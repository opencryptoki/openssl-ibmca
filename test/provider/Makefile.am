TESTS_PERL = \
tls.pl		\
ecsign.pl	\
ecderive.pl	\
dhderive.pl	\
rsa512.pl	\
rsa1k.pl	\
rsa2k.pl	\
rsa4k.pl	\
rsa8k.pl	\
rsa16k.pl

TESTS = \
	rsakey		\
	eckey		\
	dhkey		\
	threadtest	\
	${TESTS_PERL}

check_PROGRAMS = rsakey eckey dhkey threadtest

dhkey_SOURCES = dhkey.c
dhkey_LDADD = -lcrypto

eckey_SOURCES = eckey.c
eckey_LDADD = -lcrypto

rsakey_SOURCES = rsakey.c
rsakey_LDADD = -lcrypto

threadtest_SOURCES = threadtest.c
threadtest_LDADD = -lcrypto -lpthread

AM_TESTS_ENVIRONMENT = export IBMCA_TEST_PATH=${top_builddir}/src/provider/.libs/ IBMCA_OPENSSL_TEST_CONF=${srcdir}/openssl-test.cnf PERL5LIB=${srcdir};
EXTRA_DIST = ${TESTS_PERL} test.pm openssl-test.cnf server-cert-rsa.pem server-key-rsa.pem server-cert-ec.pem server-key-ec.pem
