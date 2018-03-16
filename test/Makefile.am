TESTS = \
des-ecb-test.pl \
des-cbc-test.pl \
des-cfb-test.pl \
des-ofb-test.pl \
3des-ecb-test.pl \
3des-cbc-test.pl \
3des-cfb-test.pl \
3des-ofb-test.pl \
aes-128-ecb-test.pl \
aes-128-cbc-test.pl \
aes-128-cfb-test.pl \
aes-128-ofb-test.pl \
aes-192-ecb-test.pl \
aes-192-cbc-test.pl \
aes-192-cfb-test.pl \
aes-192-ofb-test.pl \
aes-256-ecb-test.pl \
aes-256-cbc-test.pl \
aes-256-cfb-test.pl \
aes-256-ofb-test.pl

AM_TESTS_ENVIRONMENT = export IBMCA_TEST_PATH=${top_builddir}/src/.libs/ibmca.so IBMCA_OPENSSL_TEST_CONF=${srcdir}/openssl-test.cnf PERL5LIB=${srcdir};
EXTRA_DIST = ${TESTS} test.pm openssl-test.cnf
