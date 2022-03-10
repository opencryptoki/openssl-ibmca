#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# See autoconf and autoscan online documentation for details.

AC_INIT([openssl-ibmca], [2.2.3], [opencryptoki-users@lists.sf.net])
AC_CONFIG_SRCDIR([src/e_ibmca.c]) # sanity check
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])

# Cmdline arguments.
AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug], [turn on debugging flags (default is off)])],
		[enable_debug="yes"],)

if test "x$enable_debug" == "xyes"; then
	CFLAGS="$CFLAGS -O0 -g -DDEBUG -Wall"
	AC_MSG_RESULT([*** Enabling debugging at user request ***])
else
	CFLAGS="$CFLAGS -O2 -Wall"
fi

# Checks for programs.
AC_DISABLE_STATIC
AC_PROG_CC
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([crypto], [RAND_add], [], AC_MSG_ERROR([*** openssl >= 1.1.1 is required ***]))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stddef.h stdlib.h \
                 string.h strings.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADER([ica_api.h], [], AC_MSG_ERROR([*** libica-devel >= 3.6.0 is required ***]))


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyaddr gethostbyname memset strcasecmp strncasecmp strstr malloc])
AC_CHECK_DECLS([ICA_FLAG_DHW,DES_ECB], [],
		AC_MSG_ERROR([*** libica-devel >= 3.6.0 are required ***]),
		[#include <ica_api.h>])

AC_ARG_WITH([libica-cex],
	[AS_HELP_STRING([--with-libica-cex],[Use libica-cex as default library])],
	[usecexonly=${withval}],
	[])

AC_ARG_WITH([libica-version],
	[AS_HELP_STRING([--with-libica-version],[Use specified libica major version (defaults to 4)])],
	[libicaversion=${withval}],
	[libicaversion=4])

if test "x$usecexonly" = xyes; then
	defaultlib="libica-cex.so.$libicaversion"
	ica="ica-cex"
else
	defaultlib="libica.so.$libicaversion"
	ica="ica"
fi
# In cex-only mode, testing the ciphers does not make any sense since
# they will fall back to OpenSSL without the engine.  So remove these
# tests from that build.
AM_CONDITIONAL([FULL_LIBICA], [test "x$usecexonly" != xyes])

AC_DEFINE_UNQUOTED([LIBICA_SHARED_LIB],["$defaultlib"])
AC_SUBST([ICA],["$ica"])

AC_CHECK_PROG([openssl_var],[openssl],[yes],[no])
if test "x$openssl_var" != xyes; then
        AC_MSG_ERROR([openssl binary required]);
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/test/Makefile.linux
	test/Makefile
	src/doc/Makefile])

AC_OUTPUT

echo "CFLAGS=$CFLAGS"
echo "default library: $defaultlib"
