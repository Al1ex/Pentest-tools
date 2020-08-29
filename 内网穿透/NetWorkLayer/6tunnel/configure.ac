AC_INIT([6tunnel],[0.13],[])
AM_INIT_AUTOMAKE([1.14 foreign silent-rules subdir-objects tar-pax])
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PATH_PROG(STRIP, strip, :)

test -d /usr/local/v6/lib && LIBS="$LIBS -L/usr/local/v6/lib"
test -d /usr/inet6/lib && LIBS="$LIBS -L/usr/inet6/lib"
test -d /usr/local/inet6/lib && LIBS="$LIBS -L/usr/local/inet6/lib"

AC_CHECK_LIB(nsl, t_accept, LIBS="$LIBS -lnsl")
AC_CHECK_LIB(socket, socket, LIBS="$LIBS -lsocket")
AC_CHECK_LIB(inet6, main, LIBS="$LIBS -linet6")

AC_STDC_HEADERS
AC_HAVE_HEADERS(sys/socket.h netinet/in.h arpa/inet.h netdb.h, , AC_MSG_ERROR([Socket related headers missing.]))
AC_CHECK_FUNCS(getaddrinfo, , AC_MSG_ERROR([Your system doesn't support IPv6.]))

AC_MSG_CHECKING([for AF_INET6])
AC_TRY_COMPILE([#include <sys/socket.h>], [int x = AF_INET6;], [
	AC_MSG_RESULT(yes)
], [
	AC_MSG_RESULT(no)
	AC_MSG_ERROR([Your system doesn't support IPv6.])
])

AC_SUBST(VERSION)
VERSION=`grep '6tunnel v' 6tunnel.c | sed 's/.*v//'`

AC_CONFIG_FILES([
        Makefile
])

AC_OUTPUT

