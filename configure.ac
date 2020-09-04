AC_INIT([xpldd], [0.1.1], [calvin@cmpct.info], [])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CXX
dnl This is optional if someone wants to add boost:;fs
AX_CXX_COMPILE_STDCXX_17()

PKG_CHECK_MODULES([LIBELF], libelf)
AC_SUBST([LIBELF_CFLAGS])
AC_SUBST([LIBELF_LIBS])

AC_OUTPUT([Makefile])
