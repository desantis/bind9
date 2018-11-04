dnl This file must follow autoconf m4 rules.  It is imported directly via
dnl autoconf.
dnl DESCRIPTION="(Development Release)"
dnl MAJORVER=9
dnl MINORVER=15
dnl PATCHVER=0
dnl RELEASETYPE=
dnl RELEASEVER=
dnl EXTENSIONS=

m4_define([bind_VERSION_MAJOR], 9)dnl
m4_define([bind_VERSION_MINOR], 15)dnl
m4_define([bind_VERSION_PATCH], 0)dnl
m4_define([bind_VERSION_EXTRA], -dev)dnl
m4_define([bind_DESCRIPTION], [(Development Release)])dnl
m4_define([bind_SRCID], [m4_esyscmd_s([if test -f srcid; then cat srcid; else git rev-parse --short HEAD 2>/dev/null; fi])])dnl

m4_define([bind_PKG_VERSION], [[bind_VERSION_MAJOR.bind_VERSION_MINOR.bind_VERSION_PATCH]bind_VERSION_EXTRA])dnl

AC_DEFUN([AX_PACKAGE_DESCRIPTION],
	 [AC_DEFINE([PACKAGE_DESCRIPTION],
		    [m4_ifnblank(bind_DESCRIPTION, [" ]bind_DESCRIPTION["], [])],
		    [An extra string to print after PACKAGE_STRING])
	  PACKAGE_DESCRIPTION=["]bind_DESCRIPTION["]
	  AC_SUBST([PACKAGE_DESCRIPTION])
	 ])

AC_DEFUN([AX_PACKAGE_SRCID],
	 [AC_DEFINE([PACKAGE_SRCID], ["][bind_SRCID]["], [A short hash from git])
	  PACKAGE_SRCID=["]bind_SRCID["]
	  AC_SUBST([PACKAGE_SRCID])
	 ])
