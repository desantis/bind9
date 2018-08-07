ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I$(srcdir)/include/			\
	-I$(srcdir)/unix/include		\
	-I$(top_srcdir)/lib/isc/unix/include	\
	-I$(top_srcdir)/lib/isc/pthreads/include\
	-I$(top_srcdir)/lib/isc/include		\
	-I$(top_srcdir)/lib/isccc/include	\
	-I$(top_srcdir)/lib/dns/include		\
	-I$(top_srcdir)/lib/ns/include		\
	-I$(top_srcdir)/lib/isccfg/include	\
	-I$(top_srcdir)/lib/irs/include		\
	-I$(top_srcdir)/lib/bind9/include	\
	$(LIBIDN2_CFLAGS)			\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)

LDADD =				\
	libdighost.la			\
	${top_builddir}/lib/libisc.la	\
	${top_builddir}/lib/libirs.la	\
	${top_builddir}/lib/libdns.la	\
	${top_builddir}/lib/libisccfg.la\
	${top_builddir}/lib/libbind9.la	\
	$(LIBIDN2_LIBS)			\
	$(OPENSSL_LIBS)

noinst_LTLIBRARIES = libdighost.la

libdighost_la_SOURCES = \
	dighost.h	\
	dighost.c

bin_PROGRAMS = dig host nslookup

nslookup_LDADD = 	\
	$(LDADD)	\
	$(READLINE_LIB)
