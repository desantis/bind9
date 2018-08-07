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
	$(OPENSSL_INCLUDES)			\
	-DNAMED_CONFFILE=\"${sysconfdir}/named.conf\"

noinst_LTLIBRARIES = libcheck-tool.la

libcheck_tool_la_SOURCES =	\
	check-tool.h		\
	check-tool.c

LDADD =					\
	libcheck-tool.la			\
	${top_builddir}/lib/libisc.la	\
	${top_builddir}/lib/libirs.la	\
	${top_builddir}/lib/libdns.la	\
	${top_builddir}/lib/libns.la	\
	${top_builddir}/lib/libisccfg.la\
	${top_builddir}/lib/libbind9.la	\
	$(LIBIDN2_LIBS)

bin_PROGRAMS = named-checkconf named-checkzone
