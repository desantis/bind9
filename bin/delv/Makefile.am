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
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	-DSYSCONFDIR=\"${sysconfdir}\"

bin_PROGRAMS = delv

delv_SOURCES =			\
	delv.c
delv_CFLAGS = $(LIBIDN2_CFLAGS)
delv_LDADD =				\
	${top_builddir}/lib/libisc.la	\
	${top_builddir}/lib/libirs.la	\
	${top_builddir}/lib/libdns.la	\
	${top_builddir}/lib/libisccfg.la\
	$(LIBIDN2_LIBS)
