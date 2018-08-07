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
	-DRNDC_KEYFILE=\"${sysconfdir}/rndc.key\"

LDADD =					\
	libconfgen.la			\
	${top_builddir}/lib/libisc.la	\
	${top_builddir}/lib/libdns.la

noinst_LTLIBRARIES = libconfgen.la

libconfgen_la_SOURCES =		\
	include/confgen/os.h	\
	keygen.h		\
	keygen.c		\
	util.h			\
	util.c			\
	unix/os.c

bin_PROGRAMS = rndc-confgen ddns-confgen
