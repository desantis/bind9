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
	$(DNSTAP_CFLAGS)			\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	-DNAMED_LOCALSTATEDIR=\"${localstatedir}\" \
	-DNAMED_SYSCONFDIR=\"${sysconfdir}\"

sbin_PROGRAMS = named

nameddir = $(includedir)/named
named_HEADERS =				\
	include/named/builtin.h		\
	include/named/config.h		\
	include/named/control.h		\
	include/named/fuzz.h		\
	include/named/geoip.h		\
	include/named/globals.h		\
	include/named/log.h		\
	include/named/logconf.h		\
	include/named/main.h		\
	include/named/server.h		\
	include/named/smf_globals.h	\
	include/named/statschannel.h	\
	include/named/tkeyconf.h	\
	include/named/tsigconf.h	\
	include/named/types.h		\
	include/named/zoneconf.h

named_SOURCES =		\
	builtin.c	\
	config.c	\
	control.c	\
	controlconf.c	\
	fuzz.c		\
	log.c		\
	logconf.c	\
	main.c		\
	server.c	\
	statschannel.c	\
	tkeyconf.c	\
	tsigconf.c	\
	zoneconf.c	\
	unix/dlz_dlopen_driver.c	\
	unix/os.c	\
	$(named_HEADERS)

if HAVE_GEOIP
named_SOURCES +=	\
	geoip.c
endif

named_LDADD =					\
	$(top_builddir)/lib/libisc.la		\
	$(top_builddir)/lib/libbind9.la		\
	$(top_builddir)/lib/libdns.la		\
	$(top_builddir)/lib/libns.la		\
	$(top_builddir)/lib/libisccc.la		\
	$(top_builddir)/lib/libisccfg.la	\
	$(top_builddir)/libltdl/libltdlc.la	\
	$(OPENSSL_LIBS)				\
	$(LIBCAP_LIBS)				\
	$(DNSTAP_LIBS)
