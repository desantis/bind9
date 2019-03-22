ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I$(top_srcdir)/lib/isc/unix/include	\
	-I$(top_srcdir)/lib/isc/pthreads/include\
	-I$(top_srcdir)/lib/isc/include		\
	-I$(top_srcdir)/lib/dns/include

check_LTLIBRARIES = sample.la

checkdir = $(libdir)/named

sample_la_SOURCES =	\
	db.c		\
	driver.c	\
	instance.c	\
	lock.c		\
	log.c		\
	syncptr.c	\
	zone.c
sample_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
