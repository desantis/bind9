AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I../unix/include			\
	-I../pthreads/include			\
	-I../include				\
	-DTESTS=\"$(abs_srcdir)\"		\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	$(CMOCKA_CFLAGS)

AM_LDFLAGS = \
	../../libisc.la	\
	libisctest.la \
	$(OPENSSL_LIBS)	\
	$(CMOCKA_LIBS)

noinst_LTLIBRARIES = libisctest.la
libisctest_la_SOURCES = isctest.c isctest.h
libisctest_la_LDFLAGS =

check_PROGRAMS = \
	aes_test \
	buffer_test \
	counter_test \
	crc64_test \
	errno_test \
	file_test \
	hash_test \
	heap_test \
	hmac_test \
	ht_test \
	lex_test \
	md_test \
	mem_test \
	netaddr_test \
	parse_test \
	pool_test \
	queue_test \
	radix_test \
	random_test \
	regex_test \
	result_test \
	safe_test \
	sockaddr_test \
	socket_test \
	symtab_test \
	task_test \
	taskpool_test \
	time_test \
	timer_test

TESTS = $(check_PROGRAMS)
