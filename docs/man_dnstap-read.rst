ISC
Internet Systems Consortium, Inc.
dnstap-read
1
BIND9
dnstap-read
print dnstap data in human-readable form
2015
2016
2017
2018
2019
Internet Systems Consortium, Inc. ("ISC")
dnstap-read
-m
-p
-x
-y
file
DESCRIPTION
===========

``dnstap-read`` reads ``dnstap`` data from a specified file and prints
it in a human-readable format. By default, ``dnstap`` data is printed in
a short summary format, but if the ``-y`` option is specified, then a
longer and more detailed YAML format is used instead.

OPTIONS
=======

-m
   Trace memory allocations; used for debugging memory leaks.

-p
   After printing the ``dnstap`` data, print the text form of the DNS
   message that was encapsulated in the ``dnstap`` frame.

-x
   After printing the ``dnstap`` data, print a hex dump of the wire form
   of the DNS message that was encapsulated in the ``dnstap`` frame.

-y
   Print ``dnstap`` data in a detailed YAML format.

SEE ALSO
========

named8, rndc8, BIND 9 Administrator Reference Manual.
