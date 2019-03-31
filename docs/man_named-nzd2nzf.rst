May 5, 2016
named-nzd2nzf
8
BIND9
named-nzd2nzf
Convert an NZD database to NZF text format
2016
2018
2019
Internet Systems Consortium, Inc. ("ISC")
named-nzd2nzf
filename
DESCRIPTION
===========

``named-nzd2nzf`` converts an NZD database to NZF format and prints it
to standard output. This can be used to review the configuration of
zones that were added to ``named`` via ``rndc addzone``. It can also be
used to restore the old file format when rolling back from a newer
version of BIND to an older version.

ARGUMENTS
=========

filename
   The name of the ``.nzd`` file whose contents should be printed.

SEE ALSO
========

BIND 9 Administrator Reference Manual

AUTHOR
======

Internet Systems Consortium
