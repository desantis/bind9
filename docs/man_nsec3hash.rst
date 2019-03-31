ISC
Internet Systems Consortium, Inc.
nsec3hash
8
BIND9
nsec3hash
generate NSEC3 hash
2009
2014
2015
2016
2017
2018
2019
Internet Systems Consortium, Inc. ("ISC")
nsec3hash
salt
algorithm
iterations
domain
nsec3hash -r
algorithm
flags
iterations
salt
domain
DESCRIPTION
===========

``nsec3hash`` generates an NSEC3 hash based on a set of NSEC3
parameters. This can be used to check the validity of NSEC3 records in a
signed zone.

If this command is invoked as ``nsec3hash -r``, it takes arguments in an
order matching the first four fields of an NSEC3 record, followed by the
domain name: algorithm, flags, iterations, salt, domain. This makes it
convenient to copy and paste a portion of an NSEC3 or NSEC3PARAM record
into a command line to confirm the correctness of an NSEC3 hash.

ARGUMENTS
=========

salt
   The salt provided to the hash algorithm.

algorithm
   A number indicating the hash algorithm. Currently the only supported
   hash algorithm for NSEC3 is SHA-1, which is indicated by the number
   1; consequently "1" is the only useful value for this argument.

flags
   Provided for compatibility with NSEC3 record presentation format, but
   ignored since the flags do not affect the hash.

iterations
   The number of additional times the hash should be performed.

domain
   The domain name to be hashed.

SEE ALSO
========

BIND 9 Administrator Reference Manual, RFC 5155.
