.. Troubleshooting:

Troubleshooting
===============

.. _common_problems:

Common Problems
---------------

It's not working; how can I figure out what's wrong?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The best solution to solving installation and configuration issues is to
take preventative measures by setting up logging files beforehand. The
log files provide a source of hints and information that can be used to
figure out what went wrong and how to fix the problem.

EDNS compliance issues
~~~~~~~~~~~~~~~~~~~~~~

EDNS (Extended DNS) is a standard that was first specified in 1999. It
is required for DNSSEC validation, DNS COOKIE options, and other
features. There are broken and outdated DNS servers and firewalls still
in use which misbehave when queried with EDNS; for example, they may
drop EDNS queries rather than replying with FORMERR. BIND and other
recursive name servers have traditionally employed workarounds in this
situation, retrying queries in different ways and eventually falling
back to plain DNS queries without EDNS.

Such workarounds cause unnecessary resolution delays, increase code
complexity, and prevent deployment of new DNS features. As of February
2019, all major DNS software vendors have agreed to remove these
workarounds; see https://dnsflagday.net for further details. This change
was implemented in BIND as of release 9.14.0.

As a result, some domains may be non-resolvable without manual
intervention. In these cases, resolution can be restored by adding
``server`` clauses for the offending servers, specifying ``edns no`` or
``send-cookie no``, depending on the specific noncompliance.

To determine which ``server`` clause to use, run the following commands
to send queries to the authoritative servers for the broken domain:

::

           dig soa <zone> @<server> +dnssec
           dig soa <zone> @<server> +dnssec +nocookie
           dig soa <zone> @<server> +noedns
     

If the first command fails but the second succeeds, the server most
likely needs ``send-cookie no``. If the first two fail but the third
succeeds, then the server needs EDNS to be fully disabled with
``edns no``.

Please contact the administrators of noncompliant domains and encourage
them to upgrade their broken DNS servers.

Incrementing and Changing the Serial Number
-------------------------------------------

Zone serial numbers are just numbers — they aren't date related. A lot
of people set them to a number that represents a date, usually of the
form YYYYMMDDRR. Occasionally they will make a mistake and set them to a
"date in the future" then try to correct them by setting them to the
"current date". This causes problems because serial numbers are used to
indicate that a zone has been updated. If the serial number on the slave
server is lower than the serial number on the master, the slave server
will attempt to update its copy of the zone.

Setting the serial number to a lower number on the master server than
the slave server means that the slave will not perform updates to its
copy of the zone.

The solution to this is to add 2147483647 (2^31-1) to the number, reload
the zone and make sure all slaves have updated to the new zone serial
number, then reset the number to what you want it to be, and reload the
zone again.

.. _more_help:

Where Can I Get Help?
---------------------

The Internet Systems Consortium (ISC) offers a wide range of support and
service agreements for BIND and DHCP servers. Four levels of premium
support are available and each level includes support for all ISC
programs, significant discounts on products and training, and a
recognized priority on bug fixes and non-funded feature requests. In
addition, ISC offers a standard support agreement package which includes
services ranging from bug fix announcements to remote support. It also
includes training in BIND and DHCP.

To discuss arrangements for support, contact info@isc.org or visit the
ISC web page at http://www.isc.org/services/support/ to read more.
