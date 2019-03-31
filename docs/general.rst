.. General:

General DNS Reference Information
=================================

.. _ipv6addresses:

IPv6 addresses (AAAA)
---------------------

IPv6 addresses are 128-bit identifiers for interfaces and sets of
interfaces which were introduced in the DNS to facilitate scalable
Internet routing. There are three types of addresses: *Unicast*, an
identifier for a single interface; *Anycast*, an identifier for a set of
interfaces; and *Multicast*, an identifier for a set of interfaces. Here
we describe the global Unicast address scheme. For more information, see
RFC 3587, "Global Unicast Address Format."

IPv6 unicast addresses consist of a *global routing prefix*, a *subnet
identifier*, and an *interface identifier*.

The global routing prefix is provided by the upstream provider or ISP,
and (roughly) corresponds to the IPv4 *network* section of the address
range. The subnet identifier is for local subnetting, much the same as
subnetting an IPv4 /16 network into /24 subnets. The interface
identifier is the address of an individual interface on a given network;
in IPv6, addresses belong to interfaces rather than to machines.

The subnetting capability of IPv6 is much more flexible than that of
IPv4: subnetting can be carried out on bit boundaries, in much the same
way as Classless InterDomain Routing (CIDR), and the DNS PTR
representation ("nibble" format) makes setting up reverse zones easier.

The Interface Identifier must be unique on the local link, and is
usually generated automatically by the IPv6 implementation, although it
is usually possible to override the default setting if necessary. A
typical IPv6 address might look like:
``2001:db8:201:9:a00:20ff:fe81:2b32``

IPv6 address specifications often contain long strings of zeros, so the
architects have included a shorthand for specifying them. The double
colon (`::') indicates the longest possible string of zeros that can
fit, and can be used only once in an address.

.. _bibliography:

Bibliography (and Suggested Reading)
------------------------------------

.. _rfcs:

Request for Comments (RFCs)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Specification documents for the Internet protocol suite, including the
DNS, are published as part of the Request for Comments (RFCs) series of
technical notes. The standards themselves are defined by the Internet
Engineering Task Force (IETF) and the Internet Engineering Steering
Group (IESG). RFCs can be obtained online via FTP at:

`ftp://www.isi.edu/in-notes/RFCxxxx.txt <ftp://www.isi.edu/in-notes/>`__

(where xxxx is the number of the RFC). RFCs are also available via the
Web at:

http://www.ietf.org/rfc/.

Standards
---------

RFC974 PartridgeC. Mail Routing and the Domain System January 1986

RFC1034 MockapetrisP.V. Domain Names — Concepts and Facilities November
1987

RFC1035 MockapetrisP. V. Domain Names — Implementation and Specification
November 1987

.. _proposed_standards:

Proposed Standards
------------------

RFC2181 ElzR., R. Bush Clarifications to the DNS Specification July 1997

RFC2308 AndrewsM. Negative Caching of DNS Queries March 1998

RFC1995 OhtaM. Incremental Zone Transfer in DNS August 1996

RFC1996 VixieP. A Mechanism for Prompt Notification of Zone Changes
August 1996

RFC2136 VixieP. S.Thomson Y.Rekhter J.Bound Dynamic Updates in the
Domain Name System April 1997

RFC2671 P.Vixie Extension Mechanisms for DNS (EDNS0) August 1997

RFC2672 M.Crawford Non-Terminal DNS Name Redirection August 1999

RFC2845 VixieP. O.Gudmundsson D.Eastlake3rd B.Wellington Secret Key
Transaction Authentication for DNS (TSIG) May 2000

RFC2930 D.Eastlake3rd Secret Key Establishment for DNS (TKEY RR)
September 2000

RFC2931 D.Eastlake3rd DNS Request and Transaction Signatures (SIG(0)s)
September 2000

RFC3007 B.Wellington Secure Domain Name System (DNS) Dynamic Update
November 2000

RFC3645 S.Kwan P.Garg J.Gilroy L.Esibov J.Westhead R.Hall Generic
Security Service Algorithm for Secret Key Transaction Authentication for
DNS (GSS-TSIG) October 2003

DNS Security Proposed Standards
-------------------------------

RFC3225 D.Conrad Indicating Resolver Support of DNSSEC December 2001

RFC3833 D.Atkins R.Austein Threat Analysis of the Domain Name System
(DNS) August 2004

RFC4033 R.Arends R.Austein M.Larson D.Massey S.Rose DNS Security
Introduction and Requirements March 2005

RFC4034 R.Arends R.Austein M.Larson D.Massey S.Rose Resource Records for
the DNS Security Extensions March 2005

RFC4035 R.Arends R.Austein M.Larson D.Massey S.Rose Protocol
Modifications for the DNS Security Extensions March 2005

Other Important RFCs About DNS Implementation
---------------------------------------------

RFC1535 GavronE. A Security Problem and Proposed Correction With Widely
Deployed DNS Software October 1993

RFC1536 KumarA. J.Postel C.Neuman P.Danzig S.Miller Common DNS
Implementation Errors and Suggested Fixes October 1993

RFC1982 ElzR. R.Bush Serial Number Arithmetic August 1996

RFC4074 MorishitaY. T.Jinmei Common Misbehaviour Against DNS Queries for
IPv6 Addresses May 2005

Resource Record Types
---------------------

RFC1183 EverhartC.F. L. A.Mamakos R.Ullmann P.Mockapetris New DNS RR
Definitions October 1990

RFC1706 ManningB. R.Colella DNS NSAP Resource Records October 1994

RFC2168 DanielR. M.Mealling Resolution of Uniform Resource Identifiers
using the Domain Name System June 1997

RFC1876 DavisC. P.Vixie T.Goodwin I.Dickinson A Means for Expressing
Location Information in the Domain Name System January 1996

RFC2052 GulbrandsenA. P.Vixie A DNS RR for Specifying the Location of
Services October 1996

RFC2163 AllocchioA. Using the Internet DNS to Distribute MIXER
Conformant Global Address Mapping January 1998

RFC2230 AtkinsonR. Key Exchange Delegation Record for the DNS October
1997

RFC2536 EastlakeD.3rd DSA KEYs and SIGs in the Domain Name System (DNS)
March 1999

RFC2537 EastlakeD.3rd RSA/MD5 KEYs and SIGs in the Domain Name System
(DNS) March 1999

RFC2538 EastlakeD.3rd GudmundssonO. Storing Certificates in the Domain
Name System (DNS) March 1999

RFC2539 EastlakeD.3rd Storage of Diffie-Hellman Keys in the Domain Name
System (DNS) March 1999

RFC2540 EastlakeD.3rd Detached Domain Name System (DNS) Information
March 1999

RFC2782 GulbrandsenA. VixieP. EsibovL. A DNS RR for specifying the
location of services (DNS SRV) February 2000

RFC2915 MeallingM. DanielR. The Naming Authority Pointer (NAPTR) DNS
Resource Record September 2000

RFC3110 EastlakeD.3rd RSA/SHA-1 SIGs and RSA KEYs in the Domain Name
System (DNS) May 2001

RFC3123 KochP. A DNS RR Type for Lists of Address Prefixes (APL RR) June
2001

RFC3596 ThomsonS. C.Huitema V.Ksinant M.Souissi DNS Extensions to
support IP version 6 October 2003

RFC3597 GustafssonA. Handling of Unknown DNS Resource Record (RR) Types
September 2003

DNS and the Internet
--------------------

RFC1101 MockapetrisP. V. DNS Encoding of Network Names and Other Types
April 1989

RFC1123 BradenR. Requirements for Internet Hosts - Application and
Support October 1989

RFC1591 PostelJ. Domain Name System Structure and Delegation March 1994

RFC2317 EidnesH. G.de Groot P.Vixie Classless IN-ADDR.ARPA Delegation
March 1998

RFC2826 Internet Architecture Board IAB Technical Comment on the Unique
DNS Root May 2000

RFC2929 EastlakeD.3rd Brunner-WilliamsE. ManningB. Domain Name System
(DNS) IANA Considerations September 2000

DNS Operations
--------------

RFC1033 LottorM. Domain administrators operations guide November 1987

RFC1537 BeertemaP. Common DNS Data File Configuration Errors October
1993

RFC1912 BarrD. Common DNS Operational and Configuration Errors February
1996

RFC2010 ManningB. P.Vixie Operational Criteria for Root Name Servers
October 1996

RFC2219 HamiltonM. R.Wright Use of DNS Aliases for Network Services
October 1997

Internationalized Domain Names
------------------------------

RFC2825 IAB DaigleR. A Tangled Web: Issues of I18N, Domain Names, and
the Other Internet protocols May 2000

RFC3490 FaltstromP. HoffmanP. CostelloA. Internationalizing Domain Names
in Applications (IDNA) March 2003

RFC3491 HoffmanP. BlanchetM. Nameprep: A Stringprep Profile for
Internationalized Domain Names March 2003

RFC3492 CostelloA. Punycode: A Bootstring encoding of Unicode for
Internationalized Domain Names in Applications (IDNA) March 2003

Other DNS-related RFCs
----------------------

   **Note**

   Note: the following list of RFCs, although DNS-related, are not
   concerned with implementing software.

RFC1464 RosenbaumR. Using the Domain Name System To Store Arbitrary
String Attributes May 1993

RFC1713 RomaoA. Tools for DNS Debugging November 1994

RFC1794 BriscoT. DNS Support for Load Balancing April 1995

RFC2240 VaughanO. A Legal Basis for Domain Name Allocation November 1997

RFC2345 KlensinJ. T.Wolf G.Oglesby Domain Names and Company Name
Retrieval May 1998

RFC2352 VaughanO. A Convention For Using Legal Names as Domain Names May
1998

RFC3071 KlensinJ. Reflections on the DNS, RFC 1591, and Categories of
Domains February 2001

RFC3258 HardieT. Distributing Authoritative Name Servers via Shared
Unicast Addresses April 2002

RFC3901 DurandA. J.Ihren DNS IPv6 Transport Operational Guidelines
September 2004

Obsolete and Unimplemented Experimental RFC
-------------------------------------------

RFC1712 FarrellC. M.Schulze S.Pleitner D.Baldoni DNS Encoding of
Geographical Location November 1994

RFC2673 CrawfordM. Binary Labels in the Domain Name System August 1999

RFC2874 CrawfordM. HuitemaC. DNS Extensions to Support IPv6 Address
Aggregation and Renumbering July 2000

Obsoleted DNS Security RFCs
---------------------------

   **Note**

   Most of these have been consolidated into RFC4033, RFC4034 and
   RFC4035 which collectively describe DNSSECbis.

RFC2065 Eastlake3rdD. C.Kaufman Domain Name System Security Extensions
January 1997

RFC2137 Eastlake3rdD. Secure Domain Name System Dynamic Update April
1997

RFC2535 Eastlake3rdD. Domain Name System Security Extensions March 1999

RFC3008 WellingtonB. Domain Name System Security (DNSSEC) Signing
Authority November 2000

RFC3090 LewisE. DNS Security Extension Clarification on Zone Status
March 2001

RFC3445 MasseyD. RoseS. Limiting the Scope of the KEY Resource Record
(RR) December 2002

RFC3655 WellingtonB. GudmundssonO. Redefinition of DNS Authenticated
Data (AD) bit November 2003

RFC3658 GudmundssonO. Delegation Signer (DS) Resource Record (RR)
December 2003

RFC3755 WeilerS. Legacy Resolver Compatibility for Delegation Signer
(DS) May 2004

RFC3757 KolkmanO. SchlyterJ. LewisE. Domain Name System KEY (DNSKEY)
Resource Record (RR) Secure Entry Point (SEP) Flag April 2004

RFC3845 SchlyterJ. DNS Security (DNSSEC) NextSECure (NSEC) RDATA Format
August 2004

.. _internet_drafts:

Internet Drafts
~~~~~~~~~~~~~~~

Internet Drafts (IDs) are rough-draft working documents of the Internet
Engineering Task Force. They are, in essence, RFCs in the preliminary
stages of development. Implementors are cautioned not to regard IDs as
archival, and they should not be quoted or cited in any formal documents
unless accompanied by the disclaimer that they are "works in progress."
IDs have a lifespan of six months after which they are deleted unless
updated by their authors.

.. _more_about_bind:

Other Documents About BIND
~~~~~~~~~~~~~~~~~~~~~~~~~~

AlbitzPaul CricketLiu DNS and BIND 1998 Sebastopol, CA: O'Reilly and
Associates
