#!/bin/sh
#
# Copyright (C) 2010, 2012-2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.*
rm -f rndc.out*
rm -f */named.conf
rm -f */named.memstats
rm -f ns2/*.nzf
rm -f ns2/*.nzf~
rm -f ns2/*.nzd ns2/*.nzd-lock
rm -f ns2/core*
rm -f ns2/inline.db.jbk
rm -f ns2/inline.db.signed
rm -f ns2/inlineslave.bk*
rm -f ns*/named.lock
rm -f ns*/named.run
rm -f ns2/nzf-*
rm -f ns3/named.conf
rm -f ns3/*.nzf ns3/*.nzf~
rm -f ns3/*.nzd ns3/*.nzd-lock
rm -f ns3/inlineslave.db
