#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Creates the system tests output file from the various test.output files.  It
# then searches that file and prints the number of tests passed, failed, not
# run.  It also checks whether the IP addresses 10.53.0.[1-8] were set up and,
# if not, prints a warning.
#
# Usage:
#    retry.sh
#
# Status return:
# 0 - no tests failed
# 1 - one or more tests failed

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

SYSTESTDIR=""

display () {
    while IFS= read -r __LINE ; do
       echoinfo "$__LINE"
    done
}

if [ ! -f systests.output ]; then
    echofail "I:'systests.output' not found."
    exit 0
fi

# first, preserve artifacts from the tests that are failing
fails=$(grep 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' systests.output |
        awk -F: 'START { print ". ./conf.sh" }
              $1 == "R" && $3 == "FAIL" { printf "%s ", $2 }
              END { print "" }')

# if there were no failed tests, we're done
[ -n "$fails" ] || exit 0

tar cf failed-tests.tar $fails
sh testsummary.sh > summary.prev

tar uf failed-tests.tar systests.output
echo_i "Test failures detected"
echo_i "Artifacts from failed tests stored in 'failed-tests.tar'"
echo_i "Rerunning failed tests:"

grep 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' systests.output | \
    awk -F: 'START { print ". ./conf.sh" }
        $1 == "R" && $3 == "FAIL" { retests = retests " test-"$2; }
        END { if (retests) { print "make -f parallel.mk " retests } }' | \
    $SHELL | display

echo_i "Original test results (after first pass):"
cat summary.prev | display
rm -f summary.prev

echo_i "Updated test results (after second pass):"
sh testsummary.sh
