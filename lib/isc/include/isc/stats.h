/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


#ifndef ISC_STATS_H
#define ISC_STATS_H 1

/*! \file isc/stats.h */

#include <inttypes.h>

#include <isc/atomic.h>
#include <isc/types.h>
#include <isc/magic.h>
#include <isc/util.h>
#include <isc/rwlock.h>

ISC_LANG_BEGINDECLS

typedef atomic_int_fast64_t isc_stat_t;
#define ISC_STATS_MAGIC			ISC_MAGIC('S', 't', 'a', 't')
#define ISC_STATS_VALID(x)		ISC_MAGIC_VALID(x, ISC_STATS_MAGIC)

struct isc_stats {
	/*% Unlocked */
	unsigned int	magic;
	isc_mem_t	*mctx;
	int		ncounters;

	isc_mutex_t	lock;
	unsigned int	references; /* locked by lock */

	/*%
	 * Locked by counterlock or unlocked if efficient rwlock is not
	 * available.
	 */
	isc_stat_t	*counters;

	/*%
	 * We don't want to lock the counters while we are dumping, so we first
	 * copy the current counter values into a local array.  This buffer
	 * will be used as the copy destination.  It's allocated on creation
	 * of the stats structure so that the dump operation won't fail due
	 * to memory allocation failure.
	 * XXX: this approach is weird for non-threaded build because the
	 * additional memory and the copy overhead could be avoided.  We prefer
	 * simplicity here, however, under the assumption that this function
	 * should be only rarely called.
	 */
	uint64_t	*copiedcounters;
};

/*%<
 * Flag(s) for isc_stats_dump().
 */
#define ISC_STATSDUMP_VERBOSE	0x00000001 /*%< dump 0-value counters */

/*%<
 * Dump callback type.
 */
typedef void (*isc_stats_dumper_t)(isc_statscounter_t, uint64_t, void *);

isc_result_t
isc_stats_create(isc_mem_t *mctx, isc_stats_t **statsp, int ncounters);
/*%<
 * Create a statistics counter structure of general type.  It counts a general
 * set of counters indexed by an ID between 0 and ncounters -1.
 *
 * Requires:
 *\li	'mctx' must be a valid memory context.
 *
 *\li	'statsp' != NULL && '*statsp' == NULL.
 *
 * Returns:
 *\li	ISC_R_SUCCESS	-- all ok
 *
 *\li	anything else	-- failure
 */

void
isc_stats_attach(isc_stats_t *stats, isc_stats_t **statsp);
/*%<
 * Attach to a statistics set.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 *
 *\li	'statsp' != NULL && '*statsp' == NULL
 */

void
isc_stats_detach(isc_stats_t **statsp);
/*%<
 * Detaches from the statistics set.
 *
 * Requires:
 *\li	'statsp' != NULL and '*statsp' is a valid isc_stats_t.
 */

int
isc_stats_ncounters(isc_stats_t *stats);
/*%<
 * Returns the number of counters contained in stats.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 *
 */

#define isc_stats_increment(stats, counter) do { \
	atomic_fetch_add_explicit(&stats->counters[counter], 1, \
				  memory_order_relaxed); } while(0)
/*%<
 * Increment the counter-th counter of stats.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 *
 *\li	counter is less than the maximum available ID for the stats specified
 *	on creation.
 */


#define isc_stats_decrement(stats, counter) do { \
	atomic_fetch_sub_explicit(&stats->counters[counter], 1, \
				  memory_order_relaxed); } while(0)
/*%<
 * Decrement the counter-th counter of stats.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 */

void
isc_stats_dump(isc_stats_t *stats, isc_stats_dumper_t dump_fn, void *arg,
	       unsigned int options);
/*%<
 * Dump the current statistics counters in a specified way.  For each counter
 * in stats, dump_fn is called with its current value and the given argument
 * arg.  By default counters that have a value of 0 is skipped; if options has
 * the ISC_STATSDUMP_VERBOSE flag, even such counters are dumped.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 */

void
isc_stats_set(isc_stats_t *stats, uint64_t val,
	      isc_statscounter_t counter);
/*%<
 * Set the given counter to the specfied value.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 */

void
isc_stats_set(isc_stats_t *stats, uint64_t val,
	      isc_statscounter_t counter);
/*%<
 * Set the given counter to the specfied value.
 *
 * Requires:
 *\li	'stats' is a valid isc_stats_t.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_STATS_H */
