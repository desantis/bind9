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


/*! \file */

#include <config.h>

#include <inttypes.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/stats.h>

static isc_result_t
create_stats(isc_mem_t *mctx, int ncounters, isc_stats_t **statsp) {
	isc_stats_t *stats;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(statsp != NULL && *statsp == NULL);

	stats = isc_mem_get(mctx, sizeof(*stats));
	if (stats == NULL)
		return (ISC_R_NOMEMORY);

	isc_mutex_init(&stats->lock);

	stats->counters = isc_mem_get(mctx, sizeof(isc_stat_t) * ncounters);
	if (stats->counters == NULL) {
		result = ISC_R_NOMEMORY;
		goto clean_mutex;
	}
	stats->copiedcounters = isc_mem_get(mctx,
					    sizeof(uint64_t) * ncounters);
	if (stats->copiedcounters == NULL) {
		result = ISC_R_NOMEMORY;
		goto clean_counters;
	}

	stats->references = 1;
	memset(stats->counters, 0, sizeof(isc_stat_t) * ncounters);
	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->ncounters = ncounters;
	stats->magic = ISC_STATS_MAGIC;

	*statsp = stats;

	return (result);

clean_counters:
	isc_mem_put(mctx, stats->counters, sizeof(isc_stat_t) * ncounters);

clean_mutex:
	isc_mutex_destroy(&stats->lock);
	isc_mem_put(mctx, stats, sizeof(*stats));

	return (result);
}

void
isc_stats_attach(isc_stats_t *stats, isc_stats_t **statsp) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(statsp != NULL && *statsp == NULL);

	LOCK(&stats->lock);
	stats->references++;
	UNLOCK(&stats->lock);

	*statsp = stats;
}

void
isc_stats_detach(isc_stats_t **statsp) {
	isc_stats_t *stats;

	REQUIRE(statsp != NULL && ISC_STATS_VALID(*statsp));

	stats = *statsp;
	*statsp = NULL;

	LOCK(&stats->lock);
	stats->references--;

	if (stats->references == 0) {
		isc_mem_put(stats->mctx, stats->copiedcounters,
			    sizeof(isc_stat_t) * stats->ncounters);
		isc_mem_put(stats->mctx, stats->counters,
			    sizeof(isc_stat_t) * stats->ncounters);
		UNLOCK(&stats->lock);
		isc_mutex_destroy(&stats->lock);
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
		return;
	}

	UNLOCK(&stats->lock);
}

int
isc_stats_ncounters(isc_stats_t *stats) {
	REQUIRE(ISC_STATS_VALID(stats));

	return (stats->ncounters);
}

isc_result_t
isc_stats_create(isc_mem_t *mctx, isc_stats_t **statsp, int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	return (create_stats(mctx, ncounters, statsp));
}


void
isc_stats_dump(isc_stats_t *stats, isc_stats_dumper_t dump_fn,
	       void *arg, unsigned int options)
{
	int i;

	REQUIRE(ISC_STATS_VALID(stats));

	for (i = 0; i < stats->ncounters; i++) {
		stats->copiedcounters[i] =
			atomic_load_explicit(&stats->counters[i],
					     memory_order_relaxed);
	}

	for (i = 0; i < stats->ncounters; i++) {
		if ((options & ISC_STATSDUMP_VERBOSE) == 0 &&
		    stats->copiedcounters[i] == 0)
				continue;
		dump_fn((isc_statscounter_t)i, stats->copiedcounters[i], arg);
	}
}

void
isc_stats_set(isc_stats_t *stats, uint64_t val,
	      isc_statscounter_t counter)
{
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	atomic_store_explicit(&stats->counters[counter], val,
			      memory_order_relaxed);
}
