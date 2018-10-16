#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/thread.h>
#include <isc/mem.h>
#include <isc/hash.h>
#include <isc/time.h>
#include <isc/util.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <dns/name.h>
#include <dns/lowac.h>
#include <stdlib.h>

#include <ck_ht.h>
#include <ck_fifo.h>
#include <ck_queue.h>

#define MAXIMUM_PKT_SIZE 1024


struct dns_lowac_entry {
	dns_name_t	      name;
	isc_region_t	      key;
	uint16_t	      flags;
	isc_time_t	      expire;
	ck_ht_hash_t	      hash;
	unsigned char	      blob[MAXIMUM_PKT_SIZE];
	uint32_t	      blobsize;
	isc_refcount_t	      refcount;

	/*
	 * Set to 'true' when we enqueue this entry on remq.
	 * Nothing serious will happen if we enqueue the entry
	 * on remq multiple times as we're refcounting.
	 * It's not locked in any way as it can only change
	 * from false to true during runtime.
	 */
	bool	    remq_enqueued;

	bool	    inht;
};


struct dns_lowac {
	bool			running;
	ck_ht_t			ht;
	isc_mem_t *		mctx;
	isc_interval_t		expiry;
	isc_thread_t		thread;
	int			count;
	ck_ht_iterator_t	htit;
	ck_fifo_mpmc_t		inq;
	ck_fifo_mpmc_t		remq;
};

static void *
rthread(void*d);

static void *
ht_malloc(size_t r)
{
	return(malloc(r));
}

static void
ht_free(void *p, size_t b, bool r)
{
	(void)b;
	(void)r;
	free(p);
	return;
}

static void
ht_hash_wrapper(struct ck_ht_hash *h, const void *key, size_t length,
		uint64_t seed)
{
	(void)seed;
	h->value = isc_hash_function(key, length, false, NULL);
	return;
}

static struct ck_malloc my_allocator = {
	.malloc = ht_malloc,
	.free = ht_free
};

static void
free_entry(dns_lowac_t *lowac, dns_lowac_entry_t *entry) {
	dns_name_free(&entry->name, lowac->mctx);
	isc_mem_put(lowac->mctx, entry, sizeof(*entry));
}

static bool
dequeue_input_entry(dns_lowac_t*lowac) {
	dns_lowac_entry_t *entry = NULL;
	ck_fifo_mpmc_entry_t *garbage = NULL;
	if (ck_fifo_mpmc_dequeue(&lowac->inq, &entry,
				 &garbage) == true) {
		isc_mem_put(lowac->mctx, garbage,
			    sizeof(*garbage));
		ck_ht_entry_t htentry;
		ck_ht_entry_t oldhtentry;

		ck_ht_entry_set(&htentry, entry->hash, entry->key.base,
				entry->key.length, entry);
		ck_ht_entry_set(&oldhtentry, entry->hash, entry->key.base,
				entry->key.length, NULL);

		if (ck_ht_get_spmc(&lowac->ht, entry->hash,
				   &oldhtentry) == false) {
			/* We don't have this entry in hashtable */
			if (ck_ht_put_spmc(&lowac->ht, entry->hash,
					   &htentry) == false) {
				printf("oddness but might happen\n");
				/* We can do it safely as it never was in
				 * hashtable */
				RUNTIME_CHECK(isc_refcount_decrement(&entry->
								     refcount) ==
					      0);
				free_entry(lowac, entry);
			} else {
				entry->inht = true;
				lowac->count++;
			}
		} else {
			dns_lowac_entry_t *oldentry =
				ck_ht_entry_value(&oldhtentry);
			/* Note: set without remove doesn't seem to work
			 * properly */
			RUNTIME_CHECK(ck_ht_remove_spmc(&lowac->ht,
							entry->hash,
							&oldhtentry) == true);
			oldentry->inht = false;
			RUNTIME_CHECK(ck_ht_set_spmc(&lowac->ht, entry->hash,
						     &htentry) == true);

			if (oldentry->remq_enqueued) {
				isc_refcount_decrement(&oldentry->refcount);
			} else {
				/*
				 * We don't need to increment refcount since we
				 * have not decremented it
				 * when removing from hashtable
				 */
				ck_fifo_mpmc_entry_t *qentry =
					isc_mem_get(lowac->mctx,
						    (sizeof(
							     ck_fifo_mpmc_entry_t)));
				entry->remq_enqueued = true;
				ck_fifo_mpmc_enqueue(&lowac->remq, qentry,
						     entry);
			}
		}
		return (true);
	}
	return (false);
}

static int
expire_entries(dns_lowac_t *lowac) {
	isc_time_t now;
	isc_time_now(&now);
	int iterated = 0;

	ck_ht_entry_t *htitentry = NULL;
	bool iterok = ck_ht_next(&lowac->ht, &lowac->htit, &htitentry);
	if (!iterok) {
		ck_ht_iterator_init(&lowac->htit);
		iterok = ck_ht_next(&lowac->ht, &lowac->htit, &htitentry);
	}
	while (iterok && htitentry != NULL && iterated < 256) {
		dns_lowac_entry_t *entry = ck_ht_entry_value(
			htitentry);
		if (isc_time_compare(&entry->expire, &now) < 0) {
			if (!ck_ht_remove_spmc(&lowac->ht, entry->hash,htitentry)) {
				/*
				 * Very unlikely, but can happen when we're between generations.
				 * TODO verify that it's ok at all, maybe we're using the iterator wrong?
				 */
				 isc_refcount_increment(&entry->refcount);
			}
			entry->inht = false;
			dns_lowac_entry_t *ent2 = ck_ht_entry_value(htitentry);
			RUNTIME_CHECK(ent2 == entry);
			/*
			 * We don't need to increment refcount since we have
			 * not decremented it when removing from hashtable.
			 */
			ck_fifo_mpmc_entry_t *qentry =
				isc_mem_get(lowac->mctx,
					    (sizeof(
						     ck_fifo_mpmc_entry_t)));
			entry->remq_enqueued = true;
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry, entry);
		}
		iterok = ck_ht_next(&lowac->ht, &lowac->htit, &htitentry);
		iterated++;
	}

	if (!iterok) {
		ck_ht_iterator_init(&lowac->htit);
	}
	return (iterated);
}

/*
 * Iterate over remq.
 * If the entry is in HT - remove it, requeue.
 * If the entry is not in HT but it is referenced - requeue.
 * If the entry is not referenced - free.
 */
static int
cleanup_entries(dns_lowac_t *lowac) {
	ck_ht_entry_t htentry;
	dns_lowac_entry_t *entry;
	ck_fifo_mpmc_entry_t *qentry = NULL;
	int removed = 0;
	int max = 100;

	while (--max > 0 &&
	       ck_fifo_mpmc_dequeue(&lowac->remq, &entry, &qentry) == true)
	{
		int rc = isc_refcount_decrement(&entry->refcount);
		if (entry->inht) {
			/*
			 * Remove entry from the hashtable, we'll remove the
			 * entry itself in the next iteration.
			 */
			ck_ht_entry_set(&htentry, entry->hash, entry->key.base,
					entry->key.length, entry);
			RUNTIME_CHECK(ck_ht_remove_spmc(&lowac->ht,
							entry->hash,
							&htentry) == true);
			entry->inht = false;
			isc_refcount_increment(&entry->refcount);
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry, entry);
		} else {
			if (rc > 1) {
				/* Requeue if still in use */
				isc_refcount_increment(&entry->refcount);
				ck_fifo_mpmc_enqueue(&lowac->remq, qentry,
						     entry);
			} else {
				isc_mem_put(lowac->mctx, qentry,
					    sizeof(*qentry));
				removed++;
				free_entry(lowac, entry);
				lowac->count--;
			}
		}
	}
	return (removed);
}

static void *
rthread(void *d) {
	dns_lowac_t *lowac = (dns_lowac_t*) d;
	ck_ht_iterator_init(&lowac->htit);
	while (lowac->running) {
		bool dequeued = dequeue_input_entry(lowac);
		if (!dequeued) {
			expire_entries(lowac);
			int removed = cleanup_entries(lowac);
			if (removed < 256) {
				usleep(10000);
			} else {
				RUNTIME_CHECK(ck_ht_gc(&lowac->ht, 128,
						       isc_random32()));
			}
		}
	}
	return (NULL);
}
dns_lowac_t*
dns_lowac_create(isc_mem_t *mctx) {
	dns_lowac_t *lowac = isc_mem_get(mctx, sizeof(dns_lowac_t));
	ck_fifo_mpmc_entry_t *inq_stub =
		isc_mem_get(mctx, sizeof(ck_fifo_mpmc_entry_t));
	ck_fifo_mpmc_entry_t *remq_stub =
		isc_mem_get(mctx, sizeof(ck_fifo_mpmc_entry_t));

	ck_fifo_mpmc_init(&lowac->inq, inq_stub);
	ck_fifo_mpmc_init(&lowac->remq, remq_stub);
	lowac->count = 0;
	lowac->running = true;
	if (ck_ht_init(&lowac->ht,
		       CK_HT_MODE_BYTESTRING | CK_HT_WORKLOAD_DELETE,
		       ht_hash_wrapper,
		       &my_allocator, 32, isc_random32()) == false) {
		abort();
	}
	isc_mem_attach(mctx, &lowac->mctx);
	isc_interval_set(&lowac->expiry, 30, 0);
	isc_thread_create(rthread, lowac, &lowac->thread);
	return (lowac);
}

void
dns_lowac_destroy(dns_lowac_t *lowac) {
	lowac->running = false;
	isc_thread_join(lowac->thread, NULL);
	dns_lowac_entry_t *entry;
	ck_fifo_mpmc_entry_t *fentry;

	/* Entries in inq can only be in inq, it's safe to free them */
	while (ck_fifo_mpmc_dequeue(&lowac->inq,
				    &entry,
				    &fentry))
	{
		isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));
		free_entry(lowac, entry);
	}

	/*
	 * Entries in remq can be freed only if they're no longer referenced
	 * by either multiple occurences in queue or HT
	 */
	while (ck_fifo_mpmc_dequeue(&lowac->remq,
				    &entry,
				    &fentry))
	{
		if (isc_refcount_decrement(&entry->refcount) == 0) {
			free_entry(lowac, entry);
		}
		isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));
	}

	/* Finally we free rest of entries from HT */
	while (ck_ht_count(&lowac->ht) > 0) {
		ck_ht_gc(&lowac->ht, 0, 0);
		ck_ht_iterator_t htit = CK_HT_ITERATOR_INITIALIZER;
		ck_ht_entry_t *htitentry = NULL;
		while (ck_ht_next(&lowac->ht, &htit, &htitentry)) {
			entry = ck_ht_entry_value(htitentry);
			ck_ht_remove_spmc(&lowac->ht, entry->hash, htitentry);
			free_entry(lowac, entry);
		}
	}


	ck_fifo_mpmc_deinit(&lowac->inq, &fentry);
	isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));

	ck_fifo_mpmc_deinit(&lowac->remq, &fentry);
	isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));

	ck_ht_destroy(&lowac->ht);
	isc_mem_putanddetach(&lowac->mctx, lowac, sizeof(*lowac));
}

isc_result_t
dns_lowac_put(dns_lowac_t *lowac, dns_name_t *name, char*packet, int size) {
	if (!lowac->running) {
		return (ISC_R_SHUTTINGDOWN);
	}
	if (size > MAXIMUM_PKT_SIZE) {
		return (ISC_R_FAILURE);
	}
	dns_lowac_entry_t *entry = isc_mem_get(lowac->mctx, sizeof(*entry));
	dns_name_init(&entry->name, NULL);
	dns_name_dup(name, lowac->mctx, &entry->name);
	memcpy(entry->blob, packet, size);
	isc_time_nowplusinterval(&entry->expire, &lowac->expiry);
	entry->blobsize = size;
	isc_refcount_init(&entry->refcount, 1);
	entry->remq_enqueued = false;
	entry->inht = false;

	dns_name_toregion(&entry->name, &entry->key);

	ck_ht_hash(&entry->hash, &lowac->ht, entry->key.base,
		   entry->key.length);
	ck_fifo_mpmc_entry_t *qentry =
		isc_mem_get(lowac->mctx, (sizeof(ck_fifo_mpmc_entry_t)));
	ck_fifo_mpmc_enqueue(&lowac->inq, qentry, entry);
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_lowac_get(dns_lowac_t *lowac, dns_name_t *name, unsigned char *blob,
	      int *blobsize, bool tcp) {
	ck_ht_entry_t htentry;
	ck_ht_hash_t h;
	isc_region_t r;

	dns_name_toregion(name, &r);
	ck_ht_hash(&h, &lowac->ht, r.base, r.length);
	ck_ht_entry_key_set(&htentry, r.base, r.length);
	if (ck_ht_get_spmc(&lowac->ht, h, &htentry) == false) {
		return (ISC_R_NOTFOUND);
	} else {
		dns_lowac_entry_t *entry = ck_ht_entry_value(&htentry);
		int oldrc = isc_refcount_increment(&entry->refcount);
		RUNTIME_CHECK(oldrc > 0);
		if (entry->remq_enqueued) {
			/* This entry is being removed, bail */
			isc_refcount_decrement(&entry->refcount);
			return (ISC_R_NOTFOUND);
		}
		isc_time_t now;
		isc_time_now(&now);
		if (isc_time_compare(&entry->expire, &now) < 0) {
			ck_fifo_mpmc_entry_t *qentry =
				isc_mem_get(lowac->mctx,
					    (sizeof(ck_fifo_mpmc_entry_t)));
			entry->remq_enqueued = true;
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry, entry);
			return (ISC_R_NOTFOUND);
		}
		if (tcp) {
			blob[0] = entry->blobsize >> 8;
			blob[1] = entry->blobsize;
			memcpy(blob + 2, entry->blob, entry->blobsize);
			*blobsize = entry->blobsize + 2;
		} else {
			memcpy(blob, entry->blob, entry->blobsize);
			*blobsize = entry->blobsize;
		}
		isc_refcount_decrement(&entry->refcount);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_FAILURE);
}
