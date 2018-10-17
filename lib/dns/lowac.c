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
#define fprintf(...) {}
#define MAXIMUM_PKT_SIZE 1024

#define LENTRY_MAGIC		ISC_MAGIC('L', 'o', 'w', 'E')
#define VALID_LENTRY(c)		ISC_MAGIC_VALID(c, LENTRY_MAGIC)

struct dns_lowac_entry {
	unsigned int	      magic;
	dns_name_t	      name;
	isc_region_t	      key;
	uint16_t	      flags;
	int64_t		      expire;
	ck_ht_hash_t	      hash;
	unsigned char	      *blob;
	uint32_t	      blobsize;
	isc_refcount_t	      refcount;
	/*
	 * Set to 'true' when we enqueue this entry on remq.
	 * Nothing serious will happen if we enqueue the entry
	 * on remq multiple times as we're refcounting.
	 * It's not locked in any way as it can only change
	 * from false to true during runtime.
	 */
	bool	    	remq_enqueued;
	isc_refcount_t	      rqrefcount;


	bool	    inht;
	
	atomic_int_fast64_t	lastusage;
};


struct dns_lowac {
	isc_mem_t *		mctx;    
	isc_thread_t		thread;  
	int			expiry;  /* Time after which records expire */

	bool			running; /* We're not shut down */
	bool			accepting; /* We're accepting packets into cache */
	
	ck_ht_t			ht;      /* Cache hash table */
	ck_ht_iterator_t	htit;    /* Hashtable maintenance iterator */

	ck_fifo_mpmc_t		inq;     /* Packet input queue */
	ck_fifo_mpmc_t		remq;    /* Removal queue */
	
	atomic_int_fast64_t	now;     /* Epoch time, updated at every loop */
	int			count; 
	
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
	entry->magic = 0xffffffff;
	dns_name_free(&entry->name, lowac->mctx);
	isc_mem_put(lowac->mctx, entry->blob, entry->blobsize);
	isc_mem_put(lowac->mctx, entry, sizeof(*entry));
}

static bool
dequeue_input_entry(dns_lowac_t*lowac) {
	dns_lowac_entry_t *entry = NULL;
	ck_fifo_mpmc_entry_t *garbage = NULL;
	if (ck_fifo_mpmc_dequeue(&lowac->inq, &entry,
				 &garbage) == true) {
		REQUIRE(VALID_LENTRY(entry));
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
			entry->inht = true;
			if (ck_ht_put_spmc(&lowac->ht, entry->hash,
					   &htentry) == false) {
				abort();
				printf("oddness but might happen\n");
				/* We can do it safely as it never was in
				 * hashtable */
				RUNTIME_CHECK(isc_refcount_decrement(&entry->
								     refcount) ==
					      1);
				free_entry(lowac, entry);
			} else {
				fprintf(stderr, "XXXInsert %p %d\n", entry, lowac->count);
				lowac->count++;
			}
		} else {
			dns_lowac_entry_t *oldentry =
				ck_ht_entry_value(&oldhtentry);
			/* Note: set without remove doesn't seem to work
			 * properly */
			oldentry->inht = false;
			RUNTIME_CHECK(ck_ht_remove_spmc(&lowac->ht,
							entry->hash,
							&oldhtentry) == true);
			entry->inht = true;
			RUNTIME_CHECK(ck_ht_set_spmc(&lowac->ht, entry->hash,
						     &htentry) == true);
			lowac->count++;
			
			/*
			 * We don't need to increment refcount since we
			 * have not decremented it
			 * when removing from hashtable
			 */
			ck_fifo_mpmc_entry_t *qentry =
				isc_mem_get(lowac->mctx,
					    (sizeof(
						     ck_fifo_mpmc_entry_t)));
			oldentry->remq_enqueued = true;
			isc_refcount_increment(&oldentry->rqrefcount);
			fprintf(stderr, "XXXenq %p %d\n", oldentry, __LINE__);
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry,
						     oldentry);
		}
		return (true);
	}
	return (false);
}

static int
expire_entries(dns_lowac_t *lowac) {
	int iterated = 0;

	ck_ht_entry_t *htitentry = NULL;
	bool iterok = ck_ht_next(&lowac->ht, &lowac->htit, &htitentry);
	if (!iterok) {
		ck_ht_iterator_init(&lowac->htit);
		iterok = ck_ht_next(&lowac->ht, &lowac->htit, &htitentry);
	}
	while (iterok && htitentry != NULL && iterated < 2048) {
		dns_lowac_entry_t *entry = ck_ht_entry_value(htitentry);
		REQUIRE(VALID_LENTRY(entry));
		if (entry->expire < atomic_load(&lowac->now)) {
			if (!ck_ht_remove_spmc(&lowac->ht, entry->hash, htitentry)) {
				abort();
				/*
				 * Very unlikely, but can happen when we're between generations.
				 * TODO verify that it's ok at all, maybe we're using the iterator wrong?
				 */
				isc_refcount_increment(&entry->refcount);
				fprintf(stderr, "INCREF %d %p\n", __LINE__, entry);
			} else {
				dns_lowac_entry_t *ent2 = ck_ht_entry_value(htitentry);
				RUNTIME_CHECK(ent2 == entry);
			} 
			entry->inht = false;
			/*
			 * We don't need to increment refcount since we have
			 * not decremented it when removing from hashtable.
			 */
			ck_fifo_mpmc_entry_t *qentry =
				isc_mem_get(lowac->mctx,
					    (sizeof(
						     ck_fifo_mpmc_entry_t)));
			entry->remq_enqueued = true;
			isc_refcount_increment(&entry->rqrefcount);
			fprintf(stderr, "XXXenq %p %d\n", entry, __LINE__);
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry, entry);
		}
		htitentry = NULL;
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
		REQUIRE(VALID_LENTRY(entry));
		int rc = isc_refcount_decrement(&entry->refcount);
		int rqrc = isc_refcount_decrement(&entry->rqrefcount);
		fprintf(stderr, "DECREF %d %p %d\n", __LINE__, entry, lowac->count);
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
			isc_refcount_increment(&entry->rqrefcount);
			/* We don't increment refcount - it was at 2 (remq + ht), it stays at 1 (remq) */
			fprintf(stderr, "INCREF %d %p\n", __LINE__, entry);
			fprintf(stderr, "XXXenq %p %d\n", entry, __LINE__);
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry, entry);
		} else {
			if (rc > 1) {
				/* Requeue if still in use and there's no other request in queue */
				/* TODO that's completely wrong, if we have two instances in the queue they will always have rc > 1 !!! */
				if (rqrc == 0) { 
					int p1 = isc_refcount_increment(&entry->rqrefcount);
					int p2 = isc_refcount_increment(&entry->refcount);
					fprintf(stderr, "INCREF %d %p %d %d\n", __LINE__, entry, p1, p2);
					fprintf(stderr, "XXXenq %p %d\n", entry, __LINE__);
					ck_fifo_mpmc_enqueue(&lowac->remq, qentry,
							     entry);
				} else {
					isc_mem_put(lowac->mctx, qentry,
					    sizeof(*qentry));
				}
				fprintf(stderr, "IGNREF %d %p\n", __LINE__, entry);
			} else {
				isc_mem_put(lowac->mctx, qentry,
					    sizeof(*qentry));
				removed++;
				free_entry(lowac, entry);
				fprintf(stderr, "XXXFree %p %d\n", entry, lowac->count);
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
		isc_time_t now;
		isc_time_now(&now);
		atomic_store(&lowac->now, now.seconds);
		bool dequeued = dequeue_input_entry(lowac);
		if (!dequeued) {
			expire_entries(lowac);
			int removed = cleanup_entries(lowac);
			if (removed < 256) {
				usleep(1000);
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
	lowac->expiry = 600;
	lowac->count = 0;
	lowac->running = true;

	if (ck_ht_init(&lowac->ht,
		       CK_HT_MODE_BYTESTRING | CK_HT_WORKLOAD_DELETE,
		       ht_hash_wrapper,
		       &my_allocator, 32, isc_random32()) == false) {
		abort();
	}

	ck_fifo_mpmc_entry_t *inq_stub =
		isc_mem_get(mctx, sizeof(ck_fifo_mpmc_entry_t));
	ck_fifo_mpmc_entry_t *remq_stub =
		isc_mem_get(mctx, sizeof(ck_fifo_mpmc_entry_t));

	ck_fifo_mpmc_init(&lowac->inq, inq_stub);
	ck_fifo_mpmc_init(&lowac->remq, remq_stub);
	
	
	lowac->mctx = NULL;
	isc_mem_attach(mctx, &lowac->mctx);

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
		if (isc_refcount_decrement(&entry->refcount) == 1) {
			fprintf(stderr, "DECREF %d %p\n", __LINE__, entry);
			free_entry(lowac, entry);
		} else {
			fprintf(stderr, "Non-unreferenced entry in remq %p\n", entry);
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
	entry->blob = isc_mem_get(lowac->mctx, size);
	memcpy(entry->blob, packet, size);
	entry->blobsize = size;
	isc_refcount_init(&entry->refcount, 1);
	isc_refcount_init(&entry->rqrefcount, 0);
	entry->expire = atomic_load(&lowac->now) + lowac->expiry;
	entry->remq_enqueued = false;
	entry->inht = false;
	entry->magic = LENTRY_MAGIC;

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
		REQUIRE(VALID_LENTRY(entry));
		int oldrc = isc_refcount_increment(&entry->refcount);
		fprintf(stderr, "INCREF %d %p\n", __LINE__, entry, oldrc);
		RUNTIME_CHECK(oldrc > 0);
		if (entry->remq_enqueued) {
			/* This entry is being removed, bail */
			isc_refcount_decrement(&entry->refcount);
			fprintf(stderr, "DECREF %d %p\n", __LINE__, entry);
			return (ISC_R_NOTFOUND);
		}
		if (entry->expire < atomic_load(&lowac->now)) {
			ck_fifo_mpmc_entry_t *qentry =
				isc_mem_get(lowac->mctx,
					    (sizeof(ck_fifo_mpmc_entry_t)));
			entry->remq_enqueued = true;
			isc_refcount_increment(&entry->rqrefcount);
			fprintf(stderr, "XXXenq %p %d\n", entry, __LINE__);
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
		fprintf(stderr, "DECREF %d %p\n", __LINE__, entry);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_FAILURE);
}
