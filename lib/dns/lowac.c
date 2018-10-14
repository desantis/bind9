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
#include <dns/name.h>
#include <dns/lowac.h>
#include <stdlib.h>

#include <ck_ht.h>
#include <ck_fifo.h>


struct dns_lowac_entry {
	dns_name_t	  name;
	uint16_t	  flags;
	isc_time_t	  expire;
	char*		  blob;
	uint32_t	  blobsize;
};


struct dns_lowac {
	bool			    running;
	ck_ht_t			    ht;
	isc_mem_t *		    mctx;
	isc_interval_t		    expiry;
	isc_thread_t		    thread;
	int			    count;
	ck_fifo_mpmc_entry_t	    mpmc_stub;
	ck_fifo_mpmc_t		    inqueue;
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
	isc_mem_put(lowac->mctx, entry->blob, entry->blobsize);
	isc_mem_put(lowac->mctx, entry, sizeof(*entry));
}


static void *
rthread(void *d) {
	dns_lowac_t *lowac = (dns_lowac_t*) d;
	ck_ht_iterator_t htit = CK_HT_ITERATOR_INITIALIZER;
	ck_ht_entry_t *htitentry = NULL;
	while (lowac->running) {
		dns_lowac_entry_t *entry = NULL;
		ck_fifo_mpmc_entry_t *garbage = NULL;
		if (ck_fifo_mpmc_dequeue(&lowac->inqueue, &entry,
					 &garbage) == true) {
			if (garbage != &lowac->mpmc_stub) {
				isc_mem_put(lowac->mctx, garbage,
					    sizeof(*garbage));
			}
//			fprintf(stderr, "XXX2 deq %p\n", entry);
			ck_ht_entry_t htentry;
			ck_ht_entry_t oldhtentry;
			ck_ht_hash_t h;
			isc_region_t r;

			dns_name_toregion(&entry->name, &r);
			ck_ht_hash(&h, &lowac->ht, r.base, r.length);
			ck_ht_entry_set(&htentry, h, r.base, r.length, entry);

			if (ck_ht_get_spmc(&lowac->ht, h,
					   &oldhtentry) == false) {
				//fprintf(stderr, "XXX3 puton %p\n", entry);
				if (ck_ht_put_spmc(&lowac->ht, h, &htentry) == false) {
					//fprintf(stderr, "Unexpected failure\n");
					free_entry(lowac, entry);
				} else {
					lowac->count++;
				}
			} else {
				dns_lowac_entry_t *oldentry =
					ck_ht_entry_value(&htentry);
				//fprintf(stderr, "XXX4 freedup %p\n", oldentry);
				free_entry(lowac, oldentry);
				ck_ht_set_spmc(&lowac->ht, h, &htentry);
			}
			isc_thread_yield();
		} else {
			usleep(10000);
			isc_time_t now;
			isc_time_now(&now);
			int i =0;
			while (ck_ht_next(&lowac->ht, &htit,
				       &htitentry) && htitentry != NULL && i < 64) {
				dns_lowac_entry_t *entry = ck_ht_entry_value(
					htitentry);
				if (isc_time_compare(&entry->expire,
						     &now) < 0) {
					isc_region_t r;
					ck_ht_hash_t h;
					dns_name_toregion(&entry->name, &r);
					ck_ht_hash(&h, &lowac->ht, r.base,
						   r.length);
					ck_ht_remove_spmc(&lowac->ht, h,
							  htitentry);
					//fprintf(stderr, "XXX5 expiry %p\n", entry);
					free_entry(lowac, entry);
					lowac->count--;
				}
				i++;
			}
			INSIST(ck_ht_gc(&lowac->ht, 16,
					isc_random32()) == true);
		}
	}
	return (NULL);
}
dns_lowac_t*
dns_lowac_create(isc_mem_t *mctx) {
	dns_lowac_t *lowac = isc_mem_get(mctx, sizeof(dns_lowac_t));
	ck_fifo_mpmc_init(&lowac->inqueue, &lowac->mpmc_stub);
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
	printf("TID %d\n", lowac->thread);
	printf("Created %p\n", lowac);
	return (lowac);
}

void
dns_lowac_destroy(dns_lowac_t *lowac) {
	printf("LOWAC %p\n", lowac);
	lowac->running = false;
	printf("Joining %d\n", lowac->thread);
	isc_thread_join(lowac->thread, NULL);
	dns_lowac_entry_t *entry;
	ck_fifo_mpmc_entry_t *fentry;
	while (ck_ht_count(&lowac->ht)>0) {
		ck_ht_gc(&lowac->ht, 0, 0);
		//fprintf(stderr, "XXX GCing %d\n", ck_ht_count(&lowac->ht));
		ck_ht_iterator_t htit = CK_HT_ITERATOR_INITIALIZER;
		ck_ht_entry_t *htitentry = NULL;
		while (ck_ht_next(&lowac->ht, &htit, &htitentry)) {
			entry = ck_ht_entry_value(htitentry);
			//fprintf(stderr, "XXX6 remove %p\n", entry);
			isc_region_t r;
			ck_ht_hash_t h;
			dns_name_toregion(&entry->name, &r);
			ck_ht_hash(&h, &lowac->ht, r.base,
						   r.length);
			bool f = ck_ht_remove_spmc(&lowac->ht, h, htitentry);
			//fprintf(stderr, "XXX8 remove %d\n", f);
			free_entry(lowac, entry);
		}
	}
	
	while (ck_fifo_mpmc_dequeue(&lowac->inqueue,
				    &entry,
				    &fentry))
	{
		printf("Dequeuing\n");
		if (fentry != &lowac->mpmc_stub) {
			isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));
		}
		free_entry(lowac, entry);
	}
	ck_fifo_mpmc_deinit(&lowac->inqueue, &fentry);
	if (fentry != &lowac->mpmc_stub) {
		isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));
	}
	ck_ht_destroy(&lowac->ht);
	isc_mem_putanddetach(&lowac->mctx, lowac, sizeof(*lowac));
}

isc_result_t
dns_lowac_put(dns_lowac_t *lowac, dns_name_t *name, char*packet, int size) {
	if (!lowac->running) {
		return (ISC_R_SHUTTINGDOWN);
	}
	dns_lowac_entry_t *entry = isc_mem_get(lowac->mctx, sizeof(*entry));
	dns_name_init(&entry->name, NULL);
	dns_name_dup(name, lowac->mctx, &entry->name);
	entry->blob = isc_mem_get(lowac->mctx, size);
	memcpy(entry->blob, packet, size);
	isc_time_nowplusinterval(&entry->expire, &lowac->expiry);
	entry->blobsize = size;
	ck_fifo_mpmc_entry_t *qentry =
		isc_mem_get(lowac->mctx, (sizeof(ck_fifo_mpmc_entry_t)));
	ck_fifo_mpmc_enqueue(&lowac->inqueue, qentry, entry);
	//fprintf(stderr, "XXX1 enq %p\n", entry);
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_lowac_get(dns_lowac_t *lowac, dns_name_t *name, char *blob, int *blobsize,
	      bool tcp) {
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
		isc_time_t now;
		isc_time_now(&now);
		if (isc_time_compare(&entry->expire, &now) < 0) {
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
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_FAILURE);
}
