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
#include <ck_queue.h>


struct dns_lowac_entry {
	dns_name_t	  name;
	uint16_t	  flags;
	isc_time_t	  expire;
	ck_ht_hash_t	  hash;
	char		  blob[1024];
	uint32_t	  blobsize;
};


struct dns_lowac {
	bool			    running;
	ck_ht_t			    ht;
	isc_mem_t *		    mctx;
	isc_interval_t		    expiry;
	isc_thread_t		    thread;
	int			    count;
	ck_fifo_mpmc_t		    inq;

	ck_fifo_mpmc_t		    remq;
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
	//fprintf(stderr, "XXX ENTRY NAME %p\n", entry);
	dns_name_free(&entry->name, lowac->mctx);
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
		if (ck_fifo_mpmc_dequeue(&lowac->inq, &entry,
					 &garbage) == true) {
			isc_mem_put(lowac->mctx, garbage,
				    sizeof(*garbage));
			ck_ht_entry_t htentry;
			ck_ht_entry_t oldhtentry;
			isc_region_t r;

			dns_name_toregion(&entry->name, &r);
			ck_ht_entry_set(&htentry, entry->hash, r.base, r.length, entry);
			ck_ht_entry_set(&oldhtentry, entry->hash, r.base, r.length, NULL);
			if (ck_ht_get_spmc(&lowac->ht, entry->hash,
					   &oldhtentry) == false) {
				if (ck_ht_put_spmc(&lowac->ht, entry->hash, &htentry) == false) {
					//fprintf(stderr, "XXX put false ENTRY NAME %p\n", entry);
	    				free_entry(lowac, entry);
				} else {
					lowac->count++;
				}
			} else {
				dns_lowac_entry_t *oldentry =
					ck_ht_entry_value(&oldhtentry);
				//fprintf(stderr, "XXX replace ENTRY NAME %p %p\n", oldentry, htentry.value);
				free_entry(lowac, oldentry);
				RUNTIME_CHECK(ck_ht_remove_spmc(&lowac->ht, entry->hash, &oldhtentry) == true);
				RUNTIME_CHECK(ck_ht_set_spmc(&lowac->ht, entry->hash, &htentry) == true);
				//fprintf(stderr, "XXX old got %p\n", ck_ht_entry_value(&htentry));
			}
			isc_thread_yield();
		} else {
			isc_time_t now;
			isc_time_now(&now);
			int removed = 0;
/*			ck_ht_entry_t htentry;
			dns_lowac_entry_t *entry;
			ck_fifo_mpmc_entry_t *garbage = NULL;
			// TODO race here!
			while (ck_fifo_mpmc_dequeue(&lowac->remq, &entry,
					 &garbage) == true) {
				removed++;
				isc_mem_put(lowac->mctx, garbage,
					    sizeof(*garbage));
				if (ck_ht_get_spmc(&lowac->ht, entry->hash,
					   &htentry) == true) {
					RUNTIME_CHECK(ck_ht_remove_spmc(&lowac->ht, entry->hash, &htentry) == true);
				} else {
					printf("Oddness\n");
				}
				free_entry(lowac, entry);
				lowac->count--;
			}
*/			
			ck_ht_iterator_init(&htit);
			bool iterok = ck_ht_next(&lowac->ht, &htit, &htitentry);
			while (iterok && htitentry != NULL && removed < 256) {
				dns_lowac_entry_t *entry = ck_ht_entry_value(
					htitentry);
				if (isc_time_compare(&entry->expire,
						     &now) < 0) {
					RUNTIME_CHECK(ck_ht_remove_spmc(&lowac->ht, entry->hash, htitentry) == true);
					dns_lowac_entry_t *ent2 = ck_ht_entry_value(htitentry);
					RUNTIME_CHECK(ent2 == entry);
					//fprintf(stderr, "XXX free timeout ENTRY NAME %p\n", entry);
					free_entry(lowac, entry);
					lowac->count--;
				}
				removed++;
				iterok = ck_ht_next(&lowac->ht, &htit, &htitentry);
			}
			if (!iterok) {
				ck_ht_iterator_init(&htit);
			}
//			INSIST(ck_ht_gc(&lowac->ht, 64,
//					isc_random32()) == true);
			if (removed < 256) {
				usleep(1000);
			}
		}
	}
	return (NULL);
}
dns_lowac_t*
dns_lowac_create(isc_mem_t *mctx) {
	dns_lowac_t *lowac = isc_mem_get(mctx, sizeof(dns_lowac_t));
	ck_fifo_mpmc_entry_t *inq_stub = isc_mem_get(mctx, sizeof(ck_fifo_mpmc_entry_t));
	ck_fifo_mpmc_entry_t *remq_stub = isc_mem_get(mctx, sizeof(ck_fifo_mpmc_entry_t));
	
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
	isc_interval_set(&lowac->expiry, 60, 0);
	isc_thread_create(rthread, lowac, &lowac->thread);
	return (lowac);
}

void
dns_lowac_destroy(dns_lowac_t *lowac) {
	lowac->running = false;
	isc_thread_join(lowac->thread, NULL);
	dns_lowac_entry_t *entry;
	ck_fifo_mpmc_entry_t *fentry;
	while (ck_ht_count(&lowac->ht)>0) {
		ck_ht_gc(&lowac->ht, 0, 0);
		ck_ht_iterator_t htit = CK_HT_ITERATOR_INITIALIZER;
		ck_ht_entry_t *htitentry = NULL;
		while (ck_ht_next(&lowac->ht, &htit, &htitentry)) {
			entry = ck_ht_entry_value(htitentry);
			ck_ht_remove_spmc(&lowac->ht, entry->hash, htitentry);
			//fprintf(stderr, "XXX cleanup %p\n", entry);
			free_entry(lowac, entry);
		}
	}
	
	while (ck_fifo_mpmc_dequeue(&lowac->inq,
				    &entry,
				    &fentry))
	{
		isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));
		//fprintf(stderr, "XXX cleanup2 %p\n", entry);
		free_entry(lowac, entry);
	}

	while (ck_fifo_mpmc_dequeue(&lowac->remq,
				    &entry,
				    &fentry))
	{
		isc_mem_put(lowac->mctx, fentry, sizeof(*fentry));
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
	if (size > 1024) {
		return (ISC_R_FAILURE);
	}
	dns_lowac_entry_t *entry = isc_mem_get(lowac->mctx, sizeof(*entry));
	dns_name_init(&entry->name, NULL);
	dns_name_dup(name, lowac->mctx, &entry->name);
	memcpy(entry->blob, packet, size);
	isc_time_nowplusinterval(&entry->expire, &lowac->expiry);
	entry->blobsize = size;
	isc_region_t r;
	dns_name_toregion(&entry->name, &r);
	ck_ht_hash(&entry->hash, &lowac->ht, r.base, r.length);
	ck_fifo_mpmc_entry_t *qentry =
		isc_mem_get(lowac->mctx, (sizeof(ck_fifo_mpmc_entry_t)));
	ck_fifo_mpmc_enqueue(&lowac->inq, qentry, entry);
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
/*			ck_fifo_mpmc_entry_t *qentry =
				isc_mem_get(lowac->mctx, (sizeof(ck_fifo_mpmc_entry_t)));
			ck_fifo_mpmc_enqueue(&lowac->remq, qentry, entry); */
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
