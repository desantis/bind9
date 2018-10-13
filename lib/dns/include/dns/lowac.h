#include <isc/mem.h>
#include <dns/name.h>
typedef struct dns_lowac_entry dns_lowac_entry_t;
typedef struct dns_lowac dns_lowac_t;

dns_lowac_t*
dns_lowac_create(isc_mem_t *mctx);

isc_result_t
dns_lowac_put(dns_lowac_t *lowac, dns_name_t *name, char* packet, int size);

isc_result_t
dns_lowac_get(dns_lowac_t *lowac, dns_name_t *name, char* blob, int* blobsize, bool tcp);



