#ifndef PML_MACHDEP
#define PML_MACHDEP

#include <pmltypes.h>
#include <pmlvm.h>

/* pml_md_getpbuf: get a u_int8_t pointer to the full packet described by the given
 * struct pml_packet_info.  
 *
 * returns the pointer on success, or NULL on failure.
 */
u_int8_t *pml_md_getpbuf(struct pml_packet_info *);

/* XXX: doc */
bool pml_md_putpbuf(struct pml_packet_info *, u_int8_t *newpkt, u_int32_t newpktlen);

/* XXX: doc */
struct pml_context *pml_md_alloc_context(void);

/* XXX: doc */
void pml_md_free_context(struct pml_context *ctx);

/* pml_md_retrieve: retrieve the contents of M from flash; returns 1 if it was
 * successfully retrieved (or empty) or 0 if an error occurred.
 *
 * after calling this, the context's m/mlen parameters will be valid either way.
 */
bool pml_md_retrieve(struct pml_context *ctx);

#endif /* PML_MACHDEP */
