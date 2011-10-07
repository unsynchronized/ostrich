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
struct pmlvm_context *pml_md_alloc_context(void);

/* pml_md_allocbuf: allocate a buffer to be freed by pml_md_free().  the buffer will
 * be initialized with zeroes. 
 * pml_md_allocbuf returns NULL if the allocations fails.
 */
void *pml_md_allocbuf(u_int32_t sz);
void pml_md_freebuf(void *buf);

/* XXX: doc */
void pml_md_free_context(struct pmlvm_context *ctx);

/* XXX: doc */
void pml_md_init(void);

/* pml_md_debug: safely log a debugging message; typically these are errors or
 * warnings.  only called when DEBUG is defined
 */
void pml_md_debug(const char *fmt, ...);

/* XXX doc */
void pml_md_debug_pkt(char *data);

/* pml_md_memmove: copies n bytes from src to dest; src and dest may be overlapping */
void pml_md_memmove(void *dest, const void *src, u_int32_t n);

/* pml_md_memset: fills sz bytes in dest with byte b */
void pml_md_memset(void *dest, u_int8_t b, u_int32_t sz);

/* pml_md_save_program: replace the currently-existing program (if one exists) with 
 * the specified data.  if successful, returns 1 and replaces the program in the
 * specified context with a copy of the data.  if unsuccessful, returns 0 and does
 * not change the existing program.
 */
bool pml_md_save_program(struct pmlvm_context *ctx, u_int8_t *newprog, u_int32_t len);

/* pml_md_currenttime: XXX clearer description */
u_int32_t pml_md_currenttime(void);

/* XXX doc */
bool pml_md_insert_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context);

/* XXX doc */
bool pml_md_insert_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo);

/* XXX doc */
bool pml_md_delete_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context);

/* XXX doc */
bool pml_md_delete_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo);

/* pml_md_divert: send a packet out the defined channel, if configured.  
 *   other channels may be configured by config commands.
 *
 *   returns 1 if the packet was successfully sent; 0 otherwise
 */
bool pml_md_divert(struct pmlvm_context *context, u_int8_t channel, u_int8_t *packet, u_int32_t packetlen);

extern int XXXprocessing;
extern u_int32_t XXXips;
extern u_int32_t XXXother;
extern u_int32_t XXXtapped;
extern u_int32_t XXXrxcount;
extern u_int32_t XXXfoo;
extern char XXXlastbuf[512];
#endif /* PML_MACHDEP */
