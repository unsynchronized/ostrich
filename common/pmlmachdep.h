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

/* pml_md_alloc_context: allocate a new instance of a struct pmlvm_context.  returns
 * a pointer to the new struct or NULL on failure
 * */
struct pmlvm_context *pml_md_alloc_context(void);

/* pml_md_allocbuf: allocate a buffer to be freed by pml_md_free().  the buffer will
 * be initialized with zeroes. 
 * pml_md_allocbuf returns NULL if the allocations fails.
 */
void *pml_md_allocbuf(u_int32_t sz);
void pml_md_freebuf(void *buf);

/* pml_md_free_context: frees a pmlvm_context previously allocated with
 * pml_md_alloc_context. 
 * */
void pml_md_free_context(struct pmlvm_context *ctx);

/* pml_md_init: initialize data for PML.  this is called once, when the device starts
 * up; the implementation should init all system-wide state here.
 */
void pml_md_init(void);

/* pml_md_debug: safely log a debugging message; typically these are errors or
 * warnings.  only called when DEBUG is defined
 */
void pml_md_debug(const char *fmt, ...);

/* pml_md_debug_pkt: log a preformatted debugging message.  data must be a C string;
 * strlen() or an analogue will be used to determine its length.
 * */
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

/* pml_md_currenttime: return a machine-dependent value that represents the current
 * time of day (ideally: seconds since UNIX epoch).  in any case, it must be
 * increasing!
 */
u_int32_t pml_md_currenttime(void);

/* pml_md_insert_m: attempt to insert nbytes bytes into M starting at offset
 * startoff.  startoff must be less than or equal to the current length of M.  any
 * previously-existing data located at M[startoff] will be moved to
 * M[startoff+nbytes].  The data from M[startoff] to M[startoff+nbytes-1] will be
 * filled with zeroes.
 *
 * if everything succeeds, returns 1; otherwise, if another error occurs (such as an
 * allocation failure), nothing will change in the context and 0 will be returned.
 */
bool pml_md_insert_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context);

/* pml_md_insert_p: attempt to insert nbytes bytes into P starting at offset
 * startoff.  startoff must be less than or equal to the current length of P.  any
 * previously-existing data located at P[startoff] will be moved to
 * P[startoff+nbytes].  The data from P[startoff] to P[startoff+nbytes-1] will be
 * filled with zeroes.
 *
 * if everything succeeds, returns 1; otherwise, if another error occurs (such as an
 * allocation failure), nothing will change in the context and 0 will be returned.
 */
bool pml_md_insert_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo);

/* pml_md_delete_m: delete nbytes bytes from M, starting at offset startoff.  any
 * data located at M[startoff+nbytes] and beyond will be moved to M[startoff].
 *
 * returns 1 on success; on failure, changes nothing and returns 0.
 */
bool pml_md_delete_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context);

/* pml_md_delete_m: delete nbytes bytes from P, starting at offset startoff.  any
 * data located at P[startoff+nbytes] and beyond will be moved to P[startoff].
 *
 * returns 1 on success; on failure, changes nothing and returns 0.
 */
bool pml_md_delete_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo);

/* pml_md_divert: send a packet out the defined channel, if configured.  
 *   other channels may be configured by config commands.
 *
 *   returns 1 if the packet was successfully sent; 0 otherwise
 */
bool pml_md_divert(struct pmlvm_context *context, u_int8_t channel, u_int8_t *packet, u_int32_t packetlen);

extern int XXXprocessing;
#endif /* PML_MACHDEP */
