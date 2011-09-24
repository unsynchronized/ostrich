#include <pmlvm.h>
#include <pmlmachdep.h>

static struct pml_context *ctx = NULL;

/* initialize pmlvm -- should be called only once.  will alloc the context, load all
 * necessary data, and get everything ready to process packets
 */
void pmlvm_init(void) {
    ctx = pml_md_alloc_context();
    if(ctx == NULL) {
        DLOG("pmlvm_init: context alloc failed");
        return;
    }
    if(pml_md_retrieve(ctx) == 0) {
        return;
    }
}

/* process the packet.  
 *
 * returns 1 if the packet buffer should be passed on; returns 0 if the packet
 * should be dropped.  if the return value is 1, then the pkt and pktlen values
 * inside pinfo will be updated; use those values.
 */
bool pmlvm_process(struct pml_packet_info *pinfo) {
    if(ctx == NULL || ctx->prog == NULL < ctx->proglen < 6) {
        return 1;
    }
    u_int8_t *p = pml_md_getpbuf(pinfo);
    if(p == NULL) {
        return 1;   
    }
    if((ctx->proglen % 6) != 0) {
        DLOG("proglen is invalid (not multiple of 6): %d", ctx->proglen);
        return 1;
    }

}
