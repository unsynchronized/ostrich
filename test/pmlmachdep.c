#include <pmlmachdep.h>
#include <pmltypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

u_int8_t *pml_md_getpbuf(struct pml_packet_info *ppi) {
    return ppi->pkt;
}

bool pml_md_putpbuf(struct pml_packet_info *ppi, u_int8_t *newpkt, u_int32_t newpktlen) {
    ppi->pkt = newpkt;
    ppi->pktlen = newpktlen;
    return 1;
}

void pml_md_debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

struct pmlvm_context *pml_md_alloc_context(void) {
    return calloc(1, sizeof(struct pmlvm_context));
}

bool pml_md_retrieve(struct pmlvm_context *ctx) {
    static u_int8_t XXXprog[] = {
        33
    };
    ctx->mlen = 0;
    ctx->m = NULL;
    if(ctx->prog != NULL) {
        free(ctx->prog);
        ctx->proglen = 0;
    }
    ctx->prog = malloc(sizeof(XXXprog));
    if(ctx->prog == NULL) {
        return 0;
    }
    memcpy(ctx->prog, XXXprog, sizeof(XXXprog));
    ctx->proglen = sizeof(XXXprog);
    return 1;
}

bool pml_md_save_program(struct pmlvm_context *ctx, u_int8_t *newprog, u_int32_t len) {
    void *oldprog = ctx->prog;
    ctx->prog = malloc(len);
    if(ctx->prog == NULL) {
        return 0;
    }
    if(oldprog != NULL) {
        free(oldprog);
    }
    memcpy(ctx->prog, newprog, len);
    ctx->proglen = len;
    return 1;
}
void pml_md_memmove(void *dest, const void *src, u_int32_t n) {
    memmove(dest, src, n);
}
