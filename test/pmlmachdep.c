#include <pmlmachdep.h>
#include <pmltypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

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
    fprintf(stderr, "\n");
    va_end(ap);
}

struct pmlvm_context *pml_md_alloc_context(void) {
    return calloc(1, sizeof(struct pmlvm_context));
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

void pml_md_memset(void *dest, u_int8_t b, u_int32_t sz) {
    memset(dest, b, sz);
}
void pml_md_memmove(void *dest, const void *src, u_int32_t n) {
    memmove(dest, src, n);
}

u_int32_t pml_md_currenttime(void) {
    return time(NULL);
}

/* beforehand: nbytes is checked, startoff must be <= the length */
bool pml_md_insert_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context) {
    const u_int32_t newsz = context->mlen + nbytes;
    printf("XXX: newsz: mlen 0x%x  nbytes 0x%x  0x%x\n", context->mlen, nbytes, newsz); /* XXX */
    u_int8_t *newm;
    if(context->mlen > 0) {
        newm = realloc(context->m, newsz);
        if(newm == NULL) {
            return 0;
        }
        if(startoff < context->mlen) {
            memmove(&newm[startoff+nbytes], &newm[startoff], (context->mlen)-startoff);
        }
        memset(&newm[startoff], 0, nbytes);
    } else {
        newm = calloc(1, newsz);
        if(newm == NULL) {
            return 0;
        }
    }
    context->m = newm;
    context->mlen = newsz;
    return 1;
}

bool pml_md_delete_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context) {
    if(context->mlen == 0) {
        DLOG("tried to DELETE from M when M was empty");
        return 0;
    }
    const u_int32_t newsz = context->mlen - nbytes;
    if(newsz == 0) {
        free(context->m);
        context->m = NULL;
        context->mlen = 0;
        return 1;
    }
    memmove(&context->m[startoff], &context->m[startoff+nbytes], nbytes);
    context->mlen = newsz;
    return 1;
}

/* XXX doc */
bool pml_md_insert_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo) {
    const u_int32_t newsz = pinfo->pktlen + nbytes;
    u_int8_t *newp;
    if(pinfo->pktlen > 0) {
        newp = realloc(pinfo->pkt, newsz);
        if(newp == NULL) {
            return 0;
        }
        if(startoff < pinfo->pktlen) {
            memmove(&newp[startoff+nbytes], &newp[startoff], (pinfo->pktlen)-startoff);
        }
        memset(&newp[startoff], 0, nbytes);
    } else {
        newp = calloc(1, newsz);
        if(newp == NULL) {
            return 0;
        }
    }
    pinfo->pkt = newp;
    pinfo->pktlen = newsz;
    return 1;
}

/* XXX doc */
bool pml_md_delete_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo) {
    if(pinfo->pktlen == 0) {
        DLOG("tried to DELETE from P when P was empty");
        return 0;
    }
    const u_int32_t newsz = pinfo->pktlen - nbytes;
    if(newsz == 0) {
        free(pinfo->pkt);
        pinfo->pkt = NULL;
        pinfo->pktlen = 0;
        return 1;
    }
    u_int8_t *p = pinfo->pkt;
    memmove(&p[startoff], &p[startoff+nbytes], nbytes);
    pinfo->pktlen = newsz;
    return 1;
}

