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

bool pml_md_retrieve(struct pmlvm_context *ctx) {
    static u_int8_t XXXprog[] = {
/*   0 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_P_N, PML_MOV_ADDR_A), 0x00, 0x00, 0x00, 0x60,
/*   6 */   PML_ADD, PML_MATH_N, 0x1, 0x1, 0x1, 0x1,

/*  12 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0x00, 0x00, 0x00, 0x10,
/*  18 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0x00, 0x00, 0x00, 0x0,
/*  24 */   PML_INSERT, PML_INSERT_M, 0x0, 0x0, 0x0, 0x0, 

/*  30 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0x11, 0x22, 0x33, 0x44,
/*  36 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_X, PML_MOV_ADDR_M_N), 0x0, 0x0, 0x0, 0x6,

/*  42 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0x00, 0x00, 0x00, 0x10,
/*  48 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0x00, 0x00, 0x00, 0x0,
/*  54 */   PML_DELETE, PML_INSERT_M, 0x0, 0x0, 0x0, 0x0, 

/*  60 */   PML_MOVS, PML_MOVS_TDB(PML_MOVS_P_LEN, PML_MOVS_ADDR_A), 0, 0, 0, 0,
/*  66 */   PML_MOVS, PML_MOVS_TDB(PML_MOVS_M_LEN, PML_MOVS_ADDR_X), 0, 0, 0, 0,
/*  72 */   PML_JLT, PML_JCOND_X, 0, 0, 0, 18,
/*  78 */   PML_SUB, PML_MATH_X, 0, 0, 0, 0,
/*  84 */   PML_INSERT, PML_INSERT_M, 0, 0, 0, 0,
/*  90 */   PML_MOVS, PML_MOVS_TDB(PML_MOVS_P_LEN, PML_MOVS_ADDR_A), 0, 0, 0, 0,
/*  96 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_Y), 0, 0, 0, 0,
/* 102 */   PML_COPY, PML_COPY_P_TO_M, 0, 0, 0, 0,
/* 108 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0, 0, 0, 14,
/* 114 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_P_N, PML_MOV_ADDR_Y), 0, 0, 0, 24,
/* 120 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0, 0, 0, 0,
/* 126 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_A, PML_MOV_ADDR_M_N), 0, 0, 0, 24,
/* 132 */   PML_CHECKSUM, PML_CHECKSUM_IPV4_M_X, 0, 0, 0, 0,
/* 138 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_A, PML_MOV_ADDR_M_N), 0, 0, 0, 24,

/* 144 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_P_N, PML_MOV_ADDR_Y), 0, 0, 0, 40,
/* 150 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0, 0, 0, 0,
/* 156 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_A, PML_MOV_ADDR_M_N), 0, 0, 0, 40,
/* 132 */   PML_CHECKSUM, PML_CHECKSUM_UDP4_M_X, 0, 0, 0, 0,

/*     */

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

