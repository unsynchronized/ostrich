#include <pmlvm.h>
#include <pmlmachdep.h>

static struct pmlvm_context *ctx = NULL;

static u_int32_t pc = 0, x = 0, y = 0, a = 0;
static bool processflag;
static struct pml_packet_info *curppi;

static void pml_copy(u_int8_t *p);
static void pml_mov(u_int8_t *p);

#define EXTRACT4(x) ((((u_int8_t)((x)[0])) << 24) \
                    | (((u_int8_t)((x)[1])) << 16) \
                    | (((u_int8_t)((x)[2])) << 8) \
                    | (((u_int8_t)((x)[3]))))

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

#define CHECK_MLEN check_mlen
static bool check_mlen(u_int32_t idx, u_int32_t len) {
    /* XXX: double check this is okay to prevent overflows */
    if(len == 0) {
        DLOG("CHECK_MLEN len is 0");
        return 0;
    }
    u_int32_t endidx = idx + len - 1;      /* intentional wraparound */
    if(endidx < idx) {
        return 0;
    }
    if(endidx < ctx->mlen) {
        return 1;
    } 
    return 0;
}

#define CHECK_PLEN check_plen
static bool check_plen(u_int32_t idx, u_int32_t len) {
    if(len == 0) {
        DLOG("CHECK_PLEN len is 0");
        return 0;
    }
    u_int32_t endidx = idx + len - 1;
    if(endidx < idx) {
        return 0;
    }
    if(endidx < curppi->pktlen) {
        return 1;
    }
    return 0;
}

static void pml_copy(u_int8_t *p) {
    const u_int8_t type = ctx->prog[pc+1];
    if(type == PML_COPY_M_TO_P) {
        if(CHECK_MLEN(x, a) == 0 || CHECK_PLEN(y, a) == 0) {
            a = 0;
            return;
        }
        pml_md_memmove(&p[y], &ctx->m[x], a);
    } else {
        if(CHECK_PLEN(x, a) == 0 || CHECK_MLEN(y, a) == 0) {
            a = 0;
            return;
        }
        pml_md_memmove(&ctx->m[y], &p[x], a);
    }
    a = 1;
}

static void pml_mov(u_int8_t *p) {
    u_int8_t dsb = ctx->prog[pc+1];
    u_int8_t src = PML_MOV_SRC(dsb), dst = PML_MOV_DST(dsb);
    if(src == dst || src > PML_MOV_MAX || dst > PML_MOV_MAX) {
        return;
    }
    u_int32_t n = EXTRACT4(&ctx->prog[pc+2]);
    if(ctx->prog[pc] == PML_MOVW) {
        u_int32_t srcval;
        switch(src) {
            case PML_MOV_ADDR_A: srcval = a; break;
            case PML_MOV_ADDR_X: srcval = x; break;
            case PML_MOV_ADDR_Y: srcval = y; break;
            case PML_MOV_ADDR_M_N: 
                if(CHECK_MLEN(n, 4) == 0) {
                    return;
                }
                srcval = (ctx->m[n] << 24)
                         | (ctx->m[n+1] << 16)
                         | (ctx->m[n+2] << 8)
                         | (ctx->m[n+3]);
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 4) == 0) {
                    return;
                }
                srcval = (p[n] << 24)
                         | (p[n+1] << 16)
                         | (p[n+2] << 8)
                         | (p[n+3]);
                break;
            case PML_MOV_ADDR_M_X_N: {
                u_int32_t i = n+x;   /* wraparound OK here */
                if(CHECK_MLEN(i, 4) == 0) {
                    return;
                }
                srcval = (ctx->m[i] << 24)
                         | (ctx->m[i+1] << 16)
                         | (ctx->m[i+2] << 8)
                         | (ctx->m[i+3]);
                }
                break;
        }

    }
}

/* check_crc32: returns 1 iff len > 0 and the area of size len bytes starting at buf
 * contains data with a crc32 matching crccheck.  returns 0 otherwise.
 */
bool check_crc32(u_int8_t *buf, u_int32_t len, u_int32_t crccheck) {
    /* XXX XXX XXX */
    return 1;
}

/* process the packet.  
 *
 * returns 1 if the packet buffer should be passed on; returns 0 if the packet
 * should be dropped.  if the return value is 1, then the pkt and pktlen values
 * inside pinfo will be updated; use those values.
 */
bool pmlvm_process(struct pml_packet_info *pinfo) {
    curppi = pinfo;
    processflag = 1;
    if(ctx == NULL || ctx->prog == NULL || ctx->proglen < 6) {
        return processflag;
    }
    u_int8_t *p = pml_md_getpbuf(pinfo);
    if(p == NULL) {
        return processflag;   
    }
    if((ctx->proglen % 6) != 0) {
        DLOG("proglen is invalid (not multiple of 6): %d", ctx->proglen);
        return processflag;
    }
    pc = x = y = a = 0;
    bool stopflag = 0;

    while(stopflag == 0 && pc < ctx->proglen) {
        const u_int8_t opcode = ctx->prog[pc];
        switch(opcode) {
            case PML_EXIT:
                stopflag = 1;
                break;
            /* XXX default */
            case PML_COPY:
                if(ctx->prog[pc+1] > PML_COPY_MAX) {
                    a = 0;
                } else {
                    pml_copy(p);
                }
                break;
            case PML_NEWPROG: {
                    const u_int8_t type = ctx->prog[pc+1];
                    u_int32_t crc = EXTRACT4(&ctx->prog[pc+2]);
                    if(type == PML_NEWPROG_P) {
                        if(CHECK_PLEN(x, a) == 0) {
                            a = 0;
                            break;
                        }
                        if(check_crc32(&p[x], a, crc) == 0) {
                            a = 0;
                            break;
                        }
                        if(pml_md_save_program(ctx, &p[x], a) == 0) {
                            a = 0;
                            break;
                        }
                        stopflag = 1;
                    } else if(type == PML_NEWPROG_M) {
                        if(CHECK_MLEN(x, a) == 0) {
                            a = 0;
                            break;
                        }
                        if(check_crc32(&ctx->m[x], a, crc) == 0) {
                            a = 0;
                            break;
                        }
                        if(pml_md_save_program(ctx, &ctx->m[x], a) == 0) {
                            a = 0;
                            break;
                        }
                        stopflag = 1;
                    } else {
                        a = 0;
                    }
                }
                break;
            case PML_MOVB:
            case PML_MOVW:
            case PML_MOVH:
                pml_mov(p);
                break;
        }
    }

    return processflag;
}
