#include <pmlvm.h>
#include <pmlmachdep.h>
#include <assert.h>   // XXX: remove

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
#define EXTRACT2(x) ((((u_int8_t)((x)[0])) << 8) | (((u_int8_t)((x)[1]))))

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

static void pml_math(u_int8_t opcode) {
    const u_int8_t type = ctx->prog[pc+1];
    u_int32_t roperand;
    if(type == PML_MATH_N) {
        roperand = EXTRACT4(&ctx->prog[pc+2]);
    } else if(type == PML_MATH_X) {
        roperand = x;
    } else if(type == PML_MATH_Y) {
        roperand = y;
    } else {        /* XXX: should be checking before getting here */
        return;
    }
    switch(opcode) {
        case PML_ADD:
            a = a + roperand;
            break;
        case PML_SUB:
            a = a - roperand;
            break;
        case PML_MUL:
            a = a * roperand;
            break;
        case PML_DIV:
            if(roperand == 0) {
                a = 0;
            } else {
                a = a / roperand;
            }
            break;
        case PML_AND:
            a = a & roperand;
            break;
        case PML_OR:
            a = a | roperand;
            break;
        case PML_XOR:
            a = a ^ roperand;
            break;
        case PML_SHL:
            a = a << roperand;
            break;
        case PML_SHR:
            a = a >> roperand;
            break;
        default:
            assert(0);  /* XXX should be checking */
            break;
    }
}
static void pml_mov(u_int8_t *p) {
    u_int8_t dsb = ctx->prog[pc+1];
    u_int8_t src = PML_MOV_SRC(dsb), dst = PML_MOV_DST(dsb);
    if(src == dst || src > PML_MOV_MAX || dst > PML_MOV_DST_MAX) {
        return;
    }
    u_int32_t n = EXTRACT4(&ctx->prog[pc+2]);
    if(ctx->prog[pc] == PML_MOVW) {
        u_int32_t srcval;
        switch(src) {
            case PML_MOV_ADDR_A: 
                srcval = a; 
                break;
            case PML_MOV_ADDR_X: 
                srcval = x; 
                break;
            case PML_MOV_ADDR_Y: 
                srcval = y; 
                break;
            case PML_MOV_ADDR_N: 
                srcval = n; 
                break;
            case PML_MOV_ADDR_COMP_A: 
                srcval = ~(a); 
                break;
            case PML_MOV_ADDR_NEG_A: {
                    int32_t nega = (int32_t)a;  /* intentional cast */
                    nega = -nega;
                    srcval = (u_int32_t)nega;   /* intentional cast */
                }
                break;
            case PML_MOV_ADDR_M_N: 
                if(CHECK_MLEN(n, 4) == 0) {
                    return;
                }
                srcval = EXTRACT4(&ctx->m[n]);
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 4) == 0) {
                    return;
                }
                srcval = EXTRACT4(&p[n]);
                break;
            case PML_MOV_ADDR_M_X_N: {
                    u_int32_t i = n+x;   /* wraparound OK here */
                    if(CHECK_MLEN(i, 4) == 0) {
                        return;
                    }
                    srcval = EXTRACT4(&ctx->m[i]);
                }
                break;
            case PML_MOV_ADDR_P_X_N: {
                    u_int32_t i = n+x;  /* wraparound OK here */
                    if(CHECK_PLEN(i, 4) == 0) {
                        return;
                    }
                    srcval = EXTRACT4(&p[i]);
                }
                break;
            case PML_MOV_ADDR_IP4HDR_P:
                if(CHECK_PLEN(x, 1) == 0) {
                    return;
                }
                srcval = 4 * (p[x] & 0xf);
                break;
            case PML_MOV_ADDR_IP4HDR_M:
                if(CHECK_MLEN(x, 1) == 0) {
                    return;
                }
                srcval = 4 * (ctx->m[x] & 0xf);
                break;
            default:
                assert(0);  // XXX rm
                break;
        }
        switch(dst) {
            case PML_MOV_ADDR_A: 
                a = srcval;
                break;
            case PML_MOV_ADDR_X:
                x = srcval;
                break;
            case PML_MOV_ADDR_Y:
                y = srcval;
                break;
            case PML_MOV_ADDR_M_N:
                if(CHECK_MLEN(n, 4) == 0) {
                    return;
                }
                ctx->m[n] = ((srcval >> 24) & 0xff);
                ctx->m[n+1] = ((srcval >> 16) & 0xff);
                ctx->m[n+2] = ((srcval >> 8) & 0xff);
                ctx->m[n+3] = (srcval & 0xff);
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 4) == 0) {
                    return;
                }
                p[n] = ((srcval >> 24) & 0xff);
                p[n+1] = ((srcval >> 16) & 0xff);
                p[n+2] = ((srcval >> 8) & 0xff);
                p[n+3] = (srcval & 0xff);
                break;
            case PML_MOV_ADDR_M_X_N: {
                    u_int32_t i = n+x;   /* wraparound OK here */
                    if(CHECK_MLEN(i, 4) == 0) {
                        return;
                    }
                    ctx->m[i] = ((srcval >> 24) & 0xff);
                    ctx->m[i+1] = ((srcval >> 16) & 0xff);
                    ctx->m[i+2] = ((srcval >> 8) & 0xff);
                    ctx->m[i+3] = (srcval & 0xff);
                }
                break;
            case PML_MOV_ADDR_P_X_N: {
                    u_int32_t i = n+x;  /* wraparound OK here */
                    if(CHECK_PLEN(i, 4) == 0) {
                        return;
                    }
                    p[i] = ((srcval >> 24) & 0xff);
                    p[i+1] = ((srcval >> 16) & 0xff);
                    p[i+2] = ((srcval >> 8) & 0xff);
                    p[i+3] = (srcval & 0xff);
                }
                break;
            default:
                assert(0);  // XXX rm
                break;
        }
    } else if(ctx->prog[pc] == PML_MOVH) {
        u_int16_t srcval;
        switch(src) {
            case PML_MOV_ADDR_A: 
                srcval = (a & 0xffff); 
                break;
            case PML_MOV_ADDR_X: 
                srcval = (x & 0xffff);
                break;
            case PML_MOV_ADDR_Y: 
                srcval = (y & 0xffff); 
                break;
            case PML_MOV_ADDR_N: 
                srcval = (n & 0xffff); 
                break;
            case PML_MOV_ADDR_COMP_A: 
                srcval = ~((a & 0xffff)); 
                break;
            case PML_MOV_ADDR_NEG_A: {
                    srcval = (a & 0xffff);
                    int16_t nega = (int16_t)srcval;  /* intentional cast */
                    nega = -nega;
                    srcval = (u_int16_t)nega;   /* intentional cast */
                }
                break;
            case PML_MOV_ADDR_M_N: 
                if(CHECK_MLEN(n, 2) == 0) {
                    return;
                }
                srcval = EXTRACT2(&ctx->m[n]);
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 2) == 0) {
                    return;
                }
                srcval = EXTRACT2(&p[n]);
                break;
            case PML_MOV_ADDR_M_X_N: {
                    u_int32_t i = n+x;   /* wraparound OK here */
                    if(CHECK_MLEN(i, 2) == 0) {
                        return;
                    }
                    srcval = EXTRACT2(&ctx->m[i]);
                }
                break;
            case PML_MOV_ADDR_P_X_N: {
                    u_int32_t i = n+x;  /* wraparound OK here */
                    if(CHECK_PLEN(i, 2) == 0) {
                        return;
                    }
                    srcval = EXTRACT2(&p[i]);
                }
                break;
            case PML_MOV_ADDR_IP4HDR_P:
                if(CHECK_PLEN(x, 1) == 0) {
                    return;
                }
                srcval = 4 * (p[x] & 0xf);
                break;
            case PML_MOV_ADDR_IP4HDR_M:
                if(CHECK_MLEN(x, 1) == 0) {
                    return;
                }
                srcval = 4 * (ctx->m[x] & 0xf);
                break;
            default:
                assert(0);  // XXX rm
                break;
        }
        switch(dst) {
            case PML_MOV_ADDR_A: 
                a = (a & 0xffff0000) | srcval;
                break;
            case PML_MOV_ADDR_X:
                x = (x & 0xffff0000) | srcval;
                break;
            case PML_MOV_ADDR_Y:
                y = (y & 0xffff0000) | srcval;
                break;
            case PML_MOV_ADDR_M_N:
                if(CHECK_MLEN(n, 2) == 0) {
                    return;
                }
                ctx->m[n] = ((srcval >> 8) & 0xff);
                ctx->m[n+1] = (srcval & 0xff);
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 2) == 0) {
                    return;
                }
                p[n] = ((srcval >> 8) & 0xff);
                p[n+1] = (srcval & 0xff);
                break;
            case PML_MOV_ADDR_M_X_N: {
                    u_int32_t i = n+x;   /* wraparound OK here */
                    if(CHECK_MLEN(i, 2) == 0) {
                        return;
                    }
                    ctx->m[i] = ((srcval >> 8) & 0xff);
                    ctx->m[i+1] = (srcval & 0xff);
                }
                break;
            case PML_MOV_ADDR_P_X_N: {
                    u_int32_t i = n+x;  /* wraparound OK here */
                    if(CHECK_PLEN(i, 2) == 0) {
                        return;
                    }
                    p[i] = ((srcval >> 8) & 0xff);
                    p[i+1] = (srcval & 0xff);
                }
                break;
            default:
                assert(0);  // XXX rm
                break;
        }
    } else if(ctx->prog[pc] == PML_MOVB) {
        u_int8_t srcval;
        switch(src) {
            case PML_MOV_ADDR_A: 
                srcval = (a & 0xff); 
                break;
            case PML_MOV_ADDR_X: 
                srcval = (x & 0xff);
                break;
            case PML_MOV_ADDR_Y: 
                srcval = (y & 0xff); 
                break;
            case PML_MOV_ADDR_N: 
                srcval = (n & 0xff); 
                break;
            case PML_MOV_ADDR_COMP_A: 
                srcval = ~(a & 0xff); 
                break;
            case PML_MOV_ADDR_NEG_A: {
                    srcval = (a & 0xff);
                    int8_t nega = (int8_t)srcval;  /* intentional cast */
                    nega = -nega;
                    srcval = (u_int8_t)nega;   /* intentional cast */
                }
                break;
            case PML_MOV_ADDR_M_N: 
                if(CHECK_MLEN(n, 1) == 0) {
                    return;
                }
                srcval = ctx->m[n];
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 1) == 0) {
                    return;
                }
                srcval = p[n];
                break;
            case PML_MOV_ADDR_M_X_N: {
                    u_int32_t i = n+x;   /* wraparound OK here */
                    if(CHECK_MLEN(i, 1) == 0) {
                        return;
                    }
                    srcval = ctx->m[i];
                }
                break;
            case PML_MOV_ADDR_P_X_N: {
                    u_int32_t i = n+x;  /* wraparound OK here */
                    if(CHECK_PLEN(i, 1) == 0) {
                        return;
                    }
                    srcval = p[i];
                }
                break;
            case PML_MOV_ADDR_IP4HDR_P:
                if(CHECK_PLEN(x, 1) == 0) {
                    return;
                }
                srcval = 4 * (p[x] & 0xf);
                break;
            case PML_MOV_ADDR_IP4HDR_M:
                if(CHECK_MLEN(x, 1) == 0) {
                    return;
                }
                srcval = 4 * (ctx->m[x] & 0xf);
                break;
            default:
                assert(0);  // XXX rm
                break;
        }
        switch(dst) {
            case PML_MOV_ADDR_A: 
                a = (a & 0xffffff00) | srcval;
                break;
            case PML_MOV_ADDR_X:
                x = (x & 0xffffff00) | srcval;
                break;
            case PML_MOV_ADDR_Y:
                y = (y & 0xffffff00) | srcval;
                break;
            case PML_MOV_ADDR_M_N:
                if(CHECK_MLEN(n, 1) == 0) {
                    return;
                }
                ctx->m[n] = srcval;
                break;
            case PML_MOV_ADDR_P_N:
                if(CHECK_PLEN(n, 1) == 0) {
                    return;
                }
                p[n] = srcval;
                break;
            case PML_MOV_ADDR_M_X_N: {
                    u_int32_t i = n+x;   /* wraparound OK here */
                    if(CHECK_MLEN(i, 1) == 0) {
                        return;
                    }
                    ctx->m[i] = srcval;
                }
                break;
            case PML_MOV_ADDR_P_X_N: {
                    u_int32_t i = n+x;  /* wraparound OK here */
                    if(CHECK_PLEN(i, 1) == 0) {
                        return;
                    }
                    p[i] = srcval;
                }
                break;
            default:
                assert(0);  // XXX rm
                break;
        }
    } else {
        assert(0);  // XXX shouldn't happen
    }
}

#ifdef DEBUG
void pmlvm_debug(void) {
    if(ctx) {
        DLOG("p_d: mlen 0x%x  proglen 0x%x  pc 0x%x  a %08x  x %08x  y %08x", ctx->mlen, ctx->proglen, pc, a, x, y);
    } else {
        DLOG("p_d: no ctx");
    }
}
#endif

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
        DLOG("program too short");
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
            case PML_ADD:
            case PML_SUB:
            case PML_MUL:
            case PML_DIV:
            case PML_AND:
            case PML_OR:
            case PML_XOR:
            case PML_SHL:
            case PML_SHR:
                if(ctx->prog[pc+1] > 2) {
                    DLOG("invalid math source specifier");
                    stopflag = 1;
                    break;
                }
                pml_math(opcode);
                break;
            default:
                assert(0);  // XXX nothing
                stopflag = 1;
                break;
            case PML_JMP: {
                    const u_int8_t type = ctx->prog[pc+1];
                    const int32_t n = (int32_t) EXTRACT4(&ctx->prog[pc+2]);
                    u_int32_t destpc;
                    if(type == PML_JMP_OFF_N) {
                        destpc = pc + n;        /* wraparound okay here */
                    } else if(type == PML_JMP_OFF_A_N) {
                        destpc = pc + a + n;    /* wraparound okay here */
                    } else {
                        DLOG("invalid JMP offset type");
                        stopflag = 1;
                        break;
                    }
                    if(destpc >= ctx->proglen || (destpc % 6) != 0) {
                        DLOG("invalid JMP offset: 0x%x", destpc);
                        stopflag = 1;
                        break;
                    }
                    pc = destpc;
                    continue;
                }
                break;
            case PML_JGT:
            case PML_JLT:
            case PML_JGE:
            case PML_JLE:
            case PML_JEQ:
            case PML_JSET: {
                    const u_int8_t type = ctx->prog[pc+1];
                    const int32_t n = (int32_t) EXTRACT4(&ctx->prog[pc+2]);
                    u_int32_t roperand, destpc;
                    if(type == PML_JCOND_0) {
                        roperand = 0;
                    } else if(type == PML_JCOND_X) {
                        roperand = x;
                    } else if(type == PML_JCOND_Y) {
                        roperand = y;
                    } else {
                        DLOG("invalid conditional jump offset type");
                        stopflag = 1;
                        break;
                    }
                    destpc = pc + n;        /* wraparound okay here */
                    if(destpc >= ctx->proglen || (destpc % 6) != 0) {
                        DLOG("invalid conditional jump offset: 0x%x", destpc);
                        stopflag = 1;
                        break;
                    }
                    bool branch = 0;
                    switch(opcode) {
                        case PML_JGT:
                            branch = (a > roperand) ? 1 : 0;
                            break;
                        case PML_JLT:
                            branch = (a < roperand) ? 1 : 0;
                            break;
                        case PML_JGE:
                            branch = (a >= roperand) ? 1 : 0;
                            break;
                        case PML_JLE:
                            branch = (a <= roperand) ? 1 : 0;
                            break;
                        case PML_JEQ:
                            branch = (a == roperand) ? 1 : 0;
                            break;
                        case PML_JSET: 
                            branch = ((a & roperand) != 0) ? 1 : 0;
                            break;
                    }
                    if(branch) {
                        pc = destpc;
                        continue;
                    }
                }
                break;
        }
        pc += 6;
    }

    return processflag;
}
