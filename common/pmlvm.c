#include <pmlvm.h>
#include <pmlmachdep.h>
#include <pmlutils.h>
#ifdef DEBUG
#include <assert.h>   // XXX: remove
#define DASSERT(x) assert(x)
#else
#define DASSERT(x)
#endif  /* DEBUG */


static struct pmlvm_context *ctx = NULL;

static u_int32_t pc = 0, x = 0, y = 0, a = 0;
static bool processflag;
static struct pml_packet_info *curppi;

static void pml_copy(u_int8_t *p);
static void pml_mov(u_int8_t *p);
static void pml_sum_phdr4(u_int8_t *pkt, u_int16_t len, u_int32_t *sum);
static void pml_sum_comp(u_int8_t *buf, u_int16_t len, u_int32_t *sum);
static u_int16_t pml_sum_finish(u_int32_t sum);

/* pmlvm_current_context: return a valid pointer to the current PML context used by
 * the VM, if there is one; or NULL if there isn't.
 */
struct pmlvm_context *pmlvm_current_context(void) {
    return ctx;
}

/* initialize pmlvm -- should be called only once.  will alloc the context, load all
 * necessary data, and get everything ready to process packets
 */
void pmlvm_init(u_int8_t *program, u_int32_t proglen, u_int8_t *m, u_int32_t mlen) {
    ctx = pml_md_alloc_context();
    if(ctx == NULL) {
        DLOG("pmlvm_init: context alloc failed");
        return;
    }
    ctx->prog = program;
    ctx->proglen = proglen;
    ctx->m = m;
    ctx->mlen = mlen;
}

typedef union phdru { 
    u_int8_t buf[12];
    struct phdr {
        u_int8_t srcaddr[4];
        u_int8_t dstaddr[4];
        u_int8_t zero;
        u_int8_t protocol;
        u_int16_t len;
    } phdr;
} phdru;

/* calculate the sum of all 16-bit words in the TCP/UDP pseudoheader, given a pointer
 * to the start of an IPv4 packet and the length to be used in the calculation.
 *
 * The calculated sum is added to the value already stored in *sum.
 */
static void pml_sum_phdr4(u_int8_t *pkt, u_int16_t len, u_int32_t *sum) {
    phdru pu;
    pu.phdr.srcaddr[0] = pkt[12];
    pu.phdr.srcaddr[1] = pkt[13];
    pu.phdr.srcaddr[2] = pkt[14];
    pu.phdr.srcaddr[3] = pkt[15];
    pu.phdr.dstaddr[0] = pkt[16];
    pu.phdr.dstaddr[1] = pkt[17];
    pu.phdr.dstaddr[2] = pkt[18];
    pu.phdr.dstaddr[3] = pkt[19];
    pu.phdr.zero = 0;
    pu.phdr.protocol = pkt[9];
    pu.phdr.len = (len << 8) | (len >> 8);
    pml_sum_comp(pu.buf, 12, sum);
}

/* calculate the sum of all 16-bit words in the given buffer, padding with zeroes if
 * necessary.  the calculated sum is added to the value aready stored in *sum.
 */
static void pml_sum_comp(u_int8_t *buf, u_int16_t len, u_int32_t *sum) {
    u_int16_t *wptr = (u_int16_t *)buf;
    u_int32_t s = 0;
    while(len > 1) {
        s += *wptr;
        wptr++;
        len -= 2;
    }
    if(len == 1) {
        buf = (u_int8_t *)wptr;
        s += ((u_int16_t)((buf[0] & 0xff) ));
    }
    *sum = *sum + s;
}

/* finish calculating an ip checksum */
static u_int16_t pml_sum_finish(u_int32_t s) {
    int32_t sum = (u_int32_t)s;
    u_int16_t osum;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    osum = (~sum & 0xffff);
    return (osum << 8) | (osum >> 8);
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
    } else if(type == PML_COPY_P_TO_M) {
        if(CHECK_PLEN(x, a) == 0 || CHECK_MLEN(y, a) == 0) {
            a = 0;
            return;
        }
        pml_md_memmove(&ctx->m[y], &p[x], a);
    } else if(type == PML_COPY_ZERO_P) {
        if(CHECK_PLEN(y, a) == 0) {
            a = 0;
            return;
        }
        pml_md_memset(&p[y], 0, a);
    } else if(type == PML_COPY_ZERO_M) {
        if(CHECK_MLEN(y, a) == 0) {
            a = 0;
            return;
        }
        pml_md_memset(&ctx->m[y], 0, a);
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
            DASSERT(0);  /* XXX should be checking */
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
                DASSERT(0);  // XXX rm
                return;
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
                DASSERT(0);  // XXX rm
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
                DASSERT(0);  // XXX rm
                return;
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
                DASSERT(0);  // XXX rm
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
                DASSERT(0);  // XXX rm
                return;
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
                DASSERT(0);  // XXX rm
                break;
        }
    } else {
        DASSERT(0);  // XXX shouldn't happen
    }
}

/* type is beforehand to ensure it's a valid value */
void pml_checksum(const u_int8_t type) {
    u_int8_t *p = curppi->pkt;
    switch(type) {
        case PML_CHECKSUM_IPV4_M_X:
            {
                if(CHECK_MLEN(x, 1) == 0) {
                    DLOG("CHECKSUM IPV4 M[X] with too-short M");
                    a = 0;
                    return;
                }
                u_int16_t tlen = (ctx->m[x] & 0xf) * 4;
                if(CHECK_MLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM IPV4 M[X]: not enough space to accommodate len in header");
                    a = 0;
                    return;
                }
                u_int32_t sumtemp = 0;
                pml_sum_comp(&ctx->m[x], tlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_IPV4_P_X:
            {
                if(CHECK_PLEN(x, 1) == 0) {
                    DLOG("CHECKSUM IPV4 P[X] with too-short P");
                    a = 0;
                    return;
                }
                u_int16_t tlen = (p[x] & 0xf) * 4;
                if(CHECK_PLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM IPV4 P[X]: not enough space to accommodate len in header");
                    a = 0;
                    return;
                }
                u_int32_t sumtemp = 0;
                pml_sum_comp(&p[x], tlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_ICMP4_M_X:
            {
                if(CHECK_MLEN(x, 4) == 0) {
                    DLOG("CHECKSUM ICMP4 M[X] with too-short M");
                    a = 0;
                    return;
                }
                u_int16_t tlen = ((ctx->m[x+2] & 0xff) << 16) | (ctx->m[x+3] & 0xff);
                u_int16_t iphlen = (ctx->m[x] & 0xf) * 4;
                if(tlen <= iphlen) {
                    DLOG("CHECKSUM ICMP4 M[X]: total len is not larger than ip hdr len");
                    a = 0;
                    return;
                }
                if(CHECK_MLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM ICMP4 M[X]: not enough space to accommodate len in header");
                    a = 0;
                    return;
                }
                u_int32_t sumtemp = 0;
                pml_sum_comp(&ctx->m[x+iphlen], tlen-iphlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_ICMP4_P_X:
            {
                if(CHECK_PLEN(x, 4) == 0) {
                    DLOG("CHECKSUM ICMP4 P[X] with too-short P");
                    a = 0;
                    return;
                }
                u_int16_t tlen = ((p[x+2] & 0xff) << 16) | (p[x+3] & 0xff);
                u_int16_t iphlen = (p[x] & 0xf) * 4;
                if(tlen <= iphlen) {
                    DLOG("CHECKSUM ICMP4 P[X]: total len is not larger than ip hdr len");
                    a = 0;
                    return;
                }
                if(CHECK_PLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM ICMP4 P[X]: not enough space to accommodate len in header");
                    a = 0;
                    return;
                }
                u_int32_t sumtemp = 0;
                pml_sum_comp(&p[x+iphlen], tlen-iphlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_UDP4_M_X:
            {
                if(CHECK_MLEN(x, 4) == 0) {
                    DLOG("CHECKSUM UDP4 M[X] with too-short M");
                    a = 0;
                    return;
                }
                u_int16_t tlen = ((ctx->m[x+2] & 0xff) << 16) | (ctx->m[x+3] & 0xff);
                u_int16_t iphlen = (ctx->m[x] & 0xf) * 4;
                if(tlen < (iphlen + 8)) {
                    DLOG("CHECKSUM UDP4 M[X]: total len is too small");
                    a = 0;
                    return;
                }
                if(CHECK_MLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM UDP4 M[X]: not enough space to accommodate len");
                    a = 0;
                    return;
                }
                const u_int16_t udplen = ((ctx->m[x+iphlen+4] & 0xff) << 16) | (ctx->m[x+iphlen+5] & 0xff);
                u_int32_t sumtemp = 0;
                pml_sum_phdr4(&ctx->m[x], udplen, &sumtemp);
                pml_sum_comp(&ctx->m[x+iphlen], tlen-iphlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_UDP4_P_X:
            {
                if(CHECK_PLEN(x, 4) == 0) {
                    DLOG("CHECKSUM UDP4 P[X] with too-short P");
                    a = 0;
                    return;
                }
                u_int16_t tlen = ((p[x+2] & 0xff) << 16) | (p[x+3] & 0xff);
                u_int16_t iphlen = (p[x] & 0xf) * 4;
                if(tlen < (iphlen + 8)) {
                    DLOG("CHECKSUM UDP4 P[X]: total len is too small");
                    a = 0;
                    return;
                }
                if(CHECK_PLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM UDP4 P[X]: not enough space to accommodate len");
                    a = 0;
                    return;
                }
                const u_int16_t udplen = ((p[x+iphlen+4] & 0xff) << 16) | (p[x+iphlen+5] & 0xff);
                u_int32_t sumtemp = 0;
                pml_sum_phdr4(&p[x], udplen, &sumtemp);
                pml_sum_comp(&p[x+iphlen], tlen-iphlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_TCP4_M_X:
            {
                if(CHECK_MLEN(x, 4) == 0) {
                    DLOG("CHECKSUM TCP4 M[X] with too-short M");
                    a = 0;
                    return;
                }
                u_int16_t tlen = ((ctx->m[x+2] & 0xff) << 16) | (ctx->m[x+3] & 0xff);
                u_int16_t iphlen = (ctx->m[x] & 0xf) * 4;
                if(tlen < (iphlen + 20)) {
                    DLOG("CHECKSUM TCP4 M[X]: total len is too small");
                    a = 0;
                    return;
                }
                if(CHECK_MLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM TCP4 M[X]: not enough space to accommodate len");
                    a = 0;
                    return;
                }
                const u_int16_t tcplen = tlen-iphlen;
                u_int32_t sumtemp = 0;
                pml_sum_phdr4(&ctx->m[x], tcplen, &sumtemp);
                pml_sum_comp(&ctx->m[x+iphlen], tlen-iphlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
        case PML_CHECKSUM_TCP4_P_X:
            {
                if(CHECK_PLEN(x, 4) == 0) {
                    DLOG("CHECKSUM TCP4 P[X] with too-short P");
                    a = 0;
                    return;
                }
                u_int16_t tlen = ((p[x+2] & 0xff) << 16) | (p[x+3] & 0xff);
                u_int16_t iphlen = (p[x] & 0xf) * 4;
                if(tlen < (iphlen + 20)) {
                    DLOG("CHECKSUM TCP4 P[X]: total len is too small");
                    a = 0;
                    return;
                }
                if(CHECK_PLEN(x, tlen) == 0) {
                    DLOG("CHECKSUM TCP4 P[X]: not enough space to accommodate len");
                    a = 0;
                    return;
                }
                const u_int16_t tcplen = tlen-iphlen;
                u_int32_t sumtemp = 0;
                pml_sum_phdr4(&p[x], tcplen, &sumtemp);
                pml_sum_comp(&p[x+iphlen], tlen-iphlen, &sumtemp);
                a = pml_sum_finish(sumtemp);
            }
            break;
    }
}

#ifdef DEBUG
void hexdump(char *const buf, unsigned long size);

void pmlvm_debug(void) {
    if(ctx) {
        DLOG("p_d: mlen 0x%x  proglen 0x%x  pc 0x%x  a %08x  x %08x  y %08x", ctx->mlen, ctx->proglen, pc, a, x, y);
#if 0
        if(ctx->mlen > 0) {
            DLOG("m:");
            hexdump((char * const)ctx->m, ctx->mlen);
        }
#endif
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
 *
 * maxinsns is the maximum number of instructions to execute, period.
 */
bool pmlvm_process(struct pml_packet_info *pinfo, u_int32_t maxinsns) {
    curppi = pinfo;
    u_int32_t insncount = 0;
    const u_int32_t initialplen = pinfo->pktlen;
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

    while(insncount < maxinsns && stopflag == 0 && pc < ctx->proglen) {
        p = pml_md_getpbuf(pinfo);
        const u_int8_t opcode = ctx->prog[pc];
        //pml_md_debug("XXX pc %d a %08x x %08x y %08x", pc, a, x, y);
#ifdef DEBUG
        DLOG("%04d/%04d: PC % 4d: a %08x x %08x y %08x : %02x %02x %02x %02x %02x %02x", insncount, maxinsns, pc, a, x, y,
                (ctx->prog[pc] & 0xff), (ctx->prog[pc+1] & 0xff),
                (ctx->prog[pc+2] & 0xff), (ctx->prog[pc+3] & 0xff),
                (ctx->prog[pc+4] & 0xff), (ctx->prog[pc+5] & 0xff));
#endif
        insncount++;
        XXXrxcount++;
        switch(opcode) {
            case PML_SETFLAG:
                {
                    const u_int8_t type = ctx->prog[pc+1];
                    if(type != PML_FLAG_DELIVERPACKET) {
                        DLOG("invalid SETFLAG flag type: 0x%x", (u_int32_t)type);
                        break;
                    }
                    const u_int32_t n = EXTRACT4(&ctx->prog[pc+2]);
                    if(n > 1) {
                        DLOG("SETFLAG DELIVER_PACKET argument is invalid: 0x%x", n);
                        break;
                    }
                    processflag = (n == 0) ? 0 : 1;
                }
                break;
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
            case PML_MOVS: {
                    const u_int8_t tdb = ctx->prog[pc+1];
                    const int32_t n = (int32_t) EXTRACT4(&ctx->prog[pc+2]);
                    u_int8_t type = PML_MOVS_TYPE(tdb), dst = PML_MOVS_DST(tdb);
                    u_int32_t srcval = 0;
                    if(type > PML_MOVS_TYPE_MAX) {
                        DLOG("invalid MOVS type: 0x%x", type);
                        stopflag = 1;
                        break;
                    }
                    if(dst > PML_MOVS_DST_MAX) {
                        DLOG("invalid MOVS destination type: 0x%x", dst);
                        stopflag = 1;
                        break;
                    }
                    switch(type) {
                        case PML_MOVS_P_LEN:
                            srcval = pinfo->pktlen;
                            break;
                        case PML_MOVS_M_LEN:
                            srcval = ctx->mlen;
                            break;
                        case PML_MOVS_P_INITIALLEN:
                            srcval = initialplen;
                            break;
                        case PML_MOVS_TL_PROTO:
                            srcval = pinfo->tlproto;
                            break;
                        case PML_MOVS_IP_HDROFF:
                            srcval = pinfo->iphdroff;
                            break;
                        case PML_MOVS_ETH_HDROFF:
                            srcval = pinfo->ethhdroff;
                            break;
                        case PML_MOVS_IP4TL_HDROFF:
                            srcval = pinfo->ip4tlhdroff;
                            break;
                        case PML_MOVS_CUR_TIME:
                            srcval = pml_md_currenttime();
                            break;
                        case PML_MOVS_PC:
                            srcval = pc;
                            break;
                        default:
                            DASSERT(0);  // XXX: shouldn't get here
                            break;
                    }
                    switch(dst) {
                        case PML_MOVS_ADDR_A: 
                            a = srcval;
                            break;
                        case PML_MOVS_ADDR_X:
                            x = srcval;
                            break;
                        case PML_MOVS_ADDR_Y:
                            y = srcval;
                            break;
                        case PML_MOVS_ADDR_M_N:
                            if(CHECK_MLEN(n, 4) == 0) {
                                stopflag = 1;
                                break;
                            }
                            ctx->m[n] = ((srcval >> 24) & 0xff);
                            ctx->m[n+1] = ((srcval >> 16) & 0xff);
                            ctx->m[n+2] = ((srcval >> 8) & 0xff);
                            ctx->m[n+3] = (srcval & 0xff);
                            break;
                        case PML_MOVS_ADDR_P_N:
                            if(CHECK_PLEN(n, 4) == 0) {
                                stopflag = 1;
                                break;
                            }
                            p[n] = ((srcval >> 24) & 0xff);
                            p[n+1] = ((srcval >> 16) & 0xff);
                            p[n+2] = ((srcval >> 8) & 0xff);
                            p[n+3] = (srcval & 0xff);
                            break;
                        case PML_MOVS_ADDR_M_X_N: {
                                u_int32_t i = n+x;   /* wraparound OK here */
                                if(CHECK_MLEN(i, 4) == 0) {
                                    stopflag = 1;
                                    break;
                                }
                                ctx->m[i] = ((srcval >> 24) & 0xff);
                                ctx->m[i+1] = ((srcval >> 16) & 0xff);
                                ctx->m[i+2] = ((srcval >> 8) & 0xff);
                                ctx->m[i+3] = (srcval & 0xff);
                            }
                            break;
                        case PML_MOVS_ADDR_P_X_N: {
                                u_int32_t i = n+x;  /* wraparound OK here */
                                if(CHECK_PLEN(i, 4) == 0) {
                                    stopflag = 1;
                                    break;
                                }
                                p[i] = ((srcval >> 24) & 0xff);
                                p[i+1] = ((srcval >> 16) & 0xff);
                                p[i+2] = ((srcval >> 8) & 0xff);
                                p[i+3] = (srcval & 0xff);
                            }
                            break;
                        default:
                            DASSERT(0);  // XXX rm
                            break;
                    }
                }
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
                    y = pc;
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
                        y = pc;
                        pc = destpc;
                        continue;
                    }
                }
                break;
            case PML_INSERT: { 
                    if(a == 0) {
                        a = 1;
                        break;
                    }
                    const u_int8_t type = ctx->prog[pc+1];
                    if(type == PML_INSERT_M) {
                        if(x > ctx->mlen) {
                            DLOG("INSERT M offset in X is past the end of M");
                            stopflag = 1;
                            break;
                        }
                        a = pml_md_insert_m(a, x, ctx);
                    } else if(type == PML_INSERT_P) {
                        if(x > pinfo->pktlen) {
                            DLOG("INSERT P offset in X is past the end of P");
                            stopflag = 1;
                            break;
                        }
                        a = pml_md_insert_p(a, x, pinfo);
                    } else {
                        DLOG("invalid INSERT type: 0x%x", type);
                        stopflag = 1;
                        break;
                    }
                }
                break;
            case PML_DELETE: {
                    if(a == 0) {
                        a = 1;
                        break;
                    }
                    const u_int8_t type = ctx->prog[pc+1];
                    if(type == PML_DELETE_M) {
                        if(x >= ctx->mlen) {
                            DLOG("DELETE M offset in X is past the end of M");
                            stopflag = 1;
                            break;
                        }
                        if((ctx->mlen - x) < a) {
                            DLOG("DELETE M length extends past the end of M");
                            stopflag = 1;
                            break;
                        }
                        a = pml_md_delete_m(a, x, ctx);
                    } else if(type == PML_DELETE_P) {
                        if(x >= pinfo->pktlen) {
                            DLOG("DELETE P offset in X is past the end of P");
                            stopflag = 1;
                            break;
                        }
                        if((pinfo->pktlen - x) < a) {
                            DLOG("DELETE M length extends past the end of M");
                        }
                        a = pml_md_delete_p(a, x, pinfo);
                    } else {
                        DLOG("invalid DELETE type: 0x%x", type);
                        stopflag = 1;
                        break;
                    }
                }
                break;
            case PML_DIVERT_M:
                {
                    const u_int8_t channel = ctx->prog[pc+1];
                    const int32_t n = (int32_t) EXTRACT4(&ctx->prog[pc+2]);
                    if(CHECK_MLEN(x, n) == 0) {
                        DLOG("DIVERT M: exists past end of M x 0x%x n 0x%x", x, n);
                        a = 0;
                        break;
                    }
                    if(pml_md_divert(ctx, channel, &ctx->m[x], n)) {
                        a = 1;
                    } else {
                        a = 0;
                    }
                }
                break;
            case PML_DIVERT_P:
                {
                    const u_int8_t channel = ctx->prog[pc+1];
                    const int32_t n = (int32_t) EXTRACT4(&ctx->prog[pc+2]);
                    pml_md_debug("XXXPDP A");
                    if(CHECK_PLEN(x, n) == 0) {
                        DLOG("DIVERT P: exists past end of P x 0x%x n 0x%x", x, n);
                        a = 0;
                        break;
                    }
                    pml_md_debug("XXXPDP B");
                    if(pml_md_divert(ctx, channel, &p[x], n)) {
                        a = 1;
                    } else {
                        a = 0;
                    }
                }
                break;
            case PML_FIND:
                {
                    if(a == 0 || CHECK_PLEN(x, a) == 0 || CHECK_MLEN(y, a)) {
                        a = 0;
                        break;
                    }
                    /* XXX: investigate knuth-morris-pratt on packet-sized matches */
                    const u_int32_t len = a;
                    u_int32_t pi = x, mi;
                    a = 0;
                    for(; pi < pinfo->pktlen - (len - 1); pi++) {
                        if(p[pi] == ctx->m[y]) {
                            for(mi = 1; mi < len; mi++) {
                                if(p[pi+mi] != ctx->m[y+mi]) {
                                    break;
                                }
                            }
                            if(mi == len) {
                                a = 1;
                                x = pi;
                                break;
                            } 
                        }
                    }
                }
                break;
            case PML_CHECKSUM:
                {
                    const u_int8_t type = ctx->prog[pc+1];
                    if(type >= PML_CHECKSUM_MAX) {
                        DLOG("invalid checksum type: %x\n", type);
                        a = 0;
                        break;
                    }
                    pml_checksum(type);
                }
                break;
            default:
                DLOG("invalid PML instruction: 0x%x", opcode);
                stopflag = 1;
                break;
        }
        pc += 6;
    }
    //struct sk_buff *skb = (struct sk_buff *)pinfo->md_ptr; pml_md_debug("proc ic %d  in_irq %d  skbusers %d xx", insncount, in_irq(), atomic_read(&skb->users));   /* XXX */

    return processflag;
}
