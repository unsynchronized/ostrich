#ifndef PMLVM_H
#define PMLVM_H

#include <pmltypes.h>

#ifdef DEBUG
#define DLOG(fmt, ...) do { \
        pml_md_debug(fmt, ## __VA_ARGS__); \
    } while(0);
#else
#define DLOG(fmt, ...) 
#endif /* DEBUG */

#define TLPROTO_UNKNOWN  0
#define TLPROTO_80213    1

/* pml_packet_info: used to describe the packet to be processed.  This includes a
 * pointer to the packet itself as well as the data for most of the special variables
 * accessed via the MOVS instruction.
 */
typedef struct pml_packet_info {
    void *pkt; 
    u_int32_t pktlen;
    u_int32_t iphdroff;
    u_int32_t ethhdroff;
    u_int32_t ip4tlhdroff;
    u_int32_t vlantag;
    u_int8_t tlproto;

    struct {
        unsigned int has_iphdroff : 1;
        unsigned int has_ethhdroff : 1;
        unsigned int has_ip4tlhdroff : 1;
        unsigned int has_vlantag : 1;
    } flags;
} pml_packet_info;

/* XXX: doc */
struct pmlvm_context {
    u_int8_t *m;            /* pointer to M */
    u_int32_t mlen;         /* current length of M (bytes) */
    u_int8_t *prog;         /* program code */
    u_int32_t proglen;      /* program code len (bytes) */

    void *md_ptr;           /* free pointer; machdep layer is free to populate */
};

/* XXX: document */
struct pmlvm_context *pmlvm_current_context(void);

void pmlvm_init(u_int8_t *program, u_int32_t proglen, u_int8_t *m, u_int32_t mlen);

/* XXX: document */
bool pmlvm_process(struct pml_packet_info *pinfo);


/* PML instructions */
#define PML_EXIT        0x0
#define PML_EXEC        0x1
#define PML_DIVERT_M    0x2
#define PML_DIVERT_P    0x3
#define PML_INSERT      0x4
#define PML_DELETE      0x5
#define PML_COPY        0x6
#define PML_FIND        0x7
#define PML_CHECKSUM    0x8
#define PML_SETFLAG     0x9
#define PML_NEWPROG     0xA
#define PML_MOVB        0x10
#define PML_MOVW        0x11
#define PML_MOVH        0x12
#define PML_MOVS        0x13
#define PML_ADD         0x20
#define PML_SUB         0x21
#define PML_MUL         0x22
#define PML_DIV         0x23
#define PML_AND         0x24
#define PML_OR          0x25
#define PML_XOR         0x26
#define PML_SHL         0x27
#define PML_SHR         0x28
#define PML_JMP         0x30
#define PML_JGT         0x31
#define PML_JLT         0x32
#define PML_JGE         0x33
#define PML_JLE         0x34
#define PML_JEQ         0x35
#define PML_JSET        0x36

/* EXEC */
#define PML_EXEC_P 0
#define PML_EXEC_M 1

/* DIVERT */
#define PML_CHANNEL_RAW 0xff
#define PML_CHANNEL_IP 0xfe

/* INSERT */
#define PML_INSERT_M 0x0
#define PML_INSERT_P 0x1

/* DELETE */
#define PML_DELETE_M 0x0
#define PML_DELETE_P 0x1

/* COPY */
#define PML_COPY_M_TO_P 0x0
#define PML_COPY_P_TO_M 0x1
#define PML_COPY_ZERO_P 0x2
#define PML_COPY_ZERO_M 0x3
#define PML_COPY_MAX    0x3

/* CHECKSUM */
#define PML_CHECKSUM_IPV4_M_X   0x0
#define PML_CHECKSUM_IPV4_P_X   0x1
#define PML_CHECKSUM_ICMP4_M_X  0x2
#define PML_CHECKSUM_ICMP4_P_X  0x3
#define PML_CHECKSUM_UDP4_M_X   0x4
#define PML_CHECKSUM_UDP4_P_X   0x5
#define PML_CHECKSUM_TCP4_M_X   0x6
#define PML_CHECKSUM_TCP4_P_X   0x7
#define PML_CHECKSUM_MAX        0x7     /* don't forget to update */

/* SETFLAG */
#define PML_FLAG_DELIVERPACKET 0x0
#define PML_FLAG_MAX 0x0

/* NEWPROG */
#define PML_NEWPROG_M 0
#define PML_NEWPROG_P 1

/* MOV */
#define PML_MOV_SRC(x) ((x) & 0xf)
#define PML_MOV_DST(x) (((x) >> 4) & 0xf)
#define PML_MOV_DSB(src, dst) (((src) & 0xf) | (((dst) & 0xf) << 4))

#define PML_MOV_ADDR_A          0
#define PML_MOV_ADDR_X          1
#define PML_MOV_ADDR_Y          2
#define PML_MOV_ADDR_M_N        3
#define PML_MOV_ADDR_P_N        4
#define PML_MOV_ADDR_M_X_N      5
#define PML_MOV_ADDR_P_X_N      6
#define PML_MOV_ADDR_N          7
#define PML_MOV_ADDR_COMP_A     8
#define PML_MOV_ADDR_NEG_A      9
#define PML_MOV_ADDR_IP4HDR_P   10
#define PML_MOV_ADDR_IP4HDR_M   11
#define PML_MOV_DST_MAX         6  /* don't forget to update */
#define PML_MOV_MAX             11 /* don't forget to update */


/* MOVS */
#define PML_MOVS_TYPE(x) ((x) & 0xf)
#define PML_MOVS_DST(x) (((x) >> 4) & 0xf)
#define PML_MOVS_TDB(type, dst) (((type) & 0xf) | (((dst) & 0xf) << 4))

#define PML_MOVS_P_LEN          0
#define PML_MOVS_M_LEN          1
#define PML_MOVS_P_INITIALLEN   2
#define PML_MOVS_TL_PROTO       3
#define PML_MOVS_IP_HDROFF      4
#define PML_MOVS_ETH_HDROFF     5
#define PML_MOVS_IP4TL_HDROFF   6
#define PML_MOVS_CUR_TIME       7
#define PML_MOVS_PC             8
#define PML_MOVS_TYPE_MAX       8 /* don't forget to update */

#define PML_MOVS_ADDR_A          0
#define PML_MOVS_ADDR_X          1
#define PML_MOVS_ADDR_Y          2
#define PML_MOVS_ADDR_M_N        3
#define PML_MOVS_ADDR_P_N        4
#define PML_MOVS_ADDR_M_X_N      5
#define PML_MOVS_ADDR_P_X_N      6
#define PML_MOVS_DST_MAX         6 /* don't forget to update */

/* arithmetic/logical operations */
#define PML_MATH_N 0
#define PML_MATH_X 1
#define PML_MATH_Y 2


/* JMP */
#define PML_JMP_OFF_N   0
#define PML_JMP_OFF_A_N 1

/* conditional jumps */
#define PML_JCOND_0 0
#define PML_JCOND_X 1
#define PML_JCOND_Y 2


#endif /* PMLVM_H */
