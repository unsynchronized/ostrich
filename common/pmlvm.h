#ifndef PMLVM_H
#define PMLVM_H

#include <pmltypes.h>

#define TLPROTO_UNKNOWN  0
#define TLPROTO_ETHERNET 1

/* pmi_packet_info: used to describe the packet to be processed.  This includes a
 * pointer to the packet itself as well as the data for most of the special variables
 * accessed via the MOVS instruction.
 */
typedef struct pml_packet_info {
    void *pkt; 
    u_int32_t pktlen;
    u_int32_t iphdroff;
    u_int32_t ethhdroff;
    u_int32_t tcphdroff;
    u_int8_t tlproto;

    struct {
        unsigned int has_iphdroff : 1;
        unsigned int has_ethhdroff : 1;
        unsigned int has_tcphdroff : 1;
    } flags;
} pml_packet_info;

/* XXX: doc */
struct pmlvm_context {
    u_int8_t *m;            /* pointer to M */
    u_int32_t mlen;         /* current length of M (bytes) */
    u_int8_t *prog;         /* program code */
    u_int32_t proglen;      /* program code len (bytes) */
    u_int32_t pc;           /* current pc (byte offset) */
};


bool pmlvm_process(struct pml_packet_info *pinfo);

#endif /* PMLVM_H */
