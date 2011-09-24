#include <pmlmachdep.h>
#include <pmltypes.h>

u_int8_t *pml_md_getpbuf(struct pml_packet_info *ppi) {
    return ppi->pkt;
}

bool pml_md_putpbuf(struct pml_packet_info *ppi, u_int8_t *newpkt, u_int32_t newpktlen) {
    ppi->pkt = newpkt;
    ppi->pktlen = newpktlen;
    return 1;
}
