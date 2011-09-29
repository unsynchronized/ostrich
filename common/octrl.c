#include <pmlvm.h>
#include <pmlmachdep.h>
#include <octrlmachdep.h>
#include <octrl.h>

/* XXX REMOVE ALL OF THIS */
#define CHECK_PLEN check_plen
static struct pml_packet_info *curppi;
static bool check_plen(u_int32_t idx, u_int32_t len) {  /*  XXX XXX XXX REMOVE */
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

void octrl_init(void) {
}

bool octrl_handle_commands(struct octrl_settings *settings, struct pml_packet_info *ppi, u_int32_t dataoff, u_int16_t datalen);

bool octrl_check_command(struct octrl_settings *settings, struct pml_packet_info *ppi) {
    if(settings == NULL) {
        return 1;
    }
    if(settings->has_commandip == 0 && settings->has_commandport == 0) {
        return 1;
    }
    u_int8_t *p = pml_md_getpbuf(ppi);
    if(ppi->flags.has_iphdroff == 0 || ppi->flags.has_ip4tlhdroff == 0) {
        return 1;
    }
    const int iphdr = ppi->iphdroff, ip4tlhdroff = ppi->ip4tlhdroff;
    u_int8_t ipver = (p[iphdr] >> 4);
    curppi = ppi;
    if(settings->has_commandip) {
        if(ipver == 6) {
            u_int32_t tocheck = settings->commandiplen > 16 ? 16 : settings->commandiplen;
            if(tocheck == 0 || CHECK_PLEN(iphdr+8, 16) == 0) {
                return 1;
            }
            for(u_int32_t i = 0; i < tocheck; i++) {  
                if(p[iphdr+8+i] != settings->commandip[i]) {      /* timing attack! :-) */
                    return 1;
                }
            }
        } else {
            u_int32_t tocheck = settings->commandiplen > 4 ? 4 : settings->commandiplen;
            if(tocheck == 0 || CHECK_PLEN(iphdr+12, 4) == 0) {
                return 1;
            }
            for(u_int32_t i = 0; i < tocheck; i++) {  
                if(p[iphdr+12+i] != settings->commandip[i]) {      /* timing attack! :-) */
                    return 1;
                }
            }
        }
    }
    u_int8_t protoff = ipver == 6 ? 6 : 9;
    if(CHECK_PLEN(iphdr+protoff, 1) == 0) {
        return 1;
    }
    u_int8_t protocol = p[iphdr+protoff];
    u_int32_t dataoff;
    if(protocol == 17) {
        dataoff = 8;
    } else if(protocol == 6) {
        if(CHECK_PLEN(ip4tlhdroff+12, 1) == 0) {
            return 1;
        }
        dataoff = p[ip4tlhdroff+12] * 4;
    } else {
        return 1;
    }
    if(CHECK_PLEN(ip4tlhdroff+dataoff, 1) == 0) {
        return 1;
    }
    if(settings->has_commandport) {
        u_int16_t port = ((p[ip4tlhdroff+2] & 0xff) << 8) | (p[ip4tlhdroff+3] & 0xff);
        if(port != settings->commandport) {
            return 1;
        }
    }
    if(settings->has_cookie && settings->cookielen > 0) {
        bool found = 0;
        u_int32_t tosearch = ppi->pktlen - ip4tlhdroff - dataoff;
        u_int8_t *data = &p[ip4tlhdroff + dataoff];
        u_int32_t i = 0;
        for(i = 0; i < tosearch; i++) {
            if(data[i] != settings->cookie[0]) {
                continue;
            }
            u_int32_t j;
            for(j = 1; j < settings->cookielen && (i+j) < tosearch; j++) {
                if(data[i+j] != settings->cookie[j]) {
                    break;
                }
            }
            if(j == settings->cookielen) {
                found = 1;
                break;
            }
        }
        if(found == 0) {
            return 1;
        }
        dataoff += (i + settings->cookielen);
    }
    if(CHECK_PLEN(ip4tlhdroff+dataoff, 2) == 0) {
        DLOG("command packet too short for command data len");
        return 1;
    }
    u_int16_t pktlen = ((p[ip4tlhdroff+dataoff] & 0xff) << 8) | (p[ip4tlhdroff+dataoff+1] & 0xff);
    if(CHECK_PLEN(ip4tlhdroff+dataoff+2, pktlen) == 0) {
        DLOG("command packet too short for command data (len %hx)", pktlen);
        return 1;
    }
    octrl_handle_commands(settings, ppi, ip4tlhdroff+dataoff+2, pktlen);
    /* past this point, we're a packet.  start looking for the cookie */
    if(settings->drop_cmd_packets) {
        return 0;
    } else {
        return 1;
    }
}
bool octrl_handle_commands(struct octrl_settings *settings, struct pml_packet_info *ppi, const u_int32_t dataoff, const u_int16_t datalen) {
    u_int8_t *p = pml_md_getpbuf(ppi);
    u_int32_t i = dataoff;
    DLOG("XXX i %x  len %x\n", i, datalen);
    while(i < (dataoff+datalen)) {
        const u_int8_t opcode = p[i];

        DLOG("%x ", opcode);
        i++; /* XXX */
    }
    void exit(int x); exit(1);      /* XXX */
    return 0;
}
