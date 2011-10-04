#include <pmlvm.h>
#include <pmlmachdep.h>
#include <octrlmachdep.h>
#include <utils.h>
#include <octrl.h>
#include <version.h>

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

u_int32_t octrl_serialize_channel_size() {
    return 25;
}
void octrl_send_m(u_int32_t maddr, u_int16_t mreqlen, struct octrl_channel *outchannel) {
    struct pmlvm_context *ctx = pmlvm_current_context();
    if(ctx == NULL) {
        return;
    }
    if(ctx->m == NULL || ctx->mlen == 0) {
        u_int8_t zbuf[7];
        pml_md_memset(zbuf, 0, sizeof(zbuf));
        octrl_md_send_channel(outchannel, zbuf, sizeof(zbuf));
        return;
    } else if(maddr >= ctx->mlen 
            || ((maddr + mreqlen) < maddr)
            || ((maddr + mreqlen) > ctx->mlen)) {
        u_int8_t zbuf[7];
        pml_md_memset(zbuf, 0, sizeof(zbuf));
        zbuf[0] = OCTRL_SENDM_INVALIDRANGE;
        pml_setu32(&zbuf[1], ctx->mlen);
        octrl_md_send_channel(outchannel, zbuf, sizeof(zbuf));
        return;
    }
    const u_int32_t bufsz = 7 + mreqlen;
    u_int8_t *buf = pml_md_allocbuf(bufsz);
    if(buf == NULL) {
        return;
    }
    buf[0] = OCTRL_SENDM_VALID;
    pml_setu32(&buf[1], ctx->mlen);
    pml_setu16(&buf[5], mreqlen);
    pml_md_memmove(&buf[7], &ctx->m[maddr], mreqlen);
    octrl_md_send_channel(outchannel, buf, bufsz);
    pml_md_freebuf(buf);
}

struct octrl_channel *octrl_deserialize_channel(u_int8_t *buf) {
    struct octrl_channel *chan = pml_md_allocbuf(sizeof(struct octrl_channel));
    if(chan == NULL) {
        return NULL;
    }
    chan->channelid = buf[0];
    chan->channeltype = EXTRACT4(&buf[1]);
    pml_md_memmove(&chan->addr, &buf[5], 16);
    chan->port = EXTRACT4(&buf[21]);
    return chan;
}

void octrl_serialize_channel(struct octrl_channel *chan, u_int8_t *buf) {
    buf[0] = chan->channelid;
    buf[1] = (chan->channeltype >> 24 & 0xff);
    buf[2] = (chan->channeltype >> 16) & 0xff;
    buf[3] = (chan->channeltype >> 8) & 0xff;
    buf[4] = chan->channeltype & 0xff;
    pml_md_memmove(&buf[5], chan->addr, 16);
    buf[21] = chan->port >> 24;
    buf[22] = (chan->port >> 16) & 0xff;
    buf[23] = (chan->port >> 8) & 0xff;
    buf[24] = chan->port & 0xff;
}

/* send all flag values to the channel outchannel. */
void octrl_send_flags(struct octrl_settings *settings, struct octrl_channel *outchannel) {
    const u_int32_t bufsz = 4+((OCTRL_FLAG_MAX+1)*8);
    u_int8_t *buf = pml_md_allocbuf(bufsz);
    if(buf == NULL) {
        return;
    }
    pml_setu32(&buf[0], (OCTRL_FLAG_MAX+1)*8);
    pml_setu32(&buf[4], OCTRL_FLAG_ENABLE_COOKIE);
    pml_setu32(&buf[8], settings->cookie_enabled);
    pml_setu32(&buf[12], OCTRL_FLAG_ENABLE_PMLVM);
    pml_setu32(&buf[16], settings->processing_enabled);
    pml_setu32(&buf[20], OCTRL_FLAG_MAX_INSNS);
    pml_setu32(&buf[24], settings->maxinsns);
    octrl_md_send_channel(outchannel, buf, bufsz);
    pml_md_freebuf(buf);
}

/* send all data on channels in settings out to the channel outchannel. */
void octrl_send_channels(struct octrl_settings *settings, struct octrl_channel *outchannel) {
    const u_int32_t chansz = octrl_serialize_channel_size();
    unsigned int bufsz = (1+chansz*settings->nchannels);
    u_int8_t *buf = pml_md_allocbuf(bufsz);
    if(buf == NULL) {
        return;
    }
    buf[0] = settings->nchannels;
    for(unsigned int i = 0; i < settings->nchannels; i++) {
        octrl_serialize_channel(settings->channels[i], &buf[1+chansz*i]);
    }
    octrl_md_send_channel(outchannel, buf, bufsz);
    pml_md_freebuf(buf);
}


struct octrl_channel *octrl_get_channel(struct octrl_settings *settings, u_int8_t chanid) {
    if(settings->channels == NULL || settings->nchannels == 0) {
        return NULL;
    }
    for(u_int32_t i = 0; i < settings->nchannels; i++) {
        if(settings->channels[i]->channelid == chanid) {
            return settings->channels[i];
        }
    }
    return NULL;
}

bool octrl_handle_commands(struct octrl_settings *settings, struct pml_packet_info *ppi, u_int32_t dataoff, u_int16_t datalen);

bool octrl_check_command(struct octrl_settings *settings, struct pml_packet_info *ppi) {
    if(settings == NULL) {
        return 1;
    }
    if(settings->has_commandip == 0) {
        return 1;
    }
    u_int8_t *p = pml_md_getpbuf(ppi);
    if(ppi->flags.has_iphdroff == 0 || ppi->flags.has_ip4tlhdroff == 0) {
        return 1;
    }
    const int iphdr = ppi->iphdroff, ip4tlhdroff = ppi->ip4tlhdroff;
    u_int8_t ipver = (p[iphdr] >> 4);
    curppi = ppi;
    if(settings->has_commandip && settings->commandiplen > 0) {
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
    u_int16_t port = ((p[ip4tlhdroff+2] & 0xff) << 8) | (p[ip4tlhdroff+3] & 0xff);
    if(port != settings->commandport) {
        return 1;
    }
    if(settings->cookie_enabled && settings->cookielen > 0) {
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
    const u_int32_t iend = dataoff+datalen;
    struct octrl_channel dummychan;
    while(i < iend) {
        const u_int8_t opcode = p[i];
        DLOG("XXX OC: octrl 0x%x  i %d  iend %d", opcode, i, iend);
        
        switch(opcode) {
            case OCTRL_SEND_VERSION:
            case OCTRL_SEND_CHANNELS:
            case OCTRL_SEND_FLAGS:
            case OCTRL_SEND_M:
                {
                    u_int32_t maddr = 0;
                    u_int16_t mreqlen = 0;
                    if(opcode == OCTRL_SEND_M) {
                        if((i+6) >= iend) {
                            return 0;
                        }
                        maddr = EXTRACT4(&p[i+1]);
                        mreqlen = EXTRACT2(&p[i+5]);
                        i += 6;
                    }
                    struct octrl_channel *chan;
                    i++;
                    if(i == iend) {
                        break;
                    }
                    if(p[i] == OCTRL_SEND_CHANNEL) {
                        i++;
                        if(i == iend) {
                            return 0;
                        }
                        chan = octrl_get_channel(settings, p[i]);
                        if(chan == NULL) {
                            DLOG("target channel not found");
                            return 0;
                        }
                    } else if(p[i] == OCTRL_SEND_UDPIP4) {
                        if((i+6) >= iend) {
                            DLOG("SEND_UDPIP4 but packet too short");
                            return 0;
                        }
                        pml_md_memset(&dummychan, 0, sizeof(dummychan));
                        dummychan.channeltype = OCTRL_CHANNEL_UDP4;
                        dummychan.addr[0] = p[i+1];
                        dummychan.addr[1] = p[i+2];
                        dummychan.addr[2] = p[i+3];
                        dummychan.addr[3] = p[i+4];
                        dummychan.port = ((p[i+5] & 0xff) << 8) | (p[i+6] & 0xff);
                        chan = &dummychan;
                        i += 7;
                    } else {
                        return 0;
                    }

                    switch(opcode) {
                        case OCTRL_SEND_VERSION:
                            octrl_md_send_channel(chan, OCTRL_VERSION, OCTRL_VERSION_LEN);
                            break;
                        case OCTRL_SEND_CHANNELS:
                            octrl_send_channels(settings, chan);
                            break;
                        case OCTRL_SEND_FLAGS:
                            octrl_send_flags(settings, chan);
                            break;
                        case OCTRL_SEND_M:
                            octrl_send_m(maddr, mreqlen, chan);
                            break;
                    }
                }
                break;
            case OCTRL_SET_FILTER:
                {
                    if((i+2) >= iend) {
                        return 0;
                    }
                    u_int16_t plen = EXTRACT2(&p[i+1]);
                    i += 3;
                    if(i+plen > iend) {
                        return 0;
                    }
                    octrl_md_set_filter(&p[i], plen);
                    i += plen;
                }
                break;
            case OCTRL_SET_CHANNEL:
                if((i+octrl_serialize_channel_size()) >= iend) {
                    return 0;
                }
                i++;
                octrl_md_set_channel(&p[i]);
                i += (octrl_serialize_channel_size());
                break;
            case OCTRL_DEL_CHANNEL:
                if((i+1) >= iend) {
                    return 0;
                }
                i++;
                octrl_md_del_channel(p[i]);
                i++;
                break;
            case OCTRL_SAVE_M:
                {
                    if((i+8) >= iend) {
                        return 0;
                    }
                    i++;
                    u_int32_t maddr = EXTRACT4(&p[i]);
                    i += 4;
                    u_int32_t mlen = EXTRACT4(&p[i]);
                    i += 4;
                    octrl_md_save_m(maddr, mlen);
                }
                break;
            case OCTRL_SET_M:
                {
                    if((i+6) >= iend) {
                        return 0;
                    }
                    i++;
                    u_int32_t maddr = EXTRACT4(&p[i]);
                    i += 4;
                    u_int16_t mlen = EXTRACT2(&p[i]);
                    i += 2;
                    if((i + mlen) > iend) {  /* XXX oflow check */
                        return 0;
                    }
                    DLOG("XXX maddr %x  mlen %x", maddr, mlen & 0xffff);
                    octrl_md_set_m(maddr, &p[i], mlen);
                    i += mlen;
                }
                break;
            case OCTRL_SET_FLAG:
                {
                    if((i+5) >= iend) {
                        return 0;
                    }
                    i++;
                    u_int16_t flag = EXTRACT2(&p[i]);
                    i += 2;
                    u_int16_t dlen = EXTRACT2(&p[i]);
                    i += 2;
                    if((i + dlen) > iend) {  /* XXX oflow check */
                        return 0;
                    }
                    octrl_md_set_flag(flag, &p[i], dlen);
                    i += dlen;
                }
                break;
            case OCTRL_SET_COOKIE:
            case OCTRL_SET_CMDIP:
                {
                    if((i+2) >= iend) {
                        return 0;
                    }
                    i++;
                    u_int16_t clen = EXTRACT2(&p[i]);
                    i += 2;
                    if(clen > 0 && (i+clen) > iend) {    /* XXX oflow check */
                        return 0;
                    }
                    if(opcode == OCTRL_SET_CMDIP) {
                        octrl_md_set_cmdip((clen == 0) ? NULL : &p[i], clen);
                    } else if(opcode == OCTRL_SET_COOKIE) {
                        octrl_md_set_cookie((clen == 0) ? NULL : &p[i], clen);
                    }
                    i += clen;
                }
                break;
            case OCTRL_SET_CMDPORT:
                i++;
                DLOG("XXX i %d  iend %d", i, iend);
                if((i+2) > iend) {
                    DLOG("XXX ZPOO");
                    return 0;
                }
                const u_int16_t newport = EXTRACT2(&p[i]);
                octrl_md_set_cmdport(newport);
                i += 2;
                break;
            case OCTRL_CLEAR_M:
                octrl_md_clear_m();
                i++;
                break;
            case OCTRL_DELETE_M:
                {
                    if((i+8) >= iend) {
                        return 0;
                    }
                    i++;
                    u_int32_t maddr = EXTRACT4(&p[i]);
                    i += 4;
                    u_int32_t mlen = EXTRACT4(&p[i]);
                    i += 4;
                    pml_md_delete_m(mlen, maddr, pmlvm_current_context());
                }
                break;
            default:
                DLOG("invalid octrl command received: 0x%x", opcode);
                i++;    /* XXX; should return */
                break;
        }
    }
    if(i != iend) {DLOG("XXX i wrong i 0x%x", i); } /* XXX */
    return 0;
}
   
