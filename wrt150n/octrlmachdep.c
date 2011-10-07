#include <pmlmachdep.h>
#include <pmltypes.h>
#include <pmlvm.h>
#include <octrlmachdep.h>
#include <pmlutils.h>
#include <defaults.h>
#include <linux/vmalloc.h>

extern u_int8_t pml_fixed_m[FIXED_M_SIZE]; 

static struct octrl_settings *current_settings = NULL;

void *pml_md_vrealloc(void *ptr, size_t newsz);
void *pml_md_realloc(void *ptr, size_t newsz);

struct octrl_settings *octrl_md_retrieve_settings(void) {
    if(current_settings != NULL) {
        return current_settings;
    }
    current_settings = kmalloc(sizeof(struct octrl_settings), GFP_KERNEL);
    if(current_settings == NULL) {
        return NULL;
    }
    memset(current_settings, 0, sizeof(struct octrl_settings));

    current_settings->maxinsns = 100;
    current_settings->processing_enabled = OCTRL_DEFAULT_PROCESSING_ENABLED;
    current_settings->savedmlen = 0;
    current_settings->savedm = NULL;
    if(octrl_default_program_len > 0) {
        current_settings->program = vmalloc(octrl_default_program_len);
        if(current_settings->program != NULL) {
            current_settings->has_program = 1;
            current_settings->proglen = octrl_default_program_len;
            memcpy(current_settings->program, octrl_default_program, octrl_default_program_len);    /* XXX: slightly wasteful to alloc for this */
        }
    }

    if(octrl_default_cookie_len > 0) {
        octrl_md_set_cookie(octrl_default_cookie, octrl_default_cookie_len);
    }
    current_settings->cookie_enabled = OCTRL_DEFAULT_COOKIE_ENABLED;

    if(octrl_default_commandip_len > 0) {
        current_settings->commandip = kmalloc(octrl_default_commandip_len, GFP_KERNEL);
        u_int32_t inaddr = htonl(0xa0a0102);
        if(current_settings->commandip != NULL) {
            memcpy(current_settings->commandip, &inaddr, octrl_default_commandip_len);
            current_settings->commandiplen = octrl_default_commandip_len;
            current_settings->has_commandip = 1;
        }
    }
    current_settings->commandport = OCTRL_DEFAULT_COMMANDPORT;
    return current_settings;
}


void octrl_md_save_settings(void) {
    /* XXX: unimpl */
}
extern struct socket *pml_dbg_socket;
bool octrl_md_send_channel(struct octrl_channel *chan, u_int8_t *buf, u_int32_t len) {
    switch(chan->channeltype) {
        case OCTRL_CHANNEL_UDP4:
            {
                struct sockaddr_in daddr;
                memset(&daddr, 0, sizeof(struct sockaddr_in));
                memcpy(&daddr.sin_addr.s_addr, chan->addr, 4);
                daddr.sin_port = htons(chan->port);
                daddr.sin_family = AF_INET;

                struct msghdr msg;
                struct iovec iov;

                iov.iov_base=buf;
                iov.iov_len=len;
                msg.msg_name=NULL;
                msg.msg_iov=&iov;
                msg.msg_iovlen=1;
                msg.msg_control=NULL;
                msg.msg_controllen=0;
                msg.msg_name = &daddr;
                msg.msg_namelen = sizeof(daddr);
                msg.msg_flags = 0;
                u_int16_t tempp = pml_dbg_socket->sk->sport;
                pml_dbg_socket->sk->sport = htons(current_settings->commandport);
                udp_sendmsg(pml_dbg_socket->sk, &msg, len);
                pml_dbg_socket->sk->sport = tempp;
                return 1;
            }
            break;
    }
    return 0;
}
void octrl_md_set_filter(u_int8_t *filter, u_int32_t filterlen) {
    struct pmlvm_context *ctx = pmlvm_current_context();
    if(current_settings->proglen > 0 && current_settings->program != NULL) {
        vfree(current_settings->program);
        current_settings->proglen = 0;
        if(ctx != NULL) {
            ctx->prog = NULL;
            ctx->proglen = 0;
        }
    }
    if(filterlen > 0) {
        current_settings->program = vmalloc(filterlen);
        if(current_settings->program == NULL) {
            DLOG("couldn't allocate space for new filter");
            return;
        }
        memcpy(current_settings->program, filter, filterlen);
        current_settings->proglen = filterlen;
        if(ctx != NULL) {
            ctx->prog = current_settings->program;
            ctx->proglen = filterlen;
        }
    }
    octrl_md_save_settings();
}
void octrl_md_del_channel(u_int8_t id) {
    if(current_settings->nchannels == 0) {
        return;
    }
    u_int32_t i;
    for(i = 0; i < current_settings->nchannels; i++) {
        if(current_settings->channels[i]->channelid == id){
            pml_md_freebuf(current_settings->channels[i]);
            current_settings->channels[i] = NULL;
            u_int32_t j = i;
            for(j = i; j < (current_settings->nchannels-1); j++) {
                current_settings->channels[j] = current_settings->channels[j+1];
            }
            /* XXX: should just switch to a linked list here, we're note even
             * indexing on id
             */
            current_settings->nchannels = current_settings->nchannels - 1;
            if(current_settings->nchannels == 0) {
                pml_md_freebuf(current_settings->channels);
                current_settings->channels = NULL;
            }
            return;
        }
    }
}
void octrl_md_set_channel(u_int8_t *buffer) {
    struct octrl_channel *chan = octrl_deserialize_channel(buffer);
    if(chan == NULL) {
        DLOG("couldn't allocate space for new chan struct");
        return;
    }
    if(current_settings->nchannels == 0) {
        current_settings->channels = kmalloc(sizeof(struct octrl_channel *), GFP_KERNEL);
        if(current_settings->channels == NULL) {
            DLOG("couldn't allocate space for channels array");
            pml_md_freebuf(chan);
            return;
        }
        current_settings->channels[0] = chan;
        current_settings->nchannels = 1;
        return;
    }
    u_int32_t i;
    for(i = 0; i < current_settings->nchannels; i++) {
        if(current_settings->channels[i]->channelid == chan->channelid) {
            pml_md_freebuf(current_settings->channels[i]);
            current_settings->channels[i] = chan;
            return;
        }
    }
    struct octrl_channel **newchan = pml_md_realloc(current_settings->channels, sizeof(struct octrl_channel)*(current_settings->nchannels + 1));
    if(newchan == NULL) {
        DLOG("couldn't allocate more space for channels array");
        pml_md_freebuf(chan);
        return;
    }
    newchan[current_settings->nchannels] = chan;
    current_settings->channels = newchan;
    current_settings->nchannels = current_settings->nchannels + 1;
}
void octrl_md_save_m(u_int32_t addr, u_int32_t len) {
    /* XXX unimplemented */
    octrl_md_save_settings();
}
void octrl_md_set_m(u_int32_t addr, u_int8_t *buf, u_int32_t len) {
    if(addr+len < addr) {
        return;
    }
    struct pmlvm_context *ctx = pmlvm_current_context();
    if(ctx == NULL) {
        return;
    }
    if(addr+len > sizeof(pml_fixed_m)) {
        return;
    }
    if(ctx->mlen < addr+len) {
        ctx->mlen = (addr+len);
    }
    pml_md_memmove(&ctx->m[addr], buf, len);
}
void octrl_md_set_flag(u_int32_t flag, u_int8_t *val, u_int32_t vlen) {
    if(flag > OCTRL_FLAG_MAX) {
        DLOG("invalid flag set: 0x%x", flag);
        return;
    }
    if(flag == OCTRL_FLAG_ENABLE_COOKIE) {
        if(vlen != 1) {
            DLOG("invalid flag value length for binary flags: 0x%x", flag);
            return;
        }
        current_settings->cookie_enabled = val[0] == 0 ? 0 : 1;
    } else if(flag == OCTRL_FLAG_ENABLE_PMLVM) {
        if(vlen != 1) {
            DLOG("invalid flag value length for binary flags: 0x%x", flag);
            return;
        }
        current_settings->processing_enabled = val[0] == 0 ? 0 : 1;
    } else if(flag == OCTRL_FLAG_MAX_INSNS) {
        if(vlen != 4) {
            DLOG("invalid flag value length for binary flags: 0x%x", flag);
            return;
        }
        current_settings->maxinsns = EXTRACT4(val);
    }
    octrl_md_save_settings();
}
void octrl_md_set_cmdip(u_int8_t *newip, u_int32_t iplen) {
    u_int8_t *newaddr;
    if(iplen > 0) {
        newaddr = kmalloc(iplen, GFP_KERNEL);
        if(newaddr == NULL) {
            DLOG("couldn't allocate space for command ip");
            return;
        }
        current_settings->has_commandip = 1;
        pml_md_memmove(newaddr, newip, iplen);
    } else {
        newaddr = NULL;
        current_settings->has_commandip = 0;
    }
    if(current_settings->commandip != NULL) {
        kfree(current_settings->commandip);
    }
    current_settings->commandip = newaddr;
    current_settings->commandiplen = iplen;
    octrl_md_save_settings();
}
void octrl_md_set_cmdport(u_int16_t newport) {
    current_settings->commandport = newport;
    octrl_md_save_settings();
}
void octrl_md_set_cookie(u_int8_t *ncookie, u_int32_t clen) {
    u_int8_t *newcookie;
    if(clen > 0) {
        newcookie = pml_md_allocbuf(clen);
        if(newcookie == NULL) {
            DLOG("couldn't allocate space for cookie");
            return;
        }
        pml_md_memmove(newcookie, ncookie, clen);
    } else {
        newcookie = NULL;
    }
    if(current_settings->cookie != NULL) {
        kfree(current_settings->cookie);
    }
    current_settings->cookie = newcookie;
    current_settings->cookielen = clen;
    octrl_md_save_settings();
}
void octrl_md_clear_m(void) {
    struct pmlvm_context *ctx = pmlvm_current_context();
    if(ctx == NULL) {
        return;
    }
    if(ctx->mlen > 0) {
        pml_md_delete_m(0, ctx->mlen, ctx);
    }
}
