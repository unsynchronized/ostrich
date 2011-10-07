#include <pmlmachdep.h>
#include <pmltypes.h>
#include <pmlvm.h>
#include <octrl.h>
#include <octrlmachdep.h>
#include <linux/time.h>
#include <linux/vmalloc.h>

extern struct net_proto_family inet_family_ops;

struct inode pml_dbg_inode;
struct socket *pml_dbg_socket = &pml_dbg_inode.u.socket_i;

void pml_md_debug_pkt(char *mbuf);

void pml_md_init(void) {
    int err;
    pml_dbg_inode.i_mode = S_IFSOCK;
    pml_dbg_inode.i_sock = 1;
    pml_dbg_inode.i_uid = 0;
    pml_dbg_inode.i_gid = 0;
    init_waitqueue_head(&pml_dbg_inode.i_wait);
    init_waitqueue_head(&pml_dbg_inode.u.socket_i.wait);

    pml_dbg_socket->inode = &pml_dbg_inode;
    pml_dbg_socket->state = SS_UNCONNECTED;
    pml_dbg_socket->type=SOCK_RAW;

    if ((err=inet_family_ops.create(pml_dbg_socket, IPPROTO_UDP))<0)
            panic("Failed to create the PML control socket.\n");
    pml_dbg_socket->sk->allocation=GFP_ATOMIC;
    pml_dbg_socket->sk->sndbuf = SK_WMEM_MAX*2;
    pml_dbg_socket->sk->protinfo.af_inet.ttl = MAXTTL;
    pml_dbg_socket->sk->protinfo.af_inet.pmtudisc = IP_PMTUDISC_DONT;

    /* Unhash it so that IP input processing does not even
     * see it, we do not wish this socket to see incoming
     * packets.
     */
    pml_dbg_socket->sk->prot->unhash(pml_dbg_socket->sk);

    struct octrl_settings *settings = octrl_md_retrieve_settings();
    pmlvm_init(settings->program, settings->proglen, settings->savedm, settings->savedmlen);

}

void pml_md_debug(const char *fmt, ...) {
    char XXXtempbuf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(XXXtempbuf, sizeof(XXXtempbuf), fmt, args);
    va_end(args);
    pml_md_debug_pkt(XXXtempbuf);
}

void pml_md_debug_pkt(char *mbuf) {
    const size_t mlen = strlen(mbuf);
    struct sockaddr_in daddr;
    daddr.sin_addr.s_addr = htonl(0xa0a0102);
    daddr.sin_port = htons(6969);
    daddr.sin_family = AF_INET;

    struct msghdr msg;
    struct iovec iov;

    iov.iov_base=mbuf;
    iov.iov_len=mlen;
    msg.msg_name=NULL;
    msg.msg_iov=&iov;
    msg.msg_iovlen=1;
    msg.msg_control=NULL;
    msg.msg_controllen=0;
    msg.msg_name = &daddr;
    msg.msg_namelen = sizeof(daddr);
    msg.msg_flags = 0;
    udp_sendmsg(pml_dbg_socket->sk, &msg, mlen);
}

int XXXprocessing = 0;
u_int32_t XXXother = 0, XXXips = 0, XXXtapped = 0, XXXrxcount = 0, XXXfoo = 0;

struct sk_buff *lastsk = 0;

/* pml_md_tap: returns 1 if this packet should be dropped; 0 if not */
int pml_md_tap(struct sk_buff **skb) {
    if(lastsk == *skb) {
        XXXfoo++;
    }
    lastsk = *skb;
    if(XXXprocessing == 0) {
        return 0;
    }
    struct octrl_settings *settings = octrl_md_retrieve_settings();
    u_int32_t topush;
    struct pml_packet_info ppi;
    memset(&ppi, 0, sizeof(ppi));
    if((*skb)->protocol == htons(ETH_P_IP)) {
        if((*skb)->mac.ethernet == NULL) {
            return 0;
        }
        if((*skb)->mac.raw > (*skb)->data) {
            return 0;
        }
        topush = (*skb)->data-(*skb)->mac.raw;
        ppi.ethhdroff = 0;
        ppi.flags.has_ethhdroff = 1;
        ppi.iphdroff = topush;
        ppi.flags.has_iphdroff = 1;
        ppi.tlproto = TLPROTO_ETHERNET;
        ppi.md_ptr = (*skb);
    } else {
        XXXother++;
        return 0;
    }
    skb_push((*skb), topush);
    int retval = 0;
    ppi.pkt = (*skb)->data;
    ppi.pktlen = (*skb)->len;
    if(ppi.flags.has_iphdroff && ppi.pktlen >= (topush+20+ppi.ethhdroff)) {
        u_int16_t hdrsz = 4*((*skb)->data[ppi.iphdroff] & 0xf);
        if(ppi.pktlen > (topush+ppi.ethhdroff+hdrsz)) {
            ppi.ip4tlhdroff = topush+ppi.ethhdroff+hdrsz;
            ppi.flags.has_ip4tlhdroff = 1;
        }
    }
    XXXips++;
    bool pret = octrl_check_command(settings, &ppi);
    if(pret == 0 || ppi.pktlen == 0) {
        retval = 1;
        goto out;
    }
    if(settings->processing_enabled) {
        pret = pmlvm_process(&ppi, settings->maxinsns);
        if(pret == 0 || ppi.pktlen == 0) {
            retval = 1;
            goto out;
        }
    }

out:    /* we're inside linux; i think that means goto is okay */
    *skb = (struct sk_buff *)ppi.md_ptr;
    skb_pull(*skb, topush);
    return retval;
}
u_int8_t *pml_md_getpbuf(struct pml_packet_info *ppi) {
    return ppi->pkt;
}

bool pml_md_putpbuf(struct pml_packet_info *ppi, u_int8_t *newpkt, u_int32_t newpktlen) {
    ppi->pkt = newpkt;
    ppi->pktlen = newpktlen;
    return 1;
}

struct pmlvm_context *pml_md_alloc_context(void) {
    struct pmlvm_context *pm = kmalloc(sizeof(struct pmlvm_context), GFP_KERNEL);
    if(pm != NULL) {
        memset(pm, 0, sizeof(struct pmlvm_context));
    }
    return pm;
}

/* pml_md_allocbuf: allocate a buffer to be freed by pml_md_free().  the buffer will
 * be initialized with zeroes. 
 * pml_md_allocbuf returns NULL if the allocations fails.
 */
void *pml_md_allocbuf(u_int32_t sz) {
    return kmalloc(sz, GFP_KERNEL);
}
void pml_md_freebuf(void *buf) {
    kfree(buf);
}

void pml_md_free_context(struct pmlvm_context *ctx) {
    kfree(ctx);
}

void pml_md_memmove(void *dest, const void *src, u_int32_t n) {
    memmove(dest, src, n);
}

void pml_md_memset(void *dest, u_int8_t b, u_int32_t sz) {
    memset(dest, b, sz);
}

bool pml_md_save_program(struct pmlvm_context *ctx, u_int8_t *newprog, u_int32_t len) {
    /* XXX: implement */
    return 0;
}

u_int32_t pml_md_currenttime(void) {
    struct timeval tv;
    do_gettimeofday(&tv);
    return tv.tv_usec;
}

void *pml_md_realloc(void *ptr, size_t newsz) {
    void *newptr;
    if(in_irq()) {
        newptr = kmalloc(newsz, GFP_ATOMIC);
    } else {
        newptr = kmalloc(newsz, GFP_KERNEL);
    }
    if(newptr != NULL) {
        memcpy((u_int8_t *)newptr, (u_int8_t *)ptr, newsz);
    }
    kfree(ptr);
    return newptr;
}

u_int8_t pml_fixed_m[FIXED_M_SIZE]; 

/* beforehand: nbytes is checked, startoff must be <= the length */
bool pml_md_insert_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context) {
    const u_int32_t newsz = context->mlen + nbytes;
    if(startoff > context->mlen) {
        return 0;
    }
    if(startoff+nbytes < startoff || newsz < context->mlen) {
        return 0;
    }
    if(newsz > sizeof(pml_fixed_m)) {
        return 0;
    }
    if(context->mlen > 0) {
        if(startoff < context->mlen) {
            memmove(&pml_fixed_m[startoff+nbytes], &pml_fixed_m[startoff], (context->mlen)-startoff);
        }
        memset(&pml_fixed_m[startoff], 0, nbytes);
    } else {
        memset(pml_fixed_m, 0, sizeof(newsz));
    }
    context->m = pml_fixed_m;
    context->mlen = newsz;
    return 1;
}

bool pml_md_insert_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo) {
    const u_int32_t newsz = pinfo->pktlen + nbytes;
    struct sk_buff *skb = (struct sk_buff *)pinfo->md_ptr;
    if(skb == NULL) {
        return 0;
    }
    if(skb_is_nonlinear(skb)) {
        return 0;
    }
    if(pinfo->pktlen > 0) {
        if(skb_tailroom(skb) < nbytes) {
            pskb_expand_head(skb, 0, nbytes, GFP_KERNEL);
            pinfo->pkt = skb->data;
        }
        if(skb_tailroom(skb) < nbytes) {
            DLOG("pskb_expand_head failed");
            return 0;
        }
        skb_put(skb, nbytes);
        u_int8_t *p = (u_int8_t *)pinfo->pkt;
        if(startoff < pinfo->pktlen) {
            memmove(&p[startoff+nbytes], &p[startoff], (pinfo->pktlen)-startoff);
        }
        memset(&p[startoff], 0, nbytes);
    } else {
        /* XXX: implement */
        return 0;
    }
    pinfo->pktlen = newsz;
    return 1;
}

bool pml_md_delete_m(u_int32_t nbytes, u_int32_t startoff, struct pmlvm_context *context) {
    if(context->mlen == 0) {
        DLOG("tried to DELETE from M when M was empty");
        return 0;
    }
    if(context->mlen < nbytes) {
        DLOG("tried to DELETE too much from M");
        return 0;
    }
    const u_int32_t newsz = context->mlen - nbytes;
    if(newsz > 0) {
        memmove(&context->m[startoff], &context->m[startoff+nbytes], newsz-startoff);
    }
    context->mlen = newsz;
    return 1;
}

bool pml_md_delete_p(u_int32_t nbytes, u_int32_t startoff, struct pml_packet_info *pinfo) {
    if(pinfo->pktlen == 0) {
        DLOG("tried to DELETE from P when P was empty");
        return 0;
    }
    struct sk_buff *skb = (struct sk_buff *)pinfo->md_ptr;
    if(skb == NULL) {
        return 0;
    }
    if(nbytes == 0 || pinfo->pktlen < nbytes || skb_is_nonlinear(skb)) {
        return 0;
    }
    const u_int32_t newsz = pinfo->pktlen - nbytes;
    skb->tail -= nbytes;
    skb->len -= nbytes;
    u_int8_t *p = (u_int8_t *)pinfo->pkt;
    if(newsz > 0) {
        memmove(&p[startoff], &p[startoff+nbytes], nbytes);
    }
    pinfo->pktlen = newsz;
    return 1;
}

/* pml_md_divert: send a packet out the defined channel, if configured.  
 *   other channels may be configured by config commands.
 *
 *   returns 1 if the packet was successfully sent; 0 otherwise
 */
bool pml_md_divert(struct pmlvm_context *ctx, u_int8_t channel, u_int8_t *packet, u_int32_t packetlen) {
    struct pml_tuntap_context *ptc = (struct pml_tuntap_context *)ctx->md_ptr;
    if(ptc == NULL || packetlen == 0) {
        return 0;
    }
    pml_md_debug("div %d", channel);    /* XXX */
    struct octrl_channel *chan = octrl_get_channel(octrl_md_retrieve_settings(), channel);
    if(chan == NULL) {
        pml_md_debug("XXX no channel");
        return 0;
    }

    if(chan->channeltype == OCTRL_CHANNEL_UDP4) {
        return octrl_md_send_channel(chan, packet, packetlen);
    }
    return 0;
}


