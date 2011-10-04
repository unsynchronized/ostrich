#include <pmlmachdep.h>
#include <pmltypes.h>

extern struct net_proto_family inet_family_ops;

struct inode pml_inode;
struct socket *pml_socket = &pml_inode.u.socket_i;

void pml_md_init(void) {
    int err;
    pml_inode.i_mode = S_IFSOCK;
    pml_inode.i_sock = 1;
    pml_inode.i_uid = 0;
    pml_inode.i_gid = 0;
    init_waitqueue_head(&pml_inode.i_wait);
    init_waitqueue_head(&pml_inode.u.socket_i.wait);

    pml_socket->inode = &pml_inode;
    pml_socket->state = SS_UNCONNECTED;
    pml_socket->type=SOCK_RAW;

    if ((err=inet_family_ops.create(pml_socket, IPPROTO_UDP))<0)
            panic("Failed to create the PML control socket.\n");
    pml_socket->sk->allocation=GFP_ATOMIC;
    pml_socket->sk->sndbuf = SK_WMEM_MAX*2;
    pml_socket->sk->protinfo.af_inet.ttl = MAXTTL;
    pml_socket->sk->protinfo.af_inet.pmtudisc = IP_PMTUDISC_DONT;

    /* Unhash it so that IP input processing does not even
     *  * see it, we do not wish this socket to see incoming
     *   * packets.
     *    */
    pml_socket->sk->prot->unhash(pml_socket->sk);
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
    udp_sendmsg(pml_socket->sk, &msg, mlen);
}
