#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdbool.h>
#include <err.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> 

/*
 * TAP-based ostrich implementation.
 *
 * References:
 *   - linux Documentation/networking/tuntap.txt
 *   - VTUN example programs (http://vtun.sourceforge.net/tun)
 *   - kernel source
 *   - linux manpages: packet(7)
 */

#define DEFAULT_INIF "eth2"
#define DEBUG(fmt, x...) fprintf(stderr, fmt "\n", ## x);
#define MIN(x,y) ((x) > (y) ? (y) : (x))

void hexdump(char *const buf, unsigned long size) {
    unsigned int curpos = 0;
    for(unsigned long i = 0; i < size; i++) {
        curpos += fprintf(stderr, " %02x", (unsigned char)buf[i]);
        if(curpos >= 80 && i < (size-1)) {
            fprintf(stderr, "\n");
            curpos = 0;
        }
    }
    fprintf(stderr, "\n");
}

/*
 * instead of bothering with BPF, this is a simple hack to drop packets we don't care 
 * about.  here we're assuming a nonpublic ethernet network and filtering out TCP packets
 * with a source or destination port of 22.
 *
 * returns 1 if we should discard the packet, 0 otherwise
 */
bool should_discard(unsigned char *const packet, unsigned long size) {
    if(size < 39 || packet[12] != 8 || packet[13] != 0 || (packet[14] & 0xF0) != 0x40 || packet[23] != 6) {
        return 0;
    }
    unsigned int ihl = (packet[14] & 0xF) * 4;
    unsigned int tcp = 14+ihl;
    if((packet[tcp] == 0 && packet[tcp+1] == 22) || (packet[tcp+2] == 0 && packet[tcp+3] == 22)) {
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char *const inifname = DEFAULT_INIF;
    int tapfd = open("/dev/net/tun", O_RDWR);
    if(tapfd == -1) {
        err(1, "can't open tun device");
    }

    struct ifreq ifr;
    char ifname[IFNAMSIZ+1];
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP;
    snprintf(ifr.ifr_name, IFNAMSIZ, "whelp%%d");
    if(ioctl(tapfd, TUNSETIFF, (void *)&ifr) == -1) {
        close(tapfd);
        err(1, "can't allocate a tap interface");
    }
    strncpy(ifname, ifr.ifr_name, sizeof(ifname));
    ifname[sizeof(ifname)-1] = 0;
    DEBUG("--- created interface: %s", ifname);

    int infd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(infd == -1) {
        err(1, "can't open incoming socket");
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, inifname, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = 0;
    if(ioctl(infd, SIOCGIFINDEX, &ifr) == -1) {
        err(1, "can't get interface index for if %s", inifname);
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    if(bind(infd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        err(1, "can't bind input socket to interface");
    }

    char inbuf[262144];
    char namebuf[1024];
    char controlbuf[1024];

    while(1) {
        memset(namebuf, 0, sizeof(namebuf));
        memset(controlbuf, 0, sizeof(controlbuf));
        struct iovec iov = {
            .iov_base = inbuf,
            .iov_len = sizeof(inbuf)
        };
        struct msghdr msgh = {
            .msg_name = namebuf,
            .msg_namelen = sizeof(namebuf),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = controlbuf,
            .msg_controllen = sizeof(controlbuf),
            .msg_flags = 0
        };
        ssize_t retval = recvmsg(infd, &msgh, 0);
        if(retval == 0) {
            DEBUG("connection closed by socket");
            break;
        } else if(retval < 0) {
            if(errno == EINTR) {
                continue;
            }
            warn("error while reading from interface");
            break;
        }
        if(should_discard((unsigned char *const)inbuf, retval)) {
            continue;
        }
        DEBUG("recv %lu bytes namelen %lu  controllen %lu", (unsigned long)retval, (unsigned long)msgh.msg_namelen, (unsigned long)msgh.msg_controllen);
        if(msgh.msg_namelen > sizeof(struct sockaddr_ll)) {
            DEBUG("msg_namelen not the expected size (%lu)!  namelen:", sizeof(struct sockaddr_ll));
            hexdump(msgh.msg_name, msgh.msg_namelen);
            DEBUG("packet:");
            hexdump(inbuf, retval);
            break;
        }
        struct sockaddr_ll *insll = (struct sockaddr_ll *)msgh.msg_name;
        DEBUG("packet:");
        hexdump(inbuf, retval);
        fprintf(stderr, "address: ");
        hexdump((char * const)insll->sll_addr, MIN(insll->sll_halen, sizeof(insll->sll_addr)));

        fprintf(stderr, "\n");

    }
    close(tapfd);
    close(infd);

    return 0;
}
