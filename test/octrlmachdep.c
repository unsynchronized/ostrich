#include <octrl.h>
#include <octrlmachdep.h>
#include <pmltypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pmlmachdep.h>
#include <utils.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

static struct octrl_settings *current_settings = NULL;

struct octrl_settings *octrl_md_retrieve_settings(void) {
    if(current_settings != NULL) {
        return current_settings;
    }
    current_settings = calloc(1, sizeof(struct octrl_settings));
    if(current_settings == NULL) {
        return NULL;
    }

    static u_int8_t XXXprog[] = {
/*   0 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_P_N, PML_MOV_ADDR_A), 0x00, 0x00, 0x00, 0x60,
/*   6 */   PML_ADD, PML_MATH_N, 0x1, 0x1, 0x1, 0x1,

/*  12 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0x00, 0x00, 0x00, 0x10,
/*  18 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0x00, 0x00, 0x00, 0x0,
/*  24 */   PML_INSERT, PML_INSERT_M, 0x0, 0x0, 0x0, 0x0, 

/*  30 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0x11, 0x22, 0x33, 0x44,
/*  36 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_X, PML_MOV_ADDR_M_N), 0x0, 0x0, 0x0, 0x6,

/*  42 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0x00, 0x00, 0x00, 0x10,
/*  48 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0x00, 0x00, 0x00, 0x0,
/*  54 */   PML_DELETE, PML_INSERT_M, 0x0, 0x0, 0x0, 0x0, 

/*  60 */   PML_MOVS, PML_MOVS_TDB(PML_MOVS_P_LEN, PML_MOVS_ADDR_A), 0, 0, 0, 0,
/*  66 */   PML_MOVS, PML_MOVS_TDB(PML_MOVS_M_LEN, PML_MOVS_ADDR_X), 0, 0, 0, 0,
/*  72 */   PML_JLT, PML_JCOND_X, 0, 0, 0, 18,
/*  78 */   PML_SUB, PML_MATH_X, 0, 0, 0, 0,
/*  84 */   PML_INSERT, PML_INSERT_M, 0, 0, 0, 0,
/*  90 */   PML_MOVS, PML_MOVS_TDB(PML_MOVS_P_LEN, PML_MOVS_ADDR_A), 0, 0, 0, 0,
/*  96 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_Y), 0, 0, 0, 0,
/* 102 */   PML_COPY, PML_COPY_P_TO_M, 0, 0, 0, 0,
/* 108 */   PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0, 0, 0, 14,
/* 114 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_P_N, PML_MOV_ADDR_Y), 0, 0, 0, 24,
/* 120 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0, 0, 0, 0,
/* 126 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_A, PML_MOV_ADDR_M_N), 0, 0, 0, 24,
/* 132 */   PML_CHECKSUM, PML_CHECKSUM_IPV4_M_X, 0, 0, 0, 0,
/* 138 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_A, PML_MOV_ADDR_M_N), 0, 0, 0, 24,

/* 144 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_P_N, PML_MOV_ADDR_Y), 0, 0, 0, 40,
/* 150 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0, 0, 0, 0,
/* 156 */   PML_MOVH, PML_MOV_DSB(PML_MOV_ADDR_A, PML_MOV_ADDR_M_N), 0, 0, 0, 40,
/* 132 */   PML_CHECKSUM, PML_CHECKSUM_UDP4_M_X, 0, 0, 0, 0,

/*     */
    };
    current_settings->savedmlen = 0;
    current_settings->savedm = NULL;
    current_settings->program = malloc(sizeof(XXXprog));
    if(current_settings->program != NULL) {
        current_settings->has_program = 1;
        current_settings->proglen = sizeof(XXXprog);
        memcpy(current_settings->program, XXXprog, sizeof(XXXprog));
    }

    current_settings->cookie = malloc(6);
    if(current_settings->cookie != NULL) {
        memcpy(current_settings->cookie, "cookie", 6);
        current_settings->cookie_enabled = 1;
        current_settings->cookielen = 6;
    }
    current_settings->commandip = malloc(4);
    u_int32_t inaddr = inet_addr("192.168.0.4");
    if(current_settings->commandip != NULL) {
        memcpy(current_settings->commandip, &inaddr, 4);
        current_settings->commandiplen = 4;
        current_settings->has_commandip = 1;
    }
    current_settings->commandport = 4142;
    current_settings->has_commandport = 1;
    return current_settings;
}


#define MAX_UDP_SZ 1000
bool octrl_md_send_channel(struct octrl_channel *chan, u_int8_t *buf, u_int32_t len) {
    switch(chan->channeltype) {
        case OCTRL_CHANNEL_UDP4:
            {
                int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if(fd == -1) {
                    warn("opening udp socket");
                    return 0;
                }
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(struct sockaddr_in));
                sin.sin_family = AF_INET;
                sin.sin_port = htons(chan->port);
                memcpy(&sin.sin_addr.s_addr, chan->addr, 4);
                u_int32_t i = 0;
                while(i < len) {
                    const size_t tosend = MIN(len-i, MAX_UDP_SZ);
                    if(sendto(fd, &buf[i], tosend, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1) {
                        warn("sending udp packet");
                        close(fd);
                        return 0;
                    }
                    i += tosend;
                }
                close(fd);
            }
            break;
        default:
            DLOG("invalid channel type: %x", chan->channeltype);
            return 0;
            break;
    }
    return 1;
}

u_int8_t *pml_md_allocbuf(u_int32_t sz) {
    return calloc(1, sz);
}
void pml_md_freebuf(u_int8_t *buf) {
    free(buf);
}
