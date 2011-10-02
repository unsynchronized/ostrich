#ifndef OCTRL_H
#define OCTRL_H
#include <pmlvm.h>
#include <pmltypes.h>

typedef struct octrl_channel {
    u_int8_t channelid;         /* XXX: remove? */
    u_int32_t channeltype;      /* type of channel */
    u_int8_t addr[16];          /* destination address */
    u_int32_t port;             /* destination port */
} octrl_channel;

#define OCTRL_CHANNEL_UDP4  0x0     /* plain udp v4 packet */

#define OCTRL_SEND_CHANNEL  0x0
#define OCTRL_SEND_UDPIP4   0x1

#define OCTRL_SEND_VERSION  0x0
#define OCTRL_SET_FILTER    0x1
#define OCTRL_SEND_CHANNELS 0x3
#define OCTRL_SET_CHANNEL   0x4
#define OCTRL_DEL_CHANNEL   0x5
#define OCTRL_SEND_M        0x6
#define OCTRL_SET_M         0x7
#define OCTRL_SAVE_M        0x8
#define OCTRL_SET_FLAG      0x9
#define OCTRL_SEND_FLAGS    0xA
#define OCTRL_SET_COOKIE    0xB
#define OCTRL_SET_CMDIP     0xC
#define OCTRL_SET_CMDPORT   0xD
#define OCTRL_CLEAR_M       0xE
#define OCTRL_DELETE_M      0xF

#define OCTRL_SENDM_EMPTYM       0x0
#define OCTRL_SENDM_VALID        0x1
#define OCTRL_SENDM_INVALIDRANGE 0x2

#define OCTRL_FLAG_ENABLE_COOKIE 0x0
#define OCTRL_FLAG_ENABLE_PMLVM  0x1
#define OCTRL_FLAG_MAX           0x1  /* don't forget to update this and the serializer! */

struct octrl_settings {
    u_int8_t *cookie;           /* secret cookie preamble */
    u_int32_t cookielen;
    bool cookie_enabled;

    u_int8_t *commandip;        /* IP address of command host */
    u_int32_t commandiplen;
    bool has_commandip;

    u_int16_t commandport;      /* port number commands must be addressed to */

    u_int8_t *program;          /* initial state of program at boot */
    u_int32_t proglen;
    bool has_program;

    u_int8_t *savedm;           /* initial state of M at boot */
    u_int32_t savedmlen;

    u_int32_t max_insns;        /* max number of instructions executed per packet */
    bool processing_enabled;    /* if 1, program will be run */
    bool drop_cmd_packets;      /* if 1, drop all command packets after processing */
    
    u_int8_t nchannels;
    octrl_channel **channels;
};

/* octrl_init: call at startup to load settings (or initialize to defaults) */
void octrl_init(void);

/* octrl_check_command: given an incoming packet, determine whether it contains
 * control commands, and parse them if it does.
 *
 * returns 0 if the packet should be dropped after this stage; 1 if it should be
 * passed on to the VM stage
 */
bool octrl_check_command(struct octrl_settings *settings, struct pml_packet_info *ppi);

/* octrl_deserialize_channel: deserialize a newly-allocated (with pml_md_allocbuf()) 
 * channel from the data inside buf.
 * returns NULL if the allocation fails.
 */
struct octrl_channel *octrl_deserialize_channel(u_int8_t *buf);

/* octrl_serialize_channel: serialize the channel data and put the data in buf.  buf
 * must have octrl_serialize_channel_size() bytes available.
 */
void octrl_serialize_channel(struct octrl_channel *chan, u_int8_t *buf);

/* octrl_serialize_channel_size: returns the number of bytes necessary to serialize 
 * a struct octrl_channel.
 */
u_int32_t octrl_serialize_channel_size(void);

#endif /* OCTRL_H */
