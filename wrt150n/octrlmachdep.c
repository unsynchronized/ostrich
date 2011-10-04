#include <pmlmachdep.h>
#include <pmltypes.h>
#include <pmlvm.h>
#include <octrlmachdep.h>

static struct octrl_settings *current_settings = NULL;

struct octrl_settings *octrl_md_retrieve_settings(void) {
    if(current_settings != NULL) {
        return current_settings;
    }
    current_settings = kmalloc(sizeof(struct octrl_settings), GFP_KERNEL);
    if(current_settings == NULL) {
        return NULL;
    }
    memset(current_settings, 0, sizeof(struct octrl_settings));

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
    current_settings->maxinsns = 100;
    current_settings->processing_enabled = 0;
    current_settings->savedmlen = 0;
    current_settings->savedm = NULL;
    current_settings->program = kmalloc(sizeof(XXXprog), GFP_KERNEL);
    if(current_settings->program != NULL) {
        current_settings->has_program = 1;
        current_settings->proglen = sizeof(XXXprog);
        memcpy(current_settings->program, XXXprog, sizeof(XXXprog));    /* XXX: wasteful to alloc for this */
    }

    current_settings->cookie = kmalloc(6, GFP_KERNEL);
    if(current_settings->cookie != NULL) {
        memcpy(current_settings->cookie, "cookie", 6);
        current_settings->cookie_enabled = 1;
        current_settings->cookielen = 6;
    }
    current_settings->commandip = kmalloc(4, GFP_KERNEL);
    u_int32_t inaddr = htonl(0xc0a80005);   /* XXX: 192.168.0.5 */
    if(current_settings->commandip != NULL) {
        memcpy(current_settings->commandip, &inaddr, 4);
        current_settings->commandiplen = 4;
        current_settings->has_commandip = 1;
    }
    current_settings->commandport = 4142;
    return current_settings;
}


void octrl_md_save_settings(void) {
    /* XXX: unimpl */
}
bool octrl_md_send_channel(struct octrl_channel *chan, u_int8_t *buf, u_int32_t len) {
    /* XXX: unimpl */
    return 0;
}
void octrl_md_set_filter(u_int8_t *filter, u_int32_t filterlen) {
    /* XXX: unimpl */
    return;
}
void octrl_md_del_channel(u_int8_t id) {
    /* XXX unimpl */
}
void octrl_md_set_channel(u_int8_t *buffer) {
    /* XXX unimpl */
}
void octrl_md_save_m(u_int32_t addr, u_int32_t len) {
    /* XXX unimpl */
    octrl_md_save_settings();
}
void octrl_md_set_m(u_int32_t addr, u_int8_t *buf, u_int32_t len) {
    /* XXX unimpl */
}
void octrl_md_set_flag(u_int32_t flag, u_int8_t *val, u_int32_t vlen) {
    /* XXX unimpl */
}
void octrl_md_set_cmdip(u_int8_t *newip, u_int32_t iplen) {
    /* XXX unimpl */
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
    ctx->mlen = 0;
    if(ctx->m == NULL) {
        return;
    }
    kfree(ctx->m);
    ctx->m = NULL;
}
