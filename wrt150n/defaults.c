#include <pmlmachdep.h>
#include <pmltypes.h>
#include <pmlvm.h>
#include <octrlmachdep.h>
#include <pmlutils.h>
#include <defaults.h>

/* Here's where you should put your default settings.  These will be copied into the
 * octrl context by octrl_md_retrieve_settings.
 */
u_int8_t bigprog[] = {
/*  0 */    PML_MOVS, PML_MOVS_TDB(PML_MOVS_IP4TL_HDROFF, PML_MOVS_ADDR_A), 0x0, 0x0, 0x0, 0x0,
/*  6 */    PML_JEQ, PML_JCOND_0, 0, 0, 0, 36,
/* 12 */    PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_A), 0, 0, 0, 0,
/* 18 */    PML_MOVS, PML_MOVS_TDB(PML_MOVS_IP_HDROFF, PML_MOVS_ADDR_X), 0x0, 0x0, 0x0, 0x0,
/* 24 */    PML_MOVB, PML_MOV_DSB(PML_MOV_ADDR_P_X_N, PML_MOV_ADDR_A), 0, 0, 0, 9,
/* 30 */    PML_MOVW, PML_MOV_DSB(PML_MOV_ADDR_N, PML_MOV_ADDR_X), 0, 0, 0, 17,
/* 36 */    PML_JEQ, PML_JCOND_X, 0, 0, 0, 12,
/* 42 */    PML_EXIT, 0, 0, 0, 0, 0,
/* 54 */    PML_DIVERT_P, 1, 0xff, 0xff, 0xff, 0xff,
/* 60 */    PML_EXIT, 0, 0, 0, 0, 0,

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
u_int8_t *octrl_default_program = bigprog;
const u_int32_t octrl_default_program_len = sizeof(bigprog);

u_int8_t *octrl_default_cookie = (u_int8_t[]) { 'c', 'o', 'o', 'k', 'i', 'e' };
const u_int32_t octrl_default_cookie_len = 6;

u_int8_t *octrl_default_commandip = (u_int8_t[]){ 0xa, 0xa, 0x1, 0x2 };  /* 10.10.1.2 */
const u_int32_t octrl_default_commandip_len  = 4;


