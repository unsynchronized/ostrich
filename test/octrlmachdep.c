#include <octrl.h>
#include <octrlmachdep.h>
#include <pmltypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
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
    return current_settings;
}
