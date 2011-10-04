#include <pmltypes.h>
#include <pmlutils.h>

void pml_setu32(u_int8_t *buf, u_int32_t val) {
    buf[0] = (val >> 24) & 0xff;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >> 8) & 0xff;
    buf[3] = (val & 0xff);
}

void pml_setu16(u_int8_t *buf, u_int16_t val) {
    buf[0] = (val >> 8) & 0xff;
    buf[1] = (val & 0xff);
}
