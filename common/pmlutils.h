#ifndef UTILS_H
#define UTILS_H 

#ifndef MIN
#define MIN(x,y) ((x) > (y) ? (y) : (x))
#endif


#define EXTRACT4(x) ((((u_int8_t)((x)[0])) << 24) \
                    | (((u_int8_t)((x)[1])) << 16) \
                    | (((u_int8_t)((x)[2])) << 8) \
                    | (((u_int8_t)((x)[3]))))
#define EXTRACT2(x) ((((u_int8_t)((x)[0])) << 8) | (((u_int8_t)((x)[1]))))

void pml_setu32(u_int8_t *buf, u_int32_t val);
void pml_setu16(u_int8_t *buf, u_int16_t val);

#endif /* UTILS_H */
