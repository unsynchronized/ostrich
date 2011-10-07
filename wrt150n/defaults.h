#ifndef DEFAULTS_H
#define DEFAULTS_H

/* The PML program installed at system boot. */
extern u_int8_t *octrl_default_program;
extern const u_int32_t octrl_default_program_len;

/* default cookie; if null, then cookie will be disabled */
extern u_int8_t *octrl_default_cookie;
extern const u_int32_t octrl_default_cookie_len;

/* default command ip, already in the correct byte order */
extern u_int8_t *octrl_default_commandip;
extern const u_int32_t octrl_default_commandip_len;

#define OCTRL_DEFAULT_PROCESSING_ENABLED 1
#define OCTRL_DEFAULT_COOKIE_ENABLED 1

#define OCTRL_DEFAULT_COMMANDPORT 4142

#endif /* DEFAULTS_H */
