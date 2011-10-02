#ifndef OCTRLMACHDEP_H
#define OCTRLMACHDEP_H 
#include <octrl.h>

/* octrl_md_retrieve_settings: load settings from storage, if they exist; if not,
 * then load the default settings.
 */
struct octrl_settings *octrl_md_retrieve_settings(void);

/* octrl_md_send_channel: send a buffer out a given channel, breaking it up as
 * necessary.
 *
 * returns 1 if the send was successful; 0 if not
 */
bool octrl_md_send_channel(struct octrl_channel *chan, u_int8_t *const buf, u_int32_t len);

/* octrl_md_set_filter: replace the currently existing filter with the given data.
 * also, save the filter to persistent storage.
 * if filterlen is 0, then clear the filter entirely.
 */
void octrl_md_set_filter(u_int8_t *filter, u_int32_t filterlen);

/* octrl_md_set_channel: set a channel, saving it to persistent storage.  if the channel 
 * with the given ID exists already, replace it.
 */
void octrl_md_set_channel(u_int8_t *buffer);

/* octrl_md_save_m: replace the contents of persistent-M with M[addr], length len. if
 * len is 0, then clear the contents of persistent-M.
 */
void octrl_md_save_m(u_int32_t addr, u_int32_t len);

/* octrl_md_set_m: set the contents of M[addr], length len, to the data in the specified
 * buffer.
 */
void octrl_md_set_m(u_int32_t addr, u_int8_t *buf, u_int32_t len);

/* octrl_md_set_flag: set flag flag to the value specified by val; val's length is
 * vlen.
 */
void octrl_md_set_flag(u_int32_t flag, u_int8_t *val, u_int32_t vlen);

/* octrl_md_set_cmdip: set the command IP; length specified in iplen.
 * if iplen == 0, then ignore the buffer and clear the currently-set command IP
 */
void octrl_md_set_cmdip(u_int8_t *newip, u_int32_t iplen);

/* octrl_md_set_cmdport: set the command port. */
void octrl_md_set_cmdport(u_int16_t newport);

/* octrl_md_set_cookie: set the cookie to the specified value.  if clen == 0, then clear
 * the currently-set cookie.
 */
void octrl_md_set_cookie(u_int8_t *ncookie, u_int32_t clen);

/* octrl_clear_m: clear the current value of M. */
void octrl_md_clear_m(void);


#endif /* OCTRLMACHDEP_H */
