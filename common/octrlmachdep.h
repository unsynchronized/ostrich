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


#endif /* OCTRLMACHDEP_H */
