#ifndef OCTRLMACHDEP_H
#define OCTRLMACHDEP_H 
#include <octrl.h>

/* octrl_md_retrieve_settings: load settings from storage, if they exist; if not,
 * then load the default settings.
 */
struct octrl_settings *octrl_md_retrieve_settings(void);


#endif /* OCTRLMACHDEP_H */
