#ifndef SRC_MOD_COMMON_INIT_H_
#define SRC_MOD_COMMON_INIT_H_

#include <net/net_namespace.h>

int jool_siit_get(void);
void jool_siit_put(void);

bool is_siit_enabled(void);

#endif /* SRC_MOD_COMMON_INIT_H_ */
