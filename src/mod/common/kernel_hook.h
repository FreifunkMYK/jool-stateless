#ifndef SRC_MOD_COMMON_KERNEL_HOOK_H_
#define SRC_MOD_COMMON_KERNEL_HOOK_H_

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include "common/config.h"
#include "mod/common/nf_wrapper.h"

NF_CALLBACK(hook_ipv6, skb);
NF_CALLBACK(hook_ipv4, skb);

#endif /* SRC_MOD_COMMON_KERNEL_HOOK_H_ */
