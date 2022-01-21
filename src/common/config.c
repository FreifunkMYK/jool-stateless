#include "common/config.h"

#ifndef __KERNEL__
#include <errno.h>
#endif

struct nla_policy joolnl_struct_list_policy[JNLAL_COUNT] = {
	[JNLAL_ENTRY] = { .type = NLA_NESTED }
};
struct nla_policy joolnl_plateau_list_policy[JNLAL_COUNT] = {
	[JNLAL_ENTRY] = { .type = NLA_U16 }
};

struct nla_policy joolnl_instance_entry_policy[JNLAIE_COUNT] = {
	[JNLAIE_NS] = { .type = NLA_U32 },
	[JNLAIE_INAME] = {
#ifdef __KERNEL__
		.type = NLA_NUL_STRING,
		/* Must not include the null char (see struct nla_policy) */
		.len = INAME_MAX_SIZE - 1,
#else
		.type = NLA_STRING,
		/* Must include the null char (see validate_nla()) */
		.maxlen = INAME_MAX_SIZE,
#endif
	},
};

struct nla_policy joolnl_prefix6_policy[JNLAP_COUNT] = {
	[JNLAP_ADDR] = JOOLNL_ADDR6_POLICY,
	[JNLAP_LEN] = { .type = NLA_U8 },
};

struct nla_policy joolnl_prefix4_policy[JNLAP_COUNT] = {
	[JNLAP_ADDR] = JOOLNL_ADDR4_POLICY,
	[JNLAP_LEN] = { .type = NLA_U8 },
};

struct nla_policy joolnl_taddr6_policy[JNLAT_COUNT] = {
	[JNLAT_ADDR] = JOOLNL_ADDR6_POLICY,
	[JNLAT_PORT] = { .type = NLA_U16 },
};

struct nla_policy joolnl_taddr4_policy[JNLAT_COUNT] = {
	[JNLAT_ADDR] = JOOLNL_ADDR4_POLICY,
	[JNLAT_PORT] = { .type = NLA_U16 },
};

struct nla_policy eam_policy[JNLAE_COUNT] = {
	[JNLAE_PREFIX6] = { .type = NLA_NESTED },
	[JNLAE_PREFIX4] = { .type = NLA_NESTED },
};

struct nla_policy siit_globals_policy[JNLAG_COUNT] = {
	[JNLAG_ENABLED] = { .type = NLA_U8 },
	[JNLAG_POOL6] = { .type = NLA_NESTED },
	[JNLAG_LOWEST_IPV6_MTU] = { .type = NLA_U32 },
	[JNLAG_DEBUG] = { .type = NLA_U8 },
	[JNLAG_RESET_TC] = { .type = NLA_U8 },
	[JNLAG_RESET_TOS] = { .type = NLA_U8 },
	[JNLAG_TOS] = { .type = NLA_U8 },
	[JNLAG_PLATEAUS] = { .type = NLA_NESTED },
	[JNLAG_COMPUTE_CSUM_ZERO] = { .type = NLA_U8 },
	[JNLAG_HAIRPIN_MODE] = { .type = NLA_U8 },
	[JNLAG_RANDOMIZE_ERROR_ADDR] = { .type = NLA_U8 },
	[JNLAG_POOL6791V6] = { .type = NLA_NESTED },
	[JNLAG_POOL6791V4] = { .type = NLA_NESTED },
};

int iname_validate(const char *iname, bool allow_null)
{
	unsigned int i;

	if (!iname)
		return allow_null ? 0 : -EINVAL;

	for (i = 0; i < INAME_MAX_SIZE; i++) {
		if (iname[i] == '\0')
			return 0;
		if (iname[i] < 32) /* "if not printable" */
			break;
	}

	return -EINVAL;
}
