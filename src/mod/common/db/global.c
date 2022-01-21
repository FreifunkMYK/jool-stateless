#include "mod/common/db/global.h"

#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "common/constants.h"
#include "mod/common/address.h"
#include "mod/common/log.h"
#include "mod/common/nl/global.h"

static int validate_pool6_len(__u8 len)
{
	if (len == 32 || len == 40 || len == 48)
		return 0;
	if (len == 56 || len == 64 || len == 96)
		return 0;

	log_err("%u is not a valid prefix length (32, 40, 48, 56, 64, 96).", len);
	return -EINVAL;
}

static int validate_ubit(struct ipv6_prefix *prefix, bool force)
{
	if (force || !prefix->addr.s6_addr[8])
		return 0;

	log_err("The u-bit is nonzero; see https://github.com/NICMx/Jool/issues/174.\n"
			"Will cancel the operation. Use --force to override this.");
	return -EINVAL;
}

int pool6_validate(struct config_prefix6 *prefix, bool force)
{
	int error;

	if (!prefix->set)
		return 0;

	error = prefix6_validate(&prefix->prefix);
	if (error)
		return error;

	error = validate_pool6_len(prefix->prefix.len);
	if (error)
		return error;

	return validate_ubit(&prefix->prefix, force);
}

int globals_init(struct jool_globals *config, struct ipv6_prefix *pool6)
{
	static const __u16 PLATEAUS[] = DEFAULT_MTU_PLATEAUS;
	int error;

	config->enabled = DEFAULT_INSTANCE_ENABLED;
#ifdef DEBUG
	config->debug = true;
#else
	config->debug = false;
#endif

	if (pool6) {
		config->pool6.set = true;
		config->pool6.prefix = *pool6;
	} else {
		config->pool6.set = false;
	}

	/* TODO (fine) force */
	error = pool6_validate(&config->pool6, true);
	if (error)
		return error;

	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;
	config->lowest_ipv6_mtu = DEFAULT_LOWEST_IPV6_MTU;
	memcpy(config->plateaus.values, &PLATEAUS, sizeof(PLATEAUS));
	config->plateaus.count = ARRAY_SIZE(PLATEAUS);

	config->siit.compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
	config->siit.eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
	config->siit.randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
	config->siit.rfc6791_prefix6.set = false;
	config->siit.rfc6791_prefix4.set = false;

	return 0;
}

int globals_foreach(struct jool_globals *config,
		int (*cb)(struct joolnl_global_meta const *, void *, void *),
		void *arg,
		enum joolnl_attr_global offset)
{
	struct joolnl_global_meta const *meta;
	int error;

	joolnl_global_foreach_meta(meta) {
		if (offset) {
			if (joolnl_global_meta_id(meta) == offset)
				offset = 0;
			continue;
		}

		error = cb(meta, joolnl_global_get(meta, config), arg);
		if (error)
			return error;
	}

	return 0;
}
