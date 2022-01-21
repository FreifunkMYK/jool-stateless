#include "usr/nl/attribute.h"

#include <errno.h>
#include <netlink/errno.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>

static struct jool_result validate_mandatory_attrs(struct nlattr *attrs[],
		int maxtype, struct nla_policy const *policy)
{
	int i;

	/* All defined attributes are mandatory */
	for (i = 0; i < maxtype; i++) {
		if (policy[i].type && !attrs[i]) {
			return result_from_error(
				-EINVAL,
				"The kernel module's response is missing attribute %u.",
				i
			);
		}
	}

	return result_success();
}

/* Wrapper for genlmsg_parse(). */
struct jool_result jnla_parse_msg(struct nl_msg *msg, struct nlattr *tb[],
		int maxtype, struct nla_policy *policy,
		bool validate_mandatories)
{
	int error;

	error = genlmsg_parse(nlmsg_hdr(msg), sizeof(struct joolnlhdr), tb,
			maxtype, policy);
	if (!error) {
		return validate_mandatories
				? validate_mandatory_attrs(tb, maxtype, policy)
				: result_success();
	}

	return result_from_error(
		error,
		"Could not parse Jool's Netlink response: %s",
		nl_geterror(error)
	);
}

/* Wrapper for nla_parse_nested(). */
struct jool_result jnla_parse_nested(struct nlattr *tb[], int maxtype,
		struct nlattr *root, struct nla_policy *policy)
{
	int error;

	error = nla_parse_nested(tb, maxtype, root, policy);
	if (!error)
		return validate_mandatory_attrs(tb, maxtype, policy);

	return result_from_error(
		error,
		"Could not parse a nested attribute in Jool's Netlink response: %s",
		nl_geterror(error)
	);
}

/* Wrapper for nla_validate() for lists */
struct jool_result jnla_validate_list(struct nlattr *head, int len,
		char const *what, struct nla_policy *policy)
{
	struct nlattr *attr;
	int rem;
	int error;

	error = nla_validate(head, len, JNLAL_MAX, policy);
	if (error) {
		return result_from_error(
			error,
			"The kernel's response does not contain a valid '%s' attribute list. (Unknown cause)",
			what
		);
	}

	/* Sigh */
	nla_for_each_attr(attr, head, len, rem) {
		if (nla_type(attr) != JNLAL_ENTRY) {
			return result_from_error(
				-EINVAL,
				"The kernel's response contains unexpected attribute '%d' in its '%s' list.",
				nla_type(attr), what
			);
		}
	}

	return result_success();
}

struct nlattr *jnla_nest_start(struct nl_msg *msg, int attrtype)
{
	return nla_nest_start(msg, NLA_F_NESTED | attrtype);
}

void nla_get_addr6(struct nlattr const *attr, struct in6_addr *addr)
{
	memcpy(addr, nla_data(attr), sizeof(*addr));
}

void nla_get_addr4(struct nlattr const *attr, struct in_addr *addr)
{
	memcpy(addr, nla_data(attr), sizeof(*addr));
}

/**
 * Contract:
 * Result contains 0 on success.
 * Result contains -ENOENT if the prefix was unset.
 * Result contains something else on other errors.
 */
struct jool_result nla_get_prefix6(struct nlattr *root, struct ipv6_prefix *out)
{
	struct nlattr *attrs[JNLAP_COUNT];
	int error;

	error = nla_parse_nested(attrs, JNLAP_MAX, root, joolnl_prefix6_policy);
	if (error) {
		return result_from_error(
			-EINVAL,
			"Could not parse a nested attribute in Jool's Netlink response: %s",
			nl_geterror(error)
		);
	}

	if (!attrs[JNLAP_ADDR]) {
		return result_from_error(
			-ENOENT,
			"Invalid kernel response: IPv6 prefix lacks address."
		);
	}
	if (!attrs[JNLAP_LEN]) {
		return result_from_error(
			-EINVAL,
			"Invalid kernel response: IPv6 prefix lacks length."
		);
	}

	nla_get_addr6(attrs[JNLAP_ADDR], &out->addr);
	out->len = nla_get_u8(attrs[JNLAP_LEN]);
	return result_success();
}

/**
 * Contract:
 * Result contains 0 on success.
 * Result contains -ENOENT if the prefix was unset.
 * Result contains something else on other errors.
 */
struct jool_result nla_get_prefix4(struct nlattr *root, struct ipv4_prefix *out)
{
	struct nlattr *attrs[JNLAP_COUNT];
	int error;

	error = nla_parse_nested(attrs, JNLAP_MAX, root, joolnl_prefix4_policy);
	if (error) {
		return result_from_error(
			-EINVAL,
			"Could not parse a nested attribute in Jool's Netlink response: %s",
			nl_geterror(error)
		);
	}

	if (!attrs[JNLAP_ADDR]) {
		return result_from_error(
			-ENOENT,
			"Invalid kernel response: IPv4 prefix lacks address."
		);
	}
	if (!attrs[JNLAP_LEN]) {
		return result_from_error(
			-EINVAL,
			"Invalid kernel response: IPv4 prefix lacks length."
		);
	}

	nla_get_addr4(attrs[JNLAP_ADDR], &out->addr);
	out->len = nla_get_u8(attrs[JNLAP_LEN]);
	return result_success();
}

struct jool_result nla_get_taddr6(struct nlattr *root, struct ipv6_transport_addr *out)
{
	struct nlattr *attrs[JNLAT_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, JNLAT_MAX, root, joolnl_taddr6_policy);
	if (result.error)
		return result;

	nla_get_addr6(attrs[JNLAT_ADDR], &out->l3);
	out->l4 = nla_get_u16(attrs[JNLAT_PORT]);
	return result_success();
}

struct jool_result nla_get_taddr4(struct nlattr *root, struct ipv4_transport_addr *out)
{
	struct nlattr *attrs[JNLAT_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, JNLAT_MAX, root, joolnl_taddr4_policy);
	if (result.error)
		return result;

	nla_get_addr4(attrs[JNLAT_ADDR], &out->l3);
	out->l4 = nla_get_u16(attrs[JNLAT_PORT]);
	return result_success();
}

struct jool_result nla_get_eam(struct nlattr *root, struct eamt_entry *out)
{
	struct nlattr *attrs[JNLAE_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, JNLAE_MAX, root, eam_policy);
	if (result.error)
		return result;

	result = nla_get_prefix6(attrs[JNLAE_PREFIX6], &out->prefix6);
	if (result.error)
		return result;

	return nla_get_prefix4(attrs[JNLAE_PREFIX4], &out->prefix4);
}

struct jool_result nla_get_plateaus(struct nlattr *root,
		struct mtu_plateaus *out)
{
	struct nlattr *attr;
	int rem;
	struct jool_result result;

	result = jnla_validate_list(nla_data(root), nla_len(root), "plateus",
			joolnl_plateau_list_policy);
	if (result.error)
		return result;

	out->count = 0;
	nla_for_each_nested(attr, root, rem) {
		if (out->count >= PLATEAUS_MAX) {
			return result_from_error(
				-EINVAL,
				"The kernel's response has too many plateaus."
			);
		}
		out->values[out->count] = nla_get_u16(attr);
		out->count++;
	}

	return result_success();
}

static int nla_put_addr6(struct nl_msg *msg, int attrtype, struct in6_addr const *addr)
{
	return nla_put(msg, attrtype, sizeof(*addr), addr);
}

static int nla_put_addr4(struct nl_msg *msg, int attrtype, struct in_addr const *addr)
{
	return nla_put(msg, attrtype, sizeof(*addr), addr);
}

int nla_put_prefix6(struct nl_msg *msg, int attrtype, struct ipv6_prefix const *prefix)
{
	struct nlattr *root;

	root = jnla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	if (prefix) {
		if (nla_put_addr6(msg, JNLAP_ADDR, &prefix->addr) < 0)
			goto cancel;
		if (nla_put_u8(msg, JNLAP_LEN, prefix->len) < 0)
			goto cancel;
	} else {
		/* forces the nested attribute to exist */
		if (nla_put_u8(msg, JNLAP_LEN, 0) < 0)
			goto cancel;
	}

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -NLE_NOMEM;
}

int nla_put_prefix4(struct nl_msg *msg, int attrtype, struct ipv4_prefix const *prefix)
{
	struct nlattr *root;

	root = jnla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	if (prefix) {
		if (nla_put_addr4(msg, JNLAP_ADDR, &prefix->addr) < 0)
			goto cancel;
		if (nla_put_u8(msg, JNLAP_LEN, prefix->len) < 0)
			goto cancel;
	} else {
		/* forces the nested attribute to exist */
		if (nla_put_u8(msg, JNLAP_LEN, 0) < 0)
			goto cancel;
	}

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -NLE_NOMEM;
}

int nla_put_plateaus(struct nl_msg *msg, int attrtype, struct mtu_plateaus const *plateaus)
{
	struct nlattr *root;
	unsigned int i;

	root = jnla_nest_start(msg, attrtype);
	if (!root)
		return -NLE_NOMEM;

	for (i = 0; i < plateaus->count; i++) {
		if (nla_put_u16(msg, JNLAL_ENTRY, plateaus->values[i]) < 0) {
			nla_nest_cancel(msg, root);
			return -NLE_NOMEM;
		}
	}

	nla_nest_end(msg, root);
	return 0;
}

int nla_put_eam(struct nl_msg *msg, int attrtype, struct eamt_entry const *entry)
{
	struct nlattr *root;

	root = jnla_nest_start(msg, attrtype);
	if (!root)
		return -NLE_NOMEM;

	if (nla_put_prefix6(msg, JNLAE_PREFIX6, &entry->prefix6) < 0)
		goto cancel;
	if (nla_put_prefix4(msg, JNLAE_PREFIX4, &entry->prefix4) < 0)
		goto cancel;

	nla_nest_end(msg, root);
	return 0;

cancel:
	nla_nest_cancel(msg, root);
	return -NLE_NOMEM;
}
