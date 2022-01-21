#include "mod/common/nl/attribute.h"

#include <linux/sort.h>
#include "common/constants.h"
#include "mod/common/log.h"

static int validate_null(struct nlattr *attr, char const *name)
{
	if (!attr) {
		log_err("Invalid request: '%s' attribute is missing.", name);
		return -EINVAL;
	}

	return 0;
}

static int validate_len(struct nlattr *attr, char const *name, size_t expected_len)
{
	if (nla_len(attr) < expected_len) {
		log_err("Invalid request: %s has %d bytes instead of %zu.",
				name, nla_len(attr), expected_len);
		return -EINVAL;
	}

	return 0;
}

int jnla_get_u8(struct nlattr *attr, char const *name, __u8 *out)
{
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	*out = nla_get_u8(attr);
	return 0;
}

int jnla_get_u32(struct nlattr *attr, char const *name, __u32 *out)
{
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	*out = nla_get_u32(attr);
	return 0;
}

static int validate_str(char const *str, size_t max_size)
{
	size_t i;

	for (i = 0; i < max_size; i++)
		if (str[i] == '\0')
			return 0;

	return -EINVAL;
}

int jnla_get_str(struct nlattr *attr, char const *name, size_t size, char *out)
{
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;
	error = validate_str(nla_data(attr), size);
	if (error)
		return error;

	strcpy(out, nla_data(attr));
	return 0;
}

int jnla_get_addr6(struct nlattr *attr, char const *name, struct in6_addr *out)
{
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;
	error = validate_len(attr, name, sizeof(struct in6_addr));
	if (error)
		return error;

	memcpy(out, nla_data(attr), sizeof(*out));
	return 0;
}

int jnla_get_addr4(struct nlattr *attr, char const *name, struct in_addr *out)
{
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;
	error = validate_len(attr, name, sizeof(struct in_addr));
	if (error)
		return error;

	memcpy(out, nla_data(attr), sizeof(*out));
	return 0;
}

int jnla_get_prefix6(struct nlattr *attr, char const *name,
		struct ipv6_prefix *out)
{
	struct config_prefix6 tmp;
	int error;

	error = jnla_get_prefix6_optional(attr, name, &tmp);
	if (error)
		return error;

	if (!tmp.set) {
		log_err("Malformed %s: null despite being mandatory", name);
		return -EINVAL;
	}

	*out = tmp.prefix;
	return 0;
}

int jnla_get_prefix6_optional(struct nlattr *attr, char const *name,
		struct config_prefix6 *out)
{
	struct nlattr *attrs[JNLAP_COUNT];
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	error = jnla_parse_nested(attrs, JNLAP_MAX, attr, joolnl_prefix6_policy,
			name);
	if (error)
		return error;

	if (!attrs[JNLAP_LEN]) {
		log_err("Malformed %s: length attribute is missing", name);
		return -EINVAL;
	}
	if (!attrs[JNLAP_ADDR]) {
		out->set = false;
		return 0;
	}

	out->set = true;
	out->prefix.len = nla_get_u8(attrs[JNLAP_LEN]);
	return jnla_get_addr6(attrs[JNLAP_ADDR], "IPv6 prefix address",
			&out->prefix.addr);
}

int jnla_get_prefix4(struct nlattr *attr, char const *name,
		struct ipv4_prefix *out)
{
	struct config_prefix4 tmp;
	int error;

	error = jnla_get_prefix4_optional(attr, name, &tmp);
	if (error)
		return error;

	if (!tmp.set) {
		log_err("Malformed %s: null despite being mandatory", name);
		return -EINVAL;
	}

	*out = tmp.prefix;
	return 0;
}

int jnla_get_prefix4_optional(struct nlattr *attr, char const *name,
		struct config_prefix4 *out)
{
	struct nlattr *attrs[JNLAP_COUNT];
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	error = jnla_parse_nested(attrs, JNLAP_MAX, attr, joolnl_prefix4_policy,
			name);
	if (error)
		return error;

	if (!attrs[JNLAP_LEN]) {
		log_err("Malformed %s: length attribute is missing", name);
		return -EINVAL;
	}
	if (!attrs[JNLAP_ADDR]) {
		out->set = false;
		return 0;
	}

	out->set = true;
	out->prefix.len = nla_get_u8(attrs[JNLAP_LEN]);
	return jnla_get_addr4(attrs[JNLAP_ADDR], "IPv4 prefix address",
			&out->prefix.addr);
}

int jnla_get_taddr6(struct nlattr *attr, char const *name,
		struct ipv6_transport_addr *out)
{
	struct nlattr *attrs[JNLAT_COUNT];
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	error = jnla_parse_nested(attrs, JNLAT_MAX, attr, joolnl_taddr6_policy,
			name);
	if (error)
		return error;

	out->l4 = nla_get_u16(attrs[JNLAT_PORT]);
	return jnla_get_addr6(attrs[JNLAT_ADDR], "IPv6 address", &out->l3);
}

int jnla_get_taddr4(struct nlattr *attr, char const *name,
		struct ipv4_transport_addr *out)
{
	struct nlattr *attrs[JNLAT_COUNT];
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	error = jnla_parse_nested(attrs, JNLAT_MAX, attr, joolnl_taddr4_policy,
			name);
	if (error)
		return error;

	out->l4 = nla_get_u16(attrs[JNLAT_PORT]);
	return jnla_get_addr4(attrs[JNLAT_ADDR], "IPv4 address", &out->l3);
}

int jnla_get_eam(struct nlattr *attr, char const *name, struct eamt_entry *eam)
{
	struct nlattr *attrs[JNLAE_COUNT];
	int error;

	error = validate_null(attr, name);
	if (error)
		return error;

	error = jnla_parse_nested(attrs, JNLAE_MAX, attr, eam_policy, name);
	if (error)
		return error;

	error = jnla_get_prefix6(attrs[JNLAE_PREFIX6], "IPv6 prefix", &eam->prefix6);
	if (error)
		return error;

	return jnla_get_prefix4(attrs[JNLAE_PREFIX4], "IPv4 prefix", &eam->prefix4);
}

static int u16_compare(const void *a, const void *b)
{
	return *(__u16 *)b - *(__u16 *)a;
}

static void u16_swap(void *a, void *b, int size)
{
	__u16 t = *(__u16 *)a;
	*(__u16 *)a = *(__u16 *)b;
	*(__u16 *)b = t;
}

static int validate_plateaus(struct mtu_plateaus *plateaus)
{
	__u16 *values = plateaus->values;
	unsigned int i, j;

	/* Sort descending. */
	sort(values, plateaus->count, sizeof(*values), u16_compare, u16_swap);

	/* Remove zeroes and duplicates. */
	for (i = 0, j = 1; j < plateaus->count; j++) {
		if (values[j] == 0)
			break;
		if (values[i] != values[j]) {
			i++;
			values[i] = values[j];
		}
	}

	if (values[0] == 0) {
		log_err("The plateaus list contains nothing but zeroes.");
		return -EINVAL;
	}

	/* Update. */
	plateaus->count = i + 1;
	return 0;
}


int jnla_get_plateaus(struct nlattr *root, struct mtu_plateaus *out)
{
	struct nlattr *attr;
	int rem;
	int error;

	error = validate_null(root, "MTU plateaus");
	if (error)
		return error;
#if LINUX_VERSION_AT_LEAST(4, 12, 0, 8, 0)
	error = nla_validate(nla_data(root), nla_len(root), JNLAL_MAX,
			joolnl_plateau_list_policy, NULL);
#else
	error = nla_validate(nla_data(root), nla_len(root), JNLAL_MAX,
			joolnl_plateau_list_policy);
#endif
	if (error)
		return error;

	out->count = 0;
	nla_for_each_nested(attr, root, rem) {
		if (out->count >= PLATEAUS_MAX) {
			log_err("Too many plateaus.");
			return -EINVAL;
		}

		out->values[out->count] = nla_get_u16(attr);
		out->count++;
	}

	return validate_plateaus(out);
}

int jnla_put_addr6(struct sk_buff *skb, int attrtype,
		struct in6_addr const *addr)
{
	return nla_put(skb, attrtype, sizeof(*addr), addr);
}

int jnla_put_addr4(struct sk_buff *skb, int attrtype,
		struct in_addr const *addr)
{
	return nla_put(skb, attrtype, sizeof(*addr), addr);
}

int jnla_put_prefix6(struct sk_buff *skb, int attrtype,
		struct ipv6_prefix const *prefix)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -EMSGSIZE;

	if (prefix) {
		error = jnla_put_addr6(skb, JNLAP_ADDR, &prefix->addr);
		if (error)
			goto cancel;
		error = nla_put_u8(skb, JNLAP_LEN, prefix->len);
		if (error)
			goto cancel;
	} else {
		error = nla_put_u8(skb, JNLAP_LEN, 0);
		if (error)
			goto cancel;
	}

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_prefix4(struct sk_buff *skb, int attrtype,
		struct ipv4_prefix const *prefix)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -EMSGSIZE;

	if (prefix) {
		error = jnla_put_addr4(skb, JNLAP_ADDR, &prefix->addr);
		if (error)
			goto cancel;
		error = nla_put_u8(skb, JNLAP_LEN, prefix->len);
		if (error)
			goto cancel;
	} else {
		error = nla_put_u8(skb, JNLAP_LEN, 0);
		if (error)
			goto cancel;
	}

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_taddr6(struct sk_buff *skb, int attrtype,
		struct ipv6_transport_addr const *taddr)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -EMSGSIZE;

	error = jnla_put_addr6(skb, JNLAT_ADDR, &taddr->l3);
	if (error)
		goto cancel;
	error = nla_put_u16(skb, JNLAT_PORT, taddr->l4);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_taddr4(struct sk_buff *skb, int attrtype,
		struct ipv4_transport_addr const *taddr)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -EMSGSIZE;

	error = jnla_put_addr4(skb, JNLAT_ADDR, &taddr->l3);
	if (error)
		goto cancel;
	error = nla_put_u16(skb, JNLAT_PORT, taddr->l4);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_eam(struct sk_buff *skb, int attrtype,
		struct eamt_entry const *eam)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -EMSGSIZE;

	error = jnla_put_prefix6(skb, JNLAE_PREFIX6, &eam->prefix6);
	if (error)
		goto cancel;
	error = jnla_put_prefix4(skb, JNLAE_PREFIX4, &eam->prefix4);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_plateaus(struct sk_buff *skb, int attrtype,
		struct mtu_plateaus const *plateaus)
{
	struct nlattr *root;
	unsigned int i;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -EMSGSIZE;

	for (i = 0; i < plateaus->count; i++) {
		error = nla_put_u16(skb, JNLAL_ENTRY, plateaus->values[i]);
		if (error) {
			nla_nest_cancel(skb, root);
			return error;
		}
	}

	nla_nest_end(skb, root);
	return 0;
}

int jnla_parse_nested(struct nlattr *tb[], int maxtype,
		const struct nlattr *nla, const struct nla_policy *policy,
		char const *name)
{
	int error;
#if LINUX_VERSION_AT_LEAST(4, 12, 0, 8, 0)
	struct netlink_ext_ack extack;

	error = nla_parse_nested(tb, maxtype, nla, policy, &extack);
	if (error)
		log_err("The '%s' attribute is malformed: %s", name, extack._msg);
#else
	error = nla_parse_nested(tb, maxtype, nla, policy);
	if (error)
		log_err("The '%s' attribute is malformed", name);
#endif

	return error;
}


void report_put_failure(void)
{
	log_err("The allocated Netlink packet is too small to contain the response. This might be a bug; please report it. PAGE_SIZE is %lu.",
			PAGE_SIZE);
}
