#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/msg.h>

#include "common/config.h"
#include "common/constants.h"
#include "file.h"
#include "usr/util/cJSON.h"
#include "usr/util/file.h"
#include "usr/util/str_utils.h"
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"
#include "usr/nl/global.h"
#include "usr/nl/json.h"

#define OPTNAME_INAME 			"instance"
#define OPTNAME_GLOBAL			"global"
#define OPTNAME_EAMT			"eamt"
#define OPTNAME_BLACKLIST		"blacklist4"
#define OPTNAME_DENYLIST		"denylist4"
#define OPTNAME_MAX_ITERATIONS		"max-iterations"

/* TODO (warning) These variables prevent this module from being thread-safe. */
static struct joolnl_socket sk;
static char const *iname;
static __u8 force;

struct json_meta {
	char const *name; /* This being NULL signals the end of the array. */
	/* Second argument is @arg1 and third argument is @arg2. */
	struct jool_result (*handler)(cJSON *, void const *, void *);
	void const *arg1;
	void *arg2;
	bool mandatory;
	bool already_found;
};

/*
 * =================================
 * ======== Error functions ========
 * =================================
 */

static struct jool_result duplicates_found(char const *name)
{
	return result_from_error(
		-EEXIST,
		"Multiple '%s' tags found. Aborting...", name
	);
}

static struct jool_result missing_tag(char const *parent, char const *child)
{
	return result_from_error(
		-EINVAL,
		"Object '%s' is missing the '%s' child.",
		parent ? parent : "<unnamed>", child
	);
}

static struct jool_result string_expected(const char *field, cJSON *json)
{
	return type_mismatch(field, json, "String");
}

/*
 * =================================
 * ============= Utils =============
 * =================================
 */

static bool tagname_equals(cJSON const *json, char const *name)
{
	return strcasecmp(json->string, name) == 0;
}

/*
 * ==================================
 * ===== Generic object handlers ====
 * ==================================
 */

static struct jool_result handle_child(struct cJSON *child,
		struct json_meta *metadata)
{
	struct json_meta *meta;

	if (tagname_equals(child, "comment"))
		return result_success();

	for (meta = metadata; meta->name; meta++) {
		if (tagname_equals(child, meta->name)) {
			if (meta->already_found)
				return duplicates_found(meta->name);
			meta->already_found = true;
			return meta->handler(child, meta->arg1, meta->arg2);
		}
	}

	return result_from_error(-EINVAL, "Unknown tag: '%s'", child->string);
}

static struct jool_result handle_object(cJSON *obj, struct json_meta *metadata)
{
	struct json_meta *meta;
	cJSON *child;
	struct jool_result result;

	if (obj->type != cJSON_Object)
		return type_mismatch(obj->string, obj, "Object");

	for (child = obj->child; child; child = child->next) {
		result = handle_child(child, metadata);
		if (result.error)
			return result;
	}

	for (meta = metadata; meta->name; meta++)
		if (meta->mandatory && !meta->already_found)
			return missing_tag(obj->string, meta->name);

	return result_success();
}

static struct jool_result handle_array(cJSON *json, int attrtype, char *name,
		struct jool_result (*entry_handler)(cJSON *, struct nl_msg *))
{
	struct nl_msg *msg;
	struct nlattr *root;
	unsigned int entries_written;
	struct jool_result result;

	if (json->type != cJSON_Array)
		return type_mismatch(name, json, "Array");

	msg = NULL;
	root = NULL;
	entries_written = 0;
	for (json = json->child; json; json = json->next) {
		if (msg == NULL) {
			result = joolnl_alloc_msg(&sk, iname, JNLOP_FILE_HANDLE,
					force, &msg);
			if (result.error)
				return result;

			root = jnla_nest_start(msg, attrtype);
			if (!root)
				goto too_small;
		}

		result = entry_handler(json, msg);
		if (result.error) {
			if (result.error != -NLE_NOMEM)
				return result;
			result_cleanup(&result);

			if (entries_written == 0)
				goto too_small;

			nla_nest_end(msg, root);
			result = joolnl_request(&sk, msg, NULL, NULL);
			if (result.error)
				return result;

			msg = NULL;
			json = json->prev;
			entries_written = 0;
		} else {
			entries_written++;
		}
	}

	if (entries_written == 0)
		return result_success();

	nla_nest_end(msg, root);
	return joolnl_request(&sk, msg, NULL, NULL);

too_small:
	nlmsg_free(msg);
	return joolnl_err_msgsize();
}

static struct jool_result write_global(struct cJSON *json, void const *meta,
		void *msg)
{
	return joolnl_global_json2nl(meta, json, msg);
}

static struct jool_result create_globals_meta(struct nl_msg *msg,
		struct json_meta **result)
{
	struct joolnl_global_meta const *gmeta;
	struct json_meta *jmeta;

	*result = calloc(joolnl_global_meta_count() + 1, sizeof(struct json_meta));
	if (!(*result))
		return result_from_enomem();

	jmeta = *result;
	joolnl_global_foreach_meta(gmeta) {
		jmeta->name = joolnl_global_meta_name(gmeta);
		jmeta->handler = write_global;
		jmeta->arg1 = gmeta;
		jmeta->arg2 = msg;
		jmeta->mandatory = false;
		jmeta->already_found = false;
		jmeta++;
	}
	memset(jmeta, 0, sizeof(*jmeta));

	return result_success();
}

static struct jool_result handle_global(cJSON *json)
{
	struct nl_msg *msg;
	struct nlattr *root;
	struct json_meta *meta;
	struct jool_result result;

	result = joolnl_alloc_msg(&sk, iname, JNLOP_FILE_HANDLE, force, &msg);
	if (result.error)
		return result;

	root = jnla_nest_start(msg, JNLAR_GLOBALS);
	if (!root) {
		result = joolnl_err_msgsize();
		goto revert_msg;
	}

	result = create_globals_meta(msg, &meta);
	if (result.error)
		goto revert_msg;

	result = handle_object(json, meta);
	if (result.error)
		goto revert_meta;

	nla_nest_end(msg, root);
	free(meta);
	return joolnl_request(&sk, msg, NULL, NULL);

revert_meta:
	free(meta);
revert_msg:
	nlmsg_free(msg);
	return result;
}

/*
 * =================================
 * === Parsers of database fields ==
 * =================================
 */

static struct jool_result json2prefix6(cJSON *json, void const *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_prefix6(json->valuestring, arg2)
			: string_expected(json->string, json);
}

static struct jool_result json2prefix4(cJSON *json, void const *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_prefix4(json->valuestring, arg2)
			: string_expected(json->string, json);
}

/*
 * =================================
 * ===== Database tag handlers =====
 * =================================
 */

static struct jool_result handle_eam_entry(cJSON *json, struct nl_msg *msg)
{
	struct eamt_entry eam;
	struct json_meta meta[] = {
		{ "ipv6 prefix", json2prefix6, NULL, &eam.prefix6, true },
		{ "ipv4 prefix", json2prefix4, NULL, &eam.prefix4, true },
		{ NULL },
	};
	struct jool_result result;

	result = handle_object(json, meta);
	if (result.error)
		return result;

	return (nla_put_eam(msg, JNLAL_ENTRY, &eam) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result handle_denylist_entry(cJSON *json, struct nl_msg *msg)
{
	struct ipv4_prefix prefix;
	struct jool_result result;

	if (json->type != cJSON_String)
		return string_expected("denylist entry", json);

	result = str_to_prefix4(json->valuestring, &prefix);
	if (result.error)
		return result;

	return (nla_put_prefix4(msg, JNLAL_ENTRY, &prefix) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

/*
 * ==========================================
 * = Second level tag handlers, second pass =
 * ==========================================
 */

static struct jool_result do_nothing(cJSON *json, void const *arg1, void *arg2)
{
	return result_success();
}

static struct jool_result handle_global_tag(cJSON *json, void const *arg1, void *arg2)
{
	return handle_global(json);
}

static struct jool_result handle_eamt_tag(cJSON *json, void const *arg1, void *arg2)
{
	return handle_array(json, JNLAR_EAMT_ENTRIES, OPTNAME_EAMT, handle_eam_entry);
}

static struct jool_result handle_bl4_tag(cJSON *json, void const *arg1, void *arg2)
{
	return handle_array(json, JNLAR_BL4_ENTRIES, OPTNAME_BLACKLIST, handle_denylist_entry);
}

static struct jool_result handle_dl4_tag(cJSON *json, void const *arg1, void *arg2)
{
	return handle_array(json, JNLAR_BL4_ENTRIES, OPTNAME_DENYLIST, handle_denylist_entry);
}

/*
 * ==================================
 * = Root tag handlers, second pass =
 * ==================================
 */

static struct jool_result parse_siit_json(cJSON *json)
{
	struct json_meta meta[] = {
		/* instance and framework were already handled. */
		{ OPTNAME_INAME, do_nothing, NULL, NULL, true },
		{ OPTNAME_GLOBAL, handle_global_tag, NULL, NULL, false },
		{ OPTNAME_EAMT, handle_eamt_tag, NULL, NULL, false },
		{ OPTNAME_BLACKLIST, handle_bl4_tag, NULL, NULL, false },
		{ OPTNAME_DENYLIST, handle_dl4_tag, NULL, NULL, false },
		{ NULL },
	};

	return handle_object(json, meta);
}

/*
 * =========================================
 * = Second level tag handlers, first pass =
 * =========================================
 */

static struct jool_result handle_instance_tag(cJSON *json, void const *_iname,
		void *arg2)
{
	int error;

	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	error = iname_validate(json->valuestring, false);
	if (error)
		return result_from_error(error, INAME_VALIDATE_ERRMSG);
	if (_iname && strcmp(_iname, json->valuestring) != 0) {
		return result_from_error(
			-EINVAL,
			"The -i command line argument (%s) does not match the instance name defined in the file (%s).\n"
			"You might want to delete one of them.",
			(char const *)_iname, json->valuestring
		);
	}

	iname = json->valuestring;
	return result_success();
}

/*
 * ================================
 * = Root tag handler, first pass =
 * ================================
 */

/*
 * Sets the @iname global variable according to @_iname and @json.
 */
static struct jool_result prepare_instance(char const *_iname, cJSON *json)
{
	struct json_meta meta[] = {
		{ OPTNAME_INAME, handle_instance_tag, _iname, NULL, false },
		/* The rest will be handled later. */
		{ OPTNAME_GLOBAL, do_nothing },
		{ OPTNAME_EAMT, do_nothing },
		{ OPTNAME_BLACKLIST, do_nothing },
		{ OPTNAME_DENYLIST, do_nothing },
		{ NULL },
	};
	struct jool_result result;

	iname = NULL;

	/*
	 * We want to be a little lenient if the user defines both -i and the
	 * instance tag. Normally, we would complain about the duplication, but
	 * we don't want to return negative reinforcement if the user is simply
	 * used to input -i and the strings are the same. This would only be
	 * irritating.
	 * So don't do `iname = _iname` yet.
	 */
	result.error = iname_validate(_iname, true);
	if (result.error)
		return result_from_error(result.error, INAME_VALIDATE_ERRMSG);

	result = handle_object(json, meta);
	if (result.error)
		return result;

	if (!iname && !_iname)
		return missing_tag("root", OPTNAME_INAME);
	if (!iname)
		iname = _iname;

	return result;
}

/*
 * =================================
 * ======== Outer functions ========
 * =================================
 */

static struct jool_result send_ctrl_msg(bool init)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(&sk, iname, JNLOP_FILE_HANDLE, 0, &msg);
	if (result.error)
		return result;

	if (init)
		NLA_PUT(msg, JNLAR_ATOMIC_INIT, 0, NULL);
	else
		NLA_PUT(msg, JNLAR_ATOMIC_END, 0, NULL);

	result = joolnl_request(&sk, msg, NULL, NULL);
	if (result.error)
		return result;

	return result_success();

nla_put_failure:
	nlmsg_free(msg);
	return result;
}

static struct jool_result do_parsing(char const *iname, char *buffer)
{
	cJSON *json;
	struct jool_result result;

	json = cJSON_Parse(buffer);
	if (!json) {
		return result_from_error(
			-EINVAL,
			"The JSON parser got confused around the beginning of this string:\n"
			"%s", cJSON_GetErrorPtr()
		);
	}

	result = prepare_instance(iname, json);
	if (result.error)
		goto fail;

	result = send_ctrl_msg(true);
	if (result.error)
		goto fail;

	result = parse_siit_json(json);

	if (result.error)
		goto fail;

	/*
	 * Send the control message before deleting, because @iname might point
	 * to the json object, and send_ctrl_msg() needs @iname.
	 */
	result = send_ctrl_msg(false);
	cJSON_Delete(json);
	return result;

fail:
	cJSON_Delete(json);
	return result;
}

struct jool_result joolnl_file_parse(struct joolnl_socket *_sk,
		char const *iname, char const *file_name, bool _force)
{
	char *buffer;
	struct jool_result result;

	sk = *_sk;
	force = _force ? JOOLNLHDR_FLAGS_FORCE : 0;

	result = file_to_string(file_name, &buffer);
	if (result.error)
		return result;

	result = do_parsing(iname, buffer);
	free(buffer);
	return result;
}

static struct jool_result __json_get_iname(cJSON *root, char **out)
{
	cJSON *child;

	if (root->type != cJSON_Object)
		return type_mismatch("root", root, "Object");

	for (child = root->child; child; child = child->next) {
		if (tagname_equals(child, OPTNAME_INAME)) {
			*out = strdup(child->valuestring);
			return ((*out) != NULL)
					? result_success()
					: result_from_enomem();
		}
	}

	return result_from_error(
		-EINVAL,
		"The file does not contain an instance name."
	);
}

struct jool_result joolnl_file_get_iname(char const *file_name, char **out)
{
	char *json_string;
	cJSON *json;
	struct jool_result result;

	result = file_to_string(file_name, &json_string);
	if (result.error)
		return result;

	json = cJSON_Parse(json_string);

	free(json_string);

	if (!json) {
		return result_from_error(
			-EINVAL,
			"The JSON parser got confused around the beginning of this string:\n"
			"%s", cJSON_GetErrorPtr()
		);
	}

	result = __json_get_iname(json, out);

	cJSON_Delete(json);
	return result;
}
