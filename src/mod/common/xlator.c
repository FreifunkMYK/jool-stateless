#include "mod/common/xlator.h"

#include <linux/hashtable.h>
#include <linux/sched.h>

#include "common/types.h"
#include "common/xlat.h"
#include "db/global.h"
#include "mod/common/atomic_config.h"
#include "mod/common/kernel_hook.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/rcu.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/db/denylist4.h"
#include "mod/common/db/eam.h"
#include "mod/common/steps/handling_hairpinning_siit.h"

/** Netfilter module registration object */
static struct nf_hook_ops netfilter_hooks[] = {
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP6_PRI_NAT_DST + 25,
	}, {
		.hook = hook_ipv4,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST + 25,
	},
};

/**
 * An xlator, except it's the database node version.
 */
struct jool_instance {
	/**
	 * The actual xlator. The other modules will actually receive a shallow
	 * clone of it.
	 *
	 * TODO (fine) maybe turn this into a const.
	 */
	struct xlator jool;

	struct hlist_node table_hook;
	bool hash_set;
	u32 hash;

	struct list_head list_hook;
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	/**
	 * This points to a copy of the netfilter_hooks array.
	 *
	 * It needs to be a pointer to an array and not an array because the
	 * ops needs to survive atomic configuration; the jool_instance needs to
	 * be replaced but the ops needs to survive.
	 *
	 * This is only set if @jool.flags matches FW_NETFILTER.
	 */
	struct nf_hook_ops *nf_ops;
#endif
};

static DEFINE_HASHTABLE(instances, 6); /* The identifier is (ns, iname). */
static struct list_head __rcu *netfilter_instances;
static DEFINE_MUTEX(lock);

static u32 get_hash(struct net *ns, char const *iname)
{
	u32 hash;
	unsigned int i;

	hash = hash_ptr(ns, 32);
	for (i = 0; iname[i]; i++)
		hash = 31 * hash + iname[i];

	return hash;
}

static u32 get_instance_hash(struct jool_instance *instance)
{
	if (instance->hash_set)
		return instance->hash;

	instance->hash_set = true;
	instance->hash = get_hash(instance->jool.ns,
			instance->jool.iname);
	return instance->hash;
}

static struct jool_instance *find_instance(struct net *ns, char const *iname)
{
	struct jool_instance *instance;
	u32 hash;

	hash = get_hash(ns, iname);
	hash_for_each_possible_rcu(instances, instance, table_hook, hash)
		if ((ns == instance->jool.ns)
				&& (strcmp(iname, instance->jool.iname) == 0))
			return instance;

	return NULL;
}

static void destroy_jool_instance(struct jool_instance *instance, bool unhook)
{
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	if (unhook) {
		nf_unregister_net_hooks(instance->jool.ns,
				instance->nf_ops,
				ARRAY_SIZE(netfilter_hooks));
	}
	__wkfree("nf_hook_ops", instance->nf_ops);
#endif

	xlator_put(&instance->jool);
	log_info("Deleted instance '%s'.", instance->jool.iname);
	wkfree(struct jool_instance, instance);
}

static void xlator_get(struct xlator *jool)
{
	jstat_get(jool->stats);

	eamt_get(jool->siit.eamt);
	denylist4_get(jool->siit.denylist4);
}

/**
 * Moves the jool_instance nodes from the database (that match the @ns
 * namespace and the @xt type) to the @detached list.
 */
static void __flush_detach(struct net *ns, struct hlist_head *detached)
{
	struct jool_instance *instance;
	struct hlist_node *tmp;
	size_t i;

	hash_for_each_safe(instances, i, tmp, instance, table_hook) {
		if (instance->jool.ns == ns) {
			hash_del_rcu(&instance->table_hook);
			hlist_add_head(&instance->table_hook, detached);
			list_del_rcu(&instance->list_hook);
		}
	}
}

/**
 * Actually deletes all of the jool_instance nodes listed in @detached.
 */
static void __flush_delete(struct hlist_head *detached)
{
	struct jool_instance *instance;
	struct hlist_node *tmp;

	if (hlist_empty(detached))
		return; /* Calling synchronize_rcu_bh() for no reason is bad. */

	synchronize_rcu_bh();

	hlist_for_each_entry_safe(instance, tmp, detached, table_hook)
		destroy_jool_instance(instance, true);
}

/**
 * Called whenever the user deletes a namespace. Supposed to delete all the
 * instances inserted in that namespace.
 *
 * Update 2019-10-15: Also called during modprobe -r.
 */
void jool_xlator_flush_net(struct net *ns)
{
	HLIST_HEAD(detached);

	mutex_lock(&lock);
	__flush_detach(ns, &detached);
	mutex_unlock(&lock);

	__flush_delete(&detached);
}
EXPORT_SYMBOL_GPL(jool_xlator_flush_net);

/**
 * Called whenever the user deletes... several namespaces? I'm not really sure.
 * The idea seems to be to minimize the net amount of synchronize_rcu_bh()
 * calls, but the kernel seems to always call flush_net() first and
 * flush_batch() next. It seems self-defeating to me.
 *
 * Maybe delete flush_net(); I guess it's redundant.
 */
void jool_xlator_flush_batch(struct list_head *net_exit_list)
{
	struct net *ns;
	HLIST_HEAD(detached);

	mutex_lock(&lock);
	list_for_each_entry(ns, net_exit_list, exit_list)
		__flush_detach(ns, &detached);
	mutex_unlock(&lock);

	__flush_delete(&detached);
}
EXPORT_SYMBOL_GPL(jool_xlator_flush_batch);

/**
 * Initializes this module. Do not call other functions before this one.
 */
int xlator_setup(void)
{
	struct list_head *list;
#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 8, 0)
	int error;
#endif

	list = __wkmalloc("xlator DB", sizeof(struct list_head), GFP_KERNEL);
	if (!list)
		return -ENOMEM;
	INIT_LIST_HEAD(list);
	RCU_INIT_POINTER(netfilter_instances, list);

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 8, 0)
	error = nf_register_hooks(netfilter_hooks, ARRAY_SIZE(netfilter_hooks));
	if (error) {
		__wkfree("xlator DB", list);
		return error;
	}
#endif

	return 0;
}

/**
 * Graceful termination of this module. Reverts xlator_setup().
 * Will clean up any allocated memory.
 */
void xlator_teardown(void)
{
	struct list_head *ni;

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 8, 0)
	nf_unregister_hooks(netfilter_hooks, ARRAY_SIZE(netfilter_hooks));
#endif

	WARN(!hash_empty(instances), "There are elements in the xlator table after a cleanup.");
	ni = rcu_dereference_raw(netfilter_instances);
	WARN(!list_empty(ni), "There are elements in the xlator list after a cleanup.");
	__wkfree("xlator DB", ni);
}

static int init_siit(struct xlator *jool, struct ipv6_prefix *pool6)
{
	int error;

	error = globals_init(&jool->globals, pool6);
	if (error)
		return error;

	jool->stats = jstat_alloc();
	if (!jool->stats)
		goto stats_fail;
	jool->siit.eamt = eamt_alloc();
	if (!jool->siit.eamt)
		goto eamt_fail;
	jool->siit.denylist4 = denylist4_alloc();
	if (!jool->siit.denylist4)
		goto denylist4_fail;

	jool->is_hairpin = is_hairpin_siit;
	jool->handling_hairpinning = handling_hairpinning_siit;
	return 0;

denylist4_fail:
	eamt_put(jool->siit.eamt);
eamt_fail:
	jstat_put(jool->stats);
stats_fail:
	return -ENOMEM;
}

int xlator_init(struct xlator *jool, struct net *ns, char *iname,
		struct ipv6_prefix *pool6)
{
	jool->ns = ns;
	strcpy(jool->iname, iname);

	return init_siit(jool, pool6);
}

static int basic_validations(char const *iname, bool allow_null_iname)
{
	int error;

	error = iname_validate(iname, allow_null_iname);
	if (error) {
		log_err(INAME_VALIDATE_ERRMSG);
		return error;
	}
	return 0;
}

/** Basic validations when adding an xlator to the DB. */
static int basic_add_validations(char *iname, struct ipv6_prefix *pool6)
{
	int error;

	error = basic_validations(iname, false);
	if (error)
		return error;

	return 0;
}

/**
 * Checks whether an instance (whose namespace is @ns, name is @iname and flags
 * are @flags) can be added to the database without breaking its
 * rules.
 *
 * Assumes the DB mutex is locked.
 */
static int validate_collision(struct net *ns, char *iname)
{
	struct jool_instance *instance;
	size_t i;

	hash_for_each(instances, i, instance, table_hook) {
		if (instance->jool.ns != ns)
			continue;
		if (strcmp(instance->jool.iname, iname) == 0) {
			log_err("This namespace already has a Jool instance named '%s'.",
					iname);
			return -EEXIST;
		}
	}

	return 0;
}

/**
 * Requires the mutex to be locked.
 */
static int __xlator_add(struct jool_instance *new, struct xlator *result)
{
	struct list_head *list;

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	struct nf_hook_ops *ops;
	int error;

	ops = __wkmalloc("nf_hook_ops",
		ARRAY_SIZE(netfilter_hooks) * sizeof(struct nf_hook_ops),
		GFP_KERNEL);
	if (!ops)
		return -ENOMEM;

	/* All error roads from now need to free @ops. */

	memcpy(ops, netfilter_hooks, sizeof(netfilter_hooks));

	error = nf_register_net_hooks(new->jool.ns, ops,
			ARRAY_SIZE(netfilter_hooks));
	if (error) {
		__wkfree("nf_hook_ops", ops);
		return error;
	}

	new->nf_ops = ops;
#endif

	hash_add_rcu(instances, &new->table_hook, get_instance_hash(new));
	list = rcu_dereference_protected(netfilter_instances,
			lockdep_is_held(&lock));
	list_add_tail_rcu(&new->list_hook, list);

	if (result) {
		xlator_get(&new->jool);
		memcpy(result, &new->jool, sizeof(new->jool));
	}

	return 0;
}

/**
 * Adds a new Jool instance to the current namespace.
 *
 * @result: Will be initialized with a clone of the new translator. Send NULL
 *     if you're not interested.
 */
int xlator_add(char *iname, struct ipv6_prefix *pool6,
		struct xlator *result)
{
	struct jool_instance *instance;
	struct net *ns;
	int error;

	error = basic_add_validations(iname, pool6);
	if (error)
		return error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	/* All roads from now need to put @ns. */

	instance = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!instance) {
		put_net(ns);
		return -ENOMEM;
	}

	/* All *error* roads from now need to free @instance. */

	error = xlator_init(&instance->jool, ns, iname, pool6);
	if (error) {
		wkfree(struct jool_instance, instance);
		put_net(ns);
		return error;
	}
	instance->hash_set = false;
	instance->hash = 0;
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	instance->nf_ops = NULL;
#endif

	/* Error roads from now no longer need to free @instance. */
	/* Error roads from now need to properly destroy @instance. */

	mutex_lock(&lock);

	/* All roads from now on must unlock the mutex. */

	error = validate_collision(ns, iname);
	if (error)
		goto mutex_fail;

	error = __xlator_add(instance, result);
	if (error)
		goto mutex_fail;

	mutex_unlock(&lock);
	put_net(ns);
	log_info("Created instance '%s'.", iname);
	return 0;

mutex_fail:
	mutex_unlock(&lock);
	destroy_jool_instance(instance, false);
	put_net(ns);
	return error;
}

static int __xlator_rm(struct net *ns, char *iname)
{
	struct jool_instance *instance;

	mutex_lock(&lock);

	instance = find_instance(ns, iname);
	if (!instance) {
		mutex_unlock(&lock);
		log_err("The requested instance does not exist.");
		return -ESRCH;
	}

	hash_del_rcu(&instance->table_hook);
	list_del_rcu(&instance->list_hook);

	mutex_unlock(&lock);
	synchronize_rcu_bh();

	/*
	 * Nobody can kref_get the databases now:
	 * Other code should not do it because of the
	 * xlator_find() contract, and xlator_find()'s
	 * xlator_get() already happened. Other xlator_find()'s
	 * xlator_get()s are not going to get in the way either
	 * because the instance is no longer listed.
	 * So finally return everything.
	 */
	destroy_jool_instance(instance, true);
	return 0;
}

int xlator_rm(char *iname)
{
	struct net *ns;
	int error;

	error = iname_validate(iname, false);
	if (error) {
		log_err(INAME_VALIDATE_ERRMSG);
		return error;
	}

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = __xlator_rm(ns, iname);

	put_net(ns);
	return error;
}

int xlator_replace(struct xlator *jool)
{
	struct jool_instance *old;
	struct jool_instance *new;
	struct list_head *list;
	int error;

	error = basic_add_validations(jool->iname,
			jool->globals.pool6.set
					? &jool->globals.pool6.prefix
					: NULL);
	if (error)
		return error;

	new = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	memcpy(&new->jool, jool, sizeof(*jool));
	xlator_get(&new->jool);
	new->hash_set = false;
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	new->nf_ops = NULL;
#endif

	mutex_lock(&lock);

	old = find_instance(jool->ns, jool->iname);
	if (!old) {
		/* Not found, hence not replacing. Add it instead. */
		error = __xlator_add(new, NULL);
		if (error)
			destroy_jool_instance(new, false);

		mutex_unlock(&lock);
		return error;
	}

	new->hash_set = old->hash_set;
	new->hash = old->hash;
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	new->nf_ops = old->nf_ops;
#endif
	/*
	 * The old BIB must survive,
	 * because they shouldn't be reset by atomic configuration.
	 */

	hash_del(&old->table_hook);
	hash_add(instances, &new->table_hook, get_instance_hash(new));
	list = rcu_dereference_protected(netfilter_instances,
					lockdep_is_held(&lock));
	list_del_rcu(&old->list_hook);
	list_add_rcu(&new->list_hook, list);
	mutex_unlock(&lock);

	synchronize_rcu_bh();

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 8, 0)
	old->nf_ops = NULL;
#endif

	destroy_jool_instance(old, false);
	log_info("Replaced instance '%s'.", jool->iname);
	return 0;
}

int xlator_flush(void)
{
	struct net *ns;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	jool_xlator_flush_net(ns);

	put_net(ns);
	return 0;
}

/**
 * Returns the instance from the database that matches @ns, @iname and @flags.
 *
 * A result value of 0 means success,
 * -ESRCH means that no instance matches @ns, @iname and @flags,
 * and -EINVAL means that @iname is not a valid instance name.
 *
 * 0 and -ESRCH do not print error message; -EINVAL does.
 *
 * @result will be populated with the instance. Send NULL if all you want is to
 * test whether it exists or not. If not NULL, please xlator_put() @result when
 * you're done using it.
 *
 * IT IS EXTREMELY IMPORTANT THAT YOU NEVER KREF_GET ANY OF @result'S MEMBERS!!!
 * (You are not meant to fork pointers to them.)
 */
int xlator_find(struct net *ns, char const *iname, struct xlator *result)
{
	struct jool_instance *instance;
	int error;

	/*
	 * There is at least one caller to this function which cares about error
	 * code. You need to review it if you want to add or reuse error codes.
	 */
	error = basic_validations(iname, true);
	if (error)
		return error;

	rcu_read_lock_bh();

	instance = find_instance(ns, iname);
	if (!instance)
		goto not_found;

	if (result) {
		xlator_get(&instance->jool);
		memcpy(result, &instance->jool, sizeof(*result));
	}

	rcu_read_unlock_bh();
	return 0;

not_found:
	rcu_read_unlock_bh();
	return -ESRCH;
}

/**
 * xlator_find_current - Retrieves the Jool instance loaded in the current
 * namespace.
 *
 * Please xlator_put() the instance when you're done using it.
 */
int xlator_find_current(const char *iname, struct xlator *result)
{
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = xlator_find(ns, iname, result);

	put_net(ns);
	return error;
}

int xlator_find_netfilter(struct net *ns, struct xlator *result)
{
	struct list_head *list;
	struct jool_instance *instance;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(netfilter_instances);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (ns == instance->jool.ns) {
			xlator_get(&instance->jool);
			memcpy(result, &instance->jool, sizeof(*result));
			rcu_read_unlock_bh();
			return 0;
		}
	}

	rcu_read_unlock_bh();
	return -ESRCH;
}

/*
 * I am kref_put()ting and there's no lock.
 * This can be dangerous: http://lwn.net/Articles/93617/
 *
 * I believe this is safe because this module behaves as as a "home" for all
 * these objects. While this module is dropping its reference, the refcounter
 * is guaranteed to be at least 1. Nobody can get a new reference while or after
 * this happens. Therefore nobody can sneak in a kref_get during the final put.
 */
void xlator_put(struct xlator *jool)
{
	jstat_put(jool->stats);

	eamt_put(jool->siit.eamt);
	denylist4_put(jool->siit.denylist4);
	return;
}

static bool offset_equals(struct instance_entry_usr *offset,
		struct jool_instance *instance)
{
	return (offset->ns == ((__u64)instance->jool.ns & 0xFFFFFFFF))
			&& (strcmp(offset->iname, instance->jool.iname) == 0);
}

int xlator_foreach(xlator_foreach_cb cb, void *args,
		struct instance_entry_usr *offset)
{
	struct jool_instance *instance;
	unsigned int i;
	int error = 0;

	rcu_read_lock_bh();

	hash_for_each(instances, i, instance, table_hook) {
		if (offset) {
			if (offset_equals(offset, instance))
				offset = NULL;
		} else {
			error = cb(&instance->jool, args);
			if (error)
				break;
		}
	}

	rcu_read_unlock_bh();

	if (error)
		return error;
	if (offset)
		return -ESRCH;
	return 0;
}
