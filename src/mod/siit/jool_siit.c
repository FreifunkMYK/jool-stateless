#include "mod/common/init.h"

#include <linux/module.h>
#include "mod/common/kernel_hook.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateless IP/ICMP Translation (RFC 7915)");
MODULE_VERSION(JOOL_VERSION_STR);

static void flush_net(struct net *ns)
{
	jool_xlator_flush_net(ns);
}

static void flush_batch(struct list_head *net_exit_list)
{
	jool_xlator_flush_batch(net_exit_list);
}

/** Namespace-aware network operation registration object */
static struct pernet_operations joolns_ops = {
	.exit = flush_net,
	.exit_batch = flush_batch,
};

static int __init siit_init(void)
{
	int error;

	pr_debug("Inserting SIIT Jool...\n");
	/* Careful with the order */

	error = register_pernet_subsys(&joolns_ops);
	if (error)
		return error;

	/* SIIT instances can now function properly; unlock them. */
	error = jool_siit_get();
	if (error) {
		unregister_pernet_subsys(&joolns_ops);
		return error;
	}

	pr_info("SIIT Jool v" JOOL_VERSION_STR " module inserted.\n");
	return 0;
}

static void __exit siit_exit(void)
{
	jool_siit_put();
	unregister_pernet_subsys(&joolns_ops);
	pr_info("SIIT Jool v" JOOL_VERSION_STR " module removed.\n");
}

module_init(siit_init);
module_exit(siit_exit);
