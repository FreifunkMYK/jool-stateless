#include "mod/common/init.h"

#include <linux/module.h>

#include "mod/common/atomic_config.h"
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/nl_handler.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("IP/ICMP Translation (Core)");
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

static int setup_common_modules(void)
{
	int error;

	LOG_DEBUG("Initializing common modules.");
	/* Careful with the order. */

	/* Common */
	error = xlation_setup();
	if (error)
		goto xlation_fail;
	/*
	 * In kernel < 4.13, this opens the Netfilter packet gate, so all
	 * submodules needed for translation need to be up by now.
	 */
	error = xlator_setup();
	if (error)
		goto xlator_fail;
	error = nlhandler_setup();
	if (error)
		goto nlhandler_fail;
	error = register_pernet_subsys(&joolns_ops);
	if (error)
		goto nlhandler_fail;

	return 0;

nlhandler_fail:
	xlator_teardown();
xlator_fail:
	xlation_teardown();
xlation_fail:
	return error;
}

static void teardown_common_modules(void)
{
	LOG_DEBUG("Tearing down common modules.");

	/* Careful with the order. */
	unregister_pernet_subsys(&joolns_ops);

	/* Common */
	nlhandler_teardown(); /* Userspace requests no longer handled now */
	xlator_teardown(); /* Packets no longer handled by Netfilter now */
	xlation_teardown();
	atomconfig_teardown();
}

static int __init jool_init(void)
{
	int error;

	LOG_DEBUG("Inserting Core Jool...");

	error = setup_common_modules();
	if (error)
		return error;

	log_info("Core Jool v" JOOL_VERSION_STR " module inserted.");
	return 0;
}

static void __exit jool_exit(void)
{
	teardown_common_modules();

#ifdef JKMEMLEAK
	wkmalloc_print_leaks();
	wkmalloc_teardown();
#endif

	log_info("Core Jool v" JOOL_VERSION_STR " module removed.");
}

module_init(jool_init);
module_exit(jool_exit);
