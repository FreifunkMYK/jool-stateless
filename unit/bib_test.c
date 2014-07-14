#include <linux/module.h>
#include <linux/printk.h>
#include "nat64/unit/unit_test.h"
#include "nat64/unit/types.h"
#include "nat64/unit/bib.h"
#include "nat64/comm/str_utils.h"
#include "bib_db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("BIB module test.");

#define BIB_PRINT_KEY "BIB [%pI4#%u, %pI6c#%u]"
#define PRINT_BIB(bib) \
	&bib->ipv4.address, bib->ipv4.l4_id, \
	&bib->ipv6.address, bib->ipv6.l4_id

static const char* IPV4_ADDRS[] = { "1.1.1.1", "2.2.2.2" };
static const __u16 IPV4_PORTS[] = { 456, 9556 };
static const char* IPV6_ADDRS[] = { "::1", "::2", "::3" };
static const __u16 IPV6_PORTS[] = { 334, 0, 9556 };

static struct ipv4_tuple_address addr4[ARRAY_SIZE(IPV4_ADDRS)];
static struct ipv6_tuple_address addr6[ARRAY_SIZE(IPV6_ADDRS)];

/********************************************
 * Auxiliar functions.
 ********************************************/

static struct bib_entry *create_and_insert_bib(struct ipv4_tuple_address *ipv4,
		struct ipv6_tuple_address *ipv6,
		int l4proto)
{
	struct bib_entry *result;
	int error;

	result = bib_create(ipv4, ipv6, false, l4proto);
	if (!result) {
		log_err("kmalloc failed, apparently.");
		return NULL;
	}

	error = bibdb_add(result);
	if (error) {
		log_err("Could not insert the BIB entry to the table; call returned %d.", error);
		bib_kfree(result);
		return NULL;
	}

	return result;
}

static bool assert_bib_entry_equals(struct bib_entry* expected, struct bib_entry* actual,
		char* test_name)
{
	if (expected == actual)
		return true;

	if (!expected) {
		log_err("Test '%s' failed: Expected null, got " BIB_PRINT_KEY ".",
				test_name, PRINT_BIB(actual));
		return false;
	}
	if (!actual) {
		log_err("Test '%s' failed: Expected " BIB_PRINT_KEY ", got null.",
				test_name, PRINT_BIB(expected));
		return false;
	}

	if (!ipv4_tuple_addr_equals(&expected->ipv4, &actual->ipv4)
			|| !ipv6_tuple_addr_equals(&expected->ipv6, &actual->ipv6)) {
		log_err("Test '%s' failed: Expected " BIB_PRINT_KEY " got " BIB_PRINT_KEY ".",
				test_name, PRINT_BIB(expected), PRINT_BIB(actual));
		return false;
	}

	return true;
}

/**
 * Asserts the "bib" entry was correctly inserted into the tables.
 * -> if udp_table_has_it, will test the entry exists and is correctly indexed by the UDP table.
 *    Else it will assert the bib is not indexed by the UDP table.
 * -> if tcp_table_has_it, will test the entry exists and is correctly indexed by the TCP table.
 *    Else it will assert the bib is not indexed by the TCP table.
 * -> if icmp_table_has_it, will test the entry exists and is correctly indexed by the ICMP table.
 *    Else it will assert the bib is not indexed by the ICMP table.
 */
static bool assert_bib(char* test_name, struct bib_entry* bib,
		bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	bool table_has_it[3];
	int i;

	table_has_it[0] = udp_table_has_it;
	table_has_it[1] = tcp_table_has_it;
	table_has_it[2] = icmp_table_has_it;

	for (i = 0; i < 3; i++) {
		struct bib_entry *expected_bib = table_has_it[i] ? bib : NULL;
		struct bib_entry *retrieved_bib;
		int success = true;

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				bibdb_get_by_ipv4(&bib->ipv4, l4_protos[i], &retrieved_bib),
				test_name);
		success &= assert_bib_entry_equals(expected_bib, retrieved_bib, test_name);

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				bibdb_get_by_ipv6(&bib->ipv6, l4_protos[i], &retrieved_bib),
				test_name);
		success &= assert_bib_entry_equals(expected_bib, retrieved_bib, test_name);

		if (!success)
			return false;
	}

	return true;
}

/********************************************
 * Tests.
 ********************************************/

/**
 * Inserts a single entry, validates it, removes it, validates again.
 * Does not touch the session tables.
 */
static bool simple_bib(void)
{
	struct ipv4_tuple_address addr = addr4[0];
	struct bib_entry *bib;
	bool success = true;

	if (is_error(pool4_get_any_port(L4PROTO_TCP, &addr.address, &addr.l4_id)))
		return false;

	bib = bib_create(&addr, &addr6[0], false, L4PROTO_TCP);
	if (!assert_not_null(bib, "Allocation of test BIB entry"))
		return false;

	success &= assert_equals_int(0, bibdb_add(bib), "BIB insertion call");
	success &= assert_bib("BIB insertion state", bib, false, true, false);
	if (!success)
		return false;

	success &= assert_equals_int(0, bibdb_remove(bib, false), "BIB removal call");
	success &= assert_bib("BIB removal state", bib, false, false, false);
	if (!success)
		return false;

	bib_kfree(bib);
	return success;
}

struct foreach6_summary {
	bool visited[7];
};

static int foreach6_func(struct bib_entry *entry, void *arg)
{
	struct foreach6_summary *summary = arg;

	log_debug("Iterating through node %pI6c#%u.", &entry->ipv6.address, entry->ipv6.l4_id);

	if (!ipv6_addr_equals(&addr6[1].address, &entry->ipv6.address)) {
		log_err("The address was not the one requested.");
		return -EINVAL;
	}

	if (entry->ipv6.l4_id < 6 || 12 < entry->ipv6.l4_id) {
		log_err("We didn't insert a BIB with this port to the table.");
		return -EINVAL;
	}

	if (summary->visited[entry->ipv6.l4_id - 6]) {
		log_err("This is not the first time we've visited this node.");
		return -EINVAL;
	}

	summary->visited[entry->ipv6.l4_id - 6] = true;
	return 0;
}

static bool test_for_each_ipv6(void)
{
	bool success = true;
	int i;

	/* Build the tree. */
	{
		struct bib_entry *bib;
		struct ipv4_tuple_address a4;
		struct ipv6_tuple_address a6;

		a6.address = addr6[0].address;
		a6.l4_id = 5;
		a4.address = addr4[0].address;

		for (i = 0; i < 4; i++) {
			a6.l4_id++;
			if (is_error(pool4_get_any_port(L4PROTO_UDP, &a4.address, &a4.l4_id)))
				return false;

			bib = create_and_insert_bib(&a4, &a6, L4PROTO_UDP);
			if (!bib)
				return false;
		}

		a6.address = addr6[1].address;
		a6.l4_id = 5;

		for (i = 0; i < 7; i++) {
			a6.l4_id++;
			if (is_error(pool4_get_any_port(L4PROTO_UDP, &a4.address, &a4.l4_id)))
				return false;

			bib = create_and_insert_bib(&a4, &a6, L4PROTO_UDP);
			if (!bib)
				return false;
		}

		a6.address = addr6[2].address;
		a6.l4_id = 5;

		for (i = 0; i < 2; i++) {
			a6.l4_id++;
			if (is_error(pool4_get_any_port(L4PROTO_UDP, &a4.address, &a4.l4_id)))
				return false;

			bib = create_and_insert_bib(&a4, &a6, L4PROTO_UDP);
			if (!bib)
				return false;
		}
	}

	/* Print the tree. */
	/*{
		struct rb_node *node = rb_first(&bib_udp.tree6);

		while (node) {
			struct bib_entry *bib = rb_entry(node, struct bib_entry, tree6_hook);
			struct bib_entry *child;

			log_debug("bib: %pI6c - %u", &bib->ipv6.address, bib->ipv6.l4_id);

			if (node->rb_left) {
				child = rb_entry(node->rb_left, struct bib_entry, tree6_hook);
				log_debug("	Left: %pI6c - %u", &child->ipv6.address, child->ipv6.l4_id);
			} else {
				log_debug("	Left: NULL");
			}

			if (node->rb_right) {
				child = rb_entry(node->rb_right, struct bib_entry, tree6_hook);
				log_debug("	Right: %pI6c - %u", &child->ipv6.address, child->ipv6.l4_id);
			} else {
				log_debug("	Right: NULL");
			}

			node = rb_next(node);
		};
	}*/

	/* Run the for each and validate. */
	{
		struct foreach6_summary summary;

		for (i = 0; i < ARRAY_SIZE(summary.visited); i++)
			summary.visited[i] = false;

		success &= assert_equals_int(0,
				for_each_bib_ipv6(&bib_udp, &addr6[1].address, foreach6_func, &summary),
				"result");
		for (i = 0; i < 7; i++)
			success &= assert_true(summary.visited[i], "node visited.");
	}

	return success;
}

static bool is_low(u16 num)
{
	return num < 1024;
}

static bool is_high(u16 num)
{
	return !is_low(num);
}

static bool is_same_range(u16 num1, u16 num2)
{
	return is_high(num1) ? is_high(num2) : is_low(num2);
}

static bool is_same_parity(u16 num1, u16 num2)
{
	return (num1 & 0x1) == (num2 & 0x1);
}

static bool test_allocate_aux(struct tuple *tuple, struct in_addr *same_addr,
		struct in_addr *out_addr, bool test_port)
{
	struct ipv4_tuple_address result;
	bool success = true;

	success &= assert_equals_int(0, allocate_transport_address(&bib_udp, tuple, &result),
			"function result");

	/* BTW: Because in_addrs are __be32s, "1.1.1.1" is the same as "0x1010101" */
	success &= assert_true(result.address.s_addr == 0x1010101
			|| result.address.s_addr == 0x2020202,
			"Result address is in pool");
	if (same_addr)
		success &= assert_equals_ipv4(same_addr, &result.address, "Result address was recycled");
	if (test_port) {
		success &= assert_true(is_same_range(tuple->src.l4_id, result.l4_id),
				"Result port is in the requested range");
		success &= assert_true(is_same_parity(tuple->src.l4_id, result.l4_id),
				"Result port has the same parity as requested");
	}

	success &= bib_inject(&result.address, result.l4_id, &tuple->src.addr.ipv6, tuple->src.l4_id,
			L4PROTO_UDP);

	if (out_addr)
		*out_addr = result.address;

	return success;
}

static bool test_allocate_ipv4_transport_address(void)
{
	struct tuple client1tuple, client2tuple, client3tuple;
	struct in_addr client1addr4, client2addr4, client3addr4;
	struct tuple *sharing_client_tuple;
	struct in_addr *non_sharing_addr;
	struct ipv4_tuple_address result;
	unsigned int i = 0;
	bool success = true;

	if (is_error(init_ipv6_tuple(&client1tuple, "1::1", 60000, "64:ff9b::1", 60000, L4PROTO_UDP)))
		goto fail;
	if (is_error(init_ipv6_tuple(&client2tuple, "1::2", 60000, "64:ff9b::2", 60000, L4PROTO_UDP)))
		goto fail;
	if (is_error(init_ipv6_tuple(&client3tuple, "1::3", 60000, "64:ff9b::3", 60000, L4PROTO_UDP)))
		goto fail;

	log_debug("IPv6 client 1 arrives and makes 25 connections.");
	/*
	 * Because it's the same IPv6 client, all of those connections should be masked with the same
	 * IPv4 address. This minimizes confusion from remote IPv4 hosts.
	 */

	client1tuple.src.l4_id = 65511;
	if (!test_allocate_aux(&client1tuple, NULL, &client1addr4, true))
		goto fail;

	for (i = 65512; i < 65536; i++) {
		client1tuple.src.l4_id = i;
		if (!test_allocate_aux(&client1tuple, &client1addr4, NULL, true))
			goto fail;
	}

	log_debug("Client 2 arrives and make 50 connections.");
	/*
	 * All of them should share the same IPv4 address,
	 * which should be different from client1's (again, to minimize confusion).
	 */

	client2tuple.src.l4_id = 65486;
	success &= test_allocate_aux(&client2tuple, NULL, &client2addr4, true);
	success &= assert_true(client1addr4.s_addr != client2addr4.s_addr,
			"the nodes are being masked with different addresses");
	if (!success)
		goto fail;

	for (i = 65487; i < 65536; i++) {
		client2tuple.src.l4_id = i;
		if (!test_allocate_aux(&client2tuple, &client2addr4, NULL, true))
			goto fail;
	}

	log_debug("Client 1 makes another 25 connections.");
	/*
	 * Because there are still ports available, he should still get the same IPv4 address.
	 * Essentially, this proves that client2's intervention doesn't affect client 1's connections.
	 */

	for (i = 65486; i < 65511; i++) {
		client1tuple.src.l4_id = i;
		if (!test_allocate_aux(&client1tuple, &client1addr4, NULL, true))
			goto fail;
	}

	log_debug("Client 3 arrives and hogs up all of its address's low ports.");
	/*
	 * At this point, both IPv4 addresses have 50 high ports taken.
	 * Because both IPv4 addresses are taken, client 3 will share its IPv4 address with someone.
	 */
	client3tuple.src.l4_id = 0;
	if (!test_allocate_aux(&client3tuple, NULL, &client3addr4, true))
		goto fail;

	for (i = 1; i < 1024; i++) {
		client3tuple.src.l4_id = i;
		if (!test_allocate_aux(&client3tuple, &client3addr4, NULL, true))
			goto fail;
	}

	log_debug("The client that shares an address with client 3 requests a low port.");
	/*
	 * Because all of them are taken, he gets the same address but a runner-up high port instead.
	 */

	if (ipv4_addr_equals(&client1addr4, &client3addr4)) {
		sharing_client_tuple = &client1tuple;
		non_sharing_addr = &client2addr4;
	} else if (ipv4_addr_equals(&client2addr4, &client3addr4)) {
		sharing_client_tuple = &client2tuple;
		non_sharing_addr = &client1addr4;
	} else {
		log_err("Client 3 doesn't share its IPv4 address with anyone, despite validations.");
		goto fail;
	}

	sharing_client_tuple->src.l4_id = 0;
	success &= assert_equals_int(0, allocate_transport_address(&bib_udp, sharing_client_tuple,
			&result), "result 3");
	success &= assert_equals_ipv4(&client3addr4, &result.address, "runnerup still gets his addr");
	success &= assert_true(is_high(result.l4_id), "runnerup gets a high port");
	success &= bib_inject(&result.address, result.l4_id, &sharing_client_tuple->src.addr.ipv6,
			sharing_client_tuple->src.l4_id, L4PROTO_UDP);
	if (!success)
		goto fail;

	log_debug("Client 3 now hogs up all of its address's remaining ports.");
	/* 51 high ports were already taken, so this will stop early. */
	for (i = 1024; i < 65485; i++) {
		client3tuple.src.l4_id = i;
		if (!test_allocate_aux(&client3tuple, &client3addr4, NULL, i != 65484))
			goto fail;
	}

	/*
	 * At this point, client's address has 50 + 1024 + 1 + 64461 = 65536 ports taken.
	 * ie. It no longer has any ports.
	 */

	log_debug("Then, the function will fall back to use the other address.");
	client3tuple.src.l4_id = i;
	success &= assert_equals_int(0, allocate_transport_address(&bib_udp, &client3tuple, &result),
			"function result");
	success &= assert_true(client3addr4.s_addr != result.address.s_addr,
			"node gets a runnerup address");
	success &= bib_inject(&result.address, result.l4_id, &client3tuple.src.addr.ipv6,
			client3tuple.src.l4_id, L4PROTO_UDP);
	if (!success)
		goto fail;

	log_debug("It will also fall back to use the other address as the other sharing node now hogs "
			"all remaining ports.");
	/*
	 * 51 high ports ports were already taken, so this will stop early.
	 * Also, the sharing client already requested port 0, so we have to start at 1.
	 */
	for (i = 1; i < 65486; i++) {
		sharing_client_tuple->src.l4_id = i;
		if (!test_allocate_aux(sharing_client_tuple, non_sharing_addr, NULL,  i != 65485))
			goto fail;
	}

	log_debug("Now the pool is completely exhausted, so further requests cannot fall back.");
	success &= assert_equals_int(-ESRCH, allocate_transport_address(&bib_udp, &client1tuple,
			&result), "client 1's request is denied");
	success &= assert_equals_int(-ESRCH, allocate_transport_address(&bib_udp, &client2tuple,
			&result), "client 2's request is denied");
	success &= assert_equals_int(-ESRCH, allocate_transport_address(&bib_udp, &client3tuple,
			&result), "client 3's request is denied");
	return success;

fail:
	log_debug("i was %u.", i);
	return false;
}

/********************************************
 * Main.
 ********************************************/

static bool init(void)
{
	char *pool4_addrs[] = { "1.1.1.1", "2.2.2.2" };
	int i;

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr4(IPV4_ADDRS[i], &addr4[i].address)))
			return false;
		addr4[i].l4_id = IPV4_PORTS[i];
	}

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr6(IPV6_ADDRS[i], &addr6[i].address)))
			return false;
		addr6[i].l4_id = IPV6_PORTS[i];
	}

	if (is_error(pool4_init(pool4_addrs, ARRAY_SIZE(pool4_addrs))))
		return false;

	if (is_error(bibdb_init())) {
		pool4_destroy();
		return false;
	}

	return true;
}

static void end(void)
{
	bibdb_destroy();
	pool4_destroy();
}

int init_module(void)
{
	START_TESTS("BIB");

	INIT_CALL_END(init(), simple_bib(), end(), "Single BIB");
	INIT_CALL_END(init(), test_for_each_ipv6(), end(), "for-each-IPv6 function.");
	INIT_CALL_END(init(), test_allocate_ipv4_transport_address(), end(), "Allocate function.");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}