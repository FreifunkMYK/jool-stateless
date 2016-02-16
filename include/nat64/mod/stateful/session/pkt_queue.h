#ifndef _JOOL_MOD_PKT_QUEUE_H
#define _JOOL_MOD_PKT_QUEUE_H

/**
 * @file
 * As the name implies, this is just a small database of packets. These packets
 * are meant to be replied (in the form of an ICMP error) in the future.
 *
 * You can find the specifications for this in pages 28 and 29 (look up
 * "simultaneous open of TCP connections"), and 30 (look up "stored is sent
 * back") from RFC 6146.
 *
 * The RFC gets a little nonsensical here. These requirements seem to exist to
 * satisfy REQ-4 of RFC 5382
 * (http://ietf.10.n7.nabble.com/Simultaneous-connect-td222455.html), except
 * RFC 5382 wants us to cancel the ICMP error "If during this interval the NAT
 * receives and translates an outbound SYN for the connection", but this is not
 * very explicit in the specification of the V4_INIT state in RFC 6146. I mean
 * it's the only state where the session expiration triggers the ICMP message,
 * but it'd be nice to see confirmation that the stored packet can be forgotten
 * about.
 *
 * However, Marcelo Bagnulo's seemingly final comments really bend me over to
 * RFC 5382's behavior: "well, it may be sent inside an ICMP error message in
 * case the state times out and the V& SYN has not arrived."
 * (http://www.ietf.org/mail-archive/web/behave/current/msg08660.html)
 *
 * So... yeah, "Packet Storage". This is how I understand it:
 *
 * If a NAT64 receives a IPv4-UDP or a IPv4-ICMP packet for which it has no
 * state, it should reply a ICMP error because it doesn't know which IPv6 node
 * the packet should be forwarded to.
 *
 * If a NAT64 receives a IPv4-TCP packet for which it has no state, it should
 * not immediately reply a ICMP error because the IPv4 endpoint could be
 * attempting a "Simultaneous Open of TCP Connections"
 * (http://tools.ietf.org/html/rfc5128#section-3.4). What
 * happens is the NAT64 stores the packet for 6 seconds; if the IPv6 version of
 * the packet arrives, the NAT64 drops the original packet (the IPv4 node will
 * eventually realize this on its own by means of the handshake), otherwise a
 * ICMP error containing the original IPv4 packet is generated (because there's
 * no Simultaneous Open going on).
 */

#include "nat64/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/session/entry.h"

struct pktqueue {
	struct list_head node_list;
	/** The same packets, sorted by IPv4 identifiers. */
	struct rb_root node_tree;
	/** Current number of packets in the database. */
	int node_count;

	unsigned int capacity;
};

/**
 * Call during initialization for the remaining functions to work properly.
 */
void pktqueue_init(struct pktqueue *queue);
/**
 * Call during destruction to avoid memory leaks.
 */
void pktqueue_destroy(struct pktqueue *queue);

void pktqueue_config_copy(struct pktqueue *queue, struct pktqueue_config *config);
void pktqueue_config_set(struct pktqueue *queue, struct pktqueue_config *config);

/**
 * Stores packet "skb", associating it with "session".
 */
int pktqueue_add(struct pktqueue *queue, struct session_entry *session,
		struct packet *pkt);
/**
 * Removes "session"'s skb from the storage. There will be no ICMP error.
 */
void pktqueue_rm(struct pktqueue *queue, struct session_entry *session);

void pktqueue_clean(struct pktqueue *queue);


#endif /* _JOOL_MOD_PKT_QUEUE_H */