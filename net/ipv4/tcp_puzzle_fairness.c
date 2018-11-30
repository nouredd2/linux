/*
 * TCP/IP Set up for priority queues with puzzles
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#define pr_fmt(fmt) "[PQ]: " fmt

#include <linux/hashtable.h>

/** This structure will hold the entries in the hash table.
 * To deal with collisions, we must always save the key, which
 * is the ip address in the case. The only other thing we need for now
 * is the count of requests seens so far. Note that this only includes
 * the successful requests
 *
 * @ip_addr:	The ip address from which the requests are generated
 * @req_count:  The number of requests seen so far
 * @en_link:	To work with hashtables
 */
struct tcp_pr_table_entry {
	__be32	ip_addr;
	u32	req_count;

	struct hlist_node en_link;
};

u32 compute_weight(__be32 ip_addr, u8 diff)
{
	/* TODO: add the magic in here and make beautiful things happen */
	return 0;
}
