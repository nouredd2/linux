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
#include <linux/timer.h>
#include <linux/tcp.h>

#define EXPIRATION_MSECS 800

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
	__be32		ip_addr;
	atomic_t	req_count;

	struct hlist_node	en_link;
	struct timer_list	en_timer;
	struct tcp_sock		*sk;
};

void table_entry_timer_fn(unsigned long data)
{
	struct tcp_pr_table_entry *entry = (struct tcp_pr_table_entry *)data;

	/* timer has expired, remove the entry from the data */
	spin_lock(&entry->sk->pr_state_lock);
	hash_del_rcu(&entry->en_link);
	spin_unlock(&entry->sk->pr_state_lock);

	del_timer(&entry->en_timer);
	kfree(entry);
}

static struct tcp_pr_table_entry
*lookup_pr_table_entry(const struct tcp_sock *sk, __be32 key)
{
	struct tcp_pr_table_entry *entry;
	hash_for_each_possible_rcu(sk->pr_state_cache, entry, en_link, key)
		if (entry->ip_addr == key)
			return entry;
	return 0;
}

void tcp_clear_priority_queue(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct tcp_pr_table_entry *e;
	struct hlist_node *tmp;
	int i;

	spin_lock(&tsk->pr_state_lock);
	hash_for_each_safe(tsk->pr_state_cache, i, tmp, e, en_link) {
		del_timer(&e->en_timer);
		kfree(e);
	}
	spin_unlock(&tsk->pr_state_lock);
}
EXPORT_SYMBOL(tcp_clear_priority_queue);

u32 compute_weight(struct tcp_sock *sk, __be32 ip_addr, u32 diff)
{
	/* TODO: add the magic in here and make beautiful things happen */
	struct tcp_pr_table_entry *entry;
	u32 count = 1;

	/* 1. lookup in the hash table */
	entry = lookup_pr_table_entry(sk, ip_addr);
	if (!entry) {
		/* cannot be found, add a new entry for the table */
		entry = kmalloc(sizeof(struct tcp_pr_table_entry), GFP_KERNEL);
		entry->ip_addr = ip_addr;
		entry->sk = sk;
		atomic_set(&entry->req_count, 1);

		/* initialize the timer */
		setup_timer(&entry->en_timer, table_entry_timer_fn,
			    (unsigned long )entry);
		mod_timer(&entry->en_timer, jiffies + msecs_to_jiffies(EXPIRATION_MSECS));

		pr_debug("Creating new entry in the hash table\n");
		spin_lock(&sk->pr_state_lock);
		hash_add_rcu(sk->pr_state_cache, &entry->en_link, ip_addr);
		spin_unlock(&sk->pr_state_lock);
	} else {
		/* this updates the entry and we don't need to do anything else
		 **/
		pr_debug("Entry found and now updating the count\n");
		count = (u32) atomic_inc_return(&entry->req_count);
		mod_timer(&entry->en_timer, jiffies + msecs_to_jiffies(EXPIRATION_MSECS));
	}

	pr_info("Computed weight %d for ip address %x\n", diff/count, ip_addr);
	pr_info("  State = < %d > \n", count);
	return diff / count > 0 ? diff/count : diff;
}
EXPORT_SYMBOL(compute_weight);
