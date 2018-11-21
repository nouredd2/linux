/*
 * Priority queue for request sockets.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#define pr_fmt(fmt) "PQUEUE: " fmt

#include <net/inet_connection_sock.h>
#include <net/tcp.h>

static void heap_swap(struct request_sock * req, int index, int parent)
{
	//@TODO is this the correct way to implement this?  
	if(index==parent){
		return;
	}

	struct sock_common tempsc = req[index].__req_common;
	struct request_sock *temprs = req[index].dl_next;
	u16 tempmss = req[index].mss;
	u8 tempnumret = req[index].num_retrans;
	u8 tempcookie_ts:1 = req[index].cookie_ts:1;
	u8 tempnum_timeout:7 = req[index].num_timeout:7;
	u32 tempts_recent = req[index].ts_recent;
	struct timer_list temprsk_timer = req[index].rsk_timer;
	const struct request_sock_ops * temprsk_ops = req[index].rsk_ops;
	struct sock * tempsk = req[index].sk;
	u32 * tempsaved_syn = req[index].saved_syn;
	u32 tempsecid = req[index].secid;
	u32 temppeer_secid = req[index].peer_secid;
	u32 tempweight =req[index].weight;

	req[index].__req_common = req[parent].__req_common;
	req[index].dl_next = req[parent].dl_next;
	req[index].mss = req[parent].mss;
	req[index].num_retrans = req[parent].num_retrans;
	req[index].cookie_ts:1 = req[parent].cookie_ts:1;
	req[index].num_timeout:7 = req[parent].num_timeout:7;
	req[index].ts_recent = req[parent].ts_recent;
	req[index].rsk_timer = req[parent].rsk_timer;
	req[index].rsk_ops = req[parent].rsk_ops;
	req[index].sk = req[parent].sk;
	req[index].saved_syn = req[parent].saved_syn;
	req[index].secid = req[parent].secid;
	req[index].peer_secid = req[parent].peer_secid;
	req[index].weight = req[parent].weight;

	req[parent].__req_common = tempsc;
	req[parent].dl_next = temprs;
	req[parent].mss = tempmss;
	req[parent].num_retrans = tempnumret;
	req[parent].cookie_ts:1 = tempcookie_ts:1;
	req[parent].num_timeout:7 = tempnum_timeout:7;
	req[parent].ts_recent = tempts_recent;
	req[parent].rsk_timer = temprsk_timer;
	req[parent].rsk_ops = temprsk_ops;
	req[parent].sk = tempsk;
	req[parent].saved_syn = tempsaved_syn;
	req[parent].secid = tempsecid;
	req[parent].peer_secid = temppeer_secid;
	req[parent].weight = tempweight;

	return;
}
/* no need to export this since it's only used in this context */

void heapify_up(struct request_sock * req, unsigned i)
{
	int index = (int) i;
	int parent = 0;
	if (index > 1) {
		while(true) {
			parent = index / 2;

			if (parent < 1)
				return;
			else if (req[index].weight > req[parent].weight) {
				heap_swap(req,index, parent);
			}

			index = parent;
		}
	}
}
EXPORT_SYMBOL(heapify_up);
