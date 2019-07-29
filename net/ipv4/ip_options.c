// SPDX-License-Identifier: GPL-2.0
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The options processing module for ip.c
 *
 * Authors:	A.N.Kuznetsov
 *
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/cipso_ipv4.h>
#include <net/ip_fib.h>
#include <net/inet_common.h>

unsigned char ip_solution_build(struct inet_sock *isk, unsigned char *iph,
			       struct inet_solution *inet_sol)
{
	unsigned char *hdr = iph;
	unsigned char *c_nonce;
	struct ip_puzzle *inet_puzzle;
	size_t offset = 0;

	if (!inet_sol)
		return 0;

	pr_info("%s: Starting to write the solution (%p) with (%p) to packet!\n",
		__func__, inet_sol, inet_sol->solution);
	hdr = iph + sizeof(struct iphdr);
	offset = 20;

	*hdr++ = 94; // IPOPT_EXP;
	*hdr++ = 20;

	pr_info("%s: Puzzle information: ts = %x, diff = %d, idx = %d, sol = %p\n",
		__func__, inet_sol->ts, inet_sol->diff, inet_sol->idx,
		inet_sol->solution);

	/* client nonce never changes so no need to lock it */
	inet_puzzle = isk->inet_puzzle;
	c_nonce = inet_puzzle->c_nonce;
	pr_info("%s: Copying (%p) to the packet\n", __func__, inet_puzzle->c_nonce);
	memcpy(hdr, c_nonce, CLIENT_NONCE_SIZE);
	hdr += CLIENT_NONCE_SIZE;

	*((__be32 *)hdr) = inet_sol->ts;
	hdr += 4;
	*hdr++ = inet_sol->diff;
	*hdr++ = inet_sol->idx;
	memcpy(hdr, inet_sol->solution, PUZZLE_SIZE);
	hdr += PUZZLE_SIZE;

	if (hdr - (iph + sizeof(struct iphdr)) != 20)
		pr_err("woops wrote something wrong in here!\n");

	kfree(inet_sol->solution);
	kfree(inet_sol);
	return offset;
}

/*
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 */

void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
		      __be32 daddr, struct rtable *rt, int is_frag,
		      struct inet_solution *inet_sol)
{
	struct inet_sock *isk = inet_sk(skb->sk);
	unsigned char *iph = skb_network_header(skb);
	size_t offset = 0;

	/* check if we should add a solution to the packet here, I am doing this
	 * here to avoid complicating the option processing pipeline. This will
	 * add 20 bytes (Which is 4 bytes aligned) to the start of the options,
	 * so basially I will trick the rest of the option processing part by
	 * adding 20 to the current iph so that the offsets computed from before
	 * would not be changed.
	 */
	offset = ip_solution_build(isk, iph, inet_sol);

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr)+offset, opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);

	/* scale iph by 20 to account for the 20 bytes that I added before */
	iph += offset;

	if (opt->srr)
		memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

	if (!is_frag) {
		if (opt->rr_needaddr)
			ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, skb, rt);
		if (opt->ts_needaddr)
			ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, skb, rt);
		if (opt->ts_needtime) {
			__be32 midtime;

			midtime = inet_current_timestamp();
			memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
		}
		return;
	}
	if (opt->rr) {
		memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
		opt->rr = 0;
		opt->rr_needaddr = 0;
	}
	if (opt->ts) {
		memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
		opt->ts = 0;
		opt->ts_needaddr = opt->ts_needtime = 0;
	}
}

/*
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */

int __ip_options_echo(struct net *net, struct ip_options *dopt,
		      struct sk_buff *skb, const struct ip_options *sopt)
{
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;

	memset(dopt, 0, sizeof(struct ip_options));

	if (sopt->optlen == 0)
		return 0;

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->rr, optlen);
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL;
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->ts, optlen);
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				dopt->ts_needaddr = 1;
				soffset += 4;
			}
			if (sopt->ts_needtime) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 7 <= optlen) {
						__be32 addr;

						memcpy(&addr, dptr+soffset-1, 4);
						if (inet_addr_type(net, addr) != RTN_UNICAST) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			dptr[2] = soffset;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->srr) {
		unsigned char *start = sptr+sopt->srr;
		__be32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset -= 4, doffset = 4; soffset > 3; soffset -= 4, doffset += 4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&ip_hdr(skb)->saddr,
				   &start[soffset + 3], 4) == 0)
				doffset -= 4;
		}
		if (doffset > 3) {
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}
	if (sopt->cipso) {
		optlen  = sptr[sopt->cipso+1];
		dopt->cipso = dopt->optlen+sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->cipso, optlen);
		dptr += optlen;
		dopt->optlen += optlen;
	}
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */

void ip_options_fragment(struct sk_buff *skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options *opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
}

/* helper used by ip_options_compile() to call fib_compute_spec_dst()
 * at most one time.
 */
static void spec_dst_fill(__be32 *spec_dst, struct sk_buff *skb)
{
	if (*spec_dst == htonl(INADDR_ANY))
		*spec_dst = fib_compute_spec_dst(skb);
}

static struct ip_puzzle *alloc_inet_puzzle(struct sock *sk, __be32 ts)
{
	struct ip_puzzle *inet_puzzle;

	inet_puzzle = sock_kmalloc(sk, sizeof(struct ip_puzzle),
			      GFP_ATOMIC);
	if (IS_ERR(inet_puzzle))
		return inet_puzzle;

	inet_puzzle->last_touched = jiffies;
	inet_puzzle->ts = ts;
	inet_puzzle->difficulty = DEFAULT_DIFFICULTY;

	get_random_bytes(inet_puzzle->c_nonce, CLIENT_NONCE_SIZE);

	return inet_puzzle;
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 */

int ip_options_compile(struct net *net,
		       struct ip_options *opt, struct sk_buff *skb)
{
	__be32 spec_dst = htonl(INADDR_ANY);
	unsigned char *pp_ptr = NULL;
	struct rtable *rt = NULL;
	unsigned char *optptr;
	unsigned char *nonceptr;
	unsigned char *iph;
	int optlen, l, i;
	struct inet_sock *isk = inet_sk(skb->sk);
	struct ip_puzzle *inet_puz;
	__be32 ts;

	if (skb) {
		rt = skb_rtable(skb);
		optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	} else
		optptr = opt->__data;
	iph = optptr - sizeof(struct iphdr);

	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		case IPOPT_END:
			for (optptr++, l--; l > 0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		if (unlikely(l < 2)) {
			pp_ptr = optptr;
			goto error;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l) {
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/* NB: cf RFC-1812 5.2.4.1 */
			if (opt->srr) {
				pp_ptr = optptr;
				goto error;
			}
			if (!skb) {
				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7], optlen-7);
			}
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph;
			break;
		case IPOPT_RR:
			if (opt->rr) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				if (rt) {
					spec_dst_fill(&spec_dst, skb);
					memcpy(&optptr[optptr[2]-1], &spec_dst, 4);
					opt->is_changed = 1;
				}
				optptr[2] += 4;
				opt->rr_needaddr = 1;
			}
			opt->rr = optptr - iph;
			break;
		case IPOPT_TIMESTAMP:
			if (opt->ts) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				unsigned char *timeptr = NULL;
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				switch (optptr[3]&0xF) {
				case IPOPT_TS_TSONLY:
					if (skb)
						timeptr = &optptr[optptr[2]-1];
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				case IPOPT_TS_TSANDADDR:
					if (optptr[2]+7 > optlen) {
						pp_ptr = optptr + 2;
						goto error;
					}
					if (rt)  {
						spec_dst_fill(&spec_dst, skb);
						memcpy(&optptr[optptr[2]-1], &spec_dst, 4);
						timeptr = &optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1;
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				case IPOPT_TS_PRESPEC:
					if (optptr[2]+7 > optlen) {
						pp_ptr = optptr + 2;
						goto error;
					}
					{
						__be32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);
						if (inet_addr_type(net, addr) == RTN_UNICAST)
							break;
						if (skb)
							timeptr = &optptr[optptr[2]+3];
					}
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				default:
					if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				if (timeptr) {
					__be32 midtime;

					midtime = inet_current_timestamp();
					memcpy(timeptr, &midtime, 4);
					opt->is_changed = 1;
				}
			} else if ((optptr[3]&0xF) != IPOPT_TS_PRESPEC) {
				unsigned int overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			opt->ts = optptr - iph;
			break;
		case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] == 0 && optptr[3] == 0)
				opt->router_alert = optptr - iph;
			break;
		case IPOPT_CIPSO:
			if ((!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) || opt->cipso) {
				pp_ptr = optptr;
				goto error;
			}
			opt->cipso = optptr - iph;
			if (cipso_v4_validate(skb, &optptr)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		case IPOPT_EXP:
			/* ignore these packets if we are in TIME_WAIT or in
			 * CLOSE_WAIT
			 */
			pr_info("skb->sk is: %p\n", skb->sk);
			if (skb->sk->sk_state == TCP_TIME_WAIT) {
				pr_info("Got a packet while in timed wait, ignoring\n");
				/* inet_destruct_puzzle(isk); */
				goto puzzle_error;
			}
			pr_info("opt->optlen = %d\n", opt->optlen);

			/* check option length for correctness */
			if (optlen - 6 < NONCE_SIZE) {
				pr_err("Malformed puzzle packet received\n");
				goto puzzle_error;
			}

			ts = *((__be32 *)(optptr + 2));
			nonceptr = optptr + 6;

			pr_info("Trying to acquire lock (%p)\n", &isk->plock);
			pr_info("Puzzle details: optlen = %d\n", optlen);
			pr_info("ts = %x\n", ts);

			spin_lock_bh(&isk->plock);
			if (isk->inet_puzzle) {
				/* update last touched or replace */
				pr_info("Accessing: %p\n", isk->inet_puzzle);
				inet_puz = isk->inet_puzzle;
				inet_puz->last_touched = jiffies;
				isk->puzzle_seen = 1;

				if ((ntohl(ts) - ntohl(inet_puz->ts)) >= PUZZLE_TIMEOUT) {
					pr_info("puzzle expired, refresh the nonce\n");
					/* timed out, refresh nonce */
					inet_puz->ts = ts;
					for (i=0;i<NONCE_SIZE;i++)
						inet_puz->s_nonce[i] = *nonceptr++;
				}
			} else if (isk->puzzle_seen == 0) { /* This guards for the case where the socket
							   is in a waiting state after it has been destructed by the kernel */
				inet_puz = alloc_inet_puzzle(skb->sk, ts);
				if (IS_ERR(inet_puz)) {
					isk->puzzle_seen = 0;
					spin_unlock_bh(&isk->plock);
					return -EINVAL;
				}

				for (i=0;i<NONCE_SIZE;i++)
					inet_puz->s_nonce[i] = *nonceptr++;

				isk->puzzle_seen = 1;
				isk->inet_puzzle = inet_puz;
				pr_info("Allocated: %p\n", isk->inet_puzzle);
			} else
				pr_info("Puzzle already deleted, ignoring\n");
			spin_unlock_bh(&isk->plock);

			/* here's the trick, I want to drop this packet after
			 * parsing the options, so to hell with it, just return
			 * EINVAL and let the caller drop it.
			 */
			goto puzzle_error;
			break;
		case IPOPT_SEC:
		case IPOPT_SID:
		default:
			if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	if (skb) {
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((pp_ptr-iph)<<24));
	}
	return -EINVAL;

puzzle_error:
	return -EINVAL;
}
EXPORT_SYMBOL(ip_options_compile);

/*
 *	Undo all the changes done by ip_options_compile().
 */

void ip_options_undo(struct ip_options *opt)
{
	if (opt->srr) {
		unsigned  char *optptr = opt->__data+opt->srr-sizeof(struct  iphdr);
		memmove(optptr+7, optptr+3, optptr[1]-7);
		memcpy(optptr+3, &opt->faddr, 4);
	}
	if (opt->rr_needaddr) {
		unsigned  char *optptr = opt->__data+opt->rr-sizeof(struct  iphdr);
		optptr[2] -= 4;
		memset(&optptr[optptr[2]-1], 0, 4);
	}
	if (opt->ts) {
		unsigned  char *optptr = opt->__data+opt->ts-sizeof(struct  iphdr);
		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
			if ((optptr[3]&0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
		}
	}
}

static struct ip_options_rcu *ip_options_get_alloc(const int optlen)
{
	return kzalloc(sizeof(struct ip_options_rcu) + ((optlen + 3) & ~3),
		       GFP_KERNEL);
}

static int ip_options_get_finish(struct net *net, struct ip_options_rcu **optp,
				 struct ip_options_rcu *opt, int optlen)
{
	while (optlen & 3)
		opt->opt.__data[optlen++] = IPOPT_END;
	opt->opt.optlen = optlen;
	if (optlen && ip_options_compile(net, &opt->opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	kfree(*optp);
	*optp = opt;
	return 0;
}

int ip_options_get_from_user(struct net *net, struct ip_options_rcu **optp,
			     unsigned char __user *data, int optlen)
{
	struct ip_options_rcu *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen && copy_from_user(opt->opt.__data, data, optlen)) {
		kfree(opt);
		return -EFAULT;
	}
	return ip_options_get_finish(net, optp, opt, optlen);
}

int ip_options_get(struct net *net, struct ip_options_rcu **optp,
		   unsigned char *data, int optlen)
{
	struct ip_options_rcu *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen)
		memcpy(opt->opt.__data, data, optlen);
	return ip_options_get_finish(net, optp, opt, optlen);
}

void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options *opt	= &(IPCB(skb)->opt);
	unsigned char *optptr;
	struct rtable *rt = skb_rtable(skb);
	unsigned char *raw = skb_network_header(skb);

	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		ip_rt_get_source(&optptr[optptr[2]-5], skb, rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for ( srrptr = optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&opt->nexthop, &optptr[srrptr-1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_hdr(skb)->daddr = opt->nexthop;
			ip_rt_get_source(&optptr[srrptr-1], skb, rt);
			optptr[2] = srrptr+4;
		} else {
			net_crit_ratelimited("%s(): Argh! Destination lost!\n",
					     __func__);
		}
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], skb, rt);
			opt->is_changed = 1;
		}
	}
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(ip_hdr(skb));
	}
}

int ip_options_rcv_srr(struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	__be32 nexthop;
	struct iphdr *iph = ip_hdr(skb);
	unsigned char *optptr = skb_network_header(skb) + opt->srr;
	struct rtable *rt = skb_rtable(skb);
	struct rtable *rt2;
	unsigned long orefdst;
	int err;

	if (!rt)
		return 0;

	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

	for (srrptr = optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		orefdst = skb->_skb_refdst;
		skb_dst_set(skb, NULL);
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, skb->dev);
		rt2 = skb_rtable(skb);
		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			skb_dst_drop(skb);
			skb->_skb_refdst = orefdst;
			return -EINVAL;
		}
		refdst_drop(orefdst);
		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		iph->daddr = nexthop;
		opt->is_changed = 1;
	}
	if (srrptr <= srrspace) {
		opt->srr_is_hit = 1;
		opt->nexthop = nexthop;
		opt->is_changed = 1;
	}
	return 0;
}
EXPORT_SYMBOL(ip_options_rcv_srr);
