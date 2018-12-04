/*
 * TCP/IP client puzzles implementation. 
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <linux/err.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/printk.h>

#include <crypto/hash.h>
#include <crypto/drbg.h>

#include <net/tcp.h>
#include <linux/tcp.h>
#include <net/secure_seq.h>

#include <net/tcp_challenge.h>

/* keep a key for the tcp challenge. This is similar to the syncookies
 * approach, but I think in the future we want to move this out of here
 */
static u8 tcp_challenge_secret[TCPCH_KEY_SIZE] __read_mostly;

extern void get_random_bytes (void *buf, int nbytes);

static void __generate_random_key_once (void)
{
	net_get_random_once (tcp_challenge_secret, TCPCH_KEY_SIZE);
}

/* tcpch_alloc_challenge */
struct tcpch_challenge *tcpch_alloc_challenge (u32 mts, u8 mlen,
					       u8 mnz, u8 mndiff)
{
	struct tcpch_challenge *chlg;

	chlg = (struct tcpch_challenge *)
		kmalloc (sizeof (struct tcpch_challenge), GFP_KERNEL);

	if (IS_ERR(chlg))
	{
		pr_err ("Cannot allocate memory for TCP/IP challenge\n");
	}
	else
	{
		chlg->ts    = mts;
		chlg->len   = mlen;
		chlg->nz    = mnz;
		chlg->ndiff = mndiff; 
		chlg->opt_ts = false;

		/* set the data to 0 */
		chlg->cbuf = 0;
	}

	return chlg;
}

/* tcpch_alloc_solution */
struct tcpch_solution_head *tcpch_alloc_solution_head (u32 mts, u8 diff, u8 mnz, u8 mlen)
{
	struct tcpch_solution_head *solution;

	solution = (struct tcpch_solution_head *)
		kmalloc (sizeof (struct tcpch_solution_head), GFP_KERNEL);

	if (IS_ERR(solution))
	{
		pr_err ("Cannot allocate memory for TCP/IP solution\n");
	}
	else 
	{
		solution->ts = mts;
		solution->diff = diff;
		solution->nz = mnz;
		solution->len = mlen;
		solution->opt_ts = false;
		INIT_LIST_HEAD (&(solution->head));
	}

	return solution;
}

/* tcpch_alloc_solution_item */
struct tcpch_solution_item *tcpch_alloc_solution_item ()
{
	struct tcpch_solution_item *item;

	item = (struct tcpch_solution_item *)
		kmalloc (sizeof (struct tcpch_solution_item), GFP_KERNEL);
	if (IS_ERR(item))
	{
		pr_err ("Cannot allocate memory for TCP/IP solution item\n");
	}
	else 
	{
		item->sbuf = 0;
		INIT_LIST_HEAD (&(item->list));
	}


	return item;
}

/* tcpch_free_challenge */
void tcpch_free_challenge (struct tcpch_challenge *chlg)
{
	pr_debug ("Inside tcpch_free_challenge\n");
	if (chlg == 0)
	{
		return;
	}

	if (chlg->cbuf)
	{
		kfree (chlg->cbuf);
	}

	/* done free the challenge */
	kfree (chlg);
}

/* tcpch_free_challenge_safe */
void tcpch_free_challenge_safe (struct tcpch_challenge *chlg)
{
	if (chlg == 0)
		return;

	kfree (chlg);
}

/* free solution helper */
void _tcpch_free_solution_item (struct tcpch_solution_item *sol)
{
	if (sol == 0)
	{
		return;
	}

	if (sol->sbuf)
	{
		kfree (sol->sbuf);
	}

	/* done, free the solution */
	kfree (sol);
}

/* tcpch_free_solution */
void tcpch_free_solution (struct tcpch_solution_head *head)
{
	struct tcpch_solution_item *itr, *tmp;

	pr_debug ("Inside tcpch_free_solution\n");
	list_for_each_entry_safe (itr, tmp, &(head->head), list)
	{
		/* remove the iterator from the list */
		list_del (&(itr->list));

		/* free the subsolution */
		_tcpch_free_solution_item (itr);
	}

	kfree (head);
}

/* __init_sdesc_from_alg */
struct shash_desc *__init_sdesc_from_alg (struct crypto_shash *alg)
{
	struct shash_desc *sdesc;
	int size;

	size = sizeof (struct shash_desc) + crypto_shash_descsize (alg);
	sdesc = (struct shash_desc *) kmalloc (size, GFP_KERNEL);
	sdesc->tfm = alg;
	sdesc->flags = 0x0;

	return sdesc;
}

#if 0
static int __tcpch_get_random_bytes (u8 *buf, int len)
{
	/* this is not working for some reason. double check later! */
	struct crypto_rng *rng;
	char *drbg = "drbg_nopr_sha256";
	int ret;

	if (!buf || !len)
	{
		pr_err ("No output buffer provided!\n");
		return -EINVAL;
	}

	rng = crypto_alloc_rng (drbg, 0, 0);
	if (IS_ERR(rng))
	{
		pr_err ("could not allocate RNG handle for %s\n", drbg);
		return -PTR_ERR(rng);
	}

	ret = crypto_rng_get_bytes (rng, buf, len);
	if (ret < 0)
	{
		pr_err ("tcpch: generation of random bytes failed\n");
	}
	else if (ret == 0)
	{
		pr_err ("tcpch: RNG returned no data\n");
	}

	crypto_free_rng (rng);
	return ret;
} /* __tcpch_get_random_bytes */
#endif

/* @return 0 if match, +/-1 otherwise */
static int __tcpch_compare_bits (u8 *xbuf, u8 *ybuf, u16 len)
{
	int cmp, rem, idx;
	u8 cx, cy;

	if (!xbuf || !ybuf)
		return -1;

	if (len == 0)
		return 0;

	cmp = memcmp (xbuf, ybuf, len/8);

	rem = len%8;
	if (rem > 0)
	{
		idx = len/8;
		cx = xbuf[idx];
		cy = ybuf[idx];

		cx = cx >> (8-rem);
		cy = cy >> (8-rem);

		if (cx != cy) {
			return -1;
		}
	}

	return cmp;
} /* __tcpch_compare_bits */

static inline void __add_solution_item (struct tcpch_solution_head *head,
					struct tcpch_solution_item *item)
{
	if (!head || !item)
		return;

	list_add_tail (&(item->list), &(head->head));
}

struct tcpch_solution_head *__solve_challenge (struct tcpch_challenge *chlg)
{
	struct crypto_shash     *alg;
	struct shash_desc       *sdesc;
	struct tcpch_solution_head *head, *headerr;
	struct tcpch_solution_item *item;

	int err;
	int dsize;
	int found;
	u8 xlen;
	u8 *xbuf;
	u8 *zbuf;
	u8 *trial;
	u16 i;

	u32 ts;

	/* get the timestamp in microsec */
	ts = chlg->ts;

	/* create the hash algorithm */
	alg = crypto_alloc_shash ("sha256", CRYPTO_ALG_TYPE_DIGEST,
				  CRYPTO_ALG_TYPE_HASH_MASK);

	if (IS_ERR(alg))
	{
		pr_err ("Failed to create hash algo!\n");
		return ERR_PTR (-ENOMEM); /* double check error code */
	}

	sdesc = __init_sdesc_from_alg (alg);

	if (IS_ERR(sdesc))
	{
		return ERR_PTR(-ENOMEM);
	}

	/* grab x from the challenge */
	xbuf = chlg->cbuf;
	if (!xbuf) {
		pr_err ("Empty challenge detected. Returning error!\n");
		return ERR_PTR (-EINVAL);
	}

	/* create z buffer to hold trials */
	xlen = chlg->len / 16;
	zbuf = (u8 *) kmalloc (xlen, GFP_KERNEL);
	if (IS_ERR(zbuf)) {
		return ERR_PTR (-ENOMEM);
	}

	/* allocate some space for the hash */
	dsize = crypto_shash_digestsize (alg);
	trial = (u8 *) kmalloc (dsize, GFP_KERNEL);
	if (IS_ERR(trial)) {
		return ERR_PTR(-ENOMEM);
	}

	head = tcpch_alloc_solution_head (ts, chlg->ndiff, chlg->nz, chlg->len);
	for (i=0; i < chlg->nz; ++i) {
		item = 0;
		found = 0;
		do {
			err = crypto_shash_init (sdesc);
			if (err < 0) {
				pr_err ("tcpch: Failed toe init hash function!\n");
				headerr = ERR_PTR(err);
				goto out_err;
			}
			err = crypto_shash_update (sdesc, xbuf, xlen);
			err = crypto_shash_update (sdesc, (u8 *)&i, sizeof (u16));

			/* err = __tcpch_get_random_bytes (zbuf, xlen); */
			memset(zbuf, 0, xlen);
			get_random_bytes (zbuf, xlen);
			err = crypto_shash_update (sdesc, zbuf, xlen);

			/* so now we have built x || i || zi, so hash it and compare */
			memset(trial, 0, dsize);
			err = crypto_shash_final (sdesc, trial);
			if (err < 0) {
				pr_err ("tcpch_solve_challenge: Failed to compute hash operation!\n");
				headerr = ERR_PTR(err);
				goto out_err;
			}

			/* check the bits */
			found = (__tcpch_compare_bits (trial, xbuf, chlg->ndiff) == 0);
		} while (found == 0);

		/* allocate a solution struct and add it the list */
		item = tcpch_alloc_solution_item ();
		item->sbuf = (u8 *)kmalloc (xlen, GFP_KERNEL);
		memcpy (item->sbuf, zbuf, xlen);

		__add_solution_item (head, item);
	}

	kfree (trial);
	kfree (zbuf);
	crypto_free_shash (alg);
	kfree (sdesc);

	return head;

out_err:
	tcpch_free_solution (head);
	return headerr;
} /* __solve_challenge */

/* tcpch_solve_challenge */
struct tcpch_solution_head *tcpch_solve_challenge (struct tcpch_challenge *chlg)
{
	return __solve_challenge (chlg);
}
EXPORT_SYMBOL_GPL (tcpch_solve_challenge);

/* internal challenge generation */
struct tcpch_challenge *__generate_challenge (const struct inet_request_sock *ireq,
					      u32 ts, u8 len, u8 nz, u8 diff)
{
	struct crypto_shash     *alg;
	struct shash_desc       *sdesc;
	struct tcpch_challenge  *chlg;

	int  err;
	int  digestsize;
	u8  xlen;
	u8   *digest;
	u8   *xbuf;

	/* get source and destination addresses
	 * Note that I switched the source and destination
	 * here to match the outgoint packet.
	 */
	__be32 daddr = ireq->ir_loc_addr;
	__be32 saddr = ireq->ir_rmt_addr;

	/* get source and destination port numbers */
	__be16 dport = htons(ireq->ir_num);
	__be16 sport = ireq->ir_rmt_port;

	/* make sure the key is generated */
	__generate_random_key_once ();

	/* create the hash algorithm */
	alg = crypto_alloc_shash ("sha256", CRYPTO_ALG_TYPE_DIGEST,
				  CRYPTO_ALG_TYPE_HASH_MASK);

	if (IS_ERR(alg)) 
	{
		pr_err ("Failed to create hash algo!\n");
		return ERR_PTR (-ENOMEM); /* double check error code */
	}

	sdesc = __init_sdesc_from_alg (alg);

	if (IS_ERR(sdesc)) 
		return ERR_PTR(-ENOMEM);

	/* initialize hash state */
	err = crypto_shash_init (sdesc);

	/* add the key to the state */
	err = crypto_shash_update (sdesc, tcp_challenge_secret,
				   TCPCH_KEY_SIZE);

	/* create key || saddr || sport || daddr || dport || ts */
	err = crypto_shash_update (sdesc, (u8 *) tcp_challenge_secret, TCPCH_KEY_SIZE);
	err = crypto_shash_update (sdesc, (u8 *) &saddr, sizeof (__be32));
	err = crypto_shash_update (sdesc, (u8 *) &sport, sizeof (__be16));
	err = crypto_shash_update (sdesc, (u8 *) &daddr, sizeof (__be32));
	err = crypto_shash_update (sdesc, (u8 *) &dport, sizeof (__be16));
	err = crypto_shash_update (sdesc, (u8 *) &ts, sizeof (u32));

	digestsize = crypto_shash_digestsize (alg);
	digest = (u8 *) kmalloc (digestsize, GFP_KERNEL);
	if (IS_ERR(digest))
	{
		chlg = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* compute the hash of the data that we updated */
	err = crypto_shash_final (sdesc, digest);

	/* grab the lower l/2 bytes of the hash
	 * len is in bits to divide by 16
	 */
	xlen = len / 16;
	xbuf = (u8 *)kmalloc (xlen, GFP_KERNEL);

	if (IS_ERR(xbuf))
	{
		chlg = ERR_PTR (-ENOMEM);
		goto out;
	}

	/* grab the bytes */
	memcpy (xbuf, digest, xlen);

	/* Done just set up the struct  */
	chlg = tcpch_alloc_challenge (ts, len, nz, diff);
	if (! IS_ERR(chlg))
	{
		chlg->cbuf = xbuf;
	}

out:
	crypto_free_shash (alg);
	kfree (sdesc);

	return chlg;
} /*  __generate_challenge */

/* challenge generation from a specific packet */
struct tcpch_challenge *tcpch_generate_challenge (struct sk_buff *skb,
						  const struct inet_request_sock *ireq,
						  u8 len, u8 nz, u8 diff, u32 ts)
{
	/*
	   const struct iphdr *iph = ip_hdr (skb);
	   const struct tcphdr *th = tcp_hdr (skb);
	   */

	/* const struct net *net = sock_net (sk); */
	if (ts == 0)
		ts = tcp_skb_timestamp (skb);

	return __generate_challenge (ireq, ts, len, nz, diff);
} /* tcpch_generate_challenge */
EXPORT_SYMBOL_GPL (tcpch_generate_challenge);

int __verify_solution (const struct net *net, const struct iphdr *iph,
		       const struct tcphdr *th, struct timeval *stamp,
		       struct tcpch_solution_head *sol)
{
	struct crypto_shash   *alg;
	struct shash_desc     *sdesc;
	struct tcpch_solution_item *itr, *tmp;

	int ret, err;
	u16 i, j;
	u8 xlen;
	int dsize;
	u32 ts;

	__be32 saddr, daddr;
	__be16 sport, dport;

	u8 *xbuf;
	u8 *digest;

	if (!sol || !iph || !th)
	{
		pr_err ("[tcp_ch:] Invalid input to verify_solution\n");
		return -EINVAL;
	}

	/* always make sure key is generated */
	__generate_random_key_once ();

	ts = sol->ts;

	/* get source and destination addresses */
	saddr = iph->saddr;
	daddr = iph->daddr;

	/* get source and destination addresses */
	sport = th->source;
	dport = th->dest;

	/* need to build x first */
	alg = crypto_alloc_shash ("sha256", CRYPTO_ALG_TYPE_DIGEST,
				  CRYPTO_ALG_TYPE_HASH_MASK);

	if (IS_ERR(alg))
	{
		pr_err ("[tcp_ch:] Failed to create sha256 algorithm\n");
		return -PTR_ERR(alg);
	}

	sdesc = __init_sdesc_from_alg (alg);
	if (IS_ERR(sdesc))
	{
		pr_err ("tcp_ch:] Failed to create shash descriptor\n");
		crypto_free_shash (alg);
		return -PTR_ERR(sdesc);
	}

	/* initialize hash state */
	err = crypto_shash_init (sdesc);
	/* save the secret into the state */
	err = crypto_shash_update (sdesc, tcp_challenge_secret,
				   TCPCH_KEY_SIZE);

	/* create key || saddr || sport || daddr || dport || ts */
	err = crypto_shash_update (sdesc, (u8 *) tcp_challenge_secret, TCPCH_KEY_SIZE);
	err = crypto_shash_update (sdesc, (u8 *) &saddr, sizeof (__be32));
	err = crypto_shash_update (sdesc, (u8 *) &sport, sizeof (__be16));
	err = crypto_shash_update (sdesc, (u8 *) &daddr, sizeof (__be32));
	err = crypto_shash_update (sdesc, (u8 *) &dport, sizeof (__be16));
	err = crypto_shash_update (sdesc, (u8 *) &ts, sizeof (u32));

	dsize = crypto_shash_digestsize (alg);
	digest = (u8 *) kmalloc (dsize, GFP_KERNEL);
	if (IS_ERR(digest))
	{
		pr_err ("[tcp_ch:] Failed to allocate space\n");
		ret = -ENOMEM;
		goto out;
	}
	crypto_shash_final (sdesc, digest);

	xlen = net->ipv4.sysctl_tcp_challenge_len / 16;
	xbuf = (u8 *)kmalloc (xlen, GFP_KERNEL);
	if (IS_ERR(xbuf))
	{
		pr_err ("[tcp_ch:] Failed to allocate memory\n");
		ret = -ENOMEM;
		goto out_free_digest;
	}
	memcpy (xbuf, digest, xlen);

	/* now we have xbuf, the real work starts here! */
	i = 1;
	j = 0;
	list_for_each_entry_safe (itr, tmp, &(sol->head), list)
	{
		err = crypto_shash_init (sdesc);
		if (err < 0)
		{
			pr_err ("[tcp_ch:] Failed to initialize sha256\n");
			goto out_free_all;
		}

		/* build x || i || z */
		err = crypto_shash_update (sdesc, xbuf, xlen);
		err = crypto_shash_update (sdesc, (u8 *) &j, sizeof (u16));
		err = crypto_shash_update (sdesc, itr->sbuf, xlen);

		err = crypto_shash_final (sdesc, digest);

		/* compate the bits of the computed hash with x */
		ret = __tcpch_compare_bits (digest, xbuf, sol->diff);
		/*net->ipv4.sysctl_tcp_challenge_diff);*/
		if (ret != 0)
		{
			/* one of the sub puzzles failed */
			pr_err ("Verification of sub solution %d failed!\n", i);
			ret = 0;
			goto out_free_all;
		}

		/* increment count to make sure client submitted all subpuzzles */
		i++;
		j++;

		/* make sure we don't verify more than we need, if we did that 
		 * this might be a place for a possible attack */
		if (i >= net->ipv4.sysctl_tcp_challenge_nz) { break; }
	}

	/* sanity check: remove after testing */
	if (ret != 0) {
		pr_err ("[tcpch:] Something weird is happening in verify solution!\n");
		goto out_free_all;
	}

	/* if for some reason we didn't go over all required puzzles 
	 * like the client not submitting solutions to all subpuzzles*/
	if (i < net->ipv4.sysctl_tcp_challenge_nz)
		ret = 0;

	ret = net->ipv4.sysctl_tcp_challenge_nz;

out_free_all:
	kfree(xbuf);
out_free_digest:
	kfree (digest);
out:
	kfree (sdesc);
	crypto_free_shash (alg);

	return ret;
} /* __verify_solution */

int tcpch_verify_solution (struct sock *sk, struct sk_buff *skb,
			   struct tcpch_solution_head *sol)
{
	const struct iphdr *iph = ip_hdr (skb);
	const struct tcphdr *th = tcp_hdr (skb);
	struct timeval stamp;
	const struct net *net = sock_net (sk);

	skb_get_timestamp (skb, &stamp);

	return __verify_solution (net, iph, th, &stamp, sol);
}
EXPORT_SYMBOL_GPL (tcpch_verify_solution);

u32 tcpch_get_length (struct tcpch_challenge *chlg)
{
	u32 need;
	if (!chlg)
		return 0;

	/* calculate how much space do we need in bytes */
	if (! chlg->opt_ts)
		need = (4 /* for timestamp */ +
			1 /* for nz */ +
			1 /* for diff */ +
			1 /* for len */ +
			chlg->len/16 /* length of preimage */);
	else
		need = (1 + 1 + 1 + chlg->len/16);

	/* add the option bytes */
	need += 2;

	/* align to 32 bits */
	need = (need + 3) & ~3U;
	return need;
}
EXPORT_SYMBOL_GPL (tcpch_get_length);

u32 tcpch_get_solution_length (struct tcpch_solution_head *sol)
{
	u32 need;
	if (!sol)
		return 0;

	/* calculate how much space do we need in bytes */
	if (sol->opt_ts)
		need = sol->nz * (sol->len / 16);
	else
		need = 4 /* for timestamp */ + sol->nz * (sol->len / 16);

	/* add the option bytes */
	need += 2;

	/* add the mss and wscale */
	/* add 1 more for the difficulty */
	need += 2 + 1 + 1;

	/* align to 32 bits */
	need = (need + 3) & ~3U;
	return need;
}
EXPORT_SYMBOL_GPL (tcpch_get_solution_length);
