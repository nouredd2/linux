/*
 * TCP/IP client puzzles implementation. 
 *
 * Copyright (c) 2017 Mohammad A. Noureddine <nouredd2@illinois.edu>
 * University of Illinois at Urbana-Champaign
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/printk.h>
#include <linux/time.h>

#include <crypto/hash.h>

#include <net/tcp.h>
#include <linux/tcp.h>

#include <net/tcp_challenge.h>

/* keep a key for the tcp challenge. This is similar to the syncookies
 * approach, but I think in the future we want to move this out of here
 */
static u8 tcp_challenge_secret[TCPCH_KEY_SIZE] __read_mostly;


/* tcpch_alloc_challenge */
struct tcpch_challenge *tcpch_alloc_challenge (u32 mts, u16 mlen,
    u16 mnz, u16 mndiff)
{
  struct tcpch_challenge *chlg;
  
  chlg = (struct tcpch_challenge *)
                    kmalloc (sizeof (struct tcpch_challenge), GFP_KERNEL);

  if (IS_ERR(chlg))
    {
      printk ("Cannot allocate memory for TCP/IP challenge\n");
    }
  else
    {
      chlg->ts    = mts;
      chlg->len   = mlen;
      chlg->nz    = mnz;
      chlg->ndiff = mndiff; 

      /* set the data to 0 */
      chlg->cbuf = 0;
    }

  return chlg;
}

/* tcpch_alloc_solution */
struct tcpch_solution *tcpch_alloc_solution (u32 mts, u16 mnz)
{
  struct tcpch_solution *solution;

  solution = (struct tcpch_solution *)
                    kmalloc (sizeof (struct tcpch_solution), GFP_KERNEL);

  if (IS_ERR(solution))
    {
      printk ("Cannot allocate memory for TCP/IP solution\n");
    }
  else 
    {
      solution->ts = mts;
      solution->nz = mnz;
      INIT_LIST_HEAD (&(solution->list));

      /* set the data buf to 0 */
      solution->sbuf = 0;
    }

  return solution;
}

/* tcpch_free_challenge */
void tcpch_free_challenge (struct tcpch_challenge *chlg)
{
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

/* free solution helper */
void _tcpch_free_solution (struct tcpch_solution *sol)
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
void tcpch_free_solution (struct tcpch_solution *sol)
{
  struct tcpch_solution *itr, *tmp;

  list_for_each_entry_safe (itr, tmp, &(sol->list), list)
    {
      /* remove the iterator from the list */
      list_del (&(itr->list));

      /* free the subsolution */
      _tcpch_free_solution (itr);
    }
}

struct shash_desc *__init_sdesc_from_alg (struct crypto_shash *alg)
{
  struct shash_desc *sdesc = (struct shash_desc *)
                                kmalloc (sizeof (struct shash_desc), GFP_KERNEL);
  sdesc->tfm = alg;
  sdesc->flags = 0x0;

  return sdesc;
}

/* internal challenge generation */
struct tcpch_challenge *__generate_challenge (const struct iphdr *iph,
    const struct tcphdr *th, struct timeval *stamp, 
    u16 len, u16 nz, u16 diff)
{
  struct crypto_shash     *alg;
  struct shash_desc       *sdesc;
  struct tcpch_challenge  *chlg;

  int  err;
  int  digestsize;
  u16  xlen;
  u8   *digest;
  u8   *xbuf;

  /* get source and destination addresses */
  __be32 saddr = iph->saddr;
  __be32 daddr = iph->daddr;

  /* get source and destination port numbers */
  __be16 sport = th->source;
  __be16 dport = th->dest;
 
  /* also keep the initial sequence number */
  __u32 sseq = ntohl (th->seq);

  /* get the timestamp in microsec */
  long ts = (stamp->tv_sec*1000000L) + stamp->tv_usec;

  /* make sure the key is generated */
  net_get_random_once (tcp_challenge_secret, TCPCH_KEY_SIZE);

  /* create the hash algorithm */
  alg = crypto_alloc_shash ("sha256", CRYPTO_ALG_TYPE_DIGEST, 
                                CRYPTO_ALG_TYPE_HASH_MASK);

  if (IS_ERR(alg)) 
    {
      printk ("Failed to create hash algo!\n");
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

  /* create key || iss || saddr || sport || daddr || dport || ts */
  err = crypto_shash_update (sdesc, (u8 *) &sseq, sizeof(u32));
  err = crypto_shash_update (sdesc, (u8 *) &saddr, sizeof (__be32));
  err = crypto_shash_update (sdesc, (u8 *) &sport, sizeof (__be16));
  err = crypto_shash_update (sdesc, (u8 *) &daddr, sizeof (__be32));
  err = crypto_shash_update (sdesc, (u8 *) &dport, sizeof (__be16));
  err = crypto_shash_update (sdesc, (u8 *) &ts, sizeof (long));

  digestsize = crypto_shash_digestsize (alg);
  digest = (u8 *) kmalloc (digestsize, GFP_KERNEL);
  if (IS_ERR(digest))
    {
      return ERR_PTR(-ENOMEM);
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
      return ERR_PTR (-ENOMEM);
    }

  /* grab the bytes */
  memcpy (xbuf, digest, xlen);

  /* Done just set up the struct  */

  return chlg;
}

/* challenge generation from a specific packet */
struct tcpch_challenge *generate_challenge (struct sk_buff *skb,
    u16 len, u16 nz, u16 diff)
{
  const struct iphdr *iph = ip_hdr (skb);
  const struct tcphdr *th = tcp_hdr (skb);
  struct timeval stamp;
  
  skb_get_timestamp (skb, &stamp);

  return __generate_challenge (iph, th, &stamp, len, nz, diff);
}

