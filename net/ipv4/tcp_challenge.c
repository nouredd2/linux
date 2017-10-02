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

#include <linux/printk.h>
#include <linux/err.h>
#include <net/tcp_challenge.h>


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
