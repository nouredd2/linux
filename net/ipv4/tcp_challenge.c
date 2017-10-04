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
#include <linux/slab.h>

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
