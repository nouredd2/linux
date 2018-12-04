/*
 * INET		An implementation of the TCP/IP client puzzles as presented
 *    in the paper by Ari Juels in 1999
 *
 *		Definitions for the TCP/IP client challenges
 *
 * Authors:	Mohammad A. Noureddine, <nouredd2@illinois.edu>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __TCP_CHALLENGE_H
#define __TCP_CHALLENGE_H

#include <linux/list.h>

/* the default key size for the server sockets */
#define TCPCH_KEY_SIZE 256

/* the default size of each new challenge sent */
#define TCPCH_DEFAULT_SIZE 32

#define TCPCH_DEFAULT_LEN 64
#define TCPCH_DEFAULT_NZ 1
#define TCPCH_DEFAULT_NDIFF 3
#define TCPCH_DEFAULT_TO 10
#define TCPCH_DEFAULT_TIMER 1000 /* 1 second */

/* This is the basic structure that will contain each challenge. The challenge
 * is composed of one clg of length (256 bits) since it is SHA256 that we are
 * using.
 */
struct tcpch_challenge {
  u8            *cbuf;      /* the actual challenge to send to the client */

  u32          ts;         /* the timestamp of the current challenge     */
  u8           len;        /* the length of (x+z) in the puzzle          */
  u8           nz;         /* the number of subpuzzles                   */
  u8           ndiff;      /* the number of bits of difficulty           */
  bool         opt_ts;     /* flag to check wether to use the timestamp
                              from the options field in the header       */
};

/* This is the basic structure that will contain each solution to a subpuzzle.
 * The chaining of these solutions will form the full solution to a given
 * challenge
 */
struct tcpch_solution_head {
  u32            ts;         /* the timestamp used for the subpuzzle */
  u8             nz;         /* the number of subpuzzles             */
  u8             diff;       /* the number of diffuclty bits         */
  u8             len;        /* the length of (x+z) in the puzzles   */
  bool           opt_ts;     /* falg to check wether to use the
                                timestamp from the options field     */

  struct list_head  head;     /* the list of sub-solutions contained  */
};

struct tcpch_solution_item {
  u8             *sbuf;      /* the current solution                 */

  struct list_head list;     /* the list pointer for the next item   */
};

/**
 * tcpch_alloc_challenge - allocate memory for a challenge
 * @mts: The current timestamp at the server or the ts read from the packet
 * @mlen: The length of (x+z) in the challenge
 * @mnz: The number of subzpuzzles in the challenge
 * @mndiff: The number of bits of difficulty in the challenge
 *
 * Allocate memory for a Tcp challenge. This will set the chlg data to 0
 * and WILL NOT allocate memory of the buffer to hold the challenge, this
 * should be done separately.
 */
struct tcpch_challenge *tcpch_alloc_challenge(u32 mts, u8 mlen,
    u8 mnz, u8 mndiff);

/**
 * tcpch_alloc_solution - allocate memory for a challenge solution
 * @mts: The timestamp that was used for the solution
 * @diff: The number of bits of difficulty
 * @mnz: The number of subchallenges to be solved, this is only useful at
 *    the head of the list
 * @mlen: The length of (x+z) in bits
 */
struct tcpch_solution_head *tcpch_alloc_solution_head (u32 mts, u8 diff, u8 mnz, u8 mlen);

/**
 * tcpch_alloc_solution_head () - allocate memory for a challenge solution item
 *
 * @return the allocated structure with the solution buffer set to 0.
 */
struct tcpch_solution_item *tcpch_alloc_solution_item (void);

/**
 * tcpch_free_challenge() - Free the space occupied by a challenge
 * @chlg: challenge struct to be freed
 *
 * This WILL take care of freeing the memory of the actual challenge
 * there is not need to do anything after this call
 */
void tcpch_free_challenge (struct tcpch_challenge *chlg);

/*
 * tcpch_free_challenge_safe() -- Free the space occupied by a challenge
 * without handling the inner buffer
 *
 * @chlg: challenge struct to be freed
 */
void tcpch_free_challenge_safe (struct tcpch_challenge *chlg);

/**
 * tcpch_free_solution() - Free the space occupied by a solution
 * @sol: solution structure to be freed
 *
 * This WILL take care of freeing the memory occupied by each of
 * the solutions in the list. It will free up every node in the list
 * starting from the one passed as an argument.
 */
void tcpch_free_solution (struct tcpch_solution_head *head);

/*
 * tcpch_generate_challenge () - Generate challenge from a give packet
 *                  and some configuration parameters
 *
 * @skb:  incoming packet
 * @ireq: the request socket
 * @len:  the length of the challenge in bits
 * @nz:   the number of sub puzzles
 * @diff: the puzzle difficulty in bits
 * @ts:   the timestamp to be used for generating challenges
 *
 * @return the built challenge structure
 */
struct tcpch_challenge *tcpch_generate_challenge (struct sk_buff *skb,
    const struct inet_request_sock *ireq,
    u8 len, u8 nz, u8 diff, u32 ts);

/*
 * tcpch_verify_solution () - Verify a given solution of a certain challenge
 *
 * @sk:      the handling socket
 * @skb:     incoming packets
 * @sol:     the solution to verify
 *
 * @return <= 0 if it fails and > 0 if it succeeds.
 */
int tcpch_verify_solution (struct sock *sk, struct sk_buff *skb,
              struct tcpch_solution_head *sol);

/*
 * tcpch_solve_challenge () - Solve a given challenge
 *
 * @chlg:    the challenge to solve
 *
 * @return the solved challenge if successful
 */
struct tcpch_solution_head *tcpch_solve_challenge (struct tcpch_challenge *chlg);

/*
 * tcpch_get_length () - Get the length of a challenge in bytes. Aligned to 32 bits
 *
 * @chlg:   The challenge to compute the length for
 *
 * @return the challenge's length in bytes aligned to 32 bits
 */
u32 tcpch_get_length (struct tcpch_challenge *chlg);

/*
 * tcpch_get_solution_length () - Get the length of a solution in bytes. Aligned to 32 bits
 *
 * @sol:    The solution to compute the length for
 *
 * @return the solution's length in bytes aligned to 32 bits
 */
u32 tcpch_get_solution_length (struct tcpch_solution_head *sol);

/*
 * challenge_v4_check () - Check for a challenge solution and verify it.
 *
 * @sk:     The calling socket
 * @skb:    The received packet
 *
 * @return a new child socket if everything goes well
 */
struct sock *challenge_v4_check (struct sock *sk,
        struct sk_buff *skb);


#endif /* TCP_CHALLENGE_H */
