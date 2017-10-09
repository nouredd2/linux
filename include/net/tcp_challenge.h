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

#define TCPCH_DEFAULT_LEN 32
#define TCPCH_DEFAULT_NZ 5
#define TCPCH_DEFAULT_NDIFF 20

/* This is the basic structure that will contain each challenge. The challenge
 * is composed of one clg of length (256 bits) since it is SHA256 that we are
 * using.
 */
struct tcpch_challenge {
    u8            *cbuf;      /* the actual challenge to send to the client */

    u64           ts;         /* the timestamp of the current challenge     */
    u16           len;        /* the length of (x+z) in the puzzle          */
    u16           nz;         /* the number of subpuzzles                   */
    u16           ndiff;      /* the number of bits of difficulty           */
};

/* This is the basic structure that will contain each solution to a subpuzzle.
 * The chaining of these solutions will form the full solution to a given
 * challenge
 */
struct tcpch_solution {
    u64             ts;         /* the timestamp used for the subpuzzle */
    u16             nz;         /* the number of subpuzzles             */
    u16             diff;       /* the number of diffuclty bits         */
    u8              *sbuf;      /* the current solution                 */

    struct list_head  list;     /* the list of sub-solutions contained  */
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
struct tcpch_challenge *tcpch_alloc_challenge(u64 mts, u16 mlen,
    u16 mnz, u16 mndiff);

/**
 * tcpch_alloc_solution - allocate memory for a challenge solution
 * @mts: The timestamp that was used for the solution
 * @diff: The number of bits of difficulty
 * @mnz: The number of subchallenges to be solved, this is only useful at
 *    the head of the list
 *
 * Allocate memory for a Tcp challenge solution. This will set the solution
 * data to 0 and WILL NOT allocate memory to hold the solution. This contains
 * a list head to point to the next sub challenge solution.
 */
struct tcpch_solution *tcpch_alloc_solution (u64 mts, u16 diff, u16 mnz);

/**
 * tcpch_free_challenge() - Free the space occupied by a challenge
 * @chlg: challenge struct to be freed
 *
 * This WILL take care of freeing the memory of the actual challenge
 * there is not need to do anything after this call
 */
void tcpch_free_challenge (struct tcpch_challenge *chlg);

/**
 * tcpch_free_solution() - Free the space occupied by a solution
 * @sol: solution structure to be freed
 *
 * This WILL take care of freeing the memory occupied by each of
 * the solutions in the list. It will free up every node in the list
 * starting from the one passed as an argument.
 */
void tcpch_free_solution (struct tcpch_solution *sol);

/*
 * tcpch_generate_challenge () - Generate challenge from a give packet
 *                  and some configuration parameters
 *
 * @skb:  incoming packet
 * @len:  the length of the challenge in bits
 * @nz:   the number of sub puzzles
 * @diff: the puzzle difficulty in bits
 *
 */
struct tcpch_challenge *tcpch_generate_challenge (struct sk_buff *skb,
                            u16 len, u16 nz, u16 diff);


#endif /* TCP_CHALLENGE_H */
