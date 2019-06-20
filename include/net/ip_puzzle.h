#ifndef _IP_PUZZLE_H
#define _IP_PUZZLE_H

struct inet_solution;

struct inet_solution *solve_ip_puzzle(int difficulty, int pnum,
				      __be32 ts, u8 *s_nonce, u8 *c_nonce);

#endif
