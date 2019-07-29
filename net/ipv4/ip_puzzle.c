/*
 * Implementation of the puzzle solution in the IP stack
 *
 * Mohammad A. Noureddine <nouredd2@illinois.edu>
 *
 */
#define pr_fmt(fmt) "IP_Puzzle: " fmt

#include <linux/err.h>
#include <net/inet_sock.h>
#include <net/ip_puzzle.h>

#include <crypto/hash.h>
#include <crypto/drbg.h>


/* __init_sdesc_from_alg */
static inline struct shash_desc *__init_sdesc_from_alg(struct crypto_shash *alg)
{
	struct shash_desc *sdesc;
	int size;

	size = sizeof (struct shash_desc) + crypto_shash_descsize (alg);
	sdesc = (struct shash_desc *) kmalloc (size, GFP_KERNEL);
	sdesc->tfm = alg;
	sdesc->flags = 0x0;

	return sdesc;
}


/*
 * compare_msbits() - Compare the most signification bits to zero
 *
 * @buf: The buffer containing the bytes to compare
 * @buflen: The total length of the buffer in bytes
 * @bits: The number of bits to compare
 */
static int compare_msbits(const u8 *buf, int buflen, int bits)
{
	union comparator {
		u8 small;
		u16 medium;
		u32 large;
	} mask, cmp;
	u8 *tmp;

	if (bits >= buflen * 8)
		return 0;

	if (bits <= 8) {
		cmp.small = *buf;
		mask.small = 0xFF >> bits;
		if ((cmp.small | mask.small) >> (8 - bits))
			return 0;
		return 1;
	} else if (bits <= 16) {
		cmp.medium = *(u16 *)buf;
		mask.medium = 0xFFFF >> bits;
		if ((cmp.medium | mask.medium) >> (16 - bits))
			return 0;
		return 1;
	} else if (bits <= 24) {
		if (buflen > 3)
			goto handle_four_bytes;

		tmp = kmalloc(4, GFP_KERNEL);
		memcpy(tmp, buf, buflen);

		cmp.large = *(u32 *)tmp;
		mask.large = 0xFFFFFFFF >> bits;
		kfree(tmp);
		if ((cmp.large | mask.large) >> (32 - bits))
			return 0;
		return 1;
	} else if (bits <= 32) {
handle_four_bytes:
		cmp.large = *(u32 *)buf;
		mask.large = 0xFFFFFFFF >> bits;
		if ((cmp.large | mask.large) >> (32 - bits))
			return 0;
		return 1;
	} else {
		pr_err("Puzzles larger than 32 bits of difficulty are not allowed as they will hang the kernel\n");
		return 0;
	}
}

/** solve_ip_puzzle - solve an ip puzzle
 *
 * @difficulty - the difficulty at which to solve the puzzle
 * @pnum - the puzzle number
 * @ts - the timestamp to use and echo back
 * @s_none - the server's nonce
 * @c_nonce - the client's nonce
 *
 * @return an inet_solution if successful, ERR_PTR if not
 */
struct inet_solution *solve_ip_puzzle(int difficulty, int pnum, __be32 ts,
				      u8 *s_nonce, u8 *c_nonce)
{
	struct crypto_shash *alg;
	struct shash_desc *sdesc;
	u8 *trial, *out;
	int err, dsize, found;
	struct inet_solution *sol = 0;

	alg = crypto_alloc_shash("sha256", CRYPTO_ALG_TYPE_DIGEST,
				 CRYPTO_ALG_TYPE_HASH_MASK);
	if (IS_ERR(alg)) {
		pr_err("Failed to create hash algorithm!\n");
		return ERR_PTR(PTR_ERR(alg));
	}

	sdesc = __init_sdesc_from_alg(alg);
	if (IS_ERR(sdesc)) {
		pr_err("Failed to create algorithm descriptor\n");
		err = PTR_ERR(sdesc);
		goto exit_on_alg;
	}

	dsize = crypto_shash_digestsize(alg);
	out = kmalloc(dsize, GFP_KERNEL);
	if (IS_ERR(out)) {
		err = PTR_ERR(out);
		goto exit_on_desc;
	}

	trial = kmalloc(PUZZLE_SIZE, GFP_KERNEL);
	if (IS_ERR(trial)) {
		err = PTR_ERR(trial);
		goto exit_on_hash;
	}

	do {
		err = crypto_shash_init(sdesc);
		if (err < 0)
			goto exit_after_lock;

		/* try a new one */
		get_random_bytes(trial, PUZZLE_SIZE);
		err = crypto_shash_update(sdesc, trial, PUZZLE_SIZE);
		err = crypto_shash_update(sdesc, c_nonce, CLIENT_NONCE_SIZE);
		err = crypto_shash_update(sdesc, (u8 *)&ts, sizeof(__be32));

		err = crypto_shash_update(sdesc, (u8 *)&pnum, sizeof(int));
		err = crypto_shash_update(sdesc, s_nonce, NONCE_SIZE);

		err = crypto_shash_final(sdesc, out);
		if (err < 0) {
			pr_err("Hashing operation failed!\n");
			goto exit_after_lock;
		}

		if (compare_msbits(out, dsize, difficulty)) {
			pr_debug("Found the solution! Stop computing and go back!\n");
			found = 1;
			err = 0;
		} 
	} while (found == 0);

	/* create a solution and fill it out */
	sol = kmalloc(sizeof(struct inet_solution), GFP_KERNEL);
	sol->solution = kmalloc(PUZZLE_SIZE, GFP_KERNEL);
	sol->ts = ts;
	sol->diff = difficulty;
	sol->idx = pnum;
	memcpy(sol->solution, trial, PUZZLE_SIZE);
	INIT_LIST_HEAD(&sol->list);

exit_after_lock:
	kfree(trial);
exit_on_desc:
	kfree(sdesc);
exit_on_hash:
	kfree(out);
exit_on_alg:
	crypto_free_shash(alg);
	if (err < 0)
		return ERR_PTR(err);
	else
		return sol;
}
EXPORT_SYMBOL(solve_ip_puzzle);
