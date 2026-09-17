#include <metal_stdlib>
using namespace metal;

#include "shared.h"
#include "des_bitslice.metal"


/* Bitsliced Net-NTLMv1 chain generation: 32 chains per work item.
 *
 * The scalar kernel pays ~2100 instructions per chain step just building the DES
 * key schedule with DES_PC2, plus 128 S-box loads.  Bitsliced, the key schedule
 * is free -- it is only which bsKey[] index gets XORed into an S-box input --
 * and there is no memory traffic at all.
 *
 * Rainbow chains normally defeat bitslicing, because the reduction is per-chain
 * and forces a transpose in and out of bitslice form on EVERY step.  This
 * configuration escapes that completely:
 *
 *   index -> plaintext   byte charset, so the plaintext IS the index: free
 *   plaintext -> key     the 7 bytes ARE the 56 key bits: a relabelling, free
 *   mask to 2^56         drop the high bits: free
 *   + (reduction_offset + pos)   the only real work, a bitsliced ripple-carry
 *                                adder at 5 gates per bit
 *
 * So there are ZERO transposes per step -- one per chain at each end, amortised
 * over chain_len steps.
 *
 * Bit conventions, all verified against OpenSSL:
 *   - slice s lives in bit (31 - s) of every word;
 *   - key word k holds bit (55 - k) of the 56-bit index, i.e. MSB first;
 *   - a block is loaded into the IP domain via state[BASE[j] - b] for byte b,
 *     bit j, and read back the same way;
 *   - reading the RESULT additionally swaps the two 32-bit halves, which is the
 *     standard DES L/R swap before the final permutation.  Omitting that swap
 *     silently produces wrong ciphertext for every key.
 */

constant uint BS_BASE[8] = {31, 63, 23, 55, 15, 47, 7, 39};

#define BS_CHAINS_PER_ITEM 32


kernel void crackalack_netntlmv1_bs(
    device unsigned int *unused_hash_type [[buffer(0)]],
    device char *unused_charset [[buffer(1)]],
    device unsigned int *unused_plaintext_len_min [[buffer(2)]],
    device unsigned int *unused_plaintext_len_max [[buffer(3)]],
    device unsigned int *g_reduction_offset [[buffer(4)]],
    device unsigned int *g_chain_len [[buffer(5)]],
    device ulong *g_indices [[buffer(6)]],
    device unsigned int *g_pos_start [[buffer(7)]],
    device unsigned char *g_challenge [[buffer(8)]],
    uint gid [[thread_position_in_grid]]) {

  uint key[56], out[64];
  ulong chal_bits = 0;   /* in[i] is all-ones iff bit i is set */
  unsigned int reduction_offset = *g_reduction_offset;
  unsigned int chain_len = *g_chain_len;
  unsigned int pos = *g_pos_start;
  ulong base = (unsigned long)gid * BS_CHAINS_PER_ITEM;

  /* ---- transpose 32 start indices into bitslice form ---- */
  for (int k = 0; k < 56; k++)
    key[k] = 0;
  for (int s = 0; s < BS_CHAINS_PER_ITEM; s++) {
    ulong idx = g_indices[base + s];
    uint bit = 1u << (31 - s);
    for (int k = 0; k < 56; k++)
      if ((idx >> (55 - k)) & 1UL)
        key[k] |= bit;
  }

  /* ---- the fixed DES plaintext, once, in the IP domain ----
   * Held as a 64-bit mask rather than 64 words: each bitslice word of a constant
   * block is uniformly 0 or ~0, so 64 registers collapse to one scalar. */
  for (int b = 0; b < 8; b++)
    for (int j = 0; j < 8; j++)
      if ((g_challenge[b] >> j) & 1)
        chal_bits |= 1UL << (BS_BASE[j] - b);

  /* ---- walk the chains ---- */
  for (; pos < chain_len - 1; pos++) {
    for (int i = 0; i < 64; i++)
      out[i] = 0u - (uint)((chal_bits >> i) & 1UL);

    f1(&out[32], key, out);   f2(out, key, &out[32]);
    f3(&out[32], key, out);   f4(out, key, &out[32]);
    f5(&out[32], key, out);   f6(out, key, &out[32]);
    f7(&out[32], key, out);   f8(out, key, &out[32]);
    f9(&out[32], key, out);   f10(out, key, &out[32]);
    f11(&out[32], key, out);  f12(out, key, &out[32]);
    f13(&out[32], key, out);  f14(out, key, &out[32]);
    f15(&out[32], key, out);  f16(out, key, &out[32]);

    /* Read out, add the per-step constant, and store the next key -- in one
     * pass, with no intermediate val[] array.
     *
     * Ciphertext byte b bit j is bit (8b + j) of the little-endian 64-bit value
     * hash_to_index() builds; only the low 56 survive the 2^56 mask, so the rest
     * are never materialised.  (+32 mod 64) is the DES L/R swap.  The result IS
     * the next index, and bit (55-k) of the index is key word k, so the adder
     * walks bit i from LSB up while writing key[55 - i]. */
    {
      ulong addend = (unsigned long)reduction_offset + (unsigned long)pos;
      uint carry = 0;
      for (int i = 0; i < 56; i++) {
        int b = i >> 3, j = i & 7;
        uint a = out[(BS_BASE[j] - b + 32) & 63];
        uint cmask = 0u - (uint)((addend >> i) & 1UL);   /* 0 or ~0 */
        uint sum = a ^ carry ^ cmask;
        carry = (a & carry) | (cmask & (a | carry));
        key[55 - i] = sum;
      }
    }
  }

  /* ---- transpose the 32 endpoints back out ---- */
  for (int s = 0; s < BS_CHAINS_PER_ITEM; s++) {
    uint bit = 1u << (31 - s);
    ulong idx = 0;
    for (int k = 0; k < 56; k++)
      if (key[k] & bit)
        idx |= 1UL << (55 - k);
    g_indices[base + s] = idx;
  }
}
