#include "shared.h"
#include "netntlmv1_7_functions.cl"
#include "des_bitslice.cl"


/* Bitsliced precomputation for the Net-NTLMv1 7-byte tables: 32 slots per item.
 *
 * Precomputation dominates lookup cost -- it walks every chain position to the
 * end, so the work is chain_len^2 / 2.  At chain_len 2,000,000 that is 2e12 DES
 * per table index.
 *
 * Bitslicing looks impossible here because each slot starts at a different chain
 * position, so slices would need different per-step reduction constants and
 * would walk different numbers of steps.  The escape: all slots END at the same
 * position; only their starts differ, by total_devices per slot.  So walk each
 * slice scalar-ly for its own few extra steps to SYNCHRONISE them, then bitslice
 * the long common remainder, where the reduction addend is identical across
 * slices and stays a scalar constant.
 *
 * The scalar prologue costs sum(s * total_devices) = 496 * total_devices steps
 * per group of 32, against a common remainder that is typically far longer.
 *
 * Argument layout matches precompute_netntlmv1_7_batch.cl exactly so the host
 * binds both the same way; only the work-item to slot mapping differs.
 */

__constant uint BSP_BASE[8] = {31, 63, 23, 55, 15, 47, 7, 39};

#define BSP_SLOTS 32


__kernel void precompute_netntlmv1_7_bs(
    __global unsigned int *unused_hash_type,
    __global unsigned char *g_hashes,
    __global unsigned int *g_hash_len,
    __global unsigned int *g_num_hashes,
    __global char *unused_charset,
    __global unsigned int *unused_plaintext_len_min,
    __global unsigned int *unused_plaintext_len_max,
    __global unsigned int *g_table_index,
    __global unsigned long *g_chain_len,
    __global unsigned int *g_device_num,
    __global unsigned int *g_total_devices,
    __global unsigned int *g_chunk_positions,
    __global unsigned int *g_pos_start,
    __global unsigned int *g_output_len,
    __global unsigned long *g_output,
    __global unsigned char *g_challenge) {

  __local uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  __local uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(get_local_id(0), get_local_size(0),
                    l_SB1, l_SB2, l_SB3, l_SB4,
                    l_SB5, l_SB6, l_SB7, l_SB8);

  unsigned int chunk_groups = (*g_chunk_positions + BSP_SLOTS - 1) / BSP_SLOTS;
  unsigned int gid = get_global_id(0);
  unsigned int hash_idx = gid / chunk_groups;
  unsigned int group = gid % chunk_groups;

  if (hash_idx >= *g_num_hashes)
    return;

  unsigned int output_len = *g_output_len;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)(*g_chain_len);
  unsigned int total_devices = *g_total_devices;
  __global unsigned char *hash = g_hashes + ((unsigned long)hash_idx * (*g_hash_len));

  unsigned char challenge_local[8];
  for (int c = 0; c < 8; c++)
    challenge_local[c] = g_challenge[c];
  uint32_t cx, cy;
  netntlmv1_challenge_to_ip(challenge_local, &cx, &cy);

  unsigned int k0 = *g_pos_start + (group * BSP_SLOTS);

  /* Slice 0 starts latest; every later slice starts earlier and has further to
   * walk.  Synchronise them all to slice 0's start with a short scalar walk. */
  long sync_pos = ((long)chain_len - (long)(*g_device_num)) - ((long)k0 * (long)total_devices) - 1;

  unsigned long idx[BSP_SLOTS];
  unsigned int live[BSP_SLOTS];
  unsigned char plaintext[8];

  for (unsigned int s = 0; s < BSP_SLOTS; s++) {
    unsigned int k = k0 + s;
    long tcl = ((long)chain_len - (long)(*g_device_num)) - ((long)k * (long)total_devices) - 1;

    live[s] = ((k < output_len) && (tcl >= 1)) ? 1 : 0;
    idx[s] = 0;
    if (!live[s])
      continue;

    idx[s] = hash_char_to_index_netntlmv1_7(hash, reduction_offset, (unsigned int)(tcl - 1));

    for (long i = tcl; i < sync_pos; i++) {
      index_to_plaintext_netntlmv1_7(idx[s], plaintext);
      idx[s] = hash_to_index_netntlmv1_7(
          hash_netntlmv1_7_fast_ip(plaintext, cx, cy,
                                   l_SB1, l_SB2, l_SB3, l_SB4,
                                   l_SB5, l_SB6, l_SB7, l_SB8),
          reduction_offset, (unsigned int)i);
    }
  }

  uint key[56], out[64];
  for (int b = 0; b < 56; b++)
    key[b] = 0;
  for (unsigned int s = 0; s < BSP_SLOTS; s++) {
    uint bit = 1u << (31 - s);
    for (int b = 0; b < 56; b++)
      if ((idx[s] >> (55 - b)) & 1UL)
        key[b] |= bit;
  }

  unsigned long chal_bits = 0;
  for (int b = 0; b < 8; b++)
    for (int j = 0; j < 8; j++)
      if ((challenge_local[b] >> j) & 1)
        chal_bits |= 1UL << (BSP_BASE[j] - b);

  for (long i = sync_pos; i < (long)chain_len - 1; i++) {
    if (i < 1)
      continue;

    for (int w = 0; w < 64; w++)
      out[w] = 0u - (uint)((chal_bits >> w) & 1UL);

    f1(&out[32], key, out);   f2(out, key, &out[32]);
    f3(&out[32], key, out);   f4(out, key, &out[32]);
    f5(&out[32], key, out);   f6(out, key, &out[32]);
    f7(&out[32], key, out);   f8(out, key, &out[32]);
    f9(&out[32], key, out);   f10(out, key, &out[32]);
    f11(&out[32], key, out);  f12(out, key, &out[32]);
    f13(&out[32], key, out);  f14(out, key, &out[32]);
    f15(&out[32], key, out);  f16(out, key, &out[32]);

    unsigned long addend = (unsigned long)reduction_offset + (unsigned long)i;
    uint carry = 0;
    for (int bit = 0; bit < 56; bit++) {
      int b = bit >> 3, j = bit & 7;
      uint a = out[(BSP_BASE[j] - b + 32) & 63];
      uint cmask = 0u - (uint)((addend >> bit) & 1UL);
      uint sum = a ^ carry ^ cmask;
      carry = (a & carry) | (cmask & (a | carry));
      key[55 - bit] = sum;
    }
  }

  for (unsigned int s = 0; s < BSP_SLOTS; s++) {
    unsigned int k = k0 + s;
    if (k >= output_len)
      continue;

    unsigned long result = 0;
    if (live[s]) {
      uint bit = 1u << (31 - s);
      for (int b = 0; b < 56; b++)
        if (key[b] & bit)
          result |= 1UL << (55 - b);
    }
    g_output[((unsigned long)hash_idx * (unsigned long)output_len) + k] = result;
  }
}
