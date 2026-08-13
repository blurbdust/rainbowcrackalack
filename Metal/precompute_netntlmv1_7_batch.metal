#include <metal_stdlib>
using namespace metal;

#include "shared.h"
#include "netntlmv1_7_functions.metal"


/* Batched precomputation for the Net-NTLMv1 7-byte tables, the Metal
 * counterpart of CL/precompute_netntlmv1_7_batch.cl.
 *
 * Two separate wins over the generic precompute_batch.metal:
 *
 *  1. The specialized chain walk.  The generic kernel gives every thread a
 *     256-byte charset array plus a plaintext space table that it rebuilds for
 *     itself, and dispatches the hash function on a runtime type.  None of that
 *     is needed for a 7 byte Net-NTLMv1 key, where the plaintext is the index,
 *     and the DES S-boxes go in threadgroup memory.
 *
 *  2. The hash axis.  Widening a dispatch along the position axis buys nothing,
 *     because the thread at position p walks (chain_len - p) steps and the chunk
 *     runs at the speed of its longest walk.  Every hash at a given position
 *     walks the same number of steps, so widening along the hash axis adds
 *     parallelism with no divergence.
 *
 * Buffer indices match precompute_batch.metal exactly (including the ones this
 * kernel has no use for) so the host binds both the same way, with the challenge
 * appended at 15.
 *
 * The S-box load and its barrier run before any early return, because every
 * thread in a threadgroup has to reach a threadgroup barrier and this backend
 * dispatches non-uniform groups. */
kernel void precompute_netntlmv1_7_batch(
    device unsigned int *unused_hash_type [[buffer(0)]],
    device unsigned char *g_hashes [[buffer(1)]],
    device unsigned int *g_hash_len [[buffer(2)]],
    device unsigned int *g_num_hashes [[buffer(3)]],
    device char *unused_charset [[buffer(4)]],
    device unsigned int *unused_plaintext_len_min [[buffer(5)]],
    device unsigned int *unused_plaintext_len_max [[buffer(6)]],
    device unsigned int *g_table_index [[buffer(7)]],
    device ulong *g_chain_len [[buffer(8)]],
    device unsigned int *g_device_num [[buffer(9)]],
    device unsigned int *g_total_devices [[buffer(10)]],
    device unsigned int *g_chunk_positions [[buffer(11)]],
    device unsigned int *g_pos_start [[buffer(12)]],
    device unsigned int *g_output_len [[buffer(13)]],
    device ulong *g_output [[buffer(14)]],
    device unsigned char *g_challenge [[buffer(15)]],
    uint gid [[thread_position_in_grid]],
    uint lid [[thread_position_in_threadgroup]],
    uint lsz [[threads_per_threadgroup]]) {

  /* Threadgroup S-box arrays, one copy per group. */
  threadgroup uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  threadgroup uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(lid, lsz,
                    l_SB1, l_SB2, l_SB3, l_SB4,
                    l_SB5, l_SB6, l_SB7, l_SB8);

  unsigned int chunk_positions = *g_chunk_positions;
  unsigned int hash_idx = gid / chunk_positions;
  unsigned int local_pos = gid % chunk_positions;

  if (hash_idx >= *g_num_hashes)
    return;

  /* Index into this device's slice of the output. */
  unsigned int k = *g_pos_start + local_pos;
  unsigned int output_len = *g_output_len;
  if (k >= output_len)
    return;

  ulong out_idx = ((ulong)hash_idx * (ulong)output_len) + k;

  /* Range checked before subtracting so an underflow cannot masquerade as a
   * huge positive length. */
  ulong base = *g_chain_len - (ulong)(*g_device_num);
  ulong span = (ulong)k * (ulong)(*g_total_devices);

  if (base < span + 2) {   /* i.e. target_chain_len < 1 */
    g_output[out_idx] = 0;
    return;
  }
  ulong target_chain_len = base - span - 1;

  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)(*g_chain_len);

  device unsigned char *hash = g_hashes + ((ulong)hash_idx * (*g_hash_len));
  unsigned char plaintext[8];
  ulong index = hash_char_to_index_netntlmv1_7(hash, reduction_offset, (unsigned int)(target_chain_len - 1));

  unsigned char challenge_local[8];
  for (int _c = 0; _c < 8; _c++) challenge_local[_c] = g_challenge[_c];

  uint32_t cx, cy;
  netntlmv1_challenge_to_ip(challenge_local, &cx, &cy);

  for (ulong i = target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext_netntlmv1_7(index, plaintext);
    index = hash_to_index_netntlmv1_7(
        hash_netntlmv1_7_fast_ip(plaintext, cx, cy,
                                 l_SB1, l_SB2, l_SB3, l_SB4,
                                 l_SB5, l_SB6, l_SB7, l_SB8),
        reduction_offset, (unsigned int)i);
  }

  g_output[out_idx] = index;
}
