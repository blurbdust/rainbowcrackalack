#include <metal_stdlib>
using namespace metal;

#include "ntlm8_functions.metal"

/* Batched precompute for standard (non-Markov) NTLM8 tables.
 * See CL/precompute_ntlm8_batch.cl for detailed documentation. */
kernel void precompute_ntlm8_batch(
    device unsigned char *g_hashes [[buffer(0)]],
    device unsigned int *g_num_hashes [[buffer(1)]],
    device unsigned int *g_chunk_positions [[buffer(2)]],
    device unsigned int *g_charset_len [[buffer(3)]],
    device ulong *g_chain_len [[buffer(4)]],
    device unsigned int *g_pos_start [[buffer(5)]],
    device unsigned int *g_total_positions [[buffer(6)]],
    device ulong *g_output [[buffer(7)]],
    uint gid [[thread_position_in_grid]]) {

  unsigned int chunk_positions = *g_chunk_positions;
  unsigned int hash_idx = gid / chunk_positions;
  unsigned int local_pos = gid % chunk_positions;

  if (hash_idx >= *g_num_hashes) {
    return;
  }

  unsigned int absolute_pos = *g_pos_start + local_pos;
  unsigned int total_positions = *g_total_positions;

  if (absolute_pos >= total_positions) {
    return;
  }

  ulong chain_len = *g_chain_len;
  long target_chain_len = (long)chain_len - (long)absolute_pos - 1;

  if (target_chain_len < 1) {
    g_output[(ulong)hash_idx * total_positions + absolute_pos] = 0;
    return;
  }

  device unsigned char *hash = g_hashes + hash_idx * 16;
  unsigned char plaintext[8];
  ulong index = hash_char_to_index_ntlm8(hash, target_chain_len - 1);

  for (ulong i = target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext_ntlm8(index, charset, plaintext);
    index = hash_to_index_ntlm8(hash_ntlm8(plaintext), i);
  }

  g_output[(ulong)hash_idx * total_positions + absolute_pos] = index;
}
