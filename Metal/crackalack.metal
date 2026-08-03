#include <metal_stdlib>
using namespace metal;

#include "rt.metal"
#include "string.metal"


kernel void crackalack(
    device unsigned int *g_hash_type [[buffer(0)]],
    device char *g_charset [[buffer(1)]],
    device unsigned int *g_plaintext_len_min [[buffer(2)]],
    device unsigned int *g_plaintext_len_max [[buffer(3)]],
    device unsigned int *g_reduction_offset [[buffer(4)]],
    device unsigned int *g_chain_len [[buffer(5)]],
    device ulong *g_indices [[buffer(6)]],
    device unsigned int *g_pos_start [[buffer(7)]],
    uint gid [[thread_position_in_grid]]) {

  unsigned int hash_type = *g_hash_type;
  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = *g_reduction_offset;
  unsigned int chain_len = *g_chain_len;
  ulong start_index = g_indices[gid];
  unsigned int pos = *g_pos_start;

  /* charset_len derived from a NUL-terminated copy, and the plaintext-space
   * table computed in-kernel, matching the OpenCL kernel ABI (blurbdust's host
   * binds 8 args and no explicit charset_len / plaintext_space arguments). */
  unsigned int charset_len = g_strncpy(charset, g_charset, MAX_CHARSET_LEN);

  ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len;

  ulong plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  // Generate a chain, and store it in the local buffer.
  g_indices[gid] = generate_rainbow_chain(
        hash_type,
        charset,
        charset_len,
        plaintext_len_min,
        plaintext_len_max,
        reduction_offset,
        chain_len,
        start_index++,
	pos,
        plaintext_space_up_to_index,
        plaintext_space_total,
        plaintext,
        &plaintext_len,
        hash,
        &hash_len);
  return;
}
