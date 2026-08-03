#include <metal_stdlib>
using namespace metal;

#include "rt.metal"

kernel void test_hash_to_index(
    device unsigned char *g_hash [[buffer(0)]],
    device unsigned int *g_hash_len [[buffer(1)]],
    device unsigned int *g_charset_len [[buffer(2)]],
    device unsigned int *g_plaintext_len_min [[buffer(3)]],
    device unsigned int *g_plaintext_len_max [[buffer(4)]],
    device unsigned int *g_table_index [[buffer(5)]],
    device unsigned int *g_pos [[buffer(6)]],
    device ulong *g_index [[buffer(7)]],
    device unsigned char *g_debug [[buffer(8)]],
    uint gid [[thread_position_in_grid]]) {

  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len = *g_hash_len;
  unsigned int charset_len = *g_charset_len;
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int pos = *g_pos;

  ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];

  for (int i = 0; i < hash_len; i++)
    hash[i] = g_hash[i];

  ulong plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  *g_index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, pos);
  return;
}
