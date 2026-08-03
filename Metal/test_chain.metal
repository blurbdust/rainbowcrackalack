#include <metal_stdlib>
using namespace metal;

#include "rt.metal"
#include "string.metal"

kernel void test_chain(
    device char *g_charset [[buffer(0)]],
    device unsigned int *g_plaintext_len_min [[buffer(1)]],
    device unsigned int *g_plaintext_len_max [[buffer(2)]],
    device unsigned int *g_table_index [[buffer(3)]],
    device unsigned int *g_chain_len [[buffer(4)]],
    device ulong *g_start [[buffer(5)]],
    device ulong *g_end [[buffer(6)]],
    device unsigned char *g_debug [[buffer(7)]],
    uint gid [[thread_position_in_grid]]) {

  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = *g_chain_len;
  ulong start = *g_start;

  /* charset_len derived from a NUL-terminated copy, matching the OpenCL kernel
   * ABI (blurbdust's host binds no explicit charset_len argument). */
  unsigned int charset_len = g_strncpy(charset, g_charset, MAX_CHARSET_LEN);
  ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len;

  ulong plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  *g_end = generate_rainbow_chain(
    HASH_TYPE,
    charset,
    charset_len,
    plaintext_len_min,
    plaintext_len_max,
    reduction_offset,
    chain_len,
    start,
    0,
    plaintext_space_up_to_index,
    plaintext_space_total,
    plaintext,
    &plaintext_len,
    hash,
    &hash_len);

  return;
}
