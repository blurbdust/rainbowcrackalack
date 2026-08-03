#include "rt.cu"

extern "C" __global__ void test_hash_to_index(
    unsigned char *g_hash,
    unsigned int *g_hash_len,
    unsigned int *g_charset_len,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_table_index,
    unsigned int *g_pos,
    unsigned long long *g_index,
    unsigned char *g_debug) {

  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len = *g_hash_len;
  unsigned int charset_len = *g_charset_len;
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int pos = *g_pos;

  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];

  for (int i = 0; i < (int)hash_len; i++)
    hash[i] = g_hash[i];

  unsigned long long plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  *g_index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, pos);
  return;
}
