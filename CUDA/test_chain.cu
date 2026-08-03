#include "rt.cu"
#include "string.cu"

/* NOTE: This kernel intentionally matches blurbdust's 8-argument host
 * contract in test_chain.c (gpu_test_chain), i.e. the SAME argument list as
 * CL/test_chain.cl.  The bandrel reference CUDA/test_chain.cu carried a 9th
 * leading g_charset_len argument; porting that verbatim shifted every
 * subsequent argument by one under CUDA (the host only binds 8 args), so the
 * kernel read chain_len as 0 and the unsigned "pos < chain_len - 1" loop
 * underflowed to ~4 billion iterations (100% GPU, never returns).  Deriving
 * charset_len via g_strncpy here keeps host/device arg counts in lockstep. */
extern "C" __global__ void test_chain(
    char *g_charset,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_table_index,
    unsigned int *g_chain_len,
    unsigned long long *g_start,
    unsigned long long *g_end,
    unsigned char *g_debug) {

  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = *g_chain_len;
  unsigned long long start = *g_start;

  unsigned int charset_len = g_strncpy(charset, g_charset, sizeof(charset));
  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len;

  unsigned long long plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

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
