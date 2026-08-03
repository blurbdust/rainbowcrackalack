#include "rt.cu"
#include "string.cu"


extern "C" __global__ void crackalack(
    unsigned int *g_hash_type,
    char *g_charset,
    unsigned int *g_charset_len,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_reduction_offset,
    unsigned int *g_chain_len,
    unsigned long long *g_indices,
    unsigned int *g_pos_start,
    unsigned long long *g_plaintext_space_up_to_index,
    unsigned long long *g_plaintext_space_total) {

  unsigned int hash_type = *g_hash_type;
  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = *g_reduction_offset;
  unsigned int chain_len = *g_chain_len;
  unsigned long long start_index = g_indices[(blockIdx.x * blockDim.x + threadIdx.x)];
  unsigned int pos = *g_pos_start;

  unsigned int charset_len = *g_charset_len;
  g_memcpy((unsigned char *)charset, (unsigned char *)g_charset, charset_len);

  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN + 1];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len;

  copy_plaintext_space_up_to_index(plaintext_space_up_to_index, g_plaintext_space_up_to_index, plaintext_len_max);
  unsigned long long plaintext_space_total = *g_plaintext_space_total;

  /* Generate a chain, and store it in the local buffer. */
  g_indices[(blockIdx.x * blockDim.x + threadIdx.x)] = generate_rainbow_chain(
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
