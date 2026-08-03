#include "rt.cu"
#include "string.cu"


/* Parameter order must match the arg indices bound in host_thread()
 * (crackalack_gen.c), which binds 0..7.  cuLaunchKernel reads a pointer for
 * every declared parameter, so an extra leading or middle parameter silently
 * shifts every argument after it.  charset_len and the plaintext-space table
 * are therefore derived in-kernel, as in CL/crackalack.cl, rather than taken
 * as arguments the way bandrel's fork (which binds them) does. */
extern "C" __global__ void crackalack(
    unsigned int *g_hash_type,
    char *g_charset,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_reduction_offset,
    unsigned int *g_chain_len,
    unsigned long long *g_indices,
    unsigned int *g_pos_start) {

  unsigned int hash_type = *g_hash_type;
  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = *g_reduction_offset;
  unsigned int chain_len = *g_chain_len;
  unsigned long long start_index = g_indices[(blockIdx.x * blockDim.x + threadIdx.x)];
  unsigned int pos = *g_pos_start;

  /* g_strncpy copies all n bytes and does not stop at a NUL, which matters:
   * the 'byte' charset begins with 0x00, so stopping would leave charset_len
   * at 0 and collapse the plaintext space to zero. */
  unsigned int charset_len = g_strncpy(charset, g_charset, MAX_CHARSET_LEN);

  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN + 1];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int hash_len;

  unsigned long long plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

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
