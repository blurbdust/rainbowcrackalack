#include "rt.cu"
#include "string.cu"


/* Generic precomputation kernel, the CUDA counterpart of CL/precompute.cl.
 * NTLM8/NTLM9 have their own optimized kernels; every other hash type,
 * Net-NTLMv1 included, goes through this one.
 *
 * Parameter order matches the arg indices bound in host_thread_precompute()
 * (crackalack_lookup.c), which binds 0..11 unconditionally.  cuLaunchKernel
 * reads a pointer for every declared parameter, so the list must line up
 * exactly. */
extern "C" __global__ void precompute(
    unsigned int *g_hash_type,
    unsigned char *g_hash,
    unsigned int *g_hash_len,
    char *g_charset,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_table_index,
    unsigned long long *g_chain_len,
    unsigned int *g_device_num,
    unsigned int *g_total_devices,
    unsigned int *g_exec_block_scaler,
    unsigned long long *g_output) {

  unsigned int gid = (blockIdx.x * blockDim.x + threadIdx.x);

  /* Each thread walks the chain from a different starting position.  Computed
   * in signed 64-bit so an underflow stays negative and is caught below,
   * rather than wrapping to a huge positive length. */
  long long chain_len_ll = (long long)(*g_chain_len);
  long long target_chain_len = (chain_len_ll - (long long)(*g_device_num)) -
      ((long long)((unsigned long long)gid + *g_exec_block_scaler) * (long long)(*g_total_devices)) - 1;

  if (target_chain_len < 1) {
    g_output[gid] = 0;
    return;
  }

  char charset[MAX_CHARSET_LEN];
  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN + 1];
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned long long index;

  unsigned int hash_type = *g_hash_type;
  unsigned int hash_len = *g_hash_len;
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)chain_len_ll;

  /* g_strncpy copies all n bytes and does not stop at a NUL, which matters:
   * the 'byte' charset begins with 0x00, so stopping would leave charset_len
   * at 0 and collapse the plaintext space to zero. */
  unsigned int charset_len = g_strncpy(charset, g_charset, MAX_CHARSET_LEN);
  unsigned long long plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  g_memcpy(hash, g_hash, hash_len);
  index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, (unsigned int)(target_chain_len - 1));

  for (unsigned int i = (unsigned int)target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);
    do_hash(hash_type, plaintext, plaintext_len, hash, &hash_len);
    index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, i);
  }

  g_output[gid] = index;
}
