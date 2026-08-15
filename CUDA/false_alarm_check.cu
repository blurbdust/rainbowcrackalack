#include "rt.cu"
#include "string.cu"


/* Generic false-alarm check, the CUDA counterpart of CL/false_alarm_check.cl.
 *
 * Parameter order matches the arg indices bound in the false-alarm host thread
 * (crackalack_lookup.c), which binds 0..14.  cuLaunchKernel reads a pointer for
 * every declared parameter, so the list must line up exactly. */
extern "C" __global__ void false_alarm_check(
    unsigned int *g_hash_type,
    char *g_charset,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_reduction_offset,
    unsigned long long *g_plaintext_space_total,
    unsigned long long *g_plaintext_space_up_to_index,
    unsigned int *g_device_num,
    unsigned int *g_total_devices,
    unsigned int *g_num_start_indices,
    unsigned long long *g_start_indices,
    unsigned int *g_start_index_positions,
    unsigned long long *g_hash_base_indices,
    unsigned int *g_exec_block_scaler,
    unsigned long long *g_plaintext_indices) {

  unsigned int gid = (blockIdx.x * blockDim.x + threadIdx.x);

  int index_pos = (int)((*g_num_start_indices - *g_device_num) -
      ((gid + *g_exec_block_scaler) * *g_total_devices) - 1);
  if (index_pos < 0)
    return;

  char charset[MAX_CHARSET_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned int plaintext_len;
  unsigned int hash_len;

  /* g_strncpy copies all n bytes and does not stop at a NUL, which matters:
   * the 'byte' charset begins with 0x00, so stopping would leave charset_len
   * at 0 and collapse the plaintext space to zero. */
  unsigned int charset_len = g_copy_charset(charset, g_charset, MAX_CHARSET_LEN);
  unsigned int hash_type = *g_hash_type;
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = *g_reduction_offset;
  unsigned long long plaintext_space_total = *g_plaintext_space_total;
  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN + 1];

  copy_plaintext_space_up_to_index(plaintext_space_up_to_index, g_plaintext_space_up_to_index, plaintext_len_max);

  unsigned long long index = g_start_indices[index_pos], previous_index = 0;
  unsigned long long hash_base_index = g_hash_base_indices[index_pos] % plaintext_space_total;
  unsigned int endpoint = g_start_index_positions[index_pos];

  for (unsigned int pos = 0; pos < endpoint + 1; pos++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);
    do_hash(hash_type, plaintext, plaintext_len, hash, &hash_len);

    previous_index = index;
    index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, pos);

    if ((index == (hash_base_index + pos)) || (index == (hash_base_index + pos - plaintext_space_total))) {
      g_plaintext_indices[index_pos] = previous_index;
      return;
    }
  }
}
