#include "netntlmv1_7_functions.cu"


/* Argument layout matches this fork's generic false_alarm_check kernel exactly
 * (bandrel's has an extra charset_len at index 1, which shifts every later slot
 * by one), plus the challenge appended at the end.  The host therefore binds
 * 0..14 identically for both kernels and adds 15 only for this one. */
extern "C" __global__ void false_alarm_check_netntlmv1_7(
    unsigned int *unused_hash_type,
    char *unused_charset,
    unsigned int *unused_plaintext_len_min,
    unsigned int *unused_plaintext_len_max,
    unsigned int *g_reduction_offset,
    unsigned long long *unused_plaintext_space_total,
    unsigned long long *unused_pspace_table,
    unsigned int *g_device_num,
    unsigned int *g_total_devices,
    unsigned int *g_num_start_indices,
    unsigned long long *g_start_indices,
    unsigned int *g_start_index_positions,
    unsigned long long *g_hash_base_indices,
    unsigned int *g_exec_block_scaler,
    unsigned long long *g_plaintext_indices,
    unsigned char *g_challenge) {

  /* Shared-memory S-box arrays -- one copy per workgroup. */
  __shared__ uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  __shared__ uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(threadIdx.x, blockDim.x,
                     l_SB1, l_SB2, l_SB3, l_SB4,
                     l_SB5, l_SB6, l_SB7, l_SB8);

  int index_pos = (*g_num_start_indices - *g_device_num) - (((blockIdx.x * blockDim.x + threadIdx.x) + *g_exec_block_scaler) * *g_total_devices) - 1;
  if (index_pos < 0)
    return;

  unsigned int reduction_offset = *g_reduction_offset;
  unsigned char plaintext[8];
  unsigned long long index = g_start_indices[index_pos], previous_index = 0;
  unsigned long long hash_base_index = g_hash_base_indices[index_pos] & 0x00FFFFFFFFFFFFFFULL;
  unsigned int endpoint = g_start_index_positions[index_pos];

  /* Challenge initial permutation is loop-invariant: compute once. */
  uint32_t cx, cy;
  netntlmv1_challenge_to_ip(g_challenge, &cx, &cy);

  for (unsigned int pos = 0; pos < endpoint + 1; pos++) {
    index_to_plaintext_netntlmv1_7(index, plaintext);

    previous_index = index;
    index = hash_to_index_netntlmv1_7(hash_netntlmv1_7_fast_ip(plaintext, cx, cy, l_SB1, l_SB2, l_SB3, l_SB4, l_SB5, l_SB6, l_SB7, l_SB8), reduction_offset, pos);

    if ((index == (hash_base_index + pos)) || (index == (hash_base_index + pos - 72057594037927936ULL))) {
      g_plaintext_indices[index_pos] = previous_index;
      return;
    }
  }
}
