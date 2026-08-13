#include "netntlmv1_7_functions.cl"


/* Argument layout matches this fork's generic false_alarm_check kernel exactly
 * (bandrel's has an extra charset_len at index 1, which shifts every later slot
 * by one), plus the challenge appended at the end.  The host therefore binds
 * 0..14 identically for both kernels and adds 15 only for this one. */
__kernel void false_alarm_check_netntlmv1_7(
    __global unsigned int *unused_hash_type,
    __global char *unused_charset,
    __global unsigned int *unused_plaintext_len_min,
    __global unsigned int *unused_plaintext_len_max,
    __global unsigned int *g_reduction_offset,
    __global unsigned long *unused_plaintext_space_total,
    __global unsigned long *unused_pspace_table,
    __global unsigned int *g_device_num,
    __global unsigned int *g_total_devices,
    __global unsigned int *g_num_start_indices,
    __global unsigned long *g_start_indices,
    __global unsigned int *g_start_index_positions,
    __global unsigned long *g_hash_base_indices,
    __global unsigned int *g_exec_block_scaler,
    __global unsigned long *g_plaintext_indices,
    __global unsigned char *g_challenge) {

  /* Shared-memory S-box arrays -- one copy per workgroup. */
  __local uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  __local uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(get_local_id(0), get_local_size(0),
                     l_SB1, l_SB2, l_SB3, l_SB4,
                     l_SB5, l_SB6, l_SB7, l_SB8);

  int index_pos = (*g_num_start_indices - *g_device_num) - ((get_global_id(0) + *g_exec_block_scaler) * *g_total_devices) - 1;
  if (index_pos < 0)
    return;

  unsigned int reduction_offset = *g_reduction_offset;
  unsigned char plaintext[8];
  unsigned long index = g_start_indices[index_pos], previous_index = 0;
  unsigned long hash_base_index = g_hash_base_indices[index_pos] & 0x00FFFFFFFFFFFFFFUL;
  unsigned int endpoint = g_start_index_positions[index_pos];

  unsigned char challenge_local[8];
  for (int _c = 0; _c < 8; _c++) challenge_local[_c] = g_challenge[_c];

  for (unsigned int pos = 0; pos < endpoint + 1; pos++) {
    index_to_plaintext_netntlmv1_7(index, plaintext);

    previous_index = index;
    index = hash_to_index_netntlmv1_7(hash_netntlmv1_7_fast(plaintext, challenge_local, l_SB1, l_SB2, l_SB3, l_SB4, l_SB5, l_SB6, l_SB7, l_SB8), reduction_offset, pos);

    if ((index == (hash_base_index + pos)) || (index == (hash_base_index + pos - 72057594037927936UL))) {
      g_plaintext_indices[index_pos] = previous_index;
      return;
    }
  }
}
