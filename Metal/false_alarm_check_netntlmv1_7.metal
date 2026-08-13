#include <metal_stdlib>
using namespace metal;

#include "netntlmv1_7_functions.metal"


/* Specialized false alarm check for the Net-NTLMv1 7-byte tables, the Metal
 * counterpart of CL/false_alarm_check_netntlmv1_7.cl.
 *
 * Same chain walk as the generic false_alarm_check, minus the per-thread charset
 * array and plaintext space table, and with the DES S-boxes in threadgroup
 * memory.
 *
 * Buffer indices match this fork's generic false_alarm_check kernel exactly
 * (including the ones this kernel has no use for) so the host binds 0..14
 * identically for both, and adds the challenge at 15 only for this one.
 *
 * The S-box load and its barrier run before the early return below, because
 * every thread in a threadgroup has to reach a threadgroup barrier and this
 * backend dispatches non-uniform groups. */
kernel void false_alarm_check_netntlmv1_7(
    device unsigned int *unused_hash_type [[buffer(0)]],
    device char *unused_charset [[buffer(1)]],
    device unsigned int *unused_plaintext_len_min [[buffer(2)]],
    device unsigned int *unused_plaintext_len_max [[buffer(3)]],
    device unsigned int *g_reduction_offset [[buffer(4)]],
    device ulong *unused_plaintext_space_total [[buffer(5)]],
    device ulong *unused_pspace_table [[buffer(6)]],
    device unsigned int *g_device_num [[buffer(7)]],
    device unsigned int *g_total_devices [[buffer(8)]],
    device unsigned int *g_num_start_indices [[buffer(9)]],
    device ulong *g_start_indices [[buffer(10)]],
    device unsigned int *g_start_index_positions [[buffer(11)]],
    device ulong *g_hash_base_indices [[buffer(12)]],
    device unsigned int *g_exec_block_scaler [[buffer(13)]],
    device ulong *g_plaintext_indices [[buffer(14)]],
    device unsigned char *g_challenge [[buffer(15)]],
    uint gid [[thread_position_in_grid]],
    uint lid [[thread_position_in_threadgroup]],
    uint lsz [[threads_per_threadgroup]]) {

  /* Threadgroup S-box arrays, one copy per group. */
  threadgroup uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  threadgroup uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(lid, lsz,
                    l_SB1, l_SB2, l_SB3, l_SB4,
                    l_SB5, l_SB6, l_SB7, l_SB8);

  int index_pos = (int)(*g_num_start_indices) - (int)(*g_device_num) -
      (int)((gid + *g_exec_block_scaler) * (*g_total_devices)) - 1;
  if (index_pos < 0)
    return;

  unsigned int reduction_offset = *g_reduction_offset;
  unsigned char plaintext[8];
  ulong index = g_start_indices[index_pos], previous_index = 0;
  ulong hash_base_index = g_hash_base_indices[index_pos] & 0x00FFFFFFFFFFFFFFUL;
  unsigned int endpoint = g_start_index_positions[index_pos];

  unsigned char challenge_local[8];
  for (int _c = 0; _c < 8; _c++) challenge_local[_c] = g_challenge[_c];

  /* The challenge permutation is loop invariant, so do it once. */
  uint32_t cx, cy;
  netntlmv1_challenge_to_ip(challenge_local, &cx, &cy);

  for (unsigned int pos = 0; pos < endpoint + 1; pos++) {
    index_to_plaintext_netntlmv1_7(index, plaintext);

    previous_index = index;
    index = hash_to_index_netntlmv1_7(
        hash_netntlmv1_7_fast_ip(plaintext, cx, cy,
                                 l_SB1, l_SB2, l_SB3, l_SB4,
                                 l_SB5, l_SB6, l_SB7, l_SB8),
        reduction_offset, pos);

    if ((index == (hash_base_index + pos)) || (index == (hash_base_index + pos - 72057594037927936UL))) {
      g_plaintext_indices[index_pos] = previous_index;
      return;
    }
  }
}
