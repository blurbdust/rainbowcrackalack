#include <metal_stdlib>
using namespace metal;

#include "ntlm8_functions.metal"


kernel void false_alarm_check_ntlm8(
    device unsigned int *unused1 [[buffer(0)]],
    device char *unused2 [[buffer(1)]],
    device unsigned int *unused3 [[buffer(2)]],
    device unsigned int *unused4 [[buffer(3)]],
    device unsigned int *unused5 [[buffer(4)]],
    device ulong *unused6 [[buffer(5)]],
    device ulong *unused7 [[buffer(6)]],
    device unsigned int *g_device_num [[buffer(7)]],
    device unsigned int *g_total_devices [[buffer(8)]],
    device unsigned int *g_num_start_indices [[buffer(9)]],
    device ulong *g_start_indices [[buffer(10)]],
    device unsigned int *g_start_index_positions [[buffer(11)]],
    device ulong *g_hash_base_indices [[buffer(12)]],
    device unsigned int *g_exec_block_scaler [[buffer(13)]],
    device ulong *g_plaintext_indices [[buffer(14)]],
    uint gid [[thread_position_in_grid]]) {

  int index_pos = (*g_num_start_indices - *g_device_num) - ((gid + *g_exec_block_scaler) * *g_total_devices) - 1;
  if (index_pos < 0)
    return;

  unsigned char plaintext[8];
  ulong index = g_start_indices[index_pos], previous_index = 0;
  ulong hash_base_index = g_hash_base_indices[index_pos] % 6634204312890625UL;
  unsigned int endpoint = g_start_index_positions[index_pos];

  for (unsigned int pos = 0; pos < endpoint + 1; pos++) {
    index_to_plaintext_ntlm8(index, charset, plaintext);

    previous_index = index;
    index = hash_to_index_ntlm8(hash_ntlm8(plaintext), pos);

    if ((index == (hash_base_index + pos)) || (index == (hash_base_index + pos - 6634204312890625UL))) {
      g_plaintext_indices[index_pos] = previous_index;
      return;
    }
  }
}
