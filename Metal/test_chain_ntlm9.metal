#include <metal_stdlib>
using namespace metal;

#include "ntlm9_functions.metal"

/* Wide-ABI test kernel: the crackalack_unit_tests host (gpu_test_chain_ntlm9)
 * drives the *production* crackalack_ntlm9 argument layout -- five leading
 * unused slots, then g_chain_len at buffer(5), the in/out index array at
 * buffer(6), and g_pos_start at buffer(7).  This mirrors CL/crackalack_ntlm9.cl
 * exactly so chain_len lands in the right slot (binding it anywhere else makes
 * *g_chain_len read 0, and the loop condition pos < (0 - 1) underflows into a
 * ~4-billion-iteration hang). */
kernel void test_chain_ntlm9(
    device unsigned int *unused1 [[buffer(0)]],
    device char *unused2 [[buffer(1)]],
    device unsigned int *unused3 [[buffer(2)]],
    device unsigned int *unused4 [[buffer(3)]],
    device unsigned int *unused5 [[buffer(4)]],
    device unsigned int *g_chain_len [[buffer(5)]],
    device ulong *g_indices [[buffer(6)]],
    device unsigned int *g_pos_start [[buffer(7)]],
    uint gid [[thread_position_in_grid]]) {

  ulong index = g_indices[gid];
  unsigned char plaintext[9];


  for (unsigned int pos = *g_pos_start; pos < (*g_chain_len - 1); pos++) {
    index_to_plaintext_ntlm9(index, plaintext);
    index = hash_to_index_ntlm9(hash_ntlm9(plaintext), pos);
  }

  g_indices[gid] = index;
  return;
}
