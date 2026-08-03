#include <metal_stdlib>
using namespace metal;

#include "ntlm9_functions.metal"


/* 8-argument layout matching CL/crackalack_ntlm9.cl and the host bindings in
 * crackalack_gen.c / crackalack_unit_tests.c: five leading slots the kernel
 * ignores (host binds hash_type/charset/etc. there), then g_chain_len at
 * buffer(5), the in/out index array at buffer(6), and g_pos_start at buffer(7).
 * (The upstream Metal kernel carried an extra interior arg that shifted
 * chain_len to buffer(6); with the trimmed host that made *g_chain_len read the
 * wrong slot and the loop condition pos < (*g_chain_len - 1) underflowed into a
 * ~4-billion-iteration hang.) */
kernel void crackalack_ntlm9(
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
