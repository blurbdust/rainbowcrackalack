#include <metal_stdlib>
using namespace metal;

#include "ntlm8_functions.metal"


/* 8-argument layout matching CL/crackalack_ntlm8.cl and the trimmed host
 * bindings: g_indices (in/out) at buffer(6); all other slots are ignored.
 * ntlm8 uses a fixed chain length (421999), so it reads no chain_len/pos_start.
 * (The upstream Metal kernel added interior chain_len/pos_start args that
 * shifted g_indices to buffer(7); with the trimmed host that corrupted the
 * index array and the reduction loop.) */
kernel void crackalack_ntlm8(
    device unsigned int *unused1 [[buffer(0)]],
    device char *unused2 [[buffer(1)]],
    device unsigned int *unused3 [[buffer(2)]],
    device unsigned int *unused4 [[buffer(3)]],
    device unsigned int *unused5 [[buffer(4)]],
    device unsigned int *unused6 [[buffer(5)]],
    device ulong *g_indices [[buffer(6)]],
    device unsigned int *unused7 [[buffer(7)]],
    uint gid [[thread_position_in_grid]]) {
  ulong index = g_indices[gid];
  unsigned char plaintext[8];


  for (unsigned int pos = 0; pos < 421999; pos++) {
    index_to_plaintext_ntlm8(index, charset, plaintext);
    index = hash_to_index_ntlm8(hash_ntlm8(plaintext), pos);
  }

  g_indices[gid] = index;
  return;
}
