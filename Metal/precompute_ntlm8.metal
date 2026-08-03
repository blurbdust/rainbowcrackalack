#include <metal_stdlib>
using namespace metal;

#include "ntlm8_functions.metal"


kernel void precompute_ntlm8(
    device unsigned int *unused1 [[buffer(0)]],
    device unsigned char *g_hash [[buffer(1)]],
    device unsigned int *unused2 [[buffer(2)]],
    device char *unused3 [[buffer(3)]],
    device unsigned int *unused4 [[buffer(4)]],
    device unsigned int *unused5 [[buffer(5)]],
    device unsigned int *unused6 [[buffer(6)]],
    device ulong *g_chain_len [[buffer(7)]],
    device unsigned int *g_device_num [[buffer(8)]],
    device unsigned int *g_total_devices [[buffer(9)]],
    device unsigned int *g_exec_block_scaler [[buffer(10)]],
    device ulong *g_output [[buffer(11)]],
    uint gid [[thread_position_in_grid]]) {

  /* Honor the host's chain_len (buffer 7) instead of a hardcoded constant, so
   * lookups against tables of any chain length crack correctly.  (Metal `long`
   * is 32-bit; chain_len fits an unsigned int for any real table.) */
  unsigned int chain_len = (unsigned int)(*g_chain_len);
  long target_chain_len = (chain_len - *g_device_num) - ((gid + *g_exec_block_scaler) * *g_total_devices) - 1;

  if (target_chain_len < 1) {
    g_output[gid] = 0;
    return;
  }

  unsigned char plaintext[8];
  ulong index = hash_char_to_index_ntlm8(g_hash, target_chain_len - 1);

  for(unsigned int i = target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext_ntlm8(index, charset, plaintext);
    index = hash_to_index_ntlm8(hash_ntlm8(plaintext), i);
  }

  g_output[gid] = index;
}
