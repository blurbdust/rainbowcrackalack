#include <metal_stdlib>
using namespace metal;

#include "ntlm9_functions.metal"

kernel void test_hash_ntlm9(
    device char *g_input [[buffer(0)]],
    device ulong *g_output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]) {
  unsigned char input[9];

  for (int i = 0; i < 9; i++)
    input[i] = g_input[i];

  *g_output = hash_ntlm9(input);
  return;
}
