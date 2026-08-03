#include <metal_stdlib>
using namespace metal;

#include "ntlm9_functions.metal"
#include "shared.h"

kernel void test_index_to_plaintext_ntlm9(
    device ulong *g_index [[buffer(0)]],
    device unsigned char *g_plaintext [[buffer(1)]],
    uint gid [[thread_position_in_grid]]) {
  unsigned char plaintext[9];

  index_to_plaintext_ntlm9((ulong)*g_index, plaintext);

  for (int i = 0; i < 9; i++)
    g_plaintext[i] = plaintext[i];

  return;
}
