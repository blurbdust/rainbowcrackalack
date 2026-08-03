#include <metal_stdlib>
using namespace metal;

#include "rt.metal"
/* string.metal is included via rt.metal */

kernel void test_hash(
    device unsigned int *g_alg [[buffer(0)]],
    device char *g_input [[buffer(1)]],
    device unsigned int *g_input_len [[buffer(2)]],
    device unsigned char *g_output [[buffer(3)]],
    device unsigned int *g_output_len [[buffer(4)]],
    device unsigned char *g_debug [[buffer(5)]],
    uint gid [[thread_position_in_grid]]) {

  unsigned int alg = *g_alg;
  unsigned char input[MAX_PLAINTEXT_LEN];
  unsigned char output[MAX_HASH_OUTPUT_LEN];
  unsigned int input_len = *g_input_len;
  unsigned int output_len = 0;

  input[0] = 0;
  for (int i = 0; i < input_len; i++)
    input[i] = g_input[i];

  do_hash(alg, input, input_len, output, &output_len);

  *g_output_len = output_len;
  for (int i = 0; i < output_len; i++)
    g_output[i] = output[i];

  return;
}
