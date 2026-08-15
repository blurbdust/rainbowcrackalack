#include "rt.cl"
/*#include "string.cl"*/

__kernel void test_hash(
    __global unsigned int *g_alg,
    __global char *g_input,
    __global unsigned int *g_input_len,
    __global unsigned char *g_output,
    __global unsigned int *g_output_len
    , __global unsigned char *g_debug) {

  unsigned int alg = *g_alg;
  unsigned char input[MAX_PLAINTEXT_LEN];
  unsigned char output[MAX_HASH_OUTPUT_LEN];
  unsigned int input_len = *g_input_len;
  /* Deliberately NOT initialised to 0.  do_hash() writes the length through this
   * pointer, but with a zero initialiser some OpenCL implementations (Apple's,
   * and per run_regression.sh the one this project baselined on) constant-folds
   * the 0 through the inlined do_hash and drops its store, so the kernel reports
   * a zero-length hash and the empty-plaintext vector fails.  A sentinel the
   * compiler cannot assume defeats that; do_hash overwrites it either way.
   * CUDA and Metal are unaffected. */
  unsigned int output_len = 0xFFFFFFFF;

  input[0] = 0;
  for (int i = 0; i < input_len; i++)
    input[i] = g_input[i];

  do_hash(alg, input, input_len, output, &output_len /*, g_debug*/);

  *g_output_len = output_len;
  for (int i = 0; i < output_len; i++)
    g_output[i] = output[i];

  return;
}
