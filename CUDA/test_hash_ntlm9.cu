#include "ntlm9_functions.cu"

extern "C" __global__ void test_hash_ntlm9(char *g_input, unsigned long long *g_output) {
  unsigned char input[9];

  for (int i = 0; i < 9; i++)
    input[i] = g_input[i];

  *g_output = hash_ntlm9(input);
  return;
}
