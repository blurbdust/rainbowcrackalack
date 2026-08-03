#include "ntlm9_functions.cu"
#include "shared.h"

extern "C" __global__ void test_index_to_plaintext_ntlm9(unsigned long long *g_index, unsigned char *g_plaintext) {
  unsigned char plaintext[9];

  index_to_plaintext_ntlm9((unsigned long long)*g_index, plaintext);

  for (int i = 0; i < 9; i++)
    g_plaintext[i] = plaintext[i];

  return;
}
