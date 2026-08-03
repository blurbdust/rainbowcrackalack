#include "ntlm9_functions.cu"

extern "C" __global__ void test_hash_to_index_ntlm9(unsigned long long *g_hash, unsigned int *g_pos, unsigned long long *g_index) {

  *g_index = hash_to_index_ntlm9((unsigned long long)*g_hash, (unsigned int)*g_pos);

}
