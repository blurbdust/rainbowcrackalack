#include "ntlm9_functions.cu"

/* CUDA unit-test kernel for the NTLM9 chain path.
 *
 * WHY THIS EXISTS (and is CUDA-only): crackalack_unit_tests.c's
 * gpu_test_chain_ntlm9() binds an 8-argument list (five unused padding args,
 * then g_chain_len, g_indices, g_pos_start) that matches the 8-parameter
 * OpenCL production kernel CL/crackalack_ntlm9.cl.  The CUDA production kernel
 * CUDA/crackalack_ntlm9.cu (PR-B) deliberately carries a WIDER 14-parameter
 * signature (an extra reduction arg + trailing lookup args), so binding the
 * test's 8 args against it shifts g_chain_len onto the indices pointer:
 * *g_chain_len is read as a start index (e.g. 0), and the unsigned
 * "pos < (*g_chain_len - 1)" loop underflows to ~4 billion iterations
 * (100% GPU, never returns).  Rather than perturb the production kernel or
 * the OpenCL fingerprint, the unit test loads THIS kernel under CUDA only.
 * Its parameter list mirrors the host's 8-arg binding exactly. */
extern "C" __global__ void test_chain_ntlm9(
    unsigned int *unused1,
    char *unused2,
    unsigned int *unused3,
    unsigned int *unused4,
    unsigned int *unused5,
    unsigned int *g_chain_len,
    unsigned long long *g_indices,
    unsigned int *g_pos_start) {
  unsigned long long index = g_indices[blockIdx.x * blockDim.x + threadIdx.x];
  unsigned char plaintext[9];

  for (unsigned int pos = *g_pos_start; pos < (*g_chain_len - 1); pos++) {
    index_to_plaintext_ntlm9(index, plaintext);
    index = hash_to_index_ntlm9(hash_ntlm9(plaintext), pos);
  }

  g_indices[blockIdx.x * blockDim.x + threadIdx.x] = index;
  return;
}
