#include "shared.h"
#include "netntlmv1_7_functions.cu"


/* Batched precomputation for the Net-NTLMv1 7-byte tables, the CUDA
 * counterpart of CL/precompute_netntlmv1_7_batch.cl.
 *
 * Two separate wins over the generic precompute_batch.cu, which is what this
 * workload used to fall through to:
 *
 *  1. The specialized chain walk.  The generic kernel gives every thread a
 *     256-byte charset array plus a plaintext-space table, and rebuilds that
 *     table per thread; the reduction and plaintext functions are also
 *     dispatched on a runtime hash type.  For a 7-byte Net-NTLMv1 key none of
 *     that is needed -- the plaintext IS the index, in 8 bytes of registers --
 *     and the DES S-boxes go in shared memory, one copy per block.
 *
 *  2. The hash axis.  Widening a dispatch along the *position* axis buys
 *     nothing, because the thread at position p walks (chain_len - p) steps and
 *     the chunk ends up running at the speed of its longest walk.  Every hash at
 *     a given position walks exactly the same number of steps, so widening along
 *     the *hash* axis adds parallelism with no divergence.
 *
 * Argument layout is deliberately identical to precompute_batch.cu (including
 * the parameters this kernel has no use for) so the host binds both the same
 * way.  cuLaunchKernel reads a pointer for every declared parameter, so the list
 * must line up exactly.  Positions stay strided across devices as the generic
 * kernels do, so multi-GPU collation on the host is unchanged. */
extern "C" __global__ void precompute_netntlmv1_7_batch(
    unsigned int *unused_hash_type,
    unsigned char *g_hashes,
    unsigned int *g_hash_len,
    unsigned int *g_num_hashes,
    char *unused_charset,
    unsigned int *unused_plaintext_len_min,
    unsigned int *unused_plaintext_len_max,
    unsigned int *g_table_index,
    unsigned long long *g_chain_len,
    unsigned int *g_device_num,
    unsigned int *g_total_devices,
    unsigned int *g_chunk_positions,
    unsigned int *g_pos_start,
    unsigned int *g_output_len,
    unsigned long long *g_output,
    unsigned char *g_challenge) {

  /* Shared-memory S-box arrays -- one copy per block. */
  __shared__ uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  __shared__ uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(threadIdx.x, blockDim.x,
                     l_SB1, l_SB2, l_SB3, l_SB4,
                     l_SB5, l_SB6, l_SB7, l_SB8);

  unsigned int chunk_positions = *g_chunk_positions;
  unsigned int gid = (blockIdx.x * blockDim.x + threadIdx.x);
  unsigned int hash_idx = gid / chunk_positions;
  unsigned int local_pos = gid % chunk_positions;

  if (hash_idx >= *g_num_hashes)
    return;

  /* Index into this device's slice of the output. */
  unsigned int k = *g_pos_start + local_pos;
  unsigned int output_len = *g_output_len;
  if (k >= output_len)
    return;

  unsigned long long out_idx = ((unsigned long long)hash_idx * (unsigned long long)output_len) + k;

  /* Computed in signed 64-bit so an underflow stays negative and is caught
   * below, rather than wrapping to a huge positive length. */
  long long chain_len_ll = (long long)(*g_chain_len);
  long long target_chain_len = (chain_len_ll - (long long)(*g_device_num)) -
      ((long long)k * (long long)(*g_total_devices)) - 1;

  if (target_chain_len < 1) {
    g_output[out_idx] = 0;
    return;
  }

  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)chain_len_ll;

  unsigned char *hash = g_hashes + ((unsigned long long)hash_idx * (*g_hash_len));
  unsigned char plaintext[8];
  unsigned long long index = hash_char_to_index_netntlmv1_7(hash, reduction_offset, (unsigned int)(target_chain_len - 1));

  unsigned char challenge_local[8];
  for (int _c = 0; _c < 8; _c++) challenge_local[_c] = g_challenge[_c];

  for (unsigned long long i = (unsigned long long)target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext_netntlmv1_7(index, plaintext);
    index = hash_to_index_netntlmv1_7(hash_netntlmv1_7_fast(plaintext, challenge_local, l_SB1, l_SB2, l_SB3, l_SB4, l_SB5, l_SB6, l_SB7, l_SB8), reduction_offset, (unsigned int)i);
  }

  g_output[out_idx] = index;
}
