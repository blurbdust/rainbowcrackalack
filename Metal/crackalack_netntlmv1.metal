/* Specialized chain generation for the Net-NTLMv1 7-byte tables.
 *
 * Generation-side counterpart to precompute_netntlmv1_7_batch.  Until now
 * netntlmv1 generation fell through to the fully generic kernel, which per
 * chain step paid:
 *
 *   1. index_to_plaintext(): a 7-iteration loop of 64-bit / and %.  A 64-bit
 *      integer divide is emulated at ~70-100 instructions on NVIDIA, so that
 *      alone was ~1000 instructions per step.  For a 7-byte key over the byte
 *      charset the plaintext IS the index -- pure shifts.
 *
 *   2. The DES S-boxes read from constant memory.  Threads in a warp hit
 *      different addresses, which serializes; shared memory gives
 *      full-bandwidth parallel access, one copy per block.
 *
 *   3. hash_to_index(): a runtime 64-bit modulo.  The space is exactly 2^56,
 *      so it is a mask.
 *
 * The challenge goes through DES_IP once per thread rather than once per chain
 * step, and is an argument, so the same kernel serves both the
 * 1122334455667788 tables and the KGS!@#$% (LM) tables.
 *
 * Argument layout is deliberately identical to the generic generation kernel
 * -- including the parameters this kernel has no use for -- so the host binds
 * both the same way.
 */
#include <metal_stdlib>
using namespace metal;

#include "shared.h"
#include "netntlmv1_7_functions.metal"

kernel void crackalack_netntlmv1(
    device unsigned int *unused_hash_type [[buffer(0)]],
    device char *unused_charset [[buffer(1)]],
    device unsigned int *unused_plaintext_len_min [[buffer(2)]],
    device unsigned int *unused_plaintext_len_max [[buffer(3)]],
    device unsigned int *g_reduction_offset [[buffer(4)]],
    device unsigned int *g_chain_len [[buffer(5)]],
    device ulong *g_indices [[buffer(6)]],
    device unsigned int *g_pos_start [[buffer(7)]],
    device unsigned char *g_challenge [[buffer(8)]],
    uint gid [[thread_position_in_grid]],
    uint lid [[thread_position_in_threadgroup]],
    uint lsz [[threads_per_threadgroup]]) {

  threadgroup uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  threadgroup uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(lid, lsz,
                    l_SB1, l_SB2, l_SB3, l_SB4,
                    l_SB5, l_SB6, l_SB7, l_SB8);

  unsigned int reduction_offset = *g_reduction_offset;
  unsigned int chain_len = *g_chain_len;
  unsigned int pos = *g_pos_start;
  ulong index = g_indices[gid];
  unsigned char plaintext[8];

  unsigned char challenge_local[8];
  for (int _c = 0; _c < 8; _c++) challenge_local[_c] = g_challenge[_c];

  uint32_t cx, cy;
  netntlmv1_challenge_to_ip(challenge_local, &cx, &cy);

  for (; pos < chain_len - 1; pos++) {
    index_to_plaintext_netntlmv1_7(index, plaintext);
    index = hash_to_index_netntlmv1_7(
        hash_netntlmv1_7_fast_ip(plaintext, cx, cy,
                                 l_SB1, l_SB2, l_SB3, l_SB4,
                                 l_SB5, l_SB6, l_SB7, l_SB8),
        reduction_offset, pos);
  }

  g_indices[gid] = index;
}
