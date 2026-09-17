#include "shared.h"
#include "netntlmv1_7_functions.cl"


/* Specialized chain generation for the Net-NTLMv1 7-byte tables.
 *
 * This is the generation-side counterpart to precompute_netntlmv1_7_batch.cl.
 * Until now netntlmv1 generation fell through to the fully generic
 * crackalack.cl, which per chain step paid:
 *
 *   1. index_to_plaintext(): a 7-iteration loop of 64-bit / and %.  On NVIDIA a
 *      64-bit integer divide is emulated at ~70-100 instructions, so that alone
 *      was ~1000 instructions per step.  For a 7-byte key over the byte charset
 *      the plaintext IS the index -- pure shifts.
 *
 *   2. netntlmv1_hash() reading S-boxes from __constant.  Warp threads hit
 *      different addresses, which serializes on NVIDIA.  __local gives
 *      full-bandwidth parallel access, one copy per work group.
 *
 *   3. hash_to_index(): a runtime 64-bit modulo.  The space is exactly 2^56, so
 *      it is a mask.
 *
 * It also rebuilt the plaintext-space table per work item and dispatched the
 * hash on a runtime type.  None of that survives here.
 *
 * The challenge is permuted through DES_IP once per work item rather than once
 * per chain step, and is taken as an argument so the same kernel serves both
 * the 1122334455667788 tables and the KGS!@#$% (LM) tables.
 *
 * Argument layout is deliberately identical to crackalack.cl -- including the
 * arguments this kernel has no use for -- so the host binds both the same way.
 */
__kernel void crackalack_netntlmv1(
    __global unsigned int *unused_hash_type,
    __global char *unused_charset,
    __global unsigned int *unused_plaintext_len_min,
    __global unsigned int *unused_plaintext_len_max,
    __global unsigned int *g_reduction_offset,
    __global unsigned int *g_chain_len,
    __global unsigned long *g_indices,
    __global unsigned int *g_pos_start,
    __global unsigned char *g_challenge) {

  /* Shared-memory S-box arrays -- one copy per workgroup. */
  __local uint32_t l_SB1[64], l_SB2[64], l_SB3[64], l_SB4[64];
  __local uint32_t l_SB5[64], l_SB6[64], l_SB7[64], l_SB8[64];

  LOAD_LOCAL_SBOXES(get_local_id(0), get_local_size(0),
                    l_SB1, l_SB2, l_SB3, l_SB4,
                    l_SB5, l_SB6, l_SB7, l_SB8);

  unsigned int reduction_offset = *g_reduction_offset;
  unsigned int chain_len = *g_chain_len;
  unsigned int pos = *g_pos_start;
  unsigned long index = g_indices[get_global_id(0)];
  unsigned char plaintext[8];

  /* DES_IP(challenge) once, not once per step. */
  unsigned char challenge_local[8];
  for (int c = 0; c < 8; c++)
    challenge_local[c] = g_challenge[c];

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

  g_indices[get_global_id(0)] = index;
  return;
}
