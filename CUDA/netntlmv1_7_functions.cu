#include "netntlmv1_fast.cu"


/* For the byte charset (256 values, 0x00-0xFF), each byte of the index IS a
 * plaintext byte.  No division needed -- just shift and mask. */
__device__ inline void index_to_plaintext_netntlmv1_7(unsigned long long index, unsigned char *plaintext) {
  plaintext[6] = (unsigned char)(index & 0xFF);
  plaintext[5] = (unsigned char)((index >> 8) & 0xFF);
  plaintext[4] = (unsigned char)((index >> 16) & 0xFF);
  plaintext[3] = (unsigned char)((index >> 24) & 0xFF);
  plaintext[2] = (unsigned char)((index >> 32) & 0xFF);
  plaintext[1] = (unsigned char)((index >> 40) & 0xFF);
  plaintext[0] = (unsigned char)((index >> 48) & 0xFF);
}


__device__ inline unsigned long long hash_netntlmv1_7(unsigned char *plaintext, unsigned char *challenge) {
  uint32_t SK[32];
  unsigned char output[8];

  plaintext[7] = '\0';
  netntlmv1_hash(SK, plaintext, output, challenge);

  /* Pack in little-endian order to match the generic hash_to_index byte
   * assembly: ret = hash[7]<<56 | hash[6]<<48 | ... | hash[0]. */
  return ((unsigned long long)output[7] << 56) |
         ((unsigned long long)output[6] << 48) |
         ((unsigned long long)output[5] << 40) |
         ((unsigned long long)output[4] << 32) |
         ((unsigned long long)output[3] << 24) |
         ((unsigned long long)output[2] << 16) |
         ((unsigned long long)output[1] << 8) |
         ((unsigned long long)output[0]);
}


/* Fast variant using __shared__ S-boxes with a pre-permuted challenge
 * (cx/cy = DES_IP(challenge); see netntlmv1_challenge_to_ip).  Chain loops
 * compute cx/cy once and call this per step. */
__device__ inline unsigned long long hash_netntlmv1_7_fast_ip(
    unsigned char *plaintext,
    uint32_t cx, uint32_t cy,
    uint32_t *l_SB1, uint32_t *l_SB2,
    uint32_t *l_SB3, uint32_t *l_SB4,
    uint32_t *l_SB5, uint32_t *l_SB6,
    uint32_t *l_SB7, uint32_t *l_SB8) {
  uint32_t SK[32];
  unsigned char output[8];

  plaintext[7] = '\0';
  netntlmv1_hash_fast_ip(SK, plaintext, output, cx, cy,
                          l_SB1, l_SB2, l_SB3, l_SB4,
                          l_SB5, l_SB6, l_SB7, l_SB8);

  return ((unsigned long long)output[7] << 56) |
         ((unsigned long long)output[6] << 48) |
         ((unsigned long long)output[5] << 40) |
         ((unsigned long long)output[4] << 32) |
         ((unsigned long long)output[3] << 24) |
         ((unsigned long long)output[2] << 16) |
         ((unsigned long long)output[1] << 8) |
         ((unsigned long long)output[0]);
}

/* Fast variant using __shared__ S-boxes for optimized kernels. */
__device__ inline unsigned long long hash_netntlmv1_7_fast(
    unsigned char *plaintext,
    unsigned char *challenge,
    uint32_t *l_SB1, uint32_t *l_SB2,
    uint32_t *l_SB3, uint32_t *l_SB4,
    uint32_t *l_SB5, uint32_t *l_SB6,
    uint32_t *l_SB7, uint32_t *l_SB8) {
  uint32_t cx, cy;
  netntlmv1_challenge_to_ip(challenge, &cx, &cy);
  return hash_netntlmv1_7_fast_ip(plaintext, cx, cy,
                                  l_SB1, l_SB2, l_SB3, l_SB4,
                                  l_SB5, l_SB6, l_SB7, l_SB8);
}


/* Plaintext space = 256^7 = 2^56, so modulo is a bitwise AND.
 * reduction_offset = table_index * 65536. */
__device__ inline unsigned long long hash_to_index_netntlmv1_7(unsigned long long hash, unsigned int reduction_offset, unsigned int pos) {
  return (hash + reduction_offset + pos) & 0x00FFFFFFFFFFFFFFULL;
}


__device__ inline unsigned long long hash_char_to_index_netntlmv1_7(unsigned char *hash_value, unsigned int reduction_offset, unsigned int pos) {
  /* Little-endian assembly, matching the generic hash_to_index in rt.cu. */
  unsigned long long ret = hash_value[7];
  ret <<= 8;
  ret |= hash_value[6];
  ret <<= 8;
  ret |= hash_value[5];
  ret <<= 8;
  ret |= hash_value[4];
  ret <<= 8;
  ret |= hash_value[3];
  ret <<= 8;
  ret |= hash_value[2];
  ret <<= 8;
  ret |= hash_value[1];
  ret <<= 8;
  ret |= hash_value[0];

  return (ret + reduction_offset + pos) & 0x00FFFFFFFFFFFFFFULL;
}
