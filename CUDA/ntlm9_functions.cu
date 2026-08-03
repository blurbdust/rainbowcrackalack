#include "ntlm.cu"
#include "redux_functions_mul32.cu"

__device__ inline void index_to_plaintext_ntlm9(unsigned long long index, unsigned char *plaintext) {
  unsigned long long lo5;
  unsigned int       hi4;
  unsigned int       lo3;
  unsigned int       hi2;
  unsigned int       lo2;

  reduce_9chars(index, &hi4, &lo5);
  reduce_4chars(hi4, &hi2, &lo2);
  reduce_2chars(hi2, plaintext + 0, plaintext + 1);
  reduce_2chars(lo2, plaintext + 2, plaintext + 3);
  reduce_5chars(lo5, &hi2, &lo3);
  reduce_2chars(hi2, plaintext + 4, plaintext + 5);
  reduce_3chars(lo3, plaintext + 6, &lo2);
  reduce_2chars(lo2, plaintext + 7, plaintext + 8);
}

__device__ inline unsigned long long hash_ntlm9(unsigned char *plaintext) {
  unsigned int key[16] = {0};
  unsigned int output[4];

  for (int i = 0; i < 4; i++)
    key[i] = plaintext[i * 2] | (plaintext[(i * 2) + 1] << 16);

  key[4] = plaintext[8] | 0x800000;
  key[14] = 0x90;

  md4_encrypt(output, key);

  return ((unsigned long long)output[1]) << 32 | (unsigned long long)output[0];
}

__device__ inline unsigned long long hash_to_index_ntlm9(unsigned long long hash, unsigned int pos) {
  // Divide by multiply

  // floor(2 * 2**64 / 95**9) = 58
  // 29 (58/2) or 58

  unsigned int tmp;

  hash += pos;

  tmp   = ((hash >> 58) * 29) >> 6; // just right

  hash -= 630249409724609375ULL * tmp;
  if (hash >= 630249409724609375ULL) {
    hash -= 630249409724609375ULL;
  }

  return hash;
}

__device__ inline unsigned long long hash_char_to_index_ntlm9(unsigned char *hash_value, unsigned int pos) {
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

  return hash_to_index_ntlm9(ret, pos);
}
