#include "shared.h"
#include "ntlm.cu"
#include "netntlmv1.cu"

/* DES (HASH_LM) is out of scope; the OpenCL source's commented-out #include
 * block for des_bs.cl/des.cl is intentionally omitted here.  cuda_setup.c's
 * include resolver is strstr-based and doesn't respect comment boundaries,
 * so leaving commented-out #include lines would cause spurious resolution
 * attempts at NVRTC compile time. */

__device__ inline void index_to_plaintext(unsigned long long index, char *charset, unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, unsigned long long *plaintext_space_up_to_index, unsigned char *plaintext, unsigned int *plaintext_len) {

  for (int i = plaintext_len_max - 1; i >= (int)plaintext_len_min - 1; i--) {
    if (index >= plaintext_space_up_to_index[i]) {
      *plaintext_len = i + 1;
      break;
    }
  }

  unsigned long long index_x = index - plaintext_space_up_to_index[*plaintext_len - 1];
  for (int i = *plaintext_len - 1; i >= 0; i--) {
    plaintext[i] = charset[index_x % charset_len];
    index_x = index_x / charset_len;
  }

  return;
}


__device__ inline void do_hash(unsigned int hash_type, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *hash_value, unsigned int *hash_len) {

#if HASH_TYPE == HASH_NTLM
  ntlm_hash(plaintext, plaintext_len, hash_value);
  *hash_len = 16;
#elif HASH_TYPE == HASH_NETNTLMV1
  uint32_t SK[32];
  /* DES always consumes 7 bytes of plaintext.  Zero any positions beyond
   * plaintext_len so short plaintexts (e.g. 3-char numeric) match the
   * CPU reference which uses a zero-initialised buffer. */
  for (int _i = (int)plaintext_len; _i < 7; _i++) plaintext[_i] = 0;
  /* Generic path retains the historical default server challenge
   * 11 22 33 44 55 66 77 88.  Only the NetNTLMv1-7 fast-path kernels accept a
   * runtime-configurable challenge. */
  unsigned char _default_challenge[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  netntlmv1_hash(SK, plaintext, hash_value, _default_challenge);
  *hash_len = 8;
#elif HASH_TYPE == HASH_MD5
  md5_hash(plaintext, plaintext_len, hash_value);
  *hash_len = 16;
#endif

  return;
}


__device__ inline unsigned long long hash_to_index(unsigned char *hash_value, unsigned int hash_len, unsigned int reduction_offset, unsigned long long plaintext_space_total, unsigned int pos) {
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

  return (ret + reduction_offset + pos) % plaintext_space_total;
}


__device__ inline unsigned long long fill_plaintext_space_table(unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, unsigned long long *plaintext_space_up_to_index) {
  unsigned long long n = 1;

  plaintext_space_up_to_index[0] = 0;
  for (int i = 1; i <= (int)plaintext_len_max; i++) {
    n = n * charset_len;
    if (i < (int)plaintext_len_min)
      plaintext_space_up_to_index[i] = 0;
    else
      plaintext_space_up_to_index[i] = plaintext_space_up_to_index[i - 1] + n;
  }
  return plaintext_space_up_to_index[plaintext_len_max];
}


/* Copies the plaintext_space_up_to_index array from global memory to local memory. */
__device__ inline void copy_plaintext_space_up_to_index(unsigned long long *dest, unsigned long long *src, unsigned int plaintext_len_max) {
  for (int i = 0; i <= (int)plaintext_len_max; i++)
    dest[i] = src[i];
}


__device__ inline unsigned long long generate_rainbow_chain(
    unsigned int hash_type,
    char *charset,
    unsigned int charset_len,
    unsigned int plaintext_len_min,
    unsigned int plaintext_len_max,
    unsigned int reduction_offset,
    unsigned int chain_len,
    unsigned long long start,
    unsigned int pos,
    unsigned long long *plaintext_space_up_to_index,
    unsigned long long plaintext_space_total,
    unsigned char *plaintext,
    unsigned int *plaintext_len,
    unsigned char *hash,
    unsigned int *hash_len) {

  unsigned long long index = start;
  for (; pos < chain_len - 1; pos++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, plaintext_len);
    do_hash(hash_type, plaintext, *plaintext_len, hash, hash_len);
    index = hash_to_index(hash, *hash_len, reduction_offset, plaintext_space_total, pos);
  }
  return index;
}
