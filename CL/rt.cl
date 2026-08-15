#include "shared.h"
#include "ntlm.cl"
#include "netntlmv1.cl"

/*
#ifdef USE_DES_BITSLICE
#include "des_bs.cl"
#else
#include "des.cl"
#endif
*/
inline void index_to_plaintext(unsigned long index, char *charset, unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, unsigned long *plaintext_space_up_to_index, unsigned char *plaintext, unsigned int *plaintext_len) {
  
  //printf("index_to_plaintext .CL\tindex: %x; charset[1]: %02x; charset_len: %d; plaintext_len_min: %d\n", index, charset[1],  charset_len, plaintext_len_min);

  for (int i = plaintext_len_max - 1; i >= plaintext_len_min - 1; i--) {
    if (index >= plaintext_space_up_to_index[i]) {
      *plaintext_len = i + 1;
      break;
    }
  }

  unsigned long index_x = index - plaintext_space_up_to_index[*plaintext_len - 1];
  for (int i = *plaintext_len - 1; i >= 0; i--) {
    plaintext[i] = charset[index_x % charset_len];
    index_x = index_x / charset_len;
  }

  return;
}


inline void do_hash(unsigned int hash_type, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *hash_value, unsigned int *hash_len /*, __global unsigned char *g_debug*/) {

#if HASH_TYPE == HASH_NTLM
  /* This branch was lost in commit 2736101, which made NTLM hashing a silent
   * no-op on OpenCL: the hash buffer stayed zero, so hash_to_index() returned
   * just `pos` and every chain ended at chain_len-2.  Metal and CUDA kept it. */
  ntlm_hash(plaintext, plaintext_len, hash_value);
  *hash_len = 16;
#elif HASH_TYPE == HASH_NETNTLMV1
  uint32_t SK[32];
  /* DES always consumes 7 bytes of plaintext.  Zero any positions beyond
   * plaintext_len so short plaintexts match the CPU reference, which uses a
   * zero-initialised buffer.  (CUDA does this; Metal currently does not.) */
  for (int _i = (int)plaintext_len; _i < 7; _i++) plaintext[_i] = 0;
  /* Generic path retains the historical default server challenge
   * 11 22 33 44 55 66 77 88.  Only the NetNTLMv1-7 fast-path kernels accept a
   * runtime-configurable challenge. */
  unsigned char _default_challenge[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  netntlmv1_hash_challenge(SK, plaintext, hash_value, _default_challenge);
  *hash_len = 8;
#endif

  return;
}


inline unsigned long hash_to_index(unsigned char *hash_value, unsigned int hash_len, unsigned int reduction_offset, unsigned long plaintext_space_total, unsigned int pos) {
  unsigned long ret = hash_value[7];
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


inline unsigned long fill_plaintext_space_table(unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, unsigned long *plaintext_space_up_to_index) {
  unsigned long n = 1;

  plaintext_space_up_to_index[0] = 0;
  for (int i = 1; i <= plaintext_len_max; i++) {
    n = n * charset_len;
    if (i < plaintext_len_min)
      plaintext_space_up_to_index[i] = 0;
    else
      plaintext_space_up_to_index[i] = plaintext_space_up_to_index[i - 1] + n;
  }
  return plaintext_space_up_to_index[plaintext_len_max];
}


// Copies the plaintext_space_up_to_index array from global memory to local memory.
inline void copy_plaintext_space_up_to_index(unsigned long *dest, __global unsigned long *src) {
  for (int i = 0; i < MAX_PLAINTEXT_LEN; i++)
    dest[i] = src[i];
}


inline unsigned long generate_rainbow_chain(
    unsigned int hash_type,
    char *charset,
    unsigned int charset_len,
    unsigned int plaintext_len_min,
    unsigned int plaintext_len_max,
    unsigned int reduction_offset,
    unsigned int chain_len,
    unsigned long start,
    unsigned int pos,
    unsigned long *plaintext_space_up_to_index,
    unsigned long plaintext_space_total,
    unsigned char *plaintext,
    unsigned int *plaintext_len,
    unsigned char *hash,
    unsigned int *hash_len) {

  //printf("generate_rainbow_chain\thash_type: %x; charset[1]: %x; charset_len: %d; plaintext_len_min: %d; chain_len: %d\n", hash_type, charset, charset_len, plaintext_len_min, chain_len);

  unsigned long index = start;
  for (; pos < chain_len - 1; pos++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, plaintext_len);
    do_hash(hash_type, plaintext, *plaintext_len, hash, hash_len);
    index = hash_to_index(hash, *hash_len, reduction_offset, plaintext_space_total, pos);
  }
  return index;
}
