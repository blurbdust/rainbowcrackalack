/*
 * Rainbow Crackalack: cpu_rt_functions.c
 * Copyright (C) 2018-2019  Joe Testa <jtesta@positronsecurity.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms version 3 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include "cpu_rt_functions.h"
#include "shared.h"

#include <gcrypt.h>
#define GCRY_CIPHER GCRY_CIPHER_DES     // Use DES cipher
#define GCRY_MODE GCRY_CIPHER_MODE_ECB  // Use ECB mode
#define KEY_SIZE 8                      // DES key size in bytes
#define BLOCK_SIZE 8                    // DES block size in bytes
#ifdef _WIN32
#include <windows.h>
#endif



uint64_t fill_plaintext_space_table(unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, uint64_t *plaintext_space_up_to_index) {
  uint64_t n = 1;
  int i;


  plaintext_space_up_to_index[0] = 0;
  for (i = 1; i <= plaintext_len_max; i++) {
    n = n * charset_len;
    if (i < plaintext_len_min)
      plaintext_space_up_to_index[i] = 0;
    else
      plaintext_space_up_to_index[i] = plaintext_space_up_to_index[i - 1] + n;
  }
  return plaintext_space_up_to_index[plaintext_len_max];
}


uint64_t hash_to_index(unsigned char *hash_value, unsigned int hash_len, unsigned int reduction_offset, uint64_t plaintext_space_total, unsigned int pos) {
  uint64_t ret = hash_value[7];
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

  //printf("hash_to_index \treturn: %llu, ret: %llu, reduction_offset: %u, pos: %u, plaintext_space_total: %llu\n", (ret + reduction_offset + pos) % plaintext_space_total, ret, reduction_offset, pos, plaintext_space_total);

  return (ret + reduction_offset + pos) % plaintext_space_total;
}


void index_to_plaintext(uint64_t index, char *charset, unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, uint64_t *plaintext_space_up_to_index, char *plaintext, unsigned int *plaintext_len) {
  int i;
  uint64_t index_x;

  //printf("************************************** this function is CPU not GPU, index: %llu\n", index);

  for (i = plaintext_len_max - 1; i >= plaintext_len_min - 1; i--) {
    if (index >= plaintext_space_up_to_index[i]) {
      *plaintext_len = i + 1;
      if (*plaintext_len >= MAX_PLAINTEXT_LEN)
	return;

      plaintext[*plaintext_len] = '\0';
      break;
    }
  }

  index_x = index - plaintext_space_up_to_index[*plaintext_len - 1];
  for (i = *plaintext_len - 1; i >= 0; i--) {
    plaintext[i] = charset[index_x % charset_len];
    //printf("appending %02x \n", plaintext[i]);
    index_x = index_x / charset_len;
  }

  return;
}


uint64_t generate_rainbow_chain(
    unsigned int hash_type,
    char *charset,
    unsigned int charset_len,
    unsigned int plaintext_len_min,
    unsigned int plaintext_len_max,
    unsigned int reduction_offset,
    unsigned int chain_len,
    uint64_t start,
    uint64_t *plaintext_space_up_to_index,
    uint64_t plaintext_space_total,
    char *plaintext,
    unsigned int *plaintext_len,
    unsigned char *hash,
    unsigned int *hash_len) {
  uint64_t index = start;
  unsigned int pos = 0;


  if (hash_type != HASH_NTLM)
    fprintf(stderr, "\n\tWARNING: only NTLM hashes are currently supported!\n\n");

  for (; pos < chain_len - 1; pos++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, plaintext_len);
    ntlm_hash(plaintext, *plaintext_len, hash);
    index = hash_to_index(hash, *hash_len, reduction_offset, plaintext_space_total, pos);
  }
  return index;
}


/* Calculates the NTLM hash on the specified plaintext.  The result is stored in the hash
 * argument, which must be at least 16 bytes in size. */
void ntlm_hash(char *plaintext, unsigned int plaintext_len, unsigned char *hash) {
  unsigned int key[16] = {0};
  unsigned int output[4];
  int i = 0;


  if (plaintext_len > 27) {
    plaintext[27] = 0;
    plaintext_len = 27;
  }

  for (; i < (plaintext_len / 2); i++)
    key[i] = plaintext[i * 2] | (plaintext[(i * 2) + 1] << 16);

  if ((plaintext_len % 2) == 1)
    key[i] = plaintext[plaintext_len - 1] | 0x800000;
  else
    key[i] = 0x80;

  key[14] = plaintext_len << 4;

  md4_encrypt(output, key);

  i = 0;
  hash[i++] = ((output[0] >> 0) & 0xff);
  hash[i++] = ((output[0] >> 8) & 0xff);
  hash[i++] = ((output[0] >> 16) & 0xff);
  hash[i++] = ((output[0] >> 24) & 0xff);
  hash[i++] = ((output[1] >> 0) & 0xff);
  hash[i++] = ((output[1] >> 8) & 0xff);
  hash[i++] = ((output[1] >> 16) & 0xff);
  hash[i++] = ((output[1] >> 24) & 0xff);
  hash[i++] = ((output[2] >> 0) & 0xff);
  hash[i++] = ((output[2] >> 8) & 0xff);
  hash[i++] = ((output[2] >> 16) & 0xff);
  hash[i++] = ((output[2] >> 24) & 0xff);
  hash[i++] = ((output[3] >> 0) & 0xff);
  hash[i++] = ((output[3] >> 8) & 0xff);
  hash[i++] = ((output[3] >> 16) & 0xff);
  hash[i++] = ((output[3] >> 24) & 0xff);
}


/* The below copyright notice applies to the md4_encrypt() function only. */

/*
 * MD4 OpenCL kernel based on Solar Designer's MD4 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 * This code is in public domain.
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum
 * and Copyright (c) 2015, Sayantan Datta <std2048@gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1  nt_opencl_kernel.c (written by Alain Espinosa <alainesp at gmail.com>)
 * 2. http://tools.ietf.org/html/rfc1320
 * 3. http://en.wikipedia.org/wiki/MD4
 */

#define F(x, y, z)	(z ^ (x & (y ^ z)))
#define G(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)	(((x) ^ (y)) ^ (z))
#define H2(x, y, z)	((x) ^ ((y) ^ (z)))

/* The MD4 transformation for all three rounds. */
#define STEP(f, a, b, c, d, x, s)	  \
	(a) += f((b), (c), (d)) + (x); \
	(a) = ((a << s) | (a >> (32 - s)))
	//(a) = rotate((a), (uint)(s)) //(a) = ((a << s) | (a >> (32 - s))) 

void md4_encrypt(unsigned int *hash, unsigned int *W)
{
	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;

	/* Round 1 */
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[0], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[1], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[2], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[3], 19);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[4], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[5], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[6], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[7], 19);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[8], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[9], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[10], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[11], 19);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[12], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[13], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[14], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[15], 19);

	/* Round 2 */
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[0] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[4] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[8] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[12] + 0x5a827999, 13);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[1] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[5] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[9] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[13] + 0x5a827999, 13);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[2] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[6] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[10] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[14] + 0x5a827999, 13);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[3] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[7] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[11] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[15] + 0x5a827999, 13);

	/* Round 3 */
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[0] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[8] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[4] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[12] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[2] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[10] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[6] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[14] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[1] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[9] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[5] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[13] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[3] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[11] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[7] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[15] + 0x6ed9eba1, 15);

	hash[0] = hash[0] + 0x67452301;
	hash[1] = hash[1] + 0xefcdab89;
	hash[2] = hash[2] + 0x98badcfe;
	hash[3] = hash[3] + 0x10325476;
}

void setup_des_key(char key_56[], unsigned char *key)
{
  //char key[8]= {0};

  key[0] = key_56[0];
  key[1] = (key_56[0] << 7) | (key_56[1] >> 1);
  key[2] = (key_56[1] << 6) | (key_56[2] >> 2);
  key[3] = (key_56[2] << 5) | (key_56[3] >> 3);
  key[4] = (key_56[3] << 4) | (key_56[4] >> 4);
  key[5] = (key_56[4] << 3) | (key_56[5] >> 5);
  key[6] = (key_56[5] << 2) | (key_56[6] >> 6);
  key[7] = (key_56[6] << 1);
}

/*
void HashNetNTLMv1(
  unsigned char *pData,
  unsigned int  uLen,   // uLen == 7
  unsigned char Hash[8])
{
  */
void netntlmv1_hash(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *hash) {
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0); // Disable secure memory (optional)
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    gcry_cipher_hd_t handle;
    gcry_error_t err;

    // Define key and plaintext
    unsigned char magic[KEY_SIZE] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

    // Open cipher context
    err = gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_MODE, 0);
    if (err) {
        fprintf(stderr, "Failed to open cipher: %s\n", gcry_strerror(err));
        return;
    }

    // Set the key for encryption
    err = gcry_cipher_setkey(handle, plaintext, plaintext_len);
    if (err) {
        fprintf(stderr, "Failed to set key: %s\n", gcry_strerror(err));
        gcry_cipher_close(handle);
        return;
    }

    // Encrypt the plaintext
    err = gcry_cipher_encrypt(handle, hash, BLOCK_SIZE, magic, BLOCK_SIZE);
    if (err) {
        fprintf(stderr, "Encryption failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(handle);
        return;
    }

    // Clean up
    gcry_cipher_close(handle);
}
