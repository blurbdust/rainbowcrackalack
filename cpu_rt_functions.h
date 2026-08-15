#ifndef _CPU_RT_FUNCTIONS_H
#define _CPU_RT_FUNCTIONS_H

#include <stdint.h>


uint64_t fill_plaintext_space_table(unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, uint64_t *plaintext_space_up_to_index);

uint64_t hash_to_index(unsigned char *hash_value, unsigned int hash_len, unsigned int reduction_offset, uint64_t plaintext_space_total, unsigned int pos);

void index_to_plaintext(uint64_t index, char *charset, unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, uint64_t *plaintext_space_up_to_index, char *plaintext, unsigned int *plaintext_len);

void ntlm_hash(char *plaintext, unsigned int plaintext_len, unsigned char *hash);

uint64_t generate_rainbow_chain(unsigned int hash_type, char *charset, unsigned int charset_len, unsigned int plaintext_len_min, unsigned int plaintext_len_max, unsigned int reduction_offset, unsigned int chain_len, uint64_t start, uint64_t *plaintext_space_up_to_index, uint64_t plaintext_space_total, char *plaintext, unsigned int *plaintext_len, unsigned char *hash, unsigned int *hash_len);

void md4_encrypt(unsigned int *hash, unsigned int *W);

void setup_des_key(char key_56[], unsigned char *key);

const unsigned char *netntlmv1_challenge_for(unsigned int hash_type);
unsigned int is_netntlmv1_family(unsigned int hash_type);
void netntlmv1_hash(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *hash);
void netntlmv1_hash_challenge(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *hash, const unsigned char *challenge);

#endif
