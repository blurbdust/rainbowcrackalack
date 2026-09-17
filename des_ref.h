#ifndef _DES_REF_H
#define _DES_REF_H
/* Self-contained DES-ECB that does not reject weak keys. See des_ref.c. */
void des_ref_ecb_encrypt(const unsigned char key[8], const unsigned char in[8], unsigned char out[8]);
void des_ref_ecb_encrypt_56(const unsigned char key7[7], const unsigned char in[8], unsigned char out[8]);
#endif
