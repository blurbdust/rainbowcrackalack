/* Constants shared between host programs and OpenCL kernels. */

#ifndef _SHARED_H
#define _SHARED_H

#define HASH_UNDEFINED 0
#define HASH_LM 1
#define HASH_NTLM 2
#define HASH_MD5 3
#define HASH_SHA1 4
#define HASH_NETNTLMV1 9
/* Same DES construction as HASH_NETNTLMV1, but the fixed plaintext is the LM
 * magic constant "KGS!@#$%" instead of a server challenge.  A full 2^56 table
 * over this therefore inverts any LM hash half directly, whatever charset the
 * password used. */
#define HASH_NETNTLMV1_LM 10

#define MAX_PLAINTEXT_LEN 16
#define MAX_HASH_OUTPUT_LEN 16
#define MAX_CHARSET_LEN 256

#define DEBUG_LEN 32

/* Converts a table index to a reduction offset. */
#define TABLE_INDEX_TO_REDUCTION_OFFSET(_table_index) (_table_index * 65536)

#endif
