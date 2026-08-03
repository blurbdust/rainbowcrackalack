#include "rt.cu"
#include "shared.h"
#include "string.cu"

extern "C" __global__ void test_index_to_plaintext(
    char *g_charset,
    unsigned int *g_charset_len,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned long long *g_index,
    unsigned char *g_plaintext,
    unsigned int *g_plaintext_len,
    unsigned char *g_debug
) {
  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];

  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned long long index = *g_index;
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = *g_plaintext_len;

  unsigned int charset_len = *g_charset_len;
  g_memcpy((unsigned char *)charset, (unsigned char *)g_charset, charset_len);

  fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);

  *g_plaintext_len = plaintext_len;
  for (int i = 0; i < (int)plaintext_len; i++)
    g_plaintext[i] = plaintext[i];

  return;
}
