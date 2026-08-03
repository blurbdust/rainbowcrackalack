#include <metal_stdlib>
using namespace metal;

#include "rt.metal"
#include "shared.h"
#include "string.metal"

kernel void test_index_to_plaintext(
    device char *g_charset [[buffer(0)]],
    device unsigned int *g_charset_len [[buffer(1)]],
    device unsigned int *g_plaintext_len_min [[buffer(2)]],
    device unsigned int *g_plaintext_len_max [[buffer(3)]],
    device ulong *g_index [[buffer(4)]],
    device unsigned char *g_plaintext [[buffer(5)]],
    device unsigned int *g_plaintext_len [[buffer(6)]],
    device unsigned char *g_debug [[buffer(7)]],
    uint gid [[thread_position_in_grid]]) {

  ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];

  char charset[MAX_CHARSET_LEN];
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  ulong index = *g_index;
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = *g_plaintext_len;

  unsigned int charset_len = *g_charset_len;
  g_memcpy((thread unsigned char *)charset, (device unsigned char *)g_charset, charset_len);

  fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);

  *g_plaintext_len = plaintext_len;
  for (int i = 0; i < plaintext_len; i++)
    g_plaintext[i] = plaintext[i];

  return;
}
