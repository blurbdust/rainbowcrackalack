#ifndef _STRING_CU
#define _STRING_CU

/* CUDA equivalent of CL/string.cl.  Drops __global qualifiers. */
__device__ inline unsigned int g_strncpy(char *dest, char *g_src, unsigned int n) {
  int i = 0;
  for (; i < n; i++) {
    dest[i] = g_src[i];
  }
  return i;
}

__device__ inline unsigned int strlen(char *s) {
  unsigned int i = 0;
  for (; *s; i++, s++)
    ;
  return i;
}

__device__ inline void g_memcpy(unsigned char *dest, unsigned char *g_src, unsigned int n) {
  unsigned int i = 0;
  for (; i < n; i++)
    dest[i] = g_src[i];
}

__device__ inline void bzero(char *s, unsigned int n) {
  unsigned int i;
  for (i = 0; i < n; i++)
    s[i] = 0;
}

#endif
