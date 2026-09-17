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

/* Copy a charset out of device memory and return its TRUE length.
 *
 * g_strncpy() returns bytes copied, not string length: the NUL break was
 * removed in commit 2736101 because CHARSET_BYTE legitimately contains 0x00.
 * Callers using that return value as charset_len silently got 256 for EVERY
 * charset, so an ascii-32-95 table computed its space as 256^n instead of 95^n
 * (and 256^8 == 0 mod 2^64, after which "% 0" returned the dividend unreduced).
 *
 * The byte charset is the only 256-character charset and the only one starting
 * with 0x00, so strlen()==0 unambiguously means "byte" -- the same rule the
 * host already applies. */
__device__ inline unsigned int g_copy_charset(char *dest, char *g_src, unsigned int n) {
  unsigned int len = 0;
  for (unsigned int i = 0; i < n; i++)
    dest[i] = g_src[i];
  len = strlen(dest);
  return (len == 0) ? n : len;
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
