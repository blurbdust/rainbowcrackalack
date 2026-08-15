#ifndef _STRING_METAL
#define _STRING_METAL

/* Performs standard strncpy() on device source array to a local destination
 * array.  Unlike the traditional strncpy(), however, it returns the number of
 * bytes copied, not a pointer to the destination. */
inline unsigned int g_strncpy(thread char *dest, device char *g_src, unsigned int n) {
  unsigned int i = 0;
  for (; i < n; i++) {
    dest[i] = g_src[i];
    /* Deliberately no NUL break: the 'byte' charset starts with 0x00, so
     * stopping here would yield charset_len 0 and a zero plaintext space.
     * Matches CL/string.cl. */
  }
  return i;
}

inline unsigned int rc_strlen(thread char *s) {
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
inline unsigned int g_copy_charset(thread char *dest, device char *g_src, unsigned int n) {
  unsigned int len = 0;
  for (unsigned int i = 0; i < n; i++)
    dest[i] = g_src[i];
  len = rc_strlen(dest);
  return (len == 0) ? n : len;
}

inline void g_memcpy(thread unsigned char *dest, device unsigned char *g_src, unsigned int n) {
  unsigned int i = 0;
  for (; i < n; i++)
    dest[i] = g_src[i];
}

inline void bzero(thread char *s, unsigned int n) {
  unsigned int i;
  for (i = 0; i < n; i++)
    s[i] = 0;
}

#endif
