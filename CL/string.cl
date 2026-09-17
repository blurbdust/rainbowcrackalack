#ifndef _STRING_CL
#define _STRING_CL

/* Performs standard strncpy() on __global source array to a local destination
 * array.  Unlike the traditional strncpy(), however, it returns the number of
 * bytes copied, not a pointer to the destination. */
inline unsigned int g_strncpy(char *dest, __global char *g_src, unsigned int n) {
  int i = 0;
  for (; i < n; i++) {
    dest[i] = g_src[i];
    //if (dest[i] == 0)
    //  break;
  }
  return i;
}

inline unsigned int strlen(char *s) {
  unsigned int i = 0;
  for (; *s; i++, s++)
    ;
  return i;
}

/* Copy a charset out of global memory and return its TRUE length.
 *
 * g_strncpy() returns the number of bytes copied, not the string length: the
 * NUL break was removed in commit 2736101 because CHARSET_BYTE legitimately
 * contains 0x00 and a strlen-style copy stops immediately.  Callers that then
 * used the return value as charset_len silently got MAX_CHARSET_LEN (256) for
 * every charset, so an ascii-32-95 table computed its plaintext space as 256^n
 * instead of 95^n.
 *
 * The byte charset is the only 256-character charset and it is the only one
 * starting with 0x00, so a zero strlen unambiguously means "byte" -- which is
 * exactly the strlen()==0 -> 256 rule the host already applies. */
inline unsigned int g_copy_charset(char *dest, __global char *g_src, unsigned int n) {
  unsigned int len = 0;
  for (unsigned int i = 0; i < n; i++)
    dest[i] = g_src[i];
  len = strlen(dest);
  return (len == 0) ? n : len;
}

inline void g_memcpy(unsigned char *dest, __global unsigned char *g_src, unsigned int n) {
  unsigned int i = 0;
  for (; i < n; i++)
    dest[i] = g_src[i];
}

inline void bzero(char *s, unsigned int n) {
  unsigned int i;
  for (i = 0; i < n; i++)
    s[i] = 0;
}

#endif
