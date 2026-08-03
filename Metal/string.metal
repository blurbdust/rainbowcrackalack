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
