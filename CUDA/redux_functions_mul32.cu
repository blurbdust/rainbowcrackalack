__device__ inline void reduce_9chars(unsigned long long index, unsigned int *hi4, unsigned long long *lo5) {
  // Divide by multiply

  // 9 chars -> 4 chars, 5 chars
  // floor(2 * 2**ceil(log2(95**9)) / 95**5) = 297,996,874
  // 148,998,437 (297,996,874/2) or 297,996,874

  unsigned int       tmp;
  unsigned long long tmp2;

  tmp    = (unsigned int) (((unsigned long long) ((unsigned int) (index >> 32)) * 148998437) >> 28); // just right

  //tmp2 = index - 7737809375 * tmp;
  // 7737809375 == 3442842079 + 2**32
  tmp2 = index - (unsigned long long) 3442842079 * tmp - ((unsigned long long) tmp << 32);
  if (tmp2 >= 7737809375ULL) {
    tmp2 -= 7737809375ULL;
    tmp++;
  }
  *hi4 = tmp;
  *lo5 = tmp2;
}

__device__ inline void reduce_8chars(unsigned long long index, unsigned int *hi4, unsigned int *lo4) {
  unsigned int tmp;
  unsigned int tmp2;

  tmp    = (unsigned int) (((unsigned long long) ((unsigned int) (index >> 25)) * 110584777) >> 28); // just right

  tmp2 = (unsigned int) index - 81450625 * tmp;
  if (tmp2 >= 81450625) {
    tmp2 -= 81450625;
    tmp++;
  }
  *hi4 = tmp;
  *lo4 = tmp2;
}

__device__ inline void reduce_5chars(unsigned long long index, unsigned int *hi2, unsigned int *lo3) {
  unsigned int tmp;
  unsigned int tmp2;

  tmp    = ((index >> 18) * 20037) >> 16; // just right

  tmp2 = (unsigned int) index - 857375 * tmp;
  if (tmp2 >= 857375) {
    tmp2 -= 857375;
    tmp++;
  }
  *hi2 = tmp;
  *lo3 = tmp2;
}

__device__ inline void reduce_4chars(unsigned int index, unsigned int *hi2, unsigned int *lo2) {
  unsigned int tmp;
  unsigned int tmp2;

  tmp    = ((index >> 12) * 14871) >> 15; // just right

  tmp2 = index - 9025 * tmp;
  if (tmp2 >= 9025) {
    tmp2 -= 9025;
    tmp++;
  }
  *hi2 = tmp;
  *lo2 = tmp2;
}

__device__ inline void reduce_3chars(unsigned int index, unsigned char *hi1, unsigned int *lo2) {
  unsigned int tmp;
  unsigned int tmp2;

  tmp    = ((index >> 13) * 116) >> 7; // just right

  tmp2 = index - 9025 * tmp;
  if (tmp2 >= 9025) {
    tmp2 -= 9025;
    tmp++;
  }
  *hi1 = tmp + 32;
  *lo2 = tmp2;
}

__device__ inline void reduce_2chars(unsigned int index, unsigned char *hi1, unsigned char *lo2) {
  unsigned int tmp;
  unsigned int tmp2;

  tmp    = ((index >> 6) * 172) >>  8; // just right

  tmp2 = index - 95 * tmp;
  if (tmp2 >= 95) {
    tmp2 -= 95;
    tmp++;
  }
  *hi1 = tmp + 32;
  *lo2 = tmp2 + 32;
}
