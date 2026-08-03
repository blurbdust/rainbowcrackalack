/*
 * Rainbow Crackalack: rtc_compress.c
 * Copyright (C) 2018-2019  Joe Testa <jtesta@positronsecurity.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms version 3 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtc_compress.h"


/* Returns the number of bits needed to represent x (0 returns 0). */
static unsigned int bits_needed(uint64_t x) {
  if (x == 0)
    return 0;
  return 64 - __builtin_clzll(x);
}

/* Rounds b up to the nearest multiple of 8. */
static unsigned int round_up_to_8(unsigned int b) {
  return ((b + 7) / 8) * 8;
}

/* Compresses an RT file to RTC format.  Returns 0 on success, negative on error.
 * On success, if out_num_chains is not NULL, *out_num_chains is set to the number
 * of chains written.  out_num_chains is only valid when the return value is 0. */
int rtc_compress(const char *rt_filename, const char *rtc_filename, uint64_t *out_num_chains) {
  FILE *f_in = NULL, *f_out = NULL;
  uint64_t *buf = NULL;
  uint8_t *chain_buf = NULL;
  int ret = 0;

  /* Open and read the entire .rt file. */
  f_in = fopen(rt_filename, "rb");
  if (f_in == NULL) {
    fprintf(stderr, "Error: failed to open RT file %s: %s\n", rt_filename, strerror(errno));
    ret = -1;
    goto done;
  }

  if (fseek(f_in, 0, SEEK_END) != 0) {
    fprintf(stderr, "Error: fseek failed on %s: %s\n", rt_filename, strerror(errno));
    ret = -2;
    goto done;
  }
  long filesize = ftell(f_in);
  if (filesize < 0) {
    fprintf(stderr, "Error: ftell failed on %s: %s\n", rt_filename, strerror(errno));
    ret = -2;
    goto done;
  }
  rewind(f_in);

  if (filesize == 0 || (filesize % 16) != 0) {
    fprintf(stderr, "Error: RT file size (%ld) is not a multiple of 16.\n", filesize);
    ret = -3;
    goto done;
  }

  uint64_t num_chains = (uint64_t)filesize / 16;

  buf = malloc((size_t)filesize);
  if (buf == NULL) {
    fprintf(stderr, "Error: could not allocate %ld bytes for RT file.\n", filesize);
    ret = -4;
    goto done;
  }

  if (fread(buf, 1, (size_t)filesize, f_in) != (size_t)filesize) {
    fprintf(stderr, "Error while reading RT file: %s\n", strerror(errno));
    ret = -5;
    goto done;
  }

  fclose(f_in);
  f_in = NULL;

  /* start[i] = buf[i*2], end[i] = buf[i*2+1] */
  uint64_t *start = buf;       /* start[i] = buf[i*2]   */
  uint64_t *end   = buf + 1;  /* end[i]   = buf[i*2+1] */
  /* Stride is 2 uint64_t per chain; access as start[i*2] and end[i*2]. */

  /* Verify sort order (ascending by end point). */
  for (uint64_t i = 1; i < num_chains; i++) {
    if (end[i * 2] < end[(i - 1) * 2]) {
      fprintf(stderr, "Error: RT file is not sorted by end point ascending (chain %"PRIu64" end < chain %"PRIu64" end).\n", i, i - 1);
      ret = -6;
      goto done;
    }
  }

  /* Compute sMin, sMax, eMin, eMax. */
  uint64_t sMin = start[0], sMax = start[0];
  for (uint64_t i = 1; i < num_chains; i++) {
    uint64_t s = start[i * 2];
    if (s < sMin) sMin = s;
    if (s > sMax) sMax = s;
  }

  uint64_t eMinActual = end[0];          /* file is sorted, so end[0] is minimum */
  uint64_t eMax       = end[(num_chains - 1) * 2];

  uint64_t eInterval;
  if (num_chains == 1)
    eInterval = 0;
  else
    eInterval = (eMax - eMinActual) / (num_chains - 1);

  /* Compute eMin as the minimum of (end[i] - eInterval*i) over all i.
   * Use int64_t arithmetic to handle possible underflow. */
  int64_t eMin_i64 = (int64_t)eMinActual;  /* i=0 gives eMinActual */
  for (uint64_t i = 1; i < num_chains; i++) {
    int64_t val = (int64_t)end[i * 2] - (int64_t)(eInterval * i);
    if (val < eMin_i64)
      eMin_i64 = val;
  }

  /* eMin_i64 may be negative for non-uniform tables. The decoder uses unsigned 64-bit
   * arithmetic: uIndexEMin + uIndexEInterval*i + residual. Storing a negative eMin
   * as its two's-complement uint64 bit pattern is correct because the unsigned
   * addition wraps modulo 2^64 and yields the original e[i] value. */
  uint64_t eMin = (uint64_t)eMin_i64;

  /* Compute sBits and eBits. */
  unsigned int sBits = round_up_to_8(bits_needed(sMax - sMin));
  uint64_t eResidualMax = 0;
  for (uint64_t i = 0; i < num_chains; i++) {
    uint64_t residual = end[i * 2] - eMin - eInterval * i;
    if (residual > eResidualMax)
      eResidualMax = residual;
  }
  unsigned int eBits = round_up_to_8(bits_needed(eResidualMax));

  unsigned int chain_size = (sBits + eBits + 7) / 8;

  /* Guard checks.  sBits == 64 is also rejected: the decoder's right-shift
   * `buf[0] >> uIndexSBits` is undefined behavior in C when uIndexSBits == 64. */
  if (sBits >= 64 || eBits > 64 || chain_size > 16) {
    fprintf(stderr, "Error: computed field widths out of range: sBits=%u eBits=%u chain_size=%u\n",
            sBits, eBits, chain_size);
    ret = -8;
    goto done;
  }

  /* Allocate compressed chain buffer. */
  size_t chains_bytes = (size_t)num_chains * chain_size;
  if (chain_size != 0 && chains_bytes / chain_size != num_chains) {
    fprintf(stderr, "Error: chain buffer size overflow.\n");
    ret = -9;
    goto done;
  }
  chain_buf = calloc(1, chains_bytes);
  if (chain_buf == NULL) {
    fprintf(stderr, "Error: could not allocate %zu bytes for chain buffer.\n", chains_bytes);
    ret = -10;
    goto done;
  }

  /* Encode each chain. */
  for (uint64_t i = 0; i < num_chains; i++) {
    uint64_t s_delta = start[i * 2] - sMin;
    uint64_t e_residual = end[i * 2] - eMin - eInterval * i;

    unsigned __int128 packed = (unsigned __int128)s_delta
                             | ((unsigned __int128)e_residual << sBits);

    /* Write low chain_size bytes (little-endian via memcpy on LE host). */
    memcpy(chain_buf + (size_t)i * chain_size, &packed, chain_size);
  }

  /* Write RTC file. */
  f_out = fopen(rtc_filename, "wb");
  if (f_out == NULL) {
    fprintf(stderr, "Error: failed to open RTC output file %s: %s\n", rtc_filename, strerror(errno));
    ret = -11;
    goto done;
  }

  uint32_t version   = 0x30435452;
  uint16_t sBits16   = (uint16_t)sBits;
  uint16_t eBits16   = (uint16_t)eBits;

  if ((fwrite(&version,   sizeof(uint32_t), 1, f_out) != 1) ||
      (fwrite(&sBits16,   sizeof(uint16_t), 1, f_out) != 1) ||
      (fwrite(&eBits16,   sizeof(uint16_t), 1, f_out) != 1) ||
      (fwrite(&sMin,      sizeof(uint64_t), 1, f_out) != 1) ||
      (fwrite(&eMin,      sizeof(uint64_t), 1, f_out) != 1) ||
      (fwrite(&eInterval, sizeof(uint64_t), 1, f_out) != 1)) {
    fprintf(stderr, "Error while writing RTC header: %s\n", strerror(errno));
    ret = -12;
    goto done;
  }

  if (chain_size > 0) {
    if (fwrite(chain_buf, 1, chains_bytes, f_out) != chains_bytes) {
      fprintf(stderr, "Error while writing RTC chain data: %s\n", strerror(errno));
      ret = -13;
      goto done;
    }
  }

  if (out_num_chains != NULL)
    *out_num_chains = num_chains;

done:
  if (f_in != NULL) {
    fclose(f_in);
    f_in = NULL;
  }
  if (f_out != NULL) {
    fclose(f_out);
    f_out = NULL;
  }
  if (buf != NULL) {
    free(buf);
    buf = NULL;
  }
  if (chain_buf != NULL) {
    free(chain_buf);
    chain_buf = NULL;
  }

  return ret;
}
