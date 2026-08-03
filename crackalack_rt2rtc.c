/*
 * Rainbow Crackalack: crackalack_rt2rtc.c
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

#ifdef _WIN32
#include <windows.h>
#endif
#include <inttypes.h>
#include <stdio.h>

#include "rtc_compress.h"
#include "version.h"


int main(int ac, char **av) {
  char *rt_filename_input = NULL, *rtc_filename_output = NULL;
  int ret = 0;
  uint64_t num_chains = 0;

  ENABLE_CONSOLE_COLOR();
  PRINT_PROJECT_HEADER();

  if (ac != 3) {
    fprintf(stderr, "Usage: %s [rt file input] [rtc file output]\n", av[0]);
    return -1;
  }

  rt_filename_input   = av[1];
  rtc_filename_output = av[2];

  ret = rtc_compress(rt_filename_input, rtc_filename_output, &num_chains);
  if (ret != 0) {
    fprintf(stderr, "Error while compressing RT file: %s; error code: %d\n", rt_filename_input, ret);
    return -1;
  }

  printf("Successfully compressed %"PRIu64" chains in RT file \"%s\" to RTC file \"%s\".\n",
         num_chains, rt_filename_input, rtc_filename_output);
  return 0;
}
