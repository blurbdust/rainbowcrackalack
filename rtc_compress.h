/*
 * Rainbow Crackalack: rtc_compress.h
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

#ifndef RTC_COMPRESS_H
#define RTC_COMPRESS_H

#include <stdint.h>

/* Compresses an RT file to RTC format.  Returns 0 on success, negative on error.
 * On success, if out_num_chains is not NULL, *out_num_chains is set to the number
 * of chains written.  out_num_chains is only valid when the return value is 0. */
int rtc_compress(const char *rt_filename, const char *rtc_filename, uint64_t *out_num_chains);

#endif
