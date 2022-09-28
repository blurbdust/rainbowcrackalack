/*
 * Rainbow Crackalack: enumerate_chain.c
 * Copyright (C) 2019  Joe Testa <jtesta@positronsecurity.com>
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

/* Enumerates the hashes & plaintexts stored in a rainbow chain. */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "cpu_rt_functions.h"
#include "test_shared.h"


//char charset[] = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
char charset[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
#define CHARSET_LEN 256



int main(int ac, char **av) {
  uint64_t plaintext_space_total = 0;
  uint64_t plaintext_space_up_to_index[16] = {0};
  uint64_t index = 0, end_index = 0;
  char plaintext[16] = {0}, hash_hex[48] = {0};
  unsigned char hash[16] = {0};
  unsigned int plaintext_len = 0, chain_len = 0, hash_len = 16, pos = 0;


  if (ac != 5) {
    fprintf(stderr, "Usage: %s num_plaintext_chars chain_len start_index end_index\n\nExample: %s 9 803000 101781 139954541451149691\n\n", av[0], av[0]);
    return -1;
  }

  plaintext_len = strtoul(av[1], NULL, 10);
  chain_len = strtoul(av[2], NULL, 10);
  index = strtoimax(av[3], NULL, 10);
  end_index = strtoimax(av[4], NULL, 10);

  if ((plaintext_len != 7) && (plaintext_len != 8) && (plaintext_len != 9)) {
    fprintf(stderr, "Error: plaintext length must be either 8 or 9!\n");
    return -1;
  }


  plaintext_space_total = fill_plaintext_space_table(CHARSET_LEN, plaintext_len, plaintext_len, plaintext_space_up_to_index);

  printf("Position   Plaintext   Hash   Hash Index\n");
  for (pos = 0; pos < chain_len - 1; pos++) {
    index_to_plaintext(index, charset, CHARSET_LEN, plaintext_len, plaintext_len, plaintext_space_up_to_index, plaintext, &plaintext_len);
    ntlm_hash(plaintext, plaintext_len, hash);

    if (!bytes_to_hex(hash, hash_len, hash_hex, sizeof(hash_hex))) {
      fprintf(stderr, "Error while converting bytes to hex.\n");
      return -1;
    }

    index = hash_to_index(hash, hash_len, 0, plaintext_space_total, pos);
    printf("%u  %s  %s  %"PRIu64"\n", pos, plaintext, hash_hex, index);
  }

  if (index != end_index) {
    fprintf(stderr, "\nError: calculated index (%"PRIu64") != expected index (%"PRIu64")\n\n", index, end_index);
    return -1;
  }

  printf("\nSuccess.\n\n");
  return 0;
}
