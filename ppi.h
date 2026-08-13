/*
 * Rainbow Crackalack: ppi.h
 *
 * Definition of precomputed_and_potential_indices, the per-hash record the
 * lookup pipeline carries around: the precomputed end indices for a hash, the
 * candidate chain start indices the binary search turned up, and the plaintext
 * once it is cracked.
 *
 * This lived inside crackalack_lookup.c until fa_batch.c needed to read it too.
 */
#ifndef _PPI_H
#define _PPI_H

#include <stdint.h>

#include "gpu_backend.h"

/* Node in the linked list of precomputed end indices and potential start
 * indices (the latter are usually false alarms). */
struct _precomputed_and_potential_indices {
  char         *username;  /* Non-NULL if loaded file format is pwdump. */
  char         *hash;
  gpu_ulong    *precomputed_end_indices;
  gpu_uint      num_precomputed_end_indices;

  gpu_ulong    *potential_start_indices;
  unsigned int  num_potential_start_indices;
  unsigned int  potential_start_indices_size;
  unsigned int *potential_start_index_positions; /* Buffer size is always num_potential_start_indices. */

  char         *plaintext;        /* Set if hash is cracked. */
  char         *index_filename;   /* File path containing the ".index" file. */

  struct _precomputed_and_potential_indices *next;
};

typedef struct _precomputed_and_potential_indices precomputed_and_potential_indices;

#endif /* _PPI_H */
