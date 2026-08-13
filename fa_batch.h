/*
 * Rainbow Crackalack: fa_batch.h
 *
 * Accumulator for false-alarm candidates pooled across many rainbow tables.
 *
 * Checking false alarms one table at a time leaves the GPU almost entirely
 * idle: a single table typically yields on the order of a thousand candidates,
 * and the kernel is dispatched with one work item per candidate.  On a modern
 * GPU that is a rounding error's worth of occupancy, and the per-dispatch fixed
 * costs (context setup, kernel load, buffer creation) are paid every table.
 *
 * Pooling candidates until there are enough to fill the device turns thousands
 * of tiny dispatches into a handful of large ones.
 *
 * Ported from bandrel's fork (github.com/bandrel/rainbowcrackalack).
 */
#ifndef _FA_BATCH_H
#define _FA_BATCH_H

#include <stdint.h>

#include "gpu_backend.h"
#include "ppi.h"
#include "shared.h"

typedef struct {
  /* Flat candidate arrays, parallel to one another. */
  gpu_ulong    *start_indices;
  unsigned int *start_index_positions;
  gpu_ulong    *hash_base_indices;
  precomputed_and_potential_indices **ppi_refs;

  unsigned int  num_candidates;
  unsigned int  capacity;

  /* Number of tables whose candidates have been appended since the last reset. */
  unsigned int  tables_in_batch;

  /* Flush threshold (candidate count).  1 disables batching, restoring the
   * one-dispatch-per-table behaviour. */
  unsigned int  flush_threshold;
} fa_batch_t;

/* Initialize an empty batch with the given flush threshold and initial capacity
 * hint (the batch grows geometrically beyond this).  A flush_threshold of 0
 * selects the default.  Returns 0 on success, -1 on allocation failure. */
int  fa_batch_init(fa_batch_t *b, unsigned int flush_threshold, unsigned int initial_capacity);

/* Free internal arrays.  Safe to call on a zero-initialized batch. */
void fa_batch_free(fa_batch_t *b);

/* Reset to empty without freeing the backing arrays (keeps capacity). */
void fa_batch_reset(fa_batch_t *b);

/* Append every uncracked hash's currently-collected potential start indices
 * from `ppi_head` into the batch, computing each hash's base index once.
 * Returns 0 on success, -1 on allocation failure.
 *
 * `reduction_offset` and `plaintext_space_total` come from the table
 * parameters, and must be identical for every table pooled into one batch --
 * they feed hash_to_index, so mixing tables with different reduction offsets
 * would compute the wrong base index. */
int  fa_batch_append(fa_batch_t *b,
                     precomputed_and_potential_indices *ppi_head,
                     unsigned int reduction_offset,
                     uint64_t plaintext_space_total);

/* True when the batch is large enough to flush, or when `force` is set AND the
 * batch is non-empty.  An empty batch never flushes.  Callers pass force=1 when
 * the table set is exhausted or every hash is cracked. */
int  fa_batch_should_flush(const fa_batch_t *b, int force);

/* Reorder candidates by chain position.  The false-alarm kernel walks each
 * candidate's chain from its start index up to its recorded position, so a work
 * group containing wildly different positions runs at the speed of its longest
 * walk while its other lanes sit idle.  Sorting first packs similar walk lengths
 * together.  Best effort: on allocation failure the batch is left unsorted,
 * which costs speed but not correctness. */
void fa_batch_sort_by_position(fa_batch_t *b);

#endif /* _FA_BATCH_H */
