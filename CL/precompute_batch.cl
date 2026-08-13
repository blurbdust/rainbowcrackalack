#include "string.cl"
#include "rt.cl"


/* Batched generic precomputation.
 *
 * Identical chain walk to precompute.cl, but a single dispatch covers ALL
 * hashes instead of one.  That is the entire point: precomputation is
 * O(chain_len^2) per hash and was run once per hash, sequentially, so N hashes
 * cost N times one hash.
 *
 * Widening the dispatch along the *position* axis does not help -- the work item
 * at position p walks (chain_len - p) steps, so a wider chunk just runs at the
 * speed of its longest walk while the short ones idle.  The *hash* axis is free
 * of that: every hash at a given position walks exactly the same number of
 * steps, so adding hashes multiplies parallelism without adding any divergence.
 * N hashes therefore cost about the same wall time as one.
 *
 * Work item -> (hash, position) mapping:
 *   hash_idx  = gid / chunk_positions
 *   local_pos = gid % chunk_positions
 * with global work size = num_hashes * chunk_positions.
 *
 * g_hashes: all hashes concatenated, num_hashes * hash_len bytes.
 * g_output: num_hashes * output_len entries, laid out per hash:
 *           [hash0_pos0 .. hash0_posN, hash1_pos0 .. ]
 *
 * Positions are still strided across devices exactly as precompute.cl does, so
 * the host's existing cross-device collation is unchanged.
 */
__kernel void precompute_batch(
    __global unsigned int *g_hash_type,
    __global unsigned char *g_hashes,
    __global unsigned int *g_hash_len,
    __global unsigned int *g_num_hashes,
    __global char *g_charset,
    __global unsigned int *g_plaintext_len_min,
    __global unsigned int *g_plaintext_len_max,
    __global unsigned int *g_table_index,
    __global unsigned long *g_chain_len,
    __global unsigned int *g_device_num,
    __global unsigned int *g_total_devices,
    __global unsigned int *g_chunk_positions,
    __global unsigned int *g_pos_start,
    __global unsigned int *g_output_len,
    __global unsigned long *g_output) {

  unsigned int chunk_positions = *g_chunk_positions;
  unsigned int gid = get_global_id(0);
  unsigned int hash_idx = gid / chunk_positions;
  unsigned int local_pos = gid % chunk_positions;

  if (hash_idx >= *g_num_hashes)
    return;

  /* Index into this device's slice of the output. */
  unsigned int k = *g_pos_start + local_pos;
  unsigned int output_len = *g_output_len;
  if (k >= output_len)
    return;

  unsigned long out_idx = ((unsigned long)hash_idx * (unsigned long)output_len) + k;

  long target_chain_len = ((long)(*g_chain_len) - (long)(*g_device_num)) -
      ((long)k * (long)(*g_total_devices)) - 1;

  if (target_chain_len < 1) {
    g_output[out_idx] = 0;
    return;
  }

  char charset[MAX_CHARSET_LEN];
  unsigned long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned long index;

  unsigned int hash_type = *g_hash_type;
  unsigned int in_hash_len = *g_hash_len;   /* hash_len below is mutated by do_hash */
  unsigned int hash_len = in_hash_len;
  unsigned int charset_len = g_strncpy(charset, g_charset, sizeof(charset));
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = *g_chain_len;
  unsigned long plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  g_memcpy(hash, g_hashes + ((unsigned long)hash_idx * in_hash_len), in_hash_len);
  index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, target_chain_len - 1);

  for (unsigned int i = target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);
    do_hash(hash_type, plaintext, plaintext_len, hash, &hash_len);
    index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, i);
  }

  g_output[out_idx] = index;
}
