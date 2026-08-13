#include <metal_stdlib>
using namespace metal;

#include "rt.metal"
#include "string.metal"


/* Batched generic precomputation, the Metal counterpart of CL/precompute_batch.cl.
 *
 * Identical chain walk to precompute.metal, but a single dispatch covers ALL
 * hashes instead of one.  Precomputation is O(chain_len^2) per hash and used to
 * run once per hash, sequentially, so N hashes cost N times one hash.
 *
 * Widening the dispatch along the *position* axis does not help -- the thread at
 * position p walks (chain_len - p) steps, so a wider chunk runs at the speed of
 * its longest walk while the short ones idle.  The *hash* axis is free of that:
 * every hash at a given position walks exactly the same number of steps, so
 * adding hashes multiplies parallelism without adding divergence.
 *
 * Buffer indices match the OpenCL argument order so the host binds identically. */
kernel void precompute_batch(
    device unsigned int *g_hash_type [[buffer(0)]],
    device unsigned char *g_hashes [[buffer(1)]],
    device unsigned int *g_hash_len [[buffer(2)]],
    device unsigned int *g_num_hashes [[buffer(3)]],
    device char *g_charset [[buffer(4)]],
    device unsigned int *g_plaintext_len_min [[buffer(5)]],
    device unsigned int *g_plaintext_len_max [[buffer(6)]],
    device unsigned int *g_table_index [[buffer(7)]],
    device ulong *g_chain_len [[buffer(8)]],
    device unsigned int *g_device_num [[buffer(9)]],
    device unsigned int *g_total_devices [[buffer(10)]],
    device unsigned int *g_chunk_positions [[buffer(11)]],
    device unsigned int *g_pos_start [[buffer(12)]],
    device unsigned int *g_output_len [[buffer(13)]],
    device ulong *g_output [[buffer(14)]],
    uint gid [[thread_position_in_grid]]) {

  unsigned int chunk_positions = *g_chunk_positions;
  unsigned int hash_idx = gid / chunk_positions;
  unsigned int local_pos = gid % chunk_positions;

  if (hash_idx >= *g_num_hashes)
    return;

  /* Index into this device's slice of the output. */
  unsigned int k = *g_pos_start + local_pos;
  unsigned int output_len = *g_output_len;
  if (k >= output_len)
    return;

  ulong out_idx = ((ulong)hash_idx * (ulong)output_len) + k;

  /* Computed in unsigned 64-bit and range-checked before subtracting, so an
   * underflow cannot masquerade as a huge positive length. */
  ulong base = *g_chain_len - (ulong)(*g_device_num);
  ulong span = (ulong)k * (ulong)(*g_total_devices);

  if (base < span + 2) {   /* i.e. target_chain_len < 1 */
    g_output[out_idx] = 0;
    return;
  }
  ulong target_chain_len = base - span - 1;

  char charset[MAX_CHARSET_LEN];
  ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN];
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  ulong index;

  unsigned int hash_type = *g_hash_type;
  unsigned int in_hash_len = *g_hash_len;   /* hash_len below is mutated by do_hash */
  unsigned int hash_len = in_hash_len;
  unsigned int charset_len = g_strncpy(charset, g_charset, MAX_CHARSET_LEN);
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)(*g_chain_len);
  ulong plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  g_memcpy(hash, g_hashes + ((ulong)hash_idx * in_hash_len), in_hash_len);
  index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, (unsigned int)(target_chain_len - 1));

  for (unsigned int i = (unsigned int)target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);
    do_hash(hash_type, plaintext, plaintext_len, hash, &hash_len);
    index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, i);
  }

  g_output[out_idx] = index;
}
