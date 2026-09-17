#include "rt.cu"
#include "string.cu"


/* Batched generic precomputation, the CUDA counterpart of CL/precompute_batch.cl.
 *
 * Identical chain walk to precompute.cu, but a single dispatch covers ALL
 * hashes instead of one.  Precomputation is O(chain_len^2) per hash and used to
 * run once per hash, sequentially, so N hashes cost N times one hash.
 *
 * Widening the dispatch along the *position* axis does not help -- the thread at
 * position p walks (chain_len - p) steps, so a wider chunk runs at the speed of
 * its longest walk while the short ones idle.  The *hash* axis is free of that:
 * every hash at a given position walks exactly the same number of steps, so
 * adding hashes multiplies parallelism without adding divergence.  N hashes
 * therefore cost about the same wall time as one.
 *
 * Parameter order must match the arg indices bound in host_thread_precompute()
 * (crackalack_lookup.c): cuLaunchKernel reads a pointer for every declared
 * parameter, so the list has to line up exactly. */
extern "C" __global__ void precompute_batch(
    unsigned int *g_hash_type,
    unsigned char *g_hashes,
    unsigned int *g_hash_len,
    unsigned int *g_num_hashes,
    char *g_charset,
    unsigned int *g_plaintext_len_min,
    unsigned int *g_plaintext_len_max,
    unsigned int *g_table_index,
    unsigned long long *g_chain_len,
    unsigned int *g_device_num,
    unsigned int *g_total_devices,
    unsigned int *g_chunk_positions,
    unsigned int *g_pos_start,
    unsigned int *g_output_len,
    unsigned long long *g_output) {

  unsigned int chunk_positions = *g_chunk_positions;
  unsigned int gid = (blockIdx.x * blockDim.x + threadIdx.x);
  unsigned int hash_idx = gid / chunk_positions;
  unsigned int local_pos = gid % chunk_positions;

  if (hash_idx >= *g_num_hashes)
    return;

  /* Index into this device's slice of the output. */
  unsigned int k = *g_pos_start + local_pos;
  unsigned int output_len = *g_output_len;
  if (k >= output_len)
    return;

  unsigned long long out_idx = ((unsigned long long)hash_idx * (unsigned long long)output_len) + k;

  /* Computed in signed 64-bit so an underflow stays negative and is caught
   * below, rather than wrapping to a huge positive length. */
  long long chain_len_ll = (long long)(*g_chain_len);
  long long target_chain_len = (chain_len_ll - (long long)(*g_device_num)) -
      ((long long)k * (long long)(*g_total_devices)) - 1;

  if (target_chain_len < 1) {
    g_output[out_idx] = 0;
    return;
  }

  char charset[MAX_CHARSET_LEN];
  unsigned long long plaintext_space_up_to_index[MAX_PLAINTEXT_LEN + 1];
  unsigned char hash[MAX_HASH_OUTPUT_LEN];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned int plaintext_len = 0;
  unsigned long long index;

  unsigned int hash_type = *g_hash_type;
  unsigned int in_hash_len = *g_hash_len;   /* hash_len below is mutated by do_hash */
  unsigned int hash_len = in_hash_len;
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)chain_len_ll;

  /* g_strncpy copies all n bytes and does not stop at a NUL, which matters:
   * the 'byte' charset begins with 0x00, so stopping would leave charset_len
   * at 0 and collapse the plaintext space to zero. */
  unsigned int charset_len = g_copy_charset(charset, g_charset, MAX_CHARSET_LEN);
  unsigned long long plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  g_memcpy(hash, g_hashes + ((unsigned long long)hash_idx * in_hash_len), in_hash_len);
  index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, (unsigned int)(target_chain_len - 1));

  for (unsigned int i = (unsigned int)target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);
    do_hash(hash_type, plaintext, plaintext_len, hash, &hash_len);
    index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, i);
  }

  g_output[out_idx] = index;
}
