#include <metal_stdlib>
using namespace metal;

#include "rt.metal"
#include "string.metal"


/* Generic precomputation kernel, the Metal counterpart of CL/precompute.cl.
 * The NTLM8/NTLM9 tables have their own optimized kernels; every other hash
 * type, Net-NTLMv1 included, goes through this one.
 *
 * Buffer indices match the OpenCL argument order so the host binds identically. */
kernel void precompute(
    device unsigned int *g_hash_type [[buffer(0)]],
    device unsigned char *g_hash [[buffer(1)]],
    device unsigned int *g_hash_len [[buffer(2)]],
    device char *g_charset [[buffer(3)]],
    device unsigned int *g_plaintext_len_min [[buffer(4)]],
    device unsigned int *g_plaintext_len_max [[buffer(5)]],
    device unsigned int *g_table_index [[buffer(6)]],
    device ulong *g_chain_len [[buffer(7)]],
    device unsigned int *g_device_num [[buffer(8)]],
    device unsigned int *g_total_devices [[buffer(9)]],
    device unsigned int *g_exec_block_scaler [[buffer(10)]],
    device ulong *g_output [[buffer(11)]],
    uint gid [[thread_position_in_grid]]) {

  /* Each thread walks the chain from a different starting position.  Computed
   * in unsigned 64-bit and range-checked before subtracting, so an underflow
   * cannot masquerade as a huge positive length. */
  ulong base = *g_chain_len - (ulong)(*g_device_num);
  ulong span = (ulong)(gid + *g_exec_block_scaler) * (ulong)(*g_total_devices);

  if (base < span + 2) {   /* i.e. target_chain_len < 1 */
    g_output[gid] = 0;
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
  unsigned int hash_len = *g_hash_len;
  unsigned int charset_len = g_strncpy(charset, g_charset, MAX_CHARSET_LEN);
  unsigned int plaintext_len_min = *g_plaintext_len_min;
  unsigned int plaintext_len_max = *g_plaintext_len_max;
  unsigned int reduction_offset = TABLE_INDEX_TO_REDUCTION_OFFSET(*g_table_index);
  unsigned int chain_len = (unsigned int)(*g_chain_len);
  ulong plaintext_space_total = fill_plaintext_space_table(charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index);

  g_memcpy(hash, g_hash, hash_len);
  index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, (unsigned int)(target_chain_len - 1));

  for (unsigned int i = (unsigned int)target_chain_len; i < chain_len - 1; i++) {
    index_to_plaintext(index, charset, charset_len, plaintext_len_min, plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);
    do_hash(hash_type, plaintext, plaintext_len, hash, &hash_len);
    index = hash_to_index(hash, hash_len, reduction_offset, plaintext_space_total, i);
  }

  g_output[gid] = index;
}
