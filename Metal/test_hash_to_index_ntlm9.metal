#include <metal_stdlib>
using namespace metal;

#include "ntlm9_functions.metal"

kernel void test_hash_to_index_ntlm9(
    device ulong *g_hash [[buffer(0)]],
    device unsigned int *g_pos [[buffer(1)]],
    device ulong *g_index [[buffer(2)]],
    uint gid [[thread_position_in_grid]]) {

  *g_index = hash_to_index_ntlm9((ulong)*g_hash, (unsigned int)*g_pos);

}
