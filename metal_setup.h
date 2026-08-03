#ifndef _METAL_SETUP_H
#define _METAL_SETUP_H

/*
 * Rainbow Crackalack: metal_setup.h
 *
 * Metal compute backend header for macOS (Apple Silicon).  This is the
 * Metal analogue of opencl_setup.h: blurbdust's thin gpu_backend.h does
 *   #ifdef USE_METAL -> #include "metal_setup.h"
 * and nothing else, so this single header must supply EVERYTHING the
 * OpenCL build gets from BOTH gpu_backend.h and opencl_setup.h:
 *
 *   - the backend-neutral gpu_* typedefs
 *   - the GPU_RO/WO/RW, GPU_SUCCESS, GPU_TRUE/FALSE constants (+ CL_* aliases)
 *   - the device/kernel-info parameter constants (+ CL_* aliases)
 *   - GPU_KERNEL_PATH / DEFAULT_BUILD_OPTIONS
 *   - the CL* dispatch macros (CLCREATEARG*, CLCREATECONTEXT, CLCREATEQUEUE,
 *     CLRUNKERNEL, CLREADBUFFER, CLWRITEBUFFER, CLFREEBUFFER, CLWAIT, CLFLUSH,
 *     CLRELEASE*, CLMAKETESTVARS)
 *   - declarations for every function metal_setup.m defines
 *
 * All of the above are sourced from bandrel's fat gpu_backend.h USE_METAL
 * branches and from what metal_setup.m actually implements.
 *
 * IMPORTANT: this header is #included by plain C host translation units, so
 * it must NOT reference any Objective-C / Metal framework types.  The gpu_*
 * handle types are therefore opaque `void *`; the concrete id<MTLDevice> etc.
 * casts live entirely inside metal_setup.m.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_NUM_PLATFORMS 32
#define MAX_NUM_DEVICES 32


/* --- Backend-neutral GPU handle / scalar types --- */
typedef void *gpu_platform;
typedef void *gpu_device;
typedef void *gpu_context;
typedef void *gpu_queue;
typedef void *gpu_buffer;
typedef void *gpu_program;
typedef void *gpu_kernel;

typedef uint32_t gpu_uint;
typedef uint64_t gpu_ulong;
typedef int32_t  gpu_int;
typedef int      gpu_bool;


/* --- Memory-flag / status / bool constants --- */
#define GPU_RO  0x1
#define GPU_WO  0x2
#define GPU_RW  0x3

#define GPU_TRUE  1
#define GPU_FALSE 0

#define GPU_SUCCESS 0

/* Legacy CL_ flag aliases for compatibility with existing macros/host code. */
#define CL_RO GPU_RO
#define CL_WO GPU_WO
#define CL_RW GPU_RW

#define CL_TRUE  GPU_TRUE
#define CL_FALSE GPU_FALSE
#define CL_SUCCESS GPU_SUCCESS


/* --- Kernel build options / paths --- */
#define DEFAULT_BUILD_OPTIONS "-I. -IMetal"

/* GPU_KERNEL_PATH("basename") -> "basename.metal".  metal_setup.m's
 * load_kernel() also rewrites a caller-supplied ".cl" path to ".metal" and
 * prepends the Metal/ kernel dir at runtime, so callers may pass either. */
#define GPU_KERNEL_DIR ""
#define GPU_KERNEL_EXT ".metal"
#define GPU_KERNEL_PATH(basename) GPU_KERNEL_DIR basename GPU_KERNEL_EXT


/* --- Device info parameter constants (arbitrary but stable numeric IDs;
 *     match the values metal_setup.m switches on) --- */
#define GPU_DEVICE_NAME                 1
#define GPU_DEVICE_VERSION              2
#define GPU_DEVICE_VENDOR               3
#define GPU_DEVICE_AVAILABLE            4
#define GPU_DEVICE_MAX_COMPUTE_UNITS    5
#define GPU_DEVICE_GLOBAL_MEM_SIZE      6
#define GPU_DEVICE_MAX_WORK_GROUP_SIZE  7
#define GPU_DRIVER_VERSION              8

#define GPU_KERNEL_WORK_GROUP_SIZE                       1
#define GPU_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE    2

/* CL_ aliases so host code that still uses CL_ names (e.g. gws.c) compiles. */
#define CL_DEVICE_NAME                GPU_DEVICE_NAME
#define CL_DEVICE_VERSION             GPU_DEVICE_VERSION
#define CL_DEVICE_VENDOR              GPU_DEVICE_VENDOR
#define CL_DEVICE_AVAILABLE           GPU_DEVICE_AVAILABLE
#define CL_DEVICE_MAX_COMPUTE_UNITS   GPU_DEVICE_MAX_COMPUTE_UNITS
#define CL_DEVICE_GLOBAL_MEM_SIZE     GPU_DEVICE_GLOBAL_MEM_SIZE
#define CL_DEVICE_MAX_WORK_GROUP_SIZE GPU_DEVICE_MAX_WORK_GROUP_SIZE
#define CL_DRIVER_VERSION             GPU_DRIVER_VERSION

#define CL_KERNEL_WORK_GROUP_SIZE                    GPU_KERNEL_WORK_GROUP_SIZE
#define CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE GPU_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE


/* --- Function declarations (implemented in metal_setup.m) --- */

void context_callback(const char *errinfo, const void *private_info, size_t cb, void *user_data);

void get_platforms_and_devices(int disable_platform, gpu_uint platforms_buffer_size, gpu_platform *platforms, gpu_uint *num_platforms, gpu_uint devices_buffer_size, gpu_device *devices, gpu_uint *num_devices, unsigned int verbose);

void get_device_bool(gpu_device device, unsigned int param, gpu_bool *b);
void get_device_str(gpu_device device, unsigned int param, char *buf, int buf_len);
void get_device_uint(gpu_device device, unsigned int param, gpu_uint *u);
void get_device_ulong(gpu_device device, unsigned int param, gpu_ulong *ul);

void load_kernel(gpu_context context, gpu_uint num_devices, const gpu_device *devices, const char *path, const char *kernel_name, gpu_program *program, gpu_kernel *kernel, unsigned int hash_type);

void print_device_info(gpu_device *devices, gpu_uint num_devices);

void gpu_release_device(gpu_device device);


/* --- Low-level backend operations --- */

gpu_context gpu_create_context(gpu_device device);
gpu_queue   gpu_create_queue(gpu_context context, gpu_device device);
gpu_buffer  gpu_create_buffer(gpu_context context, int flags, size_t size);
gpu_buffer  gpu_create_and_fill_buffer(gpu_context context, int flags, size_t size, const void *data);
int gpu_write_buffer(gpu_queue queue, gpu_buffer buffer, size_t size, const void *ptr);
int gpu_read_buffer(gpu_queue queue, gpu_buffer buffer, size_t size, void *ptr);
int gpu_set_kernel_arg(gpu_kernel kernel, unsigned int index, size_t size, const void *value);
int gpu_set_kernel_threadgroup_mem(gpu_kernel kernel, unsigned int index, size_t size);
int gpu_enqueue_kernel(gpu_queue queue, gpu_kernel kernel, unsigned int work_dim, const size_t *global_work_size);
int gpu_flush(gpu_queue queue);
int gpu_finish(gpu_queue queue);
int gpu_get_free_memory(gpu_device device, uint64_t *free_bytes, uint64_t *total_bytes);
int gpu_get_kernel_work_group_info(gpu_kernel kernel, gpu_device device, unsigned int param, size_t param_size, void *param_value);
void gpu_release_buffer(gpu_buffer buffer);
void gpu_release_queue(gpu_queue queue);
void gpu_release_context(gpu_context context);
void gpu_release_kernel(gpu_kernel kernel);
void gpu_release_program(gpu_program program);

/* Backend-neutral: blocks until enough GPU memory is free.  No-op on Metal
 * (gpu_get_free_memory reports "unsupported"), provided for API symmetry. */
void gpu_wait_for_free_vram(gpu_device device, uint64_t needed_bytes);


/* --- Per-thread context lifecycle ---
 * CUDA requires per-thread attach/detach; OpenCL and Metal do not. */
#define gpu_thread_attach() ((void)0)
#define gpu_thread_detach() ((void)0)


/* --- Convenience / dispatch macros (Metal semantics) --- */

#define CLMAKETESTVARS() \
  int err = 0; \
  size_t global_work_size = 1; \
  gpu_queue queue = NULL;

#define _CLCREATEARG(_arg_index, _buffer, _flags, _arg_ptr, _arg_size) \
  { _buffer = gpu_create_and_fill_buffer(context, _flags, _arg_size, _arg_ptr); \
  if (_buffer == NULL) { fprintf(stderr, "Error while creating buffer for \"%s\".\n", #_arg_ptr); exit(-1); } \
  if (gpu_set_kernel_arg(kernel, _arg_index, sizeof(gpu_buffer), &_buffer) != 0) { fprintf(stderr, "Error setting kernel argument for %s at index %u.\n", #_arg_ptr, _arg_index); exit(-1); } }

#define CLCREATEARG_ARRAY(_arg_index, _buffer, _flags, _arg, _len) \
  _CLCREATEARG(_arg_index, _buffer, _flags, _arg, _len);

#define CLCREATEARG(_arg_index, _buffer, _flags, _arg, _arg_size) \
  _CLCREATEARG(_arg_index, _buffer, _flags, &_arg, _arg_size);

/* CLCREATEARG_DEBUG allocates *_debug_ptr internally via calloc.
 * Do NOT pre-allocate _debug_ptr before calling this macro. */
#define CLCREATEARG_DEBUG(_arg_index, _debug_buffer, _debug_ptr) \
  { _debug_ptr = calloc(DEBUG_LEN, sizeof(unsigned char)); \
    CLCREATEARG_ARRAY(_arg_index, _debug_buffer, GPU_RW, _debug_ptr, DEBUG_LEN); }

#define CLCREATECONTEXT(_context_callback, _device_ptr) \
  gpu_create_context(*(_device_ptr))

/* Suppress -Wunused-variable for 'err' (defined in CLMAKETESTVARS): Metal's
 * gpu_create_queue returns the queue directly rather than setting an error
 * code, so err is only written later by CLRUNKERNEL/CLFLUSH/CLWAIT. */
#define CLCREATEQUEUE(_context, _device) \
  ((void)err, gpu_create_queue(_context, _device))

#define CLRUNKERNEL(_queue, _kernel, _gws_ptr) \
  { err = gpu_enqueue_kernel(_queue, _kernel, 1, _gws_ptr); if (err != 0) { fprintf(stderr, "gpu_enqueue_kernel failed: %d\n", err); exit(-1); } }

#define CLFLUSH(_queue) \
  { err = gpu_flush(_queue); if (err != 0) { fprintf(stderr, "gpu_flush failed: %d\n", err); exit(-1); } }

#define CLWAIT(_queue) \
  { err = gpu_finish(_queue); if (err != 0) { fprintf(stderr, "gpu_finish failed: %d\n", err); exit(-1); } }

#define CLWRITEBUFFER(_buffer, _len, _ptr) \
  { err = gpu_write_buffer(queue, _buffer, _len, _ptr); \
  if (err != 0) { fprintf(stderr, "gpu_write_buffer failed: %d\n", err); exit(-1); } }

#define CLREADBUFFER(_buffer, _len, _ptr) \
  { err = gpu_read_buffer(queue, _buffer, _len, _ptr); if (err != 0) { fprintf(stderr, "gpu_read_buffer failed: %d\n", err); exit(-1); } }

#define CLFREEBUFFER(_buffer) \
  if (_buffer != NULL) { gpu_release_buffer(_buffer); _buffer = NULL; }

#define CLRELEASEQUEUE(_queue) \
  if (_queue != NULL) { gpu_release_queue(_queue); _queue = NULL; }

#define CLRELEASECONTEXT(_context) \
  if (_context != NULL) { gpu_release_context(_context); _context = NULL; }

#define CLRELEASEKERNEL(_kernel) \
  if (_kernel != NULL) { gpu_release_kernel(_kernel); _kernel = NULL; }

#define CLRELEASEPROGRAM(_program) \
  if (_program != NULL) { gpu_release_program(_program); _program = NULL; }

#endif /* _METAL_SETUP_H */
