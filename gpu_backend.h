#ifndef _GPU_BACKEND_H
#define _GPU_BACKEND_H

/*
 * Thin GPU backend selector (Option A).
 *
 * This header does NOT redeclare the rc_cl* wrapper externs or the CL*
 * dispatch macros (CL_RO/WO/RW, CLCREATEARG, CLCREATECONTEXT, CLCREATEQUEUE,
 * CLRUNKERNEL, CLREADBUFFER, CLFREEBUFFER, CLWAIT, CLFLUSH, etc.).  Those
 * remain the property of the backend-specific setup header included below.
 *
 * Its only job is to (a) select a backend and (b) expose backend-neutral
 * gpu_* type names so host code can be written once and compiled against any
 * backend.  Under the default OpenCL build the gpu_* types are plain typedefs
 * to the existing cl_* types, so the compiled result is byte-for-byte
 * identical to the pre-refactor OpenCL build.
 */

#ifdef USE_CUDA

/* CUDA backend (arrives in PR-B).  cuda_setup.h defines the gpu_* types,
 * the dispatch macros, and the rc_* / gpu_* function layer. */
#include "cuda_setup.h"

#elif defined(USE_METAL)

/* Metal backend (not part of this PR).  metal_setup.h would define the
 * gpu_* types and dispatch macros. */
#include "metal_setup.h"

#else /* default: OpenCL backend */

#include "opencl_setup.h"

/* Neutral GPU type names mapped to the OpenCL cl_* equivalents.  Names match
 * bandrel's gpu_backend.h so PR-B's CUDA/Metal typedefs drop in unchanged. */
typedef cl_platform_id   gpu_platform;
typedef cl_device_id     gpu_device;
typedef cl_context       gpu_context;
typedef cl_command_queue gpu_queue;
typedef cl_mem           gpu_buffer;
typedef cl_program       gpu_program;
typedef cl_kernel        gpu_kernel;

typedef cl_uint  gpu_uint;
typedef cl_ulong gpu_ulong;
typedef cl_int   gpu_int;
typedef cl_bool  gpu_bool;

/* Neutral memory-flag / status / bool constants.  Map to the OpenCL values.
 * opencl_setup.h already defines CL_RO/WO/RW; GPU_* are the neutral aliases. */
#define GPU_RO CL_RO
#define GPU_WO CL_WO
#define GPU_RW CL_RW

#define GPU_TRUE  CL_TRUE
#define GPU_FALSE CL_FALSE

#define GPU_SUCCESS CL_SUCCESS

#endif /* backend selection */

#endif /* _GPU_BACKEND_H */
