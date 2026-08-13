/*
 * Rainbow Crackalack: tests/cuda_stub/nvrtc.h
 *
 * Stand-in for NVRTC, the runtime CUDA compiler.  See cuda.h in this directory
 * for why these stubs exist.  The stub "compiles" any source to a fixed
 * placeholder PTX string, which is enough for cuda_setup.c's load_kernel to run
 * end to end with no toolkit installed.
 */
#ifndef _CUDA_STUB_NVRTC_H
#define _CUDA_STUB_NVRTC_H

#include <stddef.h>

typedef struct _nvrtcProgram *nvrtcProgram;

typedef enum {
  NVRTC_SUCCESS = 0,
  NVRTC_ERROR_COMPILATION = 6
} nvrtcResult;

const char *nvrtcGetErrorString(nvrtcResult result);
nvrtcResult nvrtcCreateProgram(nvrtcProgram *prog, const char *src, const char *name,
                               int num_headers, const char **headers, const char **include_names);
nvrtcResult nvrtcCompileProgram(nvrtcProgram prog, int num_options, const char **options);
nvrtcResult nvrtcGetProgramLogSize(nvrtcProgram prog, size_t *log_size);
nvrtcResult nvrtcGetProgramLog(nvrtcProgram prog, char *log);
nvrtcResult nvrtcGetPTXSize(nvrtcProgram prog, size_t *ptx_size);
nvrtcResult nvrtcGetPTX(nvrtcProgram prog, char *ptx);
nvrtcResult nvrtcDestroyProgram(nvrtcProgram *prog);

#endif /* _CUDA_STUB_NVRTC_H */
