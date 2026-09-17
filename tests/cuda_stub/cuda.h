/*
 * Rainbow Crackalack: tests/cuda_stub/cuda.h
 *
 * A stand-in for the CUDA driver API header, used only to build cuda_setup.c
 * on a machine with no CUDA toolkit and no GPU.  GitHub-hosted runners have
 * neither, so without this the entire CUDA backend goes untested in CI -- which
 * is how the fixed-size kernel arg table in cuda_setup.c shipped a crash that
 * only appeared after ~32 tables of a real lookup run.
 *
 * This declares just the surface cuda_setup.c actually uses.  It is deliberately
 * NOT a faithful CUDA header: it is never used to build a real binary, and the
 * only thing that has to match is the calling convention of each function.
 * tests/cuda_stub/cuda_stub.c supplies the implementations.
 */
#ifndef _CUDA_STUB_CUDA_H
#define _CUDA_STUB_CUDA_H

#include <stddef.h>

typedef int                 CUdevice;
typedef unsigned long long  CUdeviceptr;
typedef struct CUctx_st    *CUcontext;
typedef struct CUmod_st    *CUmodule;
typedef struct CUfunc_st   *CUfunction;
typedef struct CUstream_st *CUstream;

typedef enum {
  CUDA_SUCCESS                 = 0,
  CUDA_ERROR_INVALID_VALUE     = 1,
  CUDA_ERROR_OUT_OF_MEMORY     = 2,
  CUDA_ERROR_NO_BINARY_FOR_GPU = 209,
  CUDA_ERROR_UNSUPPORTED_PTX_VERSION = 222,
  CUDA_ERROR_INVALID_SOURCE    = 300,
  CUDA_ERROR_NOT_FOUND         = 500,
  CUDA_ERROR_UNKNOWN           = 999
} CUresult;

typedef enum {
  CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK      = 1,
  CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT       = 16,
  CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR   = 75,
  CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR   = 76
} CUdevice_attribute;

typedef enum {
  CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK = 0
} CUfunction_attribute;

#define CU_STREAM_DEFAULT 0

CUresult cuInit(unsigned int flags);
CUresult cuDriverGetVersion(int *version);
CUresult cuDeviceGetCount(int *count);
CUresult cuDeviceGet(CUdevice *device, int ordinal);
CUresult cuDeviceGetName(char *name, int len, CUdevice dev);
CUresult cuDeviceGetAttribute(int *pi, CUdevice_attribute attrib, CUdevice dev);
CUresult cuDeviceTotalMem(size_t *bytes, CUdevice dev);
CUresult cuGetErrorString(CUresult error, const char **str);

CUresult cuCtxCreate_v2(CUcontext *pctx, unsigned int flags, CUdevice dev);
CUresult cuCtxDestroy(CUcontext ctx);
CUresult cuCtxSetCurrent(CUcontext ctx);
CUresult cuCtxPushCurrent(CUcontext ctx);
CUresult cuCtxPopCurrent(CUcontext *pctx);

CUresult cuStreamCreate(CUstream *stream, unsigned int flags);
CUresult cuStreamSynchronize(CUstream stream);
CUresult cuStreamDestroy(CUstream stream);

CUresult cuMemAlloc(CUdeviceptr *dptr, size_t size);
CUresult cuMemFree(CUdeviceptr dptr);
CUresult cuMemcpyHtoD(CUdeviceptr dst, const void *src, size_t size);
CUresult cuMemcpyDtoH(void *dst, CUdeviceptr src, size_t size);
CUresult cuMemGetInfo(size_t *free, size_t *total);

CUresult cuModuleLoadData(CUmodule *module, const void *image);
CUresult cuModuleGetFunction(CUfunction *func, CUmodule mod, const char *name);
CUresult cuModuleUnload(CUmodule mod);
CUresult cuFuncGetAttribute(int *pi, CUfunction_attribute attrib, CUfunction func);

CUresult cuLaunchKernel(CUfunction f,
                        unsigned int gridDimX,  unsigned int gridDimY,  unsigned int gridDimZ,
                        unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ,
                        unsigned int sharedMemBytes, CUstream stream,
                        void **kernelParams, void **extra);

#endif /* _CUDA_STUB_CUDA_H */
