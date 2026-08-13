/*
 * Rainbow Crackalack: tests/cuda_stub/cuda_stub.h
 *
 * Test-only control surface for the fake CUDA driver in cuda_stub.c.
 */
#ifndef _CUDA_STUB_H
#define _CUDA_STUB_H

#include <stdint.h>
#include <stdio.h>

#include <cuda.h>

/* How many kernel argument slots cuLaunchKernel captures.  Matches
 * CUDA_MAX_KERNEL_ARGS in cuda_setup.c; every slot is always populated there,
 * so reading this many is safe. */
#define CUDA_STUB_MAX_CAPTURED_ARGS 32

/* When on, every cuModuleGetFunction returns the SAME CUfunction address,
 * modelling a driver that reuses an unloaded module's function address. */
void cuda_stub_set_recycle_functions(int on);

/* Outstanding cuMemAlloc / cuModuleLoadData counts. */
int  cuda_stub_live_allocations(void);
int  cuda_stub_live_modules(void);

/* Copy up to `max` argument values from the most recent cuLaunchKernel into
 * `out`; returns how many were copied. */
unsigned int cuda_stub_last_launch_args(CUdeviceptr *out, unsigned int max);
void cuda_stub_reset_launch_args(void);

#endif /* _CUDA_STUB_H */
