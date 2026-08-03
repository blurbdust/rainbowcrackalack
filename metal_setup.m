/*
 * Rainbow Crackalack: metal_setup.m
 * Metal compute backend for macOS Apple Silicon.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms version 3 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <mach-o/dyld.h>

#include "gpu_backend.h"
#include "misc.h"


/* Internal struct wrapping a Metal compute pipeline and its arg bindings. */
typedef struct {
  id<MTLComputePipelineState> pipeline;
  id<MTLLibrary> library;
  id<MTLBuffer> args[32];
  unsigned int num_args;
  /* Threadgroup memory allocations: size > 0 means allocate at that index. */
  size_t threadgroup_mem_sizes[8];
  unsigned int num_threadgroup_mem;
} metal_kernel;


/* Internal struct wrapping a Metal command queue and its owning device.
 * The semaphore is used for async dispatch: gpu_enqueue_kernel signals it
 * via a completion handler, and gpu_finish waits on it. */
typedef struct {
  id<MTLCommandQueue> queue;
  id<MTLDevice> device;
  dispatch_semaphore_t completion;
  volatile int pending;          /* 1 if a dispatch is in flight */
  id<MTLCommandBuffer> last_cmd; /* retained for error checking in gpu_finish */
} metal_queue;


void context_callback(const char *errinfo, const void *private_info, size_t cb, void *user_data) {
  printf("\n\n\tError callback invoked!\n\n\terrinfo: %s\n\n", errinfo);
}


void get_platforms_and_devices(int disable_platform, gpu_uint platforms_buffer_size, gpu_platform *platforms, gpu_uint *num_platforms, gpu_uint devices_buffer_size, gpu_device *devices, gpu_uint *num_devices, unsigned int verbose) {
  @autoreleasepool {
    NSArray<id<MTLDevice>> *allDevices = MTLCopyAllDevices();

    *num_platforms = 1;
    if (platforms != NULL)
      platforms[0] = (gpu_platform)CFBridgingRetain(@"Apple");

    *num_devices = 0;

    if (allDevices == nil || [allDevices count] == 0) {
      /* Fall back to the system default device. */
      id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
      if (dev == nil) {
        fprintf(stderr, "No Metal-compatible GPU found.\n");
        exit(-1);
      }
      devices[0] = (gpu_device)CFBridgingRetain(dev);
      *num_devices = 1;
    } else {
      for (NSUInteger i = 0; i < [allDevices count] && *num_devices < devices_buffer_size; i++) {
        devices[*num_devices] = (gpu_device)CFBridgingRetain(allDevices[i]);
        (*num_devices)++;
      }
    }

    if (verbose) {
      printf("Operating system: %s\n", get_os_name());
      printf("Found %u Metal device(s).\n", *num_devices);
      print_device_info(devices, *num_devices);
    }
  }
}


void get_device_bool(gpu_device device, unsigned int param, gpu_bool *b) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)device;
    switch (param) {
      case GPU_DEVICE_AVAILABLE:
        *b = (dev != nil) ? GPU_TRUE : GPU_FALSE;
        break;
      default:
        *b = GPU_FALSE;
        break;
    }
  }
}


void get_device_str(gpu_device device, unsigned int param, char *buf, int buf_len) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)device;
    const char *str = "";
    switch (param) {
      case GPU_DEVICE_NAME:
        str = [[dev name] UTF8String];
        break;
      case GPU_DEVICE_VERSION:
        str = "Metal";
        break;
      case GPU_DEVICE_VENDOR:
        str = "Apple";
        break;
      case GPU_DRIVER_VERSION:
        str = "Metal";
        break;
      default:
        str = "Unknown";
        break;
    }
    strncpy(buf, str, buf_len);
    buf[buf_len - 1] = '\0';
  }
}


void get_device_uint(gpu_device device, unsigned int param, gpu_uint *u) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)device;
    (void)dev;
    switch (param) {
      case GPU_DEVICE_MAX_COMPUTE_UNITS:
        /* Metal does not expose compute unit count directly.
         * Return a reasonable default for Apple Silicon. */
        *u = 10;
        break;
      default:
        *u = 0;
        break;
    }
  }
}


void get_device_ulong(gpu_device device, unsigned int param, gpu_ulong *ul) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)device;
    switch (param) {
      case GPU_DEVICE_GLOBAL_MEM_SIZE:
        *ul = [dev recommendedMaxWorkingSetSize];
        break;
      case GPU_DEVICE_MAX_WORK_GROUP_SIZE:
        /* Will be refined per-pipeline in gpu_get_kernel_work_group_info. */
        *ul = 256;
        break;
      default:
        *ul = 0;
        break;
    }
  }
}


/* Read a file into a malloc'd buffer. Caller must free(). Returns NULL on error. */
static char *read_file_to_string(const char *path) {
  FILE *f = fopen(path, "r");
  if (f == NULL)
    return NULL;

  fseek(f, 0, SEEK_END);
  long file_size = ftell(f);
  rewind(f);

  if (file_size < 0) {
    fclose(f);
    return NULL;
  }

  char *buf = calloc(file_size + 1, sizeof(char));
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }

  long bytes_read = 0;
  while (bytes_read < file_size) {
    long n = fread(buf + bytes_read, 1, file_size - bytes_read, f);
    if (n <= 0) {
      free(buf);
      fclose(f);
      return NULL;
    }
    bytes_read += n;
  }
  fclose(f);
  return buf;
}


/* Directory containing the running executable (the repo root, where the Metal/
 * kernel dir and shared.h live).  Lets kernel/include lookups succeed no matter
 * what the current working directory is.  macOS analogue of cuda_setup.c's
 * cuda_exe_dir() (which uses /proc/self/exe).  Returns 1 on success, 0 if
 * unavailable (caller then falls back to CWD-relative lookup only). */
static int metal_exe_dir(char *buf, size_t buf_size) {
  char raw[PATH_MAX];
  uint32_t rawsize = sizeof(raw);
  if (_NSGetExecutablePath(raw, &rawsize) != 0)
    return 0;   /* path didn't fit (rawsize now holds the required size) */
  char resolved[PATH_MAX];
  if (realpath(raw, resolved) == NULL) {
    strncpy(resolved, raw, sizeof(resolved) - 1);
    resolved[sizeof(resolved) - 1] = '\0';
  }
  char *slash = strrchr(resolved, '/');
  if (!slash)
    return 0;
  *slash = '\0';   /* strip the executable basename, leaving its directory */
  if (strlen(resolved) >= buf_size)
    return 0;
  strcpy(buf, resolved);
  return 1;
}


/* Read a kernel/include file, trying the CWD-relative path first (fast path
 * when run from the repo root), then the same path anchored at the executable's
 * directory, so binaries work from any working dir (e.g. a table-output dir).
 * `subdir` is "Metal" or NULL/"" for the project root.  malloc'd, caller frees. */
static char *read_kernel_file_anydir(const char *subdir, const char *name) {
  char path[1024];
  if (subdir && *subdir)
    filepath_join(path, sizeof(path), subdir, name);
  else {
    strncpy(path, name, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
  }
  char *src = read_file_to_string(path);
  if (src != NULL)
    return src;

  char exedir[PATH_MAX];
  if (metal_exe_dir(exedir, sizeof(exedir))) {
    char p[1024 + PATH_MAX];
    if (subdir && *subdir)
      snprintf(p, sizeof(p), "%s/%s/%s", exedir, subdir, name);
    else
      snprintf(p, sizeof(p), "%s/%s", exedir, name);
    src = read_file_to_string(p);
  }
  return src;
}


/* Resolve #include "..." directives by inlining file contents.
 * Metal's runtime compiler does not support include paths.
 * Search directories: "Metal/" and "." (project root for shared.h).
 * Uses an include guard set to prevent infinite recursion. */
static NSString *resolve_includes(const char *source, NSMutableSet *included) {
  NSMutableString *result = [NSMutableString string];
  const char *pos = source;

  while (*pos != '\0') {
    /* Check for #include "filename" */
    if (strncmp(pos, "#include \"", 10) == 0) {
      const char *start = pos + 10;
      const char *end = strchr(start, '"');
      if (end != NULL) {
        char filename[256] = {0};
        size_t len = end - start;
        if (len >= sizeof(filename))
          len = sizeof(filename) - 1;
        strncpy(filename, start, len);

        NSString *key = [NSString stringWithUTF8String:filename];
        if ([included containsObject:key]) {
          /* Skip to end of line. */
          pos = end + 1;
          while (*pos != '\0' && *pos != '\n')
            pos++;
          if (*pos == '\n')
            pos++;
          continue;
        }

        [included addObject:key];

        /* Try Metal/ first, then project root -- each relative to CWD and then
         * to the executable's directory (so includes resolve from any CWD). */
        char *inc_source = read_kernel_file_anydir("Metal", filename);
        if (inc_source == NULL) {
          inc_source = read_kernel_file_anydir(NULL, filename);
        }

        if (inc_source != NULL) {
          NSString *resolved = resolve_includes(inc_source, included);
          [result appendString:resolved];
          [result appendString:@"\n"];
          free(inc_source);
        } else {
          fprintf(stderr, "Warning: could not resolve #include \"%s\"\n", filename);
          /* Keep the line as-is so the Metal compiler reports the error. */
          while (*pos != '\0' && *pos != '\n') {
            [result appendFormat:@"%c", *pos];
            pos++;
          }
          if (*pos == '\n') {
            [result appendString:@"\n"];
            pos++;
          }
          continue;
        }

        /* Advance past #include line. */
        pos = end + 1;
        while (*pos != '\0' && *pos != '\n')
          pos++;
        if (*pos == '\n')
          pos++;
        continue;
      }
    }

    /* Also skip #include <metal_stdlib> and similar - Metal handles these natively. */
    if (strncmp(pos, "#include <", 10) == 0) {
      while (*pos != '\0' && *pos != '\n') {
        [result appendFormat:@"%c", *pos];
        pos++;
      }
      if (*pos == '\n') {
        [result appendString:@"\n"];
        pos++;
      }
      continue;
    }

    /* Copy character. */
    [result appendFormat:@"%c", *pos];
    pos++;
  }

  return result;
}


void load_kernel(gpu_context context, gpu_uint num_devices, const gpu_device *devices, const char *source_filename, const char *kernel_name, gpu_program *program, gpu_kernel *kernel, unsigned int hash_type) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)devices[0];

    char path[256] = {0};
    /* Change .cl extension to .metal */
    char metal_filename[256] = {0};
    strncpy(metal_filename, source_filename, sizeof(metal_filename) - 1);
    char *dot = strrchr(metal_filename, '.');
    if (dot != NULL && strcmp(dot, ".cl") == 0) {
      strcpy(dot, ".metal");
    }
    /* Populate 'path' up front so all error messages below (compile / function
     * lookup failures) report the kernel name, not an empty string. */
    filepath_join(path, sizeof(path), "Metal", metal_filename);

    /* Resolve the kernel file relative to CWD first, then to the executable's
     * directory, so lookup/generation work from any working dir. */
    char *raw_source = read_kernel_file_anydir("Metal", metal_filename);
    if (raw_source == NULL) {
      fprintf(stderr, "Failed to open Metal kernel: %s (tried CWD and executable dir)\n", path);
      exit(-1);
    }

    /* Resolve all #include "..." directives by inlining. */
    NSMutableSet *included = [NSMutableSet set];
    NSString *sourceStr = resolve_includes(raw_source, included);
    free(raw_source);

    /* Build options: define HASH_TYPE as a preprocessor macro. */
    MTLCompileOptions *opts = [[MTLCompileOptions alloc] init];
    if (@available(macOS 15.0, *)) {
      opts.mathMode = MTLMathModeFast;
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      opts.fastMathEnabled = YES;
#pragma clang diagnostic pop
    }
    NSMutableDictionary *defines = [NSMutableDictionary dictionary];
    defines[@"HASH_TYPE"] = [NSString stringWithFormat:@"%u", hash_type];
    opts.preprocessorMacros = defines;

    NSError *error = nil;
    id<MTLLibrary> library = [dev newLibraryWithSource:sourceStr options:opts error:&error];
    if (library == nil) {
      fprintf(stderr, "Failed to compile Metal kernel '%s':\n%s\n", path, [[error localizedDescription] UTF8String]);
      exit(-1);
    }

    id<MTLFunction> function = [library newFunctionWithName:[NSString stringWithUTF8String:kernel_name]];
    if (function == nil) {
      fprintf(stderr, "Failed to find function '%s' in Metal kernel '%s'.\n", kernel_name, path);
      exit(-1);
    }

    id<MTLComputePipelineState> pipeline = [dev newComputePipelineStateWithFunction:function error:&error];
    if (pipeline == nil) {
      fprintf(stderr, "Failed to create compute pipeline for '%s': %s\n", kernel_name, [[error localizedDescription] UTF8String]);
      exit(-1);
    }

    metal_kernel *mk = calloc(1, sizeof(metal_kernel));
    if (mk == NULL) {
      fprintf(stderr, "Failed to allocate metal_kernel struct.\n");
      exit(-1);
    }
    mk->pipeline = pipeline;
    mk->library = library;
    mk->num_args = 0;

    /* Retain the Objective-C objects so they survive beyond this autorelease pool. */
    CFBridgingRetain(pipeline);
    CFBridgingRetain(library);

    *program = (gpu_program)mk;
    *kernel = (gpu_kernel)mk;
  }
}


void print_device_info(gpu_device *devices, gpu_uint num_devices) {
  for (unsigned int i = 0; i < num_devices; i++) {
    char device_name[64] = {0};
    char device_version[64] = {0};
    char device_vendor[128] = {0};
    char device_driver[128] = {0};
    gpu_bool b = GPU_FALSE;
    gpu_uint max_compute_units = 0;
    gpu_ulong global_memsize = 0;
    gpu_ulong max_work_group_size = 0;

    get_device_str(devices[i], GPU_DEVICE_NAME, device_name, sizeof(device_name) - 1);
    get_device_str(devices[i], GPU_DEVICE_VERSION, device_version, sizeof(device_version) - 1);
    get_device_str(devices[i], GPU_DEVICE_VENDOR, device_vendor, sizeof(device_vendor) - 1);
    get_device_bool(devices[i], GPU_DEVICE_AVAILABLE, &b);
    get_device_uint(devices[i], GPU_DEVICE_MAX_COMPUTE_UNITS, &max_compute_units);
    get_device_ulong(devices[i], GPU_DEVICE_GLOBAL_MEM_SIZE, &global_memsize);
    get_device_ulong(devices[i], GPU_DEVICE_MAX_WORK_GROUP_SIZE, &max_work_group_size);
    get_device_str(devices[i], GPU_DRIVER_VERSION, device_driver, sizeof(device_driver) - 1);

    printf("Device #%d:\n", i);
    printf("\tVendor: %s\n", device_vendor);
    printf("\tName: %s\n", device_name);
    printf("\tVersion: %s\n", device_version);
    printf("\tDriver: %s\n", device_driver);
    printf("\tMax compute units: %u\n", max_compute_units);
    printf("\tMax work group size: %"PRIu64"\n", max_work_group_size);
    printf("\tGlobal memory size: %"PRIu64"\n", global_memsize);
    if (b == GPU_FALSE)
      printf("\t---> NOT AVAILABLE!\n");
    printf("\n");
  }
  fflush(stdout);
}


void gpu_release_device(gpu_device device) {
  if (device != NULL)
    CFRelease(device);
}


/* --- Low-level backend operations --- */

gpu_context gpu_create_context(gpu_device device) {
  /* In Metal, the device IS the context. Just retain and return it. */
  if (device != NULL)
    CFRetain(device);
  return device;
}


gpu_queue gpu_create_queue(gpu_context context, gpu_device device) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)device;

    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (q == nil) {
      fprintf(stderr, "Failed to create Metal command queue.\n");
      return NULL;
    }

    metal_queue *mq = calloc(1, sizeof(metal_queue));
    if (mq == NULL) {
      fprintf(stderr, "Failed to allocate metal_queue struct.\n");
      return NULL;
    }
    mq->queue = q;
    mq->device = dev;
    mq->completion = dispatch_semaphore_create(0);
    mq->pending = 0;
    mq->last_cmd = nil;

    CFBridgingRetain(q);

    return (gpu_queue)mq;
  }
}


gpu_buffer gpu_create_buffer(gpu_context context, int flags, size_t size) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)context;
    (void)flags; /* Metal shared memory buffers support read/write from both CPU and GPU. */

    id<MTLBuffer> buf = [dev newBufferWithLength:size options:MTLResourceStorageModeShared];
    if (buf == nil) {
      fprintf(stderr, "Failed to create Metal buffer of size %zu.\n", size);
      return NULL;
    }

    return (gpu_buffer)CFBridgingRetain(buf);
  }
}


gpu_buffer gpu_create_and_fill_buffer(gpu_context context, int flags, size_t size, const void *data) {
  @autoreleasepool {
    id<MTLDevice> dev = (__bridge id<MTLDevice>)context;

    if (flags == GPU_RO) {
      /* Private storage: GPU-only, optimal for read-only data that's written once.
       * Use a staging Shared buffer + blit command to copy data. */
      id<MTLBuffer> staging = [dev newBufferWithLength:size options:MTLResourceStorageModeShared];
      if (staging == nil) {
        fprintf(stderr, "Failed to create staging buffer of size %zu.\n", size);
        return NULL;
      }
      memcpy([staging contents], data, size);

      id<MTLBuffer> priv = [dev newBufferWithLength:size options:MTLResourceStorageModePrivate];
      if (priv == nil) {
        fprintf(stderr, "Failed to create private buffer of size %zu.\n", size);
        return NULL;
      }

      id<MTLCommandQueue> q = [dev newCommandQueue];
      id<MTLCommandBuffer> cmd = [q commandBuffer];
      id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
      [blit copyFromBuffer:staging sourceOffset:0 toBuffer:priv destinationOffset:0 size:size];
      [blit endEncoding];
      [cmd commit];
      [cmd waitUntilCompleted];

      return (gpu_buffer)CFBridgingRetain(priv);
    }

    /* Shared storage for RW/WO buffers. */
    id<MTLBuffer> buf = [dev newBufferWithLength:size options:MTLResourceStorageModeShared];
    if (buf == nil) {
      fprintf(stderr, "Failed to create shared buffer of size %zu.\n", size);
      return NULL;
    }
    memcpy([buf contents], data, size);
    return (gpu_buffer)CFBridgingRetain(buf);
  }
}


int gpu_write_buffer(gpu_queue queue, gpu_buffer buffer, size_t size, const void *ptr) {
  @autoreleasepool {
    /* Ensure any in-flight dispatch is complete before modifying buffer. */
    metal_queue *mq = (metal_queue *)queue;
    if (mq->pending)
      gpu_finish(queue);

    id<MTLBuffer> buf = (__bridge id<MTLBuffer>)buffer;
    /* Private (GPU_RO) buffers have no host-accessible pointer; contents is nil.
     * Guard so a misdirected write fails loudly instead of nil-deref crashing. */
    void *dst = [buf contents];
    if (dst == NULL) {
      fprintf(stderr, "gpu_write_buffer: buffer is not host-accessible (private storage).\n");
      return -1;
    }
    memcpy(dst, ptr, size);
    return 0;
  }
}


int gpu_read_buffer(gpu_queue queue, gpu_buffer buffer, size_t size, void *ptr) {
  @autoreleasepool {
    /* Ensure any in-flight dispatch is complete before reading buffer. */
    metal_queue *mq = (metal_queue *)queue;
    if (mq->pending)
      gpu_finish(queue);

    id<MTLBuffer> buf = (__bridge id<MTLBuffer>)buffer;
    void *src = [buf contents];
    if (src == NULL) {
      fprintf(stderr, "gpu_read_buffer: buffer is not host-accessible (private storage).\n");
      return -1;
    }
    memcpy(ptr, src, size);
    return 0;
  }
}


int gpu_set_kernel_arg(gpu_kernel kernel, unsigned int index, size_t size, const void *value) {
  metal_kernel *mk = (metal_kernel *)kernel;
  if (index >= 32) {
    fprintf(stderr, "Kernel argument index %u exceeds maximum (32).\n", index);
    return -1;
  }

  /* The value points to a gpu_buffer (which is a retained MTLBuffer). */
  gpu_buffer buf = *(gpu_buffer *)value;
  mk->args[index] = (__bridge id<MTLBuffer>)buf;

  if (index >= mk->num_args)
    mk->num_args = index + 1;

  return 0;
}


int gpu_set_kernel_threadgroup_mem(gpu_kernel kernel, unsigned int index, size_t size) {
  metal_kernel *mk = (metal_kernel *)kernel;
  if (index >= 8) {
    fprintf(stderr, "Threadgroup memory index %u exceeds maximum (8).\n", index);
    return -1;
  }
  mk->threadgroup_mem_sizes[index] = size;
  if (index >= mk->num_threadgroup_mem)
    mk->num_threadgroup_mem = index + 1;
  return 0;
}


int gpu_enqueue_kernel(gpu_queue queue, gpu_kernel kernel, unsigned int work_dim, const size_t *global_work_size) {
  @autoreleasepool {
    metal_queue *mq = (metal_queue *)queue;
    metal_kernel *mk = (metal_kernel *)kernel;

    id<MTLCommandBuffer> commandBuffer = [mq->queue commandBuffer];
    if (commandBuffer == nil) {
      fprintf(stderr, "Failed to create Metal command buffer.\n");
      return -1;
    }

    id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
    if (encoder == nil) {
      fprintf(stderr, "Failed to create Metal compute command encoder.\n");
      return -1;
    }

    [encoder setComputePipelineState:mk->pipeline];

    /* Bind all stored buffer arguments. */
    for (unsigned int i = 0; i < mk->num_args; i++) {
      if (mk->args[i] != nil) {
        [encoder setBuffer:mk->args[i] offset:0 atIndex:i];
      }
    }

    /* Bind threadgroup memory allocations. */
    for (unsigned int i = 0; i < mk->num_threadgroup_mem; i++) {
      if (mk->threadgroup_mem_sizes[i] > 0) {
        [encoder setThreadgroupMemoryLength:mk->threadgroup_mem_sizes[i] atIndex:i];
      }
    }

    NSUInteger gws = global_work_size[0];
    NSUInteger maxThreads = [mk->pipeline maxTotalThreadsPerThreadgroup];
    NSUInteger threadWidth = [mk->pipeline threadExecutionWidth];

    /* Use 8 SIMD groups per threadgroup (256 threads on M-series) for better
     * occupancy and latency hiding.  Capped at the pipeline's max. */
    NSUInteger threadgroupSize = threadWidth * 8;
    if (threadgroupSize > maxThreads)
      threadgroupSize = maxThreads;
    if (threadgroupSize > gws)
      threadgroupSize = gws;

    MTLSize gridSize = MTLSizeMake(gws, 1, 1);
    MTLSize groupSize = MTLSizeMake(threadgroupSize, 1, 1);

    [encoder dispatchThreads:gridSize threadsPerThreadgroup:groupSize];
    [encoder endEncoding];

    /* Async dispatch: signal the semaphore on completion so gpu_finish
     * can wait without blocking during the encode/commit phase. */
    mq->pending = 1;
    mq->last_cmd = commandBuffer;
    CFBridgingRetain(commandBuffer);

    dispatch_semaphore_t sem = mq->completion;
    [commandBuffer addCompletedHandler:^(id<MTLCommandBuffer> _Nonnull buf) {
      (void)buf;
      dispatch_semaphore_signal(sem);
    }];
    [commandBuffer commit];

    return 0;
  }
}


int gpu_flush(gpu_queue queue) {
  /* Metal dispatches are synchronous via commit+wait, so flush is a no-op. */
  (void)queue;
  return 0;
}


int gpu_finish(gpu_queue queue) {
  metal_queue *mq = (metal_queue *)queue;
  if (!mq->pending)
    return 0;

  dispatch_semaphore_wait(mq->completion, DISPATCH_TIME_FOREVER);
  mq->pending = 0;

  int ret = 0;
  if (mq->last_cmd != nil) {
    if ([mq->last_cmd error] != nil) {
      fprintf(stderr, "Metal command buffer error: %s\n",
              [[[mq->last_cmd error] localizedDescription] UTF8String]);
      ret = -1;
    }
    CFRelease((__bridge CFTypeRef)mq->last_cmd);
    mq->last_cmd = nil;
  }
  return ret;
}


/* VRAM-budget waiting is a CUDA-only feature; report "unsupported" so callers
 * skip waiting on Metal. */
int gpu_get_free_memory(gpu_device device, uint64_t *free_bytes, uint64_t *total_bytes) {
  (void)device; (void)free_bytes; (void)total_bytes;
  return -1;
}


/* Backend-neutral VRAM budget wait.  On Metal, gpu_get_free_memory reports
 * "unsupported", so this is a no-op (matches the OpenCL backend behavior). */
void gpu_wait_for_free_vram(gpu_device device, uint64_t needed_bytes) {
  (void)device; (void)needed_bytes;
}


int gpu_get_kernel_work_group_info(gpu_kernel kernel, gpu_device device, unsigned int param, size_t param_size, void *param_value) {
  metal_kernel *mk = (metal_kernel *)kernel;
  (void)device;

  switch (param) {
    case GPU_KERNEL_WORK_GROUP_SIZE:
      if (param_size >= sizeof(size_t))
        *(size_t *)param_value = (size_t)[mk->pipeline maxTotalThreadsPerThreadgroup];
      break;
    case GPU_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE:
      if (param_size >= sizeof(size_t))
        *(size_t *)param_value = (size_t)[mk->pipeline threadExecutionWidth];
      break;
    default:
      return -1;
  }
  return 0;
}


void gpu_release_buffer(gpu_buffer buffer) {
  if (buffer != NULL)
    CFRelease(buffer);
}


void gpu_release_queue(gpu_queue queue) {
  if (queue != NULL) {
    metal_queue *mq = (metal_queue *)queue;
    if (mq->pending)
      gpu_finish(queue);
    if (mq->last_cmd != nil)
      CFRelease((__bridge CFTypeRef)mq->last_cmd);
    if (mq->queue != nil)
      CFRelease((__bridge CFTypeRef)mq->queue);
    /* dispatch_semaphore_t is ARC-managed on modern macOS; no manual release needed. */
    free(mq);
  }
}


void gpu_release_context(gpu_context context) {
  if (context != NULL)
    CFRelease(context);
}


void gpu_release_kernel(gpu_kernel kernel) {
  if (kernel != NULL) {
    metal_kernel *mk = (metal_kernel *)kernel;
    if (mk->pipeline != nil)
      CFRelease((__bridge CFTypeRef)mk->pipeline);
    if (mk->library != nil)
      CFRelease((__bridge CFTypeRef)mk->library);
    free(mk);
  }
}


void gpu_release_program(gpu_program program) {
  /* The kernel and program share the same metal_kernel struct.
   * Release is handled in gpu_release_kernel. */
  (void)program;
}
