BUILD ?= linux
BUILD_DIR := build/$(BUILD)
OBJDIR := $(BUILD_DIR)/obj
INCDIR := $(BUILD_DIR)/include

OUTDIR := .

CC_linux   := gcc
CC_windows := x86_64-w64-mingw32-gcc
STRIP_windows := x86_64-w64-mingw32-strip

TARGET_TRIPLE_windows := x86_64-w64-mingw32
SYSROOT_windows := /usr/$(TARGET_TRIPLE_windows)
OBJDUMP_windows := $(TARGET_TRIPLE_windows)-objdump

CFLAGS_common   := -Wall -O3 -g
CPPFLAGS_common :=
LDFLAGS_common  :=

# Set CPU_OPENCL=1 to run the kernels on a CPU OpenCL device (pocl, Intel's CPU
# runtime, ...) instead of a GPU.  Used by CI, which has no GPU.  This maps to
# the TRAVIS_BUILD define that opencl_setup.c already honors.  Do not ship
# binaries built this way; they will ignore GPUs entirely.
ifeq ($(CPU_OPENCL),1)
  CPPFLAGS_common += -DTRAVIS_BUILD
endif

# RAR-compressed rainbow table support needs libunrar (libunrar-dev on Ubuntu).
# Ubuntu ships no mingw build of it, so Windows defaults to off; rar_decompress.c
# then compiles to a stub that reports a clear error instead of failing the
# build.  Override either way with UNRAR=0 or UNRAR=1.
ifeq ($(BUILD),windows)
  UNRAR ?= 0
else ifeq ($(BUILD),macos)
  UNRAR ?= 0
else
  UNRAR ?= 1
endif

ifeq ($(UNRAR),1)
  CPPFLAGS_common += -DHAVE_UNRAR
endif

EXE :=
LIBS :=
PREP := prep_none

ifeq ($(BUILD),linux)
  CC := $(CC_linux)
  EXE :=
  CPPFLAGS := $(CPPFLAGS_common)
  CFLAGS   := $(CFLAGS_common)
  LDFLAGS  := $(LDFLAGS_common)
  LIBS     := -lpthread -ldl -lgcrypt -lOpenCL
  GPU_BACKEND_OBJ := $(OBJDIR)/opencl_setup.o
endif

ifeq ($(BUILD),linux-cuda)
  # CUDA backend on Linux (NVIDIA only).  Opt-in via make linux-cuda.  Requires
  # the CUDA toolkit + NVIDIA driver; NVRTC JIT-compiles CUDA/*.cu at runtime.
  # The default make linux (OpenCL) path is completely unaffected.
  CC := $(CC_linux)
  EXE :=
  CUDA_PATH ?= /usr/local/cuda
  CPPFLAGS := $(CPPFLAGS_common) -DUSE_CUDA -I$(CUDA_PATH)/include
  CFLAGS   := $(CFLAGS_common)
  LDFLAGS  := $(LDFLAGS_common) -L$(CUDA_PATH)/lib64 -Wl,-rpath,$(CUDA_PATH)/lib64
  LIBS     := -lpthread -ldl -lgcrypt -lcuda -lnvrtc -lm
  GPU_BACKEND_OBJ := $(OBJDIR)/cuda_setup.o
endif

ifeq ($(BUILD),macos)
  # Metal backend on macOS (Apple Silicon).  Shaders compile at runtime via
  # metal_setup.m's newLibraryWithSource:, so no standalone metal toolchain is
  # required.  gcrypt comes from Homebrew (brew install libgcrypt).
  CC := clang
  EXE :=
  CPPFLAGS := $(CPPFLAGS_common) -DUSE_METAL -I/opt/homebrew/include
  CFLAGS   := $(CFLAGS_common)
  LDFLAGS  := $(LDFLAGS_common) -L/opt/homebrew/lib
  LIBS     := -lpthread -lgcrypt -lm -framework Metal -framework Foundation
  GPU_BACKEND_OBJ := $(OBJDIR)/metal_setup.o
endif

ifeq ($(BUILD),windows)
  CC := $(CC_windows)
  EXE := .exe

  CPPFLAGS := $(CPPFLAGS_common) -I$(INCDIR)
  CFLAGS   := $(CFLAGS_common)
  LDFLAGS  := $(LDFLAGS_common)

  LIBS := -lwinpthread -lgcrypt -lgpg-error -lbcrypt -lws2_32

  PREP := prep_opencl_headers
  GPU_BACKEND_OBJ := $(OBJDIR)/opencl_setup.o
endif

GPU_BACKEND_OBJ ?= $(OBJDIR)/opencl_setup.o

# Applied after the per-backend blocks above so every target picks it up.
ifeq ($(UNRAR),1)
  LIBS += -lunrar
endif

# Every backend's host source lives in the tree; compile only the one this
# BUILD selects.  metal_setup.m is Objective-C, so it is never in ALL_SRCS and
# is pulled in through GPU_BACKEND_OBJ and the %.m rule below.
ALL_SRCS := $(wildcard *.c)
ifeq ($(BUILD),linux-cuda)
  SRCS := $(filter-out opencl_setup.c,$(ALL_SRCS))
else ifeq ($(BUILD),macos)
  SRCS := $(filter-out opencl_setup.c cuda_setup.c,$(ALL_SRCS))
else
  SRCS := $(filter-out cuda_setup.c,$(ALL_SRCS))
endif
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

GEN_PROG      := crackalack_gen$(EXE)
UNITTEST_PROG := crackalack_unit_tests$(EXE)
GETCHAIN_PROG := get_chain$(EXE)
VERIFY_PROG   := crackalack_verify$(EXE)
RTC2RT_PROG   := crackalack_rtc2rt$(EXE)
RT2RTC_PROG   := crackalack_rt2rtc$(EXE)
LOOKUP_PROG   := crackalack_lookup$(EXE)
PERFECTIFY    := perfectify$(EXE)
ENUMERATE     := enumerate_chain$(EXE)

BINARIES := \
	$(OUTDIR)/$(GEN_PROG) \
	$(OUTDIR)/$(UNITTEST_PROG) \
	$(OUTDIR)/$(GETCHAIN_PROG) \
	$(OUTDIR)/$(VERIFY_PROG) \
	$(OUTDIR)/$(RTC2RT_PROG) \
	$(OUTDIR)/$(RT2RTC_PROG) \
	$(OUTDIR)/$(LOOKUP_PROG) \
	$(OUTDIR)/$(PERFECTIFY) \
	$(OUTDIR)/$(ENUMERATE)

.PHONY: all linux linux-cuda macos windows clean strip \
        prep_opencl_headers prep_none \
        bundle_windows

all: $(PREP) $(BINARIES)

linux:
	$(MAKE) BUILD=linux all

linux-cuda:
	$(MAKE) BUILD=linux-cuda all

macos:
	$(MAKE) BUILD=macos all

windows:
	$(MAKE) BUILD=windows all bundle_windows

strip: windows
	$(STRIP_windows) $(OUTDIR)/*.exe || true

$(OBJDIR) $(INCDIR):
	mkdir -p $@

prep_none:
	@true

prep_opencl_headers: | $(INCDIR)
	@if [ ! -d /usr/include/CL ]; then \
		echo "ERROR: /usr/include/CL not found. Install OpenCL headers (e.g. opencl-headers)."; \
		exit 1; \
	fi
	@mkdir -p $(INCDIR)/CL
	@cp -a /usr/include/CL/* $(INCDIR)/CL/

DEPFLAGS = -MMD -MP
DEPS := $(OBJS:.o=.d)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

# Objective-C rule for the Metal backend (macos build).  -fobjc-arc is required:
# metal_setup.m relies on ARC bridging (CFBridgingRetain, __bridge, etc.).
$(OBJDIR)/%.o: %.m | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fobjc-arc -c $< -o $@

-include $(DEPS)

$(OUTDIR)/$(GEN_PROG): \
	$(OBJDIR)/charset.o \
	$(OBJDIR)/clock.o \
	$(OBJDIR)/cpu_rt_functions.o \
	$(OBJDIR)/crackalack_gen.o \
	$(OBJDIR)/file_lock.o \
	$(OBJDIR)/gws.o \
	$(OBJDIR)/hash_validate.o \
	$(OBJDIR)/misc.o \
	$(GPU_BACKEND_OBJ) \
	$(OBJDIR)/rtc_decompress.o \
	$(OBJDIR)/verify.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(UNITTEST_PROG): \
	$(OBJDIR)/charset.o \
	$(OBJDIR)/cpu_rt_functions.o \
	$(OBJDIR)/crackalack_unit_tests.o \
	$(OBJDIR)/hash_validate.o \
	$(OBJDIR)/misc.o \
	$(GPU_BACKEND_OBJ) \
	$(OBJDIR)/test_chain.o \
	$(OBJDIR)/test_chain_ntlm9.o \
	$(OBJDIR)/test_hash.o \
	$(OBJDIR)/test_hash_ntlm9.o \
	$(OBJDIR)/test_hash_to_index.o \
	$(OBJDIR)/test_hash_to_index_ntlm9.o \
	$(OBJDIR)/test_index_to_plaintext.o \
	$(OBJDIR)/test_index_to_plaintext_ntlm9.o \
	$(OBJDIR)/test_shared.o \
	$(OBJDIR)/file_lock.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(GETCHAIN_PROG): $(OBJDIR)/get_chain.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(VERIFY_PROG): \
	$(OBJDIR)/charset.o \
	$(OBJDIR)/cpu_rt_functions.o \
	$(OBJDIR)/crackalack_verify.o \
	$(OBJDIR)/file_lock.o \
	$(OBJDIR)/hash_validate.o \
	$(OBJDIR)/misc.o \
	$(OBJDIR)/rtc_decompress.o \
	$(OBJDIR)/verify.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(RTC2RT_PROG): \
	$(OBJDIR)/rtc_decompress.o \
	$(OBJDIR)/crackalack_rtc2rt.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(RT2RTC_PROG): \
	$(OBJDIR)/rtc_compress.o \
	$(OBJDIR)/crackalack_rt2rtc.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(LOOKUP_PROG): \
	$(OBJDIR)/charset.o \
	$(OBJDIR)/clock.o \
	$(OBJDIR)/cpu_rt_functions.o \
	$(OBJDIR)/crackalack_lookup.o \
	$(OBJDIR)/fa_batch.o \
	$(OBJDIR)/file_lock.o \
	$(OBJDIR)/hash_validate.o \
	$(OBJDIR)/misc.o \
	$(GPU_BACKEND_OBJ) \
	$(OBJDIR)/rar_decompress.o \
	$(OBJDIR)/rtc_decompress.o \
	$(OBJDIR)/test_shared.o \
	$(OBJDIR)/verify.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OUTDIR)/$(PERFECTIFY): \
	$(OBJDIR)/clock.o \
	$(OBJDIR)/perfectify.o
	$(CC) $(LDFLAGS) $^ -o $@

$(OUTDIR)/$(ENUMERATE): \
	$(OBJDIR)/cpu_rt_functions.o \
	$(OBJDIR)/enumerate_chain.o \
	$(OBJDIR)/test_shared.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

bundle_windows:
	@echo "Bundling runtime DLLs into $(OUTDIR)..."
	@set -e; \
	cp -u "$(SYSROOT_windows)/bin/libgcrypt-20.dll" "$(OUTDIR)/" 2>/dev/null || true; \
	cp -u "$(SYSROOT_windows)/bin/libgpg-error-0.dll" "$(OUTDIR)/" 2>/dev/null || true; \
	cp -u "$(SYSROOT_windows)/lib/libwinpthread-1.dll" "$(OUTDIR)/" 2>/dev/null || true; \
	for exe in $(OUTDIR)/*.exe; do \
		[ -f "$$exe" ] || continue; \
		echo "  -> $$exe"; \
		"$(OBJDUMP_windows)" -p "$$exe" | awk '/DLL Name:/ {print $$3}' | while read dll; do \
			case "$$dll" in \
				KERNEL32.dll|USER32.dll|ADVAPI32.dll|WS2_32.dll|bcrypt.dll|GDI32.dll|SHELL32.dll|OLE32.dll|OLEAUT32.dll|CRYPT32.dll|ntdll.dll) \
					;; \
				*) \
					found=""; \
					for cand in \
						"$(SYSROOT_windows)/bin/$$dll" \
						"$(SYSROOT_windows)/lib/$$dll"; \
					do \
						if [ -f "$$cand" ]; then cp -u "$$cand" "$(OUTDIR)/"; found=1; break; fi; \
					done; \
					if [ -z "$$found" ]; then \
						src="$$(find "$(SYSROOT_windows)" -type f -iname "$$dll" 2>/dev/null | head -n 1)"; \
						if [ -n "$$src" ]; then cp -u "$$src" "$(OUTDIR)/"; \
						else echo "WARNING: could not locate $$dll on build machine"; fi; \
					fi; \
					;; \
			esac; \
		done; \
	done

clean:
	rm -rf build
	rm -f *.exe \
	      crackalack_gen crackalack_unit_tests get_chain crackalack_verify crackalack_rtc2rt crackalack_lookup perfectify enumerate_chain \
	      libgcrypt-20.dll libgpg-error-0.dll libwinpthread-1.dll
