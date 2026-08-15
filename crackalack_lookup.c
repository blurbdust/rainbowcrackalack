/*
 * Rainbow Crackalack: crackalack_lookup.c
 * Copyright (C) 2018-2021  Joe Testa <jtesta@positronsecurity.com>
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

/*
 * Performs GPU-accelerated password hash lookups on rainbow tables.
 */

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <unistd.h>
#define O_BINARY 0
#else
#include <sys/sysinfo.h>
#define O_BINARY 0
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <pthread.h>
#include "compat.h"  /* pthread_barrier_* shim on macOS (no-op elsewhere) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "gpu_backend.h"

#include "charset.h"
#include "clock.h"
#include "cpu_rt_functions.h"
#include "fa_batch.h"
#include "hash_validate.h"
#include "misc.h"
#include "ppi.h"
#include "rar_decompress.h"
#include "rtc_decompress.h"
#include "shared.h"
#include "test_shared.h"  /* TODO: move hex_to_bytes() elsewhere. */
#include "verify.h"
#include "version.h"

#define VERBOSE 1
#define PRECOMPUTE_KERNEL_PATH "precompute.cl"
#define PRECOMPUTE_BATCH_KERNEL_PATH "precompute_batch.cl"
#define PRECOMPUTE_NETNTLMV1_7_BATCH_KERNEL_PATH "precompute_netntlmv1_7_batch.cl"
#define FALSE_ALARM_NETNTLMV1_7_KERNEL_PATH "false_alarm_check_netntlmv1_7.cl"

/* The Net-NTLMv1 kernels take the DES plaintext as an argument, and it is now
 * selected by hash type via netntlmv1_challenge_for(): the server challenge for
 * "netntlmv1", or the LM magic constant "KGS!@#$%" for "netntlmv1-lm".  The
 * kernels derive the initial-permutation state at runtime, so nothing is
 * specialized for one particular value any more. */
#define PRECOMPUTE_NTLM8_KERNEL_PATH "precompute_ntlm8.cl"
#define PRECOMPUTE_NTLM9_KERNEL_PATH "precompute_ntlm9.cl"
#define PRECOMPUTE_NETNTLMV1_KERNEL_PATH "precompute_netntlmv1.cl"

#define FALSE_ALARM_KERNEL_PATH "false_alarm_check.cl"
#define FALSE_ALARM_NTLM8_KERNEL_PATH "false_alarm_check_ntlm8.cl"
#define FALSE_ALARM_NTLM9_KERNEL_PATH "false_alarm_check_ntlm9.cl"
#define FALSE_ALARM_NETNTLMV1_KERNEL_PATH "false_alarm_check_netntlv1.cl"

#define HASH_FILE_FORMAT_PLAIN 1
#define HASH_FILE_FORMAT_PWDUMP 2


/* precomputed_and_potential_indices lives in ppi.h so fa_batch.c can see it. */


/* Struct to represent one GPU device. */
typedef struct {
  gpu_uint device_number;
  gpu_device device;
  gpu_context context;
  gpu_program program;
  gpu_kernel kernel;
  gpu_queue queue;
  gpu_uint num_work_units;
} gpu_dev;


/* Struct to pass arguments to a host thread. */
typedef struct {
  unsigned int hash_type;
  char *hash_name;
  char *username; /* Non-NULL when pwdump format input file given. */
  char *hash; /* In hex. */
  char *charset;
  char *charset_name;
  unsigned int plaintext_len_min;
  unsigned int plaintext_len_max;
  unsigned int table_index;
  unsigned int reduction_offset;
  unsigned int chain_len;

  unsigned int total_devices;
  uint64_t *results;
  unsigned int num_results;

  /* Batched precomputation: one dispatch covers several hashes at once.
   * batch_hashes holds num_batch_hashes hex strings; results then holds
   * num_batch_hashes * num_results entries, hash-major. */
  char **batch_hashes;
  unsigned int num_batch_hashes;

  gpu_ulong *potential_start_indices;
  unsigned int num_potential_start_indices;
  
  /* Buffer size is always num_potential_start_indices. */
  unsigned int *potential_start_index_positions;
  
  /* Length is always num_potential_start_indices. */
  gpu_ulong *hash_base_indices;

  gpu_dev gpu;
} thread_args;


/* Struct to pass to binary search threads. */
typedef struct {
  gpu_ulong *rainbow_table;
  unsigned int num_chains;
  precomputed_and_potential_indices *ppi_head;
  unsigned int thread_number;
  unsigned int total_threads;
} search_thread_args;


/* Struct to hold node in linked list of preloaded tables. */
struct _preloaded_table {
  char *filepath;
  gpu_ulong *rainbow_table;
  unsigned int num_chains;
  struct _preloaded_table *next;
};
typedef struct _preloaded_table preloaded_table;

typedef struct {
  char *rt_dir;
} preloading_thread_args;


unsigned int count_tables(char *dir);
void find_rt_params(char *dir, rt_parameters *rt_params);
void free_loaded_hashes(char **usernames, char **hashes);
void *host_thread_false_alarm(void *ptr);
void *host_thread_precompute(void *ptr);
void *host_thread_precompute_batch(void *ptr);
void build_precompute_index_data(char *buf, size_t buf_size, const thread_args *args, const char *hash);
void precompute_hash(unsigned int num_devices, thread_args *args, precomputed_and_potential_indices **ppi_head, int results_ready, unsigned int batch_slot);
void precompute_hashes(unsigned int num_devices, thread_args *args, precomputed_and_potential_indices **ppi_head, char **usernames, char **hashes, unsigned int num_hashes);
void *preloading_thread(void *ptr);
void stop_table_loading(void);
void print_eta_precompute();
gpu_ulong *search_precompute_cache(char *index_data, unsigned int *num_indices, char *filename, unsigned int filename_size);
void search_tables(unsigned int total_tables, precomputed_and_potential_indices *ppi, thread_args *args);
void save_cracked_hash(precomputed_and_potential_indices *ppi, unsigned int hash_type);


/* The path of the pot file to store cracked hashes in.  This can be overridden by
 * a command line arg. */
/* Sized generously (PATH_MAX-class) so a long user-supplied pot path plus the
 * appended ".hashcat" suffix cannot silently truncate.  At 128 bytes a deep path
 * (a CI build directory, say) truncated ".hashcat" to ".hash", so the hashcat
 * pot went to the wrong filename and looked like a failed write. */
char jtr_pot_filename[4096] = "rainbowcrackalack_jtr.pot";
char hashcat_pot_filename[4096] = "rainbowcrackalack_hashcat.pot";

/* The number of seconds spent on precomputation, file I/O, searching, and false alarm
 * checking. */
double time_precomp = 0, time_io = 0, time_searching = 0, time_falsealarms = 0;

/* The total number of false alarms, chains processed, respectively. */
uint64_t num_falsealarms = 0, num_chains_processed = 0;

/* The total number of hashes cracked in this invokation and number of tables
 * processed, respectively. */
unsigned int num_cracked = 0, num_tables_processed = 0;

/* Mutex to protect the precomputed_and_potential_indices array. _*/
pthread_mutex_t ppi_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Barrier to ensure that kernels on multiple devices are all run at the same time.
 * The closed-source AMD driver on Windows effectively blocks other devices while
 * one kernel is running; this ensures parallelization in that environment, since
 * all kernels will run at once.  The open source AMD ROCm driver on Linux may or
 * may not get a very slight performance bump with this enabled. */
pthread_barrier_t barrier = {0};

/* Set to 1 if AMD GPUs found. */
unsigned int is_amd_gpu = 0;

/* The global work size, as over-ridden by the user on the command line. */
size_t user_provided_gws = 0;

/* How many false-alarm candidates to pool across tables before dispatching them
 * to the GPU (see fa_batch.h).  1 disables pooling, restoring the historical
 * one-dispatch-per-table behaviour.  Override with -fa-batch. */
unsigned int fa_batch_threshold = 16384;

/* Global work size for the precompute phase, as overridden on the command line.
 * 0 means "one work group per compute unit", which measurement says is as good
 * as anything: sweeping this from 12288 up to a single whole-output dispatch on
 * an RTX 4000 SFF Ada moved precompute by under 20% and did not even move
 * monotonically, and the ordering flipped between chain lengths.  Precompute is
 * not occupancy-limited, so this exists to retune a specific GPU rather than
 * because a better default is known.  tests/bench_precompute.py sweeps it. */
size_t user_provided_precompute_gws = 0;

/* Largest number of hashes precomputed in a single dispatch.  Each GPU holds a
 * (group size * positions per device * 8) byte output buffer, which at a
 * production chain length is a few MB per hash, so this bounds VRAM rather than
 * speed.  Override with -precompute-batch. */
#define PRECOMPUTE_BATCH_MAX_DEFAULT 32
unsigned int PRECOMPUTE_BATCH_MAX = PRECOMPUTE_BATCH_MAX_DEFAULT;

/* The platform number to disable (-1 to not disable any). */
int disable_platform = -1;

/* The total number of precomputed indices loaded into memory.  Each one of these is
 * a gpu_ulong (8 bytes). */
uint64_t total_precomputed_indices_loaded = 0;

/* Set to 1 if the NTLM8/9 message was printed.  This prevents console spam. */
unsigned int printed_precompute_optimized_message = 0;
unsigned int printed_false_alarm_optimized_message = 0;

/* The total number of tables in all subdirectories of the directory given
 * by the user. */
unsigned int total_tables = 0;

/* Set to 1 by the preloading thread to indicate that no more tables exist for loading. */
unsigned int table_loading_complete = 0;

/* The current size of the preloaded tables list. */
unsigned int num_preloaded_tables_available = 0;

/* A linked list of preloaded tables. */
preloaded_table *preloaded_table_list = NULL;

/* Condition for the main thread to wait for more tables on. */
pthread_cond_t condition_wait_for_tables = PTHREAD_COND_INITIALIZER;

/* Condition for the preloading thread to wait on (when the MAX_PRELOAD_NUM is reached). */
pthread_cond_t condition_continue_loading_tables = PTHREAD_COND_INITIALIZER;

/* The lock for the preloaded tables system. */
pthread_mutex_t preloaded_tables_lock = PTHREAD_MUTEX_INITIALIZER;

/* The time at which precomputation begins. */
struct timespec precompute_start_time = {0};

/* The time at which table searching begins. */
struct timespec search_start_time = {0};

/* Number of uncracked hashes. */
unsigned int num_hashes = 0;

/* Number of hashes precomputed so far. */
unsigned int num_hashes_precomputed = 0;

/* Total number of hashes that will be precomputed. */
unsigned int num_hashes_precomputed_total = 0;


/* The number of tables allowed in memory at once while binary searching and
 * false alarm checking is done by the main thread.
 *
 * This used to be a hard 2, loaded by a single thread.  That made table loading
 * the bottleneck of the whole run: with a window of 2 the loader can only ever
 * be one table ahead, so the consumer spent most of its time blocked waiting for
 * the next read.  It is now a runtime value sized against the loader thread
 * count and clamped to a fraction of system RAM, since each in-flight table is
 * held whole in memory (2 GiB apiece for the Net-NTLMv1 set).
 *
 * Override with MAX_PRELOAD_NUM in the environment. */
#define MAX_PRELOAD_NUM_DEFAULT 2
unsigned int max_preload_num = MAX_PRELOAD_NUM_DEFAULT;

/* How many threads read tables concurrently.  Override with RCRACK_LOAD_THREADS. */
unsigned int num_load_threads = 1;

/* Fraction of total RAM the in-flight table window is allowed to occupy. */
#define PRELOAD_RAM_FRACTION 4   /* i.e. one quarter */

#define LOCK_PPI() \
  if (pthread_mutex_lock(&ppi_mutex)) { perror("Failed to lock mutex"); exit(-1); }

#define UNLOCK_PPI() \
  if (pthread_mutex_unlock(&ppi_mutex)) { perror("Failed to unlock mutex"); exit(-1); }


/* Adds a potential start index (and position within the chain) to check for false
 * alarms. */
void add_potential_start_index_and_position(precomputed_and_potential_indices *ppi, gpu_ulong start, unsigned int position) {
  #define POTENTIAL_START_INDICES_INITIAL_SIZE 16

  LOCK_PPI();

  /* Initialize the potential_start_indices buffer if it isn't already. */
  if (ppi->potential_start_indices == NULL) {
    ppi->potential_start_indices = calloc(POTENTIAL_START_INDICES_INITIAL_SIZE, sizeof(gpu_ulong));
    ppi->potential_start_index_positions = calloc(POTENTIAL_START_INDICES_INITIAL_SIZE, sizeof(gpu_ulong));
    if ((ppi->potential_start_indices == NULL) || (ppi->potential_start_index_positions == NULL)) {
      fprintf(stderr, "Failed to initialize potential_start_indices / potential_start_index_positions buffer.\n");
      exit(-1);
    }
    ppi->potential_start_indices_size = POTENTIAL_START_INDICES_INITIAL_SIZE;
  }

  /* If its time to re-size the array... */
  if (ppi->num_potential_start_indices == ppi->potential_start_indices_size) {
    unsigned int new_size_in_ulongs = ppi->potential_start_indices_size * 2;

    /*printf("Resizing array from %u to %u.\n", ppi->potential_start_indices_size, new_size_in_ulongs);*/
    ppi->potential_start_indices = recalloc(ppi->potential_start_indices, new_size_in_ulongs * sizeof(gpu_ulong), ppi->potential_start_indices_size * sizeof(gpu_ulong));
    ppi->potential_start_index_positions = recalloc(ppi->potential_start_index_positions, new_size_in_ulongs * sizeof(gpu_ulong), ppi->potential_start_indices_size * sizeof(gpu_ulong));
    if ((ppi->potential_start_indices == NULL) || (ppi->potential_start_index_positions == NULL)) {
      fprintf(stderr, "Failed to re-allocate potential_start_indices/potential_start_index_positions buffer to %u.\n", new_size_in_ulongs);
      exit(-1);
    }
    ppi->potential_start_indices_size = new_size_in_ulongs;
  }
  ppi->potential_start_indices[ppi->num_potential_start_indices] = start;
  ppi->potential_start_index_positions[ppi->num_potential_start_indices] = position;
  ppi->num_potential_start_indices++;

  UNLOCK_PPI();
}


/* Dispatch the false-alarm kernel for every candidate currently pooled in
 * `batch`, then map the results back onto the hashes they came from.
 *
 * The candidates no longer come from a single table: search_tables() pools them
 * across tables and calls this once the pool is big enough to keep the GPU busy
 * (see fa_batch.h).  `batch` stays untouched here -- the caller resets it after
 * this returns, which is safe because this function does not return until every
 * device thread has been joined and its results consumed. */
/* Zero-padded charset buffer for the device.
 *
 * Every generic kernel copies a fixed MAX_CHARSET_LEN bytes (g_copy_charset) and
 * derives charset_len from a strlen of that copy, so the buffer must be that
 * large and NUL-padded.  Sizing it at charset_len left the kernel reading past
 * the end and depending on the allocator having zeroed it. */
static const char *padded_charset(const char *charset, unsigned int charset_len) {
  static char buf[MAX_CHARSET_LEN];
  memset(buf, 0, sizeof(buf));
  memcpy(buf, charset, (charset_len < MAX_CHARSET_LEN) ? charset_len : MAX_CHARSET_LEN);
  return buf;
}


void check_false_alarms(fa_batch_t *batch, thread_args *args) {
  pthread_t threads[MAX_NUM_DEVICES] = {0};
  char time_str[128] = {0};
  struct timespec start_time = {0};
  gpu_ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN] = {0};

  unsigned int num_potential_start_indices = batch->num_candidates;
  unsigned int i = 0, j = 0;
  unsigned int total_devices = args[0].total_devices;
  double time_delta = 0.0;

  precomputed_and_potential_indices **ppi_refs = batch->ppi_refs;


  /* If no potential matches were pooled, there's nothing else to do. */
  if (num_potential_start_indices == 0) {
    printf("No matches found in batch.\n");
    return;
  }
  printf("  Checking %u potential matches (across %u table%s)...\n",
         num_potential_start_indices, batch->tables_in_batch,
         (batch->tables_in_batch == 1) ? "" : "s");
  fflush(stdout);
  num_falsealarms += num_potential_start_indices;

  int charset_len = 0;
  if (strcmp(args->charset_name, "byte") == 0) {
    charset_len = 256;
  }
  else {
    /* Bare strlen, NOT strlen+1: this is the radix for the plaintext space, not a
     * buffer size.  The +1 conflated the two and made every non-'byte' charset
     * compute its space as 96^n instead of 95^n, so lookups found a candidate in
     * the endpoint search and then rejected it in the false-alarm check.  The
     * 'byte' charset is unaffected (both give 256), which is why Net-NTLMv1
     * tables always worked.  Matches crackalack_gen.c and verify.c. */
    charset_len = (strlen(args->charset) == 0) ? 256 : strlen(args->charset);
  }

  fill_plaintext_space_table(charset_len, args->plaintext_len_min, args->plaintext_len_max, plaintext_space_up_to_index);

  /* Order candidates by chain position before dispatch.  Adjacent work items
   * land in the same work group, and the kernel walks each chain from its start
   * index to its recorded position, so a group with mixed positions runs at the
   * speed of its longest walk.  Sorting is the single biggest win in this path. */
  fa_batch_sort_by_position(batch);

  /* Start the timer false alarm checking. */
  start_timer(&start_time);

  /* Start one thread to control each GPU. */
  for (i = 0; i < total_devices; i++) {

    /* Each thread gets the same reference to the list of potential start indices. */
    args[i].potential_start_indices = batch->start_indices;
    args[i].num_potential_start_indices = num_potential_start_indices;
    args[i].potential_start_index_positions = batch->start_index_positions;
    args[i].hash_base_indices = batch->hash_base_indices;

    if (pthread_create(&(threads[i]), NULL, &host_thread_false_alarm, &(args[i]))) {
      perror("Failed to create thread");
      exit(-1);
    }
    //printf("********************************** host_thread_false_alarm created\n");
  }

  /* Wait for all threads to finish. */
  for (i = 0; i < total_devices; i++) {
    if (pthread_join(threads[i], NULL) != 0) {
      perror("Failed to join with thread");
      exit(-1);
    }
  }
  //printf("********************************** host_thread_false_alarm joined\n");

  /* Search for valid results, and update the ppi with the plaintext. */
  for (i = 0; i < total_devices; i++) {
    for (j = 0; j < args[i].num_results; j++) {
      /* A batch can hold several candidates for the same hash, and more than
       * one of them can be genuine.  Without this the second one would overwrite
       * (and leak) the plaintext, write the pot file again and double-count the
       * crack. */
      if ((j < num_potential_start_indices) && (ppi_refs[j]->plaintext != NULL))
        continue;

      if (args[i].results[j] != 0) {
      	char plaintext[MAX_PLAINTEXT_LEN] = {0};
      	unsigned int plaintext_len = 0;
        unsigned char real_key[8] = {0};


      	index_to_plaintext(args[i].results[j], args[i].charset, charset_len, args[i].plaintext_len_min, args[i].plaintext_len_max, plaintext_space_up_to_index, plaintext, &plaintext_len);

      	/* Double check NTLM results to weed out super false alarms. */
      	if (args[i].hash_type == HASH_NTLM) {
      	  unsigned char hash[16] = {0};
      	  char hash_hex[(sizeof(hash) * 2) + 1] = {0};


      	  ntlm_hash(plaintext, plaintext_len, hash);
      	  if (!bytes_to_hex(hash, sizeof(hash), hash_hex, sizeof(hash_hex)) || \
      	      (strcmp(hash_hex, ppi_refs[j]->hash) != 0)) {
      	    /*printf("Found super false positive!: NTLM('%s') != %s\n", plaintext, ppi_refs[j]->hash);*/
      	    continue;
      	  }
      	} else if (is_netntlmv1_family(args[i].hash_type)) {

          unsigned char hash[8] = {0};
          char hash_hex[(sizeof(hash) * 2) + 1] = {0};
          char rkey_hex[(sizeof(hash) * 2) + 1] = {0};

          setup_des_key(plaintext, real_key);

          netntlmv1_hash(real_key, 8, hash);

          if (!bytes_to_hex(hash, sizeof(hash), hash_hex, sizeof(hash_hex)) || \
              (strncmp(hash_hex, ppi_refs[j]->hash, 16) != 0)) {
                bytes_to_hex(real_key, sizeof(real_key), rkey_hex, sizeof(rkey_hex));
                printf("Found super false positive!: (Net-NTLMv1('%s') == %s) != %s\n", rkey_hex, hash_hex, ppi_refs[j]->hash);
            continue;
          }
        } else {
      	  printf("WARNING: CPU code to double-check this cracked hash has not yet been added.  There is a 60%% chance this is a false positive!  A workaround is to use John The Ripper to validate this result(s).\n");
        }

      	/* Its official: we cracked a hash! */

      	/* Save the plaintext, clear the precomputed end indices list (since its
      	 * no longer useful, save the hash/plaintext combo into the pot file, and
      	 * tell the user. */
      	if (is_netntlmv1_family(args[i].hash_type)) {
      	  ppi_refs[j]->plaintext = calloc(8, 1);
      	  memcpy(ppi_refs[j]->plaintext, plaintext, 7);
      	} else {
      	  ppi_refs[j]->plaintext = strdup(plaintext);
      	}
      	ppi_refs[j]->num_precomputed_end_indices = 0;
      	FREE(ppi_refs[j]->precomputed_end_indices);

      	save_cracked_hash(ppi_refs[j], args[i].hash_type);
        if (is_netntlmv1_family(args[i].hash_type)) {
          char ptxt_hex[(sizeof(plaintext) * 2) + 1] = {0};
          bytes_to_hex((unsigned char*)plaintext, 7, ptxt_hex, sizeof(ptxt_hex));

          printf("%sHASH CRACKED => %s:1122334455667788:%s%s\n", GREENB, ppi_refs[j]->hash, ptxt_hex, CLR);
          fflush(stdout);
        } else {
          printf("%sHASH CRACKED => %s:1122334455667788:%s%s\n", GREENB, (ppi_refs[j]->username != NULL) ? ppi_refs[j]->username : ppi_refs[j]->hash, plaintext, CLR);  fflush(stdout);
        }
      }
    }
  }
  time_delta = get_elapsed(&start_time);

  time_falsealarms += time_delta;
  seconds_to_human_time(time_str, sizeof(time_str), (unsigned int)time_delta);
  printf("  Completed false alarm checks in %s.\n", time_str);  fflush(stdout);

  /* The candidate arrays belong to the batch; the caller resets it.  Only the
   * per-device result buffers are ours to free. */
  for (i = 0; i < total_devices; i++) {
    FREE(args[i].results);
    args[i].num_results = 0;
  }
}


/* Print a warning to the user if a lot of memory is used by the pre-computed indices. */
void check_memory_usage() {
  uint64_t total_memory = get_total_memory(), num_precompute_bytes = 0;
  double percent_memory_used = 0.0;


  if (total_memory == 0)
    return;

  num_precompute_bytes = total_precomputed_indices_loaded * sizeof(gpu_ulong);
  percent_memory_used = ((double)num_precompute_bytes / (double)total_memory) * 100;
  if (percent_memory_used > 65) {
    printf("\n\n\n\t!! WARNING !!\n\n\tThe pre-computed indices take up more than 65%% of total RAM!  This may result in strange failures from clFinish() and other OpenCL functions.  If this happens, either run this lookup with a smaller number of hashes at a time, or do it on a machine with more memory.\n\n\tMemory used by pre-compute indices: %"QUOTE PRIu64"\n\tTotal RAM: %"QUOTE PRIu64"\n\tPercent used: %.1f%%\n\n\n\n", num_precompute_bytes, total_memory, percent_memory_used);
  }
}


/* Free all the potential start indices. */
void clear_potential_start_indices(precomputed_and_potential_indices *ppi) {
  precomputed_and_potential_indices *ppi_cur = ppi;


  while(ppi_cur) {
    FREE(ppi_cur->potential_start_indices);
    FREE(ppi_cur->potential_start_index_positions);
    ppi_cur->num_potential_start_indices = 0;

    ppi_cur = ppi_cur->next;
  }
}


/* Returns the total number of *.rt and *.rtc in all subdirectories of the
 * specified directory. */
unsigned int count_tables(char *dir) {
  DIR *d = NULL;
  struct dirent *de = NULL;
  unsigned int ret = 0, is_file = 0, is_dir = 0;


  d = opendir(dir);
  if (d == NULL) {
    fprintf(stderr, "Failed to open directory %s: %s\n", dir, strerror(errno)); fflush(stderr);
    return 0;
  }

  while ((de = readdir(d)) != NULL) {
#ifdef _WIN32
    struct stat st = {0};
    char path[256] = {0};

    /* The d_type field of the dirent struct is not a POSIX standard, and Windows
     * doesn't support it.  So we fall back to using stat(). */
    snprintf(path, sizeof(path) - 1, "%s\\%s", dir, de->d_name);
    if (stat(path, &st) < 0) {
      fprintf(stderr, "Error: failed to stat() %s: %s.  Continuing anyway...\n", path, strerror(errno));  fflush(stderr);
      is_file = 0;
      is_dir = 0;
    } else {
      is_file = S_ISREG(st.st_mode);
      is_dir = S_ISDIR(st.st_mode);
    }
#else
    /* Linux has the d_type field, which is much more efficient to use than doing
     * another stat(). */
    is_file = (de->d_type == DT_REG) || (de->d_type == DT_LNK);
    is_dir = (de->d_type == DT_DIR);
#endif

    if (is_file && (str_ends_with(de->d_name, ".rt") || str_ends_with(de->d_name, ".rtc") || str_ends_with(de->d_name, ".rt.rar") || str_ends_with(de->d_name, ".rtc.rar")))
      ret++;
    else if (is_dir && (strcmp(de->d_name, ".") != 0) && (strcmp(de->d_name, "..") != 0)) {
      char subdir_path[1024] = {0};
      filepath_join(subdir_path, sizeof(subdir_path) - 1, dir, de->d_name);
      ret += count_tables(subdir_path);
    }
  }

  closedir(d);
  return ret;
}


/* Free the hashes we loaded from disk or command line. */
void free_loaded_hashes(char **usernames, char **hashes) {
  unsigned int i = 0;

  if (usernames != NULL) {
    for (i = 0; i < num_hashes; i++) {
      FREE(usernames[i]);
    }
    FREE(usernames);
  }

  if (hashes != NULL) {
    for (i = 0; i < num_hashes; i++) {
      FREE(hashes[i]);
    }
    FREE(hashes);
  }
  num_hashes = 0;
}


/* Recursively searches the target directory for the first rainbow table file, and uses its filename to infer
 * the rainbow table parameters. */
void find_rt_params(char *dir_name, rt_parameters *rt_params) {
  char filepath[512] = {0};
  DIR *dir = NULL;
  struct dirent *de = NULL;
  struct stat st;


  dir = opendir(dir_name);
  if (dir == NULL)  /* This directory may not allow the current process permission. */
    return;

  while ((de = readdir(dir)) != NULL) {

    /* Create an absolute path to this entity. */
    filepath_join(filepath, sizeof(filepath), dir_name, de->d_name);

    /* If this is a directory, recurse into it. */
    if ((strcmp(de->d_name, ".") != 0) && (strcmp(de->d_name, "..") != 0) && (stat(filepath, &st) == 0) && S_ISDIR(st.st_mode)) {
      find_rt_params(filepath, rt_params);

      /* If we're searching for rainbowtable parameters, and successfully parsed them
       * in the recursive call, we're done. */
      if ((rt_params != NULL) && rt_params->parsed) {
	closedir(dir); dir = NULL;
	return;
      }

    /* If this is a compressed or uncompressed rainbow table, process it! */
    } else if (str_ends_with(de->d_name, ".rt") || str_ends_with(de->d_name, ".rtc") || str_ends_with(de->d_name, ".rt.rar") || str_ends_with(de->d_name, ".rtc.rar")) {

      /* For .rar files, strip the .rar suffix to get the inner table name for parsing. */
      char parse_name[1024] = {0};
      strncpy(parse_name, de->d_name, sizeof(parse_name) - 1);
      if (str_ends_with(parse_name, ".rar")) {
	parse_name[strlen(parse_name) - 4] = '\0';
      }

      /* Try to parse them from this file name.  On success, return immediately
       * (no further processing needed), otherwise continue searching until the
       * first valid set of parameters is found. */
      parse_rt_params(rt_params, parse_name);
      if (rt_params->parsed) {
	closedir(dir); dir = NULL;
	return;
      }

    }
  }

  closedir(dir); dir = NULL;
}


/* Free the precomputed_hashes linked list. */
void free_precomputed_and_potential_indices(precomputed_and_potential_indices **ppi_head) {
  precomputed_and_potential_indices *ppi = *ppi_head, *ppi_next = NULL;


  while (ppi) {
    ppi_next = ppi->next;

    FREE(ppi->precomputed_end_indices);
    FREE(ppi->potential_start_indices);
    FREE(ppi->potential_start_index_positions);
    FREE(ppi->index_filename);
    ppi->num_potential_start_indices = 0;
    FREE(ppi->plaintext);
    FREE(ppi);

    ppi = ppi_next;
  }
  *ppi_head = NULL;
}


/* Returns the number of CPU cores on this machine. */
unsigned int get_num_cpu_cores() {
#ifdef _WIN32
  SYSTEM_INFO sysinfo = {0};

  GetSystemInfo(&sysinfo);
  return sysinfo.dwNumberOfProcessors;
#elif defined(__APPLE__)
  return (unsigned int)sysconf(_SC_NPROCESSORS_ONLN);
#else
  return get_nprocs();
#endif
}


/* A host thread which controls each GPU for false alarm checks. */
void *host_thread_false_alarm(void *ptr) {
  thread_args *args = (thread_args *)ptr;
  gpu_dev *gpu = &(args->gpu);
  gpu_context context = NULL;
  gpu_queue queue = NULL;
  gpu_kernel kernel = NULL;
  int err = 0;
  char *kernel_path = FALSE_ALARM_KERNEL_PATH, *kernel_name = "false_alarm_check";
  int use_netntlmv1_7 = 0;

  gpu_buffer challenge_buffer = NULL;
  gpu_buffer hash_type_buffer = NULL, charset_buffer = NULL, plaintext_len_min_buffer = NULL, plaintext_len_max_buffer = NULL, reduction_offset_buffer = NULL, plaintext_space_total_buffer = NULL, plaintext_space_up_to_index_buffer = NULL, device_num_buffer = NULL, total_devices_buffer = NULL, num_start_indices_buffer = NULL, start_indices_buffer = NULL, start_index_positions_buffer = NULL, hash_base_indices_buffer = NULL, output_block_buffer = NULL, exec_block_scaler_buffer = NULL;
  /*gpu_buffer debug_ulong_buffer = NULL;*/

  gpu_ulong *start_indices = NULL, *hash_base_indices = NULL, *plaintext_indices = NULL, *output_block = NULL;
  unsigned int *start_index_positions = NULL;

  unsigned int num_start_indices = 0, num_start_index_positions = 0, num_hash_base_indices = 0, num_plaintext_indices = 0, num_exec_blocks = 0, output_block_len = 0, exec_block = 0, output_block_index = 0, plaintext_indicies_index = 0;
  uint64_t plaintext_space_total = 0;
  gpu_ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN] = {0};
  size_t gws = 0, kernel_work_group_size = 0, kernel_preferred_work_group_size_multiple = 0;
  /*gpu_ulong debug_ulong[128] = {0};*/
  int charset_len = 0;
  if (strcmp(args->charset_name, "byte") == 0) {
    charset_len = 256;
  }
  else {
    /* Bare strlen, NOT strlen+1: this is the radix for the plaintext space, not a
     * buffer size.  The +1 conflated the two and made every non-'byte' charset
     * compute its space as 96^n instead of 95^n, so lookups found a candidate in
     * the endpoint search and then rejected it in the false-alarm check.  The
     * 'byte' charset is unaffected (both give 256), which is why Net-NTLMv1
     * tables always worked.  Matches crackalack_gen.c and verify.c. */
    charset_len = (strlen(args->charset) == 0) ? 256 : strlen(args->charset);
  }

  plaintext_space_total = fill_plaintext_space_table(charset_len, args->plaintext_len_min, args->plaintext_len_max, plaintext_space_up_to_index);

  num_start_indices = num_start_index_positions = num_hash_base_indices = num_plaintext_indices = args->num_potential_start_indices;

  start_indices = args->potential_start_indices;
  start_index_positions = args->potential_start_index_positions;
  hash_base_indices = args->hash_base_indices;

  plaintext_indices = calloc(num_plaintext_indices, sizeof(gpu_ulong));
  if (plaintext_indices == NULL) {
    fprintf(stderr, "Error while allocating buffers.\n");
    exit(-1);
  }

  /* If we're generating the standard NTLM 8-character tables, use the special
   * optimized kernel instead! */
  if (is_ntlm8(args->hash_type, args->charset, args->plaintext_len_min, args->plaintext_len_max, args->reduction_offset, args->chain_len)) {
    kernel_path = FALSE_ALARM_NTLM8_KERNEL_PATH;
    kernel_name = "false_alarm_check_ntlm8";
    if ((args->gpu.device_number == 0) && (printed_false_alarm_optimized_message == 0)) { /* Only the first thread prints this, and only prints it once. */
      printf("\nNote: optimized NTLM8 kernel will be used for false alarm checks.\n\n"); fflush(stdout);
      printed_false_alarm_optimized_message = 1;
    }
  } else if (is_ntlm9(args->hash_type, args->charset, args->plaintext_len_min, args->plaintext_len_max, args->reduction_offset, args->chain_len)) {
    kernel_path = FALSE_ALARM_NTLM9_KERNEL_PATH;
    kernel_name = "false_alarm_check_ntlm9";
    if ((args->gpu.device_number == 0) && (printed_false_alarm_optimized_message == 0)) { /* Only the first thread prints this, and only prints it once. */
      printf("\nNote: optimized NTLM9 kernel will be used for false alarm checks.\n\n"); fflush(stdout);
      printed_false_alarm_optimized_message = 1;
    }
  } else if (is_netntlmv1_7(args->hash_type, args->charset_name, args->plaintext_len_min, args->plaintext_len_max, args->chain_len)) {
    /* Same specialized chain walk as the precompute kernel: no per-thread
     * charset or plaintext-space table, and DES S-boxes in shared memory. */
    kernel_path = FALSE_ALARM_NETNTLMV1_7_KERNEL_PATH;
    kernel_name = "false_alarm_check_netntlmv1_7";
    use_netntlmv1_7 = 1;
    if ((args->gpu.device_number == 0) && (printed_false_alarm_optimized_message == 0)) { /* Only the first thread prints this, and only prints it once. */
      printf("\nNote: optimized Net-NTLMv1-7 kernel will be used for false alarm checks.\n\n"); fflush(stdout);
      printed_false_alarm_optimized_message = 1;
    }
  }

  /* Load the kernel. */
  gpu->context = CLCREATECONTEXT(context_callback, &(gpu->device));
  gpu->queue = CLCREATEQUEUE(gpu->context, gpu->device);
  load_kernel(gpu->context, 1, &(gpu->device), kernel_path, kernel_name, &(gpu->program), &(gpu->kernel), args->hash_type);

  /* These variables are set so the CLCREATEARG* macros work correctly. */
  context = gpu->context;
  queue = gpu->queue;
  kernel = gpu->kernel;

#if defined(USE_CUDA) || defined(USE_METAL)
  /* Neither CUDA nor Metal exposes clGetKernelWorkGroupInfo.  Both launchers
   * assume a 256-thread group with a 32-wide execution unit (a CUDA warp, an
   * Apple SIMD group). */
  kernel_work_group_size = 256;
  kernel_preferred_work_group_size_multiple = 32;
#else
  if ((rc_clGetKernelWorkGroupInfo(kernel, gpu->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(size_t), &kernel_work_group_size, NULL) != CL_SUCCESS) || \
      (rc_clGetKernelWorkGroupInfo(kernel, gpu->device, CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof(size_t), &kernel_preferred_work_group_size_multiple, NULL) != CL_SUCCESS)) {
    fprintf(stderr, "Failed to get preferred work group size!\n");
    CLRELEASEKERNEL(gpu->kernel);
    CLRELEASEPROGRAM(gpu->program);
    CLRELEASEQUEUE(gpu->queue);
    CLRELEASECONTEXT(gpu->context);
    pthread_exit(NULL);
    return NULL;
  }
#endif

  /* If the user provided a static GWS on the command line, use that.   Otherwise,
   * use the driver's work group size multiplied by the preferred multiple. */
  if (user_provided_gws > 0) {
    gws = user_provided_gws;
    printf("GPU #%u is using user-provided GWS value of %"PRIu64"\n", gpu->device_number, gws);
  } else {
    /*gws = kernel_work_group_size * kernel_preferred_work_group_size_multiple;*/

    /* TODO: fix this so that false alarm checking is done in partitions instead of
     * all at once (this can improve speed).  Currently, when GWS != num_start_indices,
     * lookups don't succeed due to some bug. */
    gws = num_start_indices;

    /* Somehow, on AMD GPUs, the kernel crashes with a message like:
     *
     *   Memory access fault by GPU node-2 (Agent handle: 0x1bb5e00) on address
     *   0x7f4c80b27000. Reason: Page not present or supervisor privilege.
     *
     * A work-around is to set the GWS to the number of start indices and just do it in
     * one pass. */
    if (is_amd_gpu)
      gws = num_start_indices;

    /*printf("GPU #%u is using dynamic GWS: %"PRIu64" (work group) x %"PRIu64" (pref. multiple) = %"PRIu64"\n", gpu->device_number, kernel_work_group_size, kernel_preferred_work_group_size_multiple, gws);*/
  }
  fflush(stdout);


  /* Count the number of times we need to run the kernel. */
  num_exec_blocks = num_start_indices / gws;
  if (num_start_indices % gws != 0)
    num_exec_blocks++;
  //printf("num_exec_blocks: %d, num_start_indices: %d\n", num_exec_blocks, num_start_indices);

  output_block_len = gws;
  output_block = calloc(output_block_len, sizeof(gpu_ulong));
  if (output_block == NULL) {
    fprintf(stderr, "Error while allocating output buffer(s).\n");
    exit(-1);
  }

  CLCREATEARG(0, hash_type_buffer, CL_RO, args->hash_type, sizeof(gpu_uint));
  CLCREATEARG_ARRAY(1, charset_buffer, CL_RO, (void *)padded_charset(args->charset, charset_len), MAX_CHARSET_LEN);
  CLCREATEARG(2, plaintext_len_min_buffer, CL_RO, args->plaintext_len_min, sizeof(gpu_uint));
  CLCREATEARG(3, plaintext_len_max_buffer, CL_RO, args->plaintext_len_max, sizeof(gpu_uint));
  CLCREATEARG(4, reduction_offset_buffer, CL_RO, args->reduction_offset, sizeof(gpu_uint));
  if (getenv("FA_DEBUG")) {
    fprintf(stderr, "[FA] charset_len=%d space=%llu n=%u start[0]=%llu pos[0]=%u base[0]=%llu\n",
            charset_len, (unsigned long long)plaintext_space_total,
            args->num_potential_start_indices,
            (unsigned long long)args->potential_start_indices[0],
            args->potential_start_index_positions[0],
            (unsigned long long)args->hash_base_indices[0]);
  }
  CLCREATEARG(5, plaintext_space_total_buffer, CL_RO, plaintext_space_total, sizeof(gpu_ulong));
  CLCREATEARG_ARRAY(6, plaintext_space_up_to_index_buffer, CL_RO, plaintext_space_up_to_index, MAX_PLAINTEXT_LEN * sizeof(gpu_ulong));
  CLCREATEARG(7, device_num_buffer, CL_RO, gpu->device_number, sizeof(gpu_uint));
  CLCREATEARG(8, total_devices_buffer, CL_RO, args->total_devices, sizeof(gpu_uint));
  CLCREATEARG(9, num_start_indices_buffer, CL_RO, num_start_indices, sizeof(gpu_uint));
  CLCREATEARG_ARRAY(10, start_indices_buffer, CL_RO, start_indices, num_start_indices * sizeof(gpu_ulong));
  CLCREATEARG_ARRAY(11, start_index_positions_buffer, CL_RO, start_index_positions, num_start_index_positions * sizeof(unsigned int));
  CLCREATEARG_ARRAY(12, hash_base_indices_buffer, CL_RO, hash_base_indices, num_hash_base_indices * sizeof(gpu_ulong));
  CLCREATEARG_ARRAY(14, output_block_buffer, CL_WO, output_block, output_block_len * sizeof(gpu_ulong));

  if (use_netntlmv1_7)
    CLCREATEARG_ARRAY(15, challenge_buffer, CL_RO, (void *)netntlmv1_challenge_for(args->hash_type), 8);

  for (exec_block = 0; exec_block < num_exec_blocks; exec_block++) {
    unsigned int exec_block_scaler = exec_block * gws;

    CLCREATEARG(13, exec_block_scaler_buffer, CL_RO, exec_block_scaler, sizeof(gpu_uint));

    if (is_amd_gpu) {
      int barrier_ret = pthread_barrier_wait(&barrier);
      if ((barrier_ret != 0) && (barrier_ret != PTHREAD_BARRIER_SERIAL_THREAD)) {
	fprintf(stderr, "pthread_barrier_wait() failed!\n"); fflush(stderr);
	exit(-1);
      }
    }

    /* Run the kernel and wait for it to finish. */
    CLRUNKERNEL(gpu->queue, gpu->kernel, &gws);
    CLFLUSH(gpu->queue);
    CLWAIT(gpu->queue);

    /* Read the results. */
    CLREADBUFFER(output_block_buffer, output_block_len * sizeof(gpu_ulong), output_block);

    output_block_index = 0;
    while ((plaintext_indicies_index < num_plaintext_indices) && (output_block_index < output_block_len))
      plaintext_indices[plaintext_indicies_index++] = output_block[output_block_index++];

    CLFREEBUFFER(exec_block_scaler_buffer);
  }

  /* Set the results so the main thread can access them. */
  args->results = plaintext_indices;
  args->num_results = num_plaintext_indices;  

  FREE(output_block);

  CLFREEBUFFER(hash_type_buffer);
  CLFREEBUFFER(charset_buffer);
  CLFREEBUFFER(plaintext_len_min_buffer);
  CLFREEBUFFER(plaintext_len_max_buffer);
  CLFREEBUFFER(reduction_offset_buffer);
  CLFREEBUFFER(plaintext_space_total_buffer);
  CLFREEBUFFER(plaintext_space_up_to_index_buffer);
  CLFREEBUFFER(device_num_buffer);
  CLFREEBUFFER(total_devices_buffer);
  CLFREEBUFFER(num_start_indices_buffer);
  CLFREEBUFFER(start_indices_buffer);
  CLFREEBUFFER(start_index_positions_buffer);
  CLFREEBUFFER(hash_base_indices_buffer);
  CLFREEBUFFER(output_block_buffer);
  CLFREEBUFFER(challenge_buffer);

  CLRELEASEKERNEL(gpu->kernel);
  CLRELEASEPROGRAM(gpu->program);
  CLRELEASEQUEUE(gpu->queue);
  CLRELEASECONTEXT(gpu->context);

  pthread_exit(NULL);
  return NULL;
}


/* A host thread which controls each GPU for BATCHED hash pre-computation.
 *
 * This is the generic path (everything except the NTLM8/NTLM9 tables, which
 * keep their own optimized single-hash kernels in host_thread_precompute).
 *
 * Precomputation is O(chain_len^2) per hash and used to run once per hash,
 * sequentially, so N hashes cost N times one hash -- the dominant start-up cost
 * of a lookup.  Batching makes N hashes cost about the same as one.
 *
 * Why this works when simply enlarging the work size does not: the work item at
 * chain position p walks (chain_len - p) steps, so widening a dispatch along the
 * position axis just makes the chunk run at the speed of its longest walk while
 * the short ones sit idle -- measured, and it bought nothing.  Every hash at a
 * given position walks exactly the same number of steps, so widening along the
 * hash axis multiplies parallelism with no added divergence at all. */
void *host_thread_precompute_batch(void *ptr) {
  thread_args *args = (thread_args *)ptr;
  gpu_dev *gpu = &(args->gpu);
  gpu_context context = NULL;
  gpu_queue queue = NULL;
  gpu_kernel kernel = NULL;
  int err = 0;

  gpu_buffer hash_type_buffer = NULL, hashes_buffer = NULL, hash_len_buffer = NULL, num_hashes_buffer = NULL, charset_buffer = NULL, plaintext_len_min_buffer = NULL, plaintext_len_max_buffer = NULL, table_index_buffer = NULL, chain_len_buffer = NULL, device_num_buffer = NULL, total_devices_buffer = NULL, chunk_positions_buffer = NULL, pos_start_buffer = NULL, output_len_buffer = NULL, output_buffer = NULL, challenge_buffer = NULL;

  /* The Net-NTLMv1 7-byte tables have a specialized kernel; see is_netntlmv1_7.
   * It takes the same arguments in the same order (ignoring the ones it has no
   * use for) plus the challenge, so only the kernel name and one extra binding
   * differ. */
  char *kernel_path = PRECOMPUTE_BATCH_KERNEL_PATH, *kernel_name = "precompute_batch";
  int use_netntlmv1_7 = 0;

  size_t chunk_positions = 0, gws = 0;
  gpu_ulong *output = NULL;
  gpu_uint output_len = 0, num_chunks = 0, chunk = 0;
  gpu_uint num_batch = args->num_batch_hashes;
  size_t total_outputs = 0;

  unsigned char *hash_binaries = NULL;
  gpu_uint hash_binary_len = 0;
  unsigned int i = 0;

  /* Concatenate every hash in the batch into one buffer.  They all share the
   * same length: the table parameters fix the hash type. */
  {
    unsigned char one[32] = {0};
    hash_binary_len = hex_to_bytes(args->batch_hashes[0], sizeof(one), one);
    if (hash_binary_len == 0) {
      fprintf(stderr, "Error: could not parse hash %s\n", args->batch_hashes[0]);
      exit(-1);
    }

    hash_binaries = calloc((size_t)num_batch * hash_binary_len, 1);
    if (hash_binaries == NULL) {
      fprintf(stderr, "Error while allocating buffer for batched hashes.\n");
      exit(-1);
    }
    for (i = 0; i < num_batch; i++) {
      gpu_uint n = hex_to_bytes(args->batch_hashes[i], sizeof(one), one);
      if (n != hash_binary_len) {
        fprintf(stderr, "Error: hash %s has length %u, expected %u\n", args->batch_hashes[i], n, hash_binary_len);
        exit(-1);
      }
      memcpy(hash_binaries + ((size_t)i * hash_binary_len), one, hash_binary_len);
    }
  }

  /* The positions are divided among the GPUs.  Round up if it doesn't divide
   * evenly; this results in slightly more work being done in order to get
   * complete coverage. */
  output_len = args->chain_len / args->total_devices;
  if ((args->chain_len % args->total_devices) != 0)
    output_len++;

  use_netntlmv1_7 = is_netntlmv1_7(args->hash_type, args->charset_name, args->plaintext_len_min, args->plaintext_len_max, args->chain_len);
  if (use_netntlmv1_7) {
    kernel_path = PRECOMPUTE_NETNTLMV1_7_BATCH_KERNEL_PATH;
    kernel_name = "precompute_netntlmv1_7_batch";
    if ((gpu->device_number == 0) && (printed_precompute_optimized_message == 0)) {
      printf("\nNote: optimized Net-NTLMv1-7 kernel will be used for precomputation.\n\n"); fflush(stdout);
      printed_precompute_optimized_message = 1;
    }
  }

  /* Load the kernel. */
  gpu->context = CLCREATECONTEXT(context_callback, &(gpu->device));
  gpu->queue = CLCREATEQUEUE(gpu->context, gpu->device);
  load_kernel(gpu->context, 1, &(gpu->device), kernel_path, kernel_name, &(gpu->program), &(gpu->kernel), args->hash_type);

  /* These variables are set so the CLCREATEARG* macros work correctly. */
  context = gpu->context;
  queue = gpu->queue;
  kernel = gpu->kernel;

#if defined(USE_CUDA) || defined(USE_METAL)
  chunk_positions = 256;  /* Fixed launch group size for both non-OpenCL backends. */
#else
  if (rc_clGetKernelWorkGroupInfo(kernel, gpu->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(size_t), &chunk_positions, NULL) != CL_SUCCESS) {
    fprintf(stderr, "Failed to get preferred work group size!\n");
    exit(-1);
  }
#endif
  chunk_positions = chunk_positions * gpu->num_work_units;

  if (user_provided_precompute_gws > 0)
    chunk_positions = user_provided_precompute_gws;
  if (chunk_positions < 1)
    chunk_positions = 1;
  if (chunk_positions > output_len)
    chunk_positions = output_len;

  num_chunks = output_len / chunk_positions;
  if ((output_len % chunk_positions) != 0)
    num_chunks++;

  /* One dispatch covers every hash at chunk_positions consecutive positions. */
  gws = (size_t)num_batch * chunk_positions;

  total_outputs = (size_t)num_batch * output_len;
  output = calloc(total_outputs, sizeof(gpu_ulong));
  if (output == NULL) {
    fprintf(stderr, "Error while allocating output buffer(s).\n");
    exit(-1);
  }

  if (gpu->device_number == 0) {
    printf("  Precompute batch: %u hash%s x %"PRIu64" positions per dispatch (%u chunk%s, %u compute units)\n",
           num_batch, (num_batch == 1) ? "" : "es", (uint64_t)chunk_positions,
           num_chunks, (num_chunks == 1) ? "" : "s", gpu->num_work_units);
    fflush(stdout);
  }

  CLCREATEARG(0, hash_type_buffer, CL_RO, args->hash_type, sizeof(gpu_uint));
  CLCREATEARG_ARRAY(1, hashes_buffer, CL_RO, hash_binaries, (size_t)num_batch * hash_binary_len);
  CLCREATEARG(2, hash_len_buffer, CL_RO, hash_binary_len, sizeof(gpu_uint));
  CLCREATEARG(3, num_hashes_buffer, CL_RO, num_batch, sizeof(gpu_uint));

  {
    int charset_len = 0;
    if (strcmp(args->charset_name, "byte") == 0)
      charset_len = 256;
    else
      /* Bare strlen, NOT strlen+1: this is the radix for the plaintext space, not a
     * buffer size.  The +1 conflated the two and made every non-'byte' charset
     * compute its space as 96^n instead of 95^n, so lookups found a candidate in
     * the endpoint search and then rejected it in the false-alarm check.  The
     * 'byte' charset is unaffected (both give 256), which is why Net-NTLMv1
     * tables always worked.  Matches crackalack_gen.c and verify.c. */
    charset_len = (strlen(args->charset) == 0) ? 256 : strlen(args->charset);
    CLCREATEARG_ARRAY(4, charset_buffer, CL_RO, (void *)padded_charset(args->charset, charset_len), MAX_CHARSET_LEN);
  }

  CLCREATEARG(5, plaintext_len_min_buffer, CL_RO, args->plaintext_len_min, sizeof(gpu_uint));
  CLCREATEARG(6, plaintext_len_max_buffer, CL_RO, args->plaintext_len_max, sizeof(gpu_uint));
  CLCREATEARG(7, table_index_buffer, CL_RO, args->table_index, sizeof(gpu_uint));
  /* chain_len is a 4-byte unsigned int in thread_args but the kernels declare it
   * 64-bit, so it must be widened here.  Binding &args->chain_len directly would
   * read 8 bytes from a 4-byte field and pick up whatever follows it in the
   * struct as the high word.  The older kernels get away with that only because
   * they truncate the value back to 32 bits before use. */
  {
    gpu_ulong chain_len_64 = args->chain_len;
    CLCREATEARG(8, chain_len_buffer, CL_RO, chain_len_64, sizeof(gpu_ulong));
  }
  CLCREATEARG(9, device_num_buffer, CL_RO, gpu->device_number, sizeof(gpu_uint));
  CLCREATEARG(10, total_devices_buffer, CL_RO, args->total_devices, sizeof(gpu_uint));

  {
    gpu_uint cp = (gpu_uint)chunk_positions;
    CLCREATEARG(11, chunk_positions_buffer, CL_RO, cp, sizeof(gpu_uint));
  }

  CLCREATEARG(13, output_len_buffer, CL_RO, output_len, sizeof(gpu_uint));

  /* The whole output lives on the device for the duration and is read back once
   * at the end, since the kernel writes each result at its absolute index. */
  CLCREATEARG_ARRAY(14, output_buffer, CL_WO, output, total_outputs * sizeof(gpu_ulong));

  if (use_netntlmv1_7)
    CLCREATEARG_ARRAY(15, challenge_buffer, CL_RO, (void *)netntlmv1_challenge_for(args->hash_type), 8);

  for (chunk = 0; chunk < num_chunks; chunk++) {
    gpu_uint pos_start = chunk * (gpu_uint)chunk_positions;

    CLCREATEARG(12, pos_start_buffer, CL_RO, pos_start, sizeof(gpu_uint));

    if (is_amd_gpu) {
      int barrier_ret = pthread_barrier_wait(&barrier);
      if ((barrier_ret != 0) && (barrier_ret != PTHREAD_BARRIER_SERIAL_THREAD)) {
	fprintf(stderr, "pthread_barrier_wait() failed!\n"); fflush(stderr);
	exit(-1);
      }
    }

    /* Run the kernel and wait for it to finish. */
    CLRUNKERNEL(gpu->queue, gpu->kernel, &gws);
    CLFLUSH(gpu->queue);
    CLWAIT(gpu->queue);

    CLFREEBUFFER(pos_start_buffer);
  }

  /* Read every hash's results back in one transfer. */
  CLREADBUFFER(output_buffer, total_outputs * sizeof(gpu_ulong), output);

  /* Set the results so the main thread can access them.  num_results is the
   * per-hash count; results holds num_batch of those back to back. */
  args->results = output;
  args->num_results = output_len;

  FREE(hash_binaries);

  CLFREEBUFFER(hash_type_buffer);
  CLFREEBUFFER(hashes_buffer);
  CLFREEBUFFER(hash_len_buffer);
  CLFREEBUFFER(num_hashes_buffer);
  CLFREEBUFFER(charset_buffer);
  CLFREEBUFFER(plaintext_len_min_buffer);
  CLFREEBUFFER(plaintext_len_max_buffer);
  CLFREEBUFFER(table_index_buffer);
  CLFREEBUFFER(chain_len_buffer);
  CLFREEBUFFER(device_num_buffer);
  CLFREEBUFFER(total_devices_buffer);
  CLFREEBUFFER(chunk_positions_buffer);
  CLFREEBUFFER(output_len_buffer);
  CLFREEBUFFER(output_buffer);
  CLFREEBUFFER(challenge_buffer);

  CLRELEASEKERNEL(gpu->kernel);
  CLRELEASEPROGRAM(gpu->program);
  CLRELEASEQUEUE(gpu->queue);
  CLRELEASECONTEXT(gpu->context);

  pthread_exit(NULL);
  return NULL;
}


/* A host thread which controls each GPU for hash pre-computation. */
void *host_thread_precompute(void *ptr) {
  thread_args *args = (thread_args *)ptr;
  gpu_dev *gpu = &(args->gpu);
  gpu_context context = NULL;
  gpu_queue queue = NULL;
  gpu_kernel kernel = NULL;
  int err = 0;
  char *kernel_path = PRECOMPUTE_KERNEL_PATH, *kernel_name = "precompute";

  gpu_buffer hash_type_buffer = NULL, hash_buffer = NULL, hash_len_buffer = NULL, charset_buffer = NULL, plaintext_len_min_buffer = NULL, plaintext_len_max_buffer = NULL, table_index_buffer = NULL, chain_len_buffer = NULL, device_num_buffer = NULL, total_devices_buffer = NULL, exec_block_scaler_buffer = NULL, output_block_buffer = NULL/*, debug_buffer = NULL*/;

  size_t gws = 0;
  gpu_ulong *output = NULL, *output_block = NULL;
  unsigned int output_len = 0, output_block_len = 0, num_exec_blocks = 0, exec_block = 0, output_index = 0, output_block_index = 0;
  /*unsigned int i = 0;*/

  unsigned char hash_binary[32] = {0};
  gpu_uint hash_binary_len = 0;


  /* Convert the hash from a hex string to bytes.*/
  hash_binary_len = hex_to_bytes(args->hash, sizeof(hash_binary), hash_binary);

  /* The work size is the chain length divided among the total number of GPUs.  Round
   * up if it doesn't divide evenly; this results in slightly more work being done in
   * order to get complete coverage. */
  output_len = args->chain_len / args->total_devices;
  if ((args->chain_len % args->total_devices) != 0)
    output_len++;

  /* If we're generating the standard NTLM 8-character tables, use the special
   * optimized kernel instead! */
  if (is_ntlm8(args->hash_type, args->charset, args->plaintext_len_min, args->plaintext_len_max, args->reduction_offset, args->chain_len)) {
    kernel_path = PRECOMPUTE_NTLM8_KERNEL_PATH;
    kernel_name = "precompute_ntlm8";
    if ((args->gpu.device_number == 0) && (printed_precompute_optimized_message == 0)) { /* Only the first thread prints this, and only prints it once. */
      printf("\nNote: optimized NTLM8 kernel will be used for precomputation.\n\n"); fflush(stdout);
      printed_precompute_optimized_message = 1;
    }
  } else if (is_ntlm9(args->hash_type, args->charset, args->plaintext_len_min, args->plaintext_len_max, args->reduction_offset, args->chain_len)) {
    kernel_path = PRECOMPUTE_NTLM9_KERNEL_PATH;
    kernel_name = "precompute_ntlm9";
    if ((args->gpu.device_number == 0) && (printed_precompute_optimized_message == 0)) { /* Only the first thread prints this, and only prints it once. */
      printf("\nNote: optimized NTLM9 kernel will be used for precomputation.\n\n"); fflush(stdout);
      printed_precompute_optimized_message = 1;
    }
  }

  /* Load the kernel. */
  gpu->context = CLCREATECONTEXT(context_callback, &(gpu->device));
  gpu->queue = CLCREATEQUEUE(gpu->context, gpu->device);
  load_kernel(gpu->context, 1, &(gpu->device), kernel_path, kernel_name, &(gpu->program), &(gpu->kernel), args->hash_type);

  /* These variables are set so the CLCREATEARG* macros work correctly. */
  context = gpu->context;
  queue = gpu->queue;
  kernel = gpu->kernel;

#if defined(USE_CUDA) || defined(USE_METAL)
  gws = 256;  /* Fixed launch group size for both non-OpenCL backends. */
#else
  if (rc_clGetKernelWorkGroupInfo(kernel, gpu->device, CL_KERNEL_WORK_GROUP_SIZE /*CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE*/, sizeof(size_t), &gws, NULL) != CL_SUCCESS) {
    fprintf(stderr, "Failed to get preferred work group size!\n");
    CLRELEASEKERNEL(gpu->kernel);
    CLRELEASEPROGRAM(gpu->program);
    CLRELEASEQUEUE(gpu->queue);
    CLRELEASECONTEXT(gpu->context);
    pthread_exit(NULL);
    return NULL;
  }
#endif
  gws = gws * gpu->num_work_units;

  /* Precomputation is dispatched as a series of blocking chunks, so it was a
   * natural suspect for the same low-occupancy problem the false-alarm path had.
   * It measured otherwise: sweeping this from 12288 up to a single dispatch
   * covering the whole output moved the phase by under 20%, non-monotonically,
   * and the best value at one chain length was the worst at another.  The phase
   * is compute-bound rather than occupancy-bound, so the historical size stands.
   * -precompute-gws is kept for per-GPU retuning; tests/bench_precompute.py
   * sweeps it cheaply by exploiting the quadratic scaling in chain length. */
  if (user_provided_precompute_gws > 0)
    gws = user_provided_precompute_gws;

  if (gws < 1) gws = 1;

  /* In the event that the global work size is larger than the number of outputs we
   * need, cap the GWS. */
  if (gws > output_len) gws = output_len;

  printf("GPU #%u precompute GWS: %"PRIu64" (%u compute units)\n",
         gpu->device_number, (uint64_t)gws, gpu->num_work_units);
  fflush(stdout);

  /* Count the number of times we need to run the kernel. */
  num_exec_blocks = output_len / gws;
  if (output_len % gws != 0)
    num_exec_blocks++;

  /*printf("Host thread #%u started; GWS: %zu.\n", gpu->device_number, gws);*/

  /* This will hold the results from this one GPU. */
  output = calloc(output_len, sizeof(gpu_ulong));

  /* Holds the results from one kernel exec. */
  output_block_len = gws;
  output_block = calloc(output_block_len, sizeof(gpu_ulong));

  if ((output == NULL) || (output_block == NULL)) {
    fprintf(stderr, "Error while allocating output buffer(s).\n");
    exit(-1);
  }

  /* Get the number of compute units in this device. */
  /*get_device_uint(gpu->device, CL_DEVICE_MAX_COMPUTE_UNITS, &(gpu->num_work_units));*/

  int charset_len = 0;
  if (strcmp(args->charset_name, "byte") == 0) {
    charset_len = 256;
  }
  else {
    /* Bare strlen, NOT strlen+1: this is the radix for the plaintext space, not a
     * buffer size.  The +1 conflated the two and made every non-'byte' charset
     * compute its space as 96^n instead of 95^n, so lookups found a candidate in
     * the endpoint search and then rejected it in the false-alarm check.  The
     * 'byte' charset is unaffected (both give 256), which is why Net-NTLMv1
     * tables always worked.  Matches crackalack_gen.c and verify.c. */
    charset_len = (strlen(args->charset) == 0) ? 256 : strlen(args->charset);
  }


  CLCREATEARG(0, hash_type_buffer, CL_RO, args->hash_type, sizeof(gpu_uint));
  CLCREATEARG_ARRAY(1, hash_buffer, CL_RO, hash_binary, hash_binary_len);
  CLCREATEARG(2, hash_len_buffer, CL_RO, hash_binary_len, sizeof(gpu_uint));
  CLCREATEARG_ARRAY(3, charset_buffer, CL_RO, (void *)padded_charset(args->charset, charset_len), MAX_CHARSET_LEN);
  CLCREATEARG(4, plaintext_len_min_buffer, CL_RO, args->plaintext_len_min, sizeof(gpu_uint));
  CLCREATEARG(5, plaintext_len_max_buffer, CL_RO, args->plaintext_len_max, sizeof(gpu_uint));
  CLCREATEARG(6, table_index_buffer, CL_RO, args->table_index, sizeof(gpu_uint));
  CLCREATEARG(7, chain_len_buffer, CL_RO, args->chain_len, sizeof(gpu_ulong));
  CLCREATEARG(8, device_num_buffer, CL_RO, gpu->device_number, sizeof(gpu_uint));
  CLCREATEARG(9, total_devices_buffer, CL_RO, args->total_devices, sizeof(gpu_uint));
  CLCREATEARG_ARRAY(11, output_block_buffer, CL_WO, output_block, output_block_len * sizeof(gpu_ulong));
  /*CLCREATEARG_DEBUG(9, debug_buffer, debug_ptr);*/

  for (exec_block = 0; exec_block < num_exec_blocks; exec_block++) {
    unsigned int exec_block_scaler = exec_block * gws;


    CLCREATEARG(10, exec_block_scaler_buffer, CL_RO, exec_block_scaler, sizeof(gpu_uint));

    if (is_amd_gpu) {
      int barrier_ret = pthread_barrier_wait(&barrier);
      if ((barrier_ret != 0) && (barrier_ret != PTHREAD_BARRIER_SERIAL_THREAD)) {
	fprintf(stderr, "pthread_barrier_wait() failed!\n"); fflush(stderr);
	exit(-1);
      }
    }

    /* Run the kernel and wait for it to finish. */
    CLRUNKERNEL(gpu->queue, gpu->kernel, &gws);
    CLFLUSH(gpu->queue);
    CLWAIT(gpu->queue);

    /* Read the results. */
    CLREADBUFFER(output_block_buffer, output_block_len * sizeof(gpu_ulong), output_block);

    /* Append this block out output to the total output for this GPU. */
    output_block_index = 0;
    while ((output_index < output_len) && (output_block_index < output_block_len))
      output[output_index++] = output_block[output_block_index++];

    CLFREEBUFFER(exec_block_scaler_buffer);
  }

  /* Set the results so the main thread can access them. */
  args->results = output;
  args->num_results = output_len;

  /*
  printf("GPU %u: ", gpu->device_number);
  for (i = 0; i < output_len; i++) {
    printf("%"PRIu64" ", output[i]);
  }
  printf("\n");
  */

  FREE(output_block);

  CLFREEBUFFER(hash_type_buffer);
  CLFREEBUFFER(hash_buffer);
  CLFREEBUFFER(hash_len_buffer);
  CLFREEBUFFER(charset_buffer);
  CLFREEBUFFER(plaintext_len_min_buffer);
  CLFREEBUFFER(plaintext_len_max_buffer);
  CLFREEBUFFER(table_index_buffer);
  CLFREEBUFFER(chain_len_buffer);
  CLFREEBUFFER(device_num_buffer);
  CLFREEBUFFER(total_devices_buffer);
  CLFREEBUFFER(exec_block_scaler_buffer);
  CLFREEBUFFER(output_block_buffer);
  /*CLFREEBUFFER(debug_buffer);*/

  CLRELEASEKERNEL(gpu->kernel);
  CLRELEASEPROGRAM(gpu->program);
  CLRELEASEQUEUE(gpu->queue);
  CLRELEASECONTEXT(gpu->context);

  pthread_exit(NULL);
  return NULL;
}


/* Build the precompute cache key for `hash` under the current table parameters.
 * The key deliberately omits the table part index and chain count, so one
 * precomputation is valid for every part of a table set. */
void build_precompute_index_data(char *buf, size_t buf_size, const thread_args *args, const char *hash) {
  snprintf(buf, buf_size - 1, "%s_%s#%d-%d_%d_%d:%s\n", args->hash_name, args->charset_name, args->plaintext_len_min, args->plaintext_len_max, args->table_index, args->chain_len, hash); /*ntlm_loweralpha#8-8_0_100:49e5bfaab1be72a6c5236f15736a3e15*/
}


/* Turn one hash's GPU results into a cache file and a ppi node.
 *
 * `results_ready` selects where the results come from.  0 means the historical
 * behaviour: check the cache and, on a miss, run the single-hash kernel for this
 * hash right here.  1 means host_thread_precompute_batch has already produced
 * results for a whole group of hashes, and this hash's slice starts at
 * batch_slot within each device's results array -- so no cache lookup and no
 * dispatch happen, only the collate-and-store half of the work. */
void precompute_hash(unsigned int num_devices, thread_args *args, precomputed_and_potential_indices **ppi_head, int results_ready, unsigned int batch_slot) {
  pthread_t threads[MAX_NUM_DEVICES] = {0};
  char filename[128] = {0}, time_str[128] = {0}, index_data[256] = {0};
  struct timespec start_time = {0};
  unsigned int i = 0, j = 0, output_index = 0;
  int k = 0;
  uint64_t *output = NULL;
  FILE *f = NULL;
  precomputed_and_potential_indices *ppi = NULL;


  /* Set the index data we're looking for (or will create later). */
  build_precompute_index_data(index_data, sizeof(index_data), args, args->hash);

  /* Search through the cache and see if we already precomputed the indices for this
   * hash.  The batch path already established this is a miss. */
  if (results_ready)
    output = NULL;
  else
    output = search_precompute_cache(index_data, &output_index, filename, sizeof(filename));

  /* Cache miss... */
  if (output == NULL) {

    if (!results_ready) {
      /* Start the timer for this hash. */
      start_timer(&start_time);

      /* Start one thread to control each GPU. */
      for (i = 0; i < num_devices; i++) {
        if (pthread_create(&(threads[i]), NULL, &host_thread_precompute, &(args[i]))) {
          perror("Failed to create thread");
          exit(-1);
        }
      }

      /* Wait for all threads to finish. */
      for (i = 0; i < num_devices; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
          perror("Failed to join with thread");
          exit(-1);
        }
      }

      num_hashes_precomputed++;

      seconds_to_human_time(time_str, sizeof(time_str), get_elapsed(&start_time));
      printf("  Completed in %s.\n", time_str);  fflush(stdout);
      print_eta_precompute();
    }

    /* Create one output array to hold all the results. */
    output = calloc(args[0].num_results * num_devices, sizeof(uint64_t));
    if (output == NULL) {
      fprintf(stderr, "Error allocating buffer for GPU results.\n");
      exit(-1);
    }

    /*
      The results end up spread out like this across many GPUs:

      GPU 0: 100 94 88 82 76 70 64 58 52 46 40 34 28 22 16 10 4 
      GPU 1: 99 93 87 81 75 69 63 57 51 45 39 33 27 21 15 9 3 
      GPU 2: 98 92 86 80 74 68 62 56 50 44 38 32 26 20 14 8 2 
      GPU 3: 97 91 85 79 73 67 61 55 49 43 37 31 25 19 13 7 1 
      GPU 4: 96 90 84 78 72 66 60 54 48 42 36 30 24 18 12 6 0 
      GPU 5: 95 89 83 77 71 65 59 53 47 41 35 29 23 17 11 5 0 

      Below, we collate the results into a single array containing "100 99 98 [...]".
    */
    for (i = 0; i < args[0].num_results; i++) {
      for (j = 0; j < num_devices; j++) {
	output[output_index] = args[j].results[((size_t)batch_slot * args[j].num_results) + i];
	output_index++;
      }
    }

    /* Now that pulled all the GPU results into one array, free them.  In the
     * batch case the array is shared by every hash in the group, so the caller
     * frees it once the whole group has been stored. */
    if (!results_ready) {
      for (i = 0; i < num_devices; i++) {
        FREE(args[i].results);
        args[i].num_results = 0;
      }
    }

    /* We may have a few extra indices in the array at the end, if the chain length
     * is not divisible by the number of GPUs.  In that case, we simply truncate the
     * end of the array. */
    if (output_index >= args[0].chain_len - 1)
      output_index = args[0].chain_len -1;
    else { /* Sanity check: this should never happen... */
      fprintf(stderr, "Error: output_index < chain_len - 1!: %u < %u\n", output_index, args[0].chain_len - 1);
      exit(-1);
    }

    /* Reverse the output buffer.
     * TODO: this logic can be merged in, above, to simplify. */
    {
      uint64_t *tmp = calloc(output_index, sizeof(uint64_t));
      if (tmp == NULL) {
	fprintf(stderr, "Failed to create temp buffer.\n");
	exit(-1);
      }

      for (i = 0; i < output_index; i++)
	tmp[i] = output[output_index - i - 1];

      FREE(output);
      output = tmp;
    }

    /* Ensure we didn't get all zeros. */
    for (k = 0; k < output_index; k++)
      if (output[k] != 0)
	break;

    if (k == output_index) {
      fprintf(stderr, "Error: all zeros in precomputation!\n");
      exit(-1);
    }

    /* Search for the first unused filename in the space of rcracki.precalc.[0-1048576]. */
    for (i = 0; i < 1048576; i++) {
      int fd = -1;

      snprintf(filename, sizeof(filename) - 1, "rcracki.precalc.%d", i);

      /* Create a file for writing with permissions of 0600. */
      fd = open(filename, O_CREAT | O_EXCL | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);

      if (fd != -1) { /* On success, convert to a file pointer. */
	f = fdopen(fd, "wb");
	break;
      }
    }

    if (f == NULL) {
      fprintf(stderr, "Error: could not create any precalc file (rcracki.precalc.[0-1048576])\n");
      exit(-1);
    }

    /* Ok, so it turns out that we generated the array backwards.  Oh well.  We will
     * just iterate backwards here to compensate. */
    /*for (k = output_index - 1; k >= 0; k--)
      fwrite(&(output[k]), sizeof(gpu_ulong), 1, f);*/

    for (k = 0; k < output_index; k++)
      fwrite(&(output[k]), sizeof(gpu_ulong), 1, f);

    FCLOSE(f);

    /* Now create the rcracki.precalc.?.index file. */
    strncat(filename, ".index", sizeof(filename) - 1);
    f = fopen(filename, "wb");
    if (f == NULL) {
      fprintf(stderr, "Error while creating file: %s\n", filename);
      exit(-1);
    } else {
      fwrite(index_data, sizeof(char), strlen(index_data), f);
      FCLOSE(f);
    }

  } else {
    num_hashes_precomputed_total--;
    printf("Using cached pre-computed indices for hash %s.\n", args->hash);  fflush(stdout);
  }

  total_precomputed_indices_loaded += output_index;

  /*
  printf("output_index: %u\nFinal array: ", output_index);

  for (i = 0; i < output_index; i++)
    printf("%"PRIu64" ", output[i]);
  printf("\n");

  printf("\nFinal array hex: ");

  for (i = 0; i < output_index; i++)
    printf("%08"PRIx64" ", output[i]);
  printf("\n");
  */

  /* Time to store the precomputed indices.  If no head exists in the linked list... */
  if (*ppi_head == NULL) {
    *ppi_head = calloc(1, sizeof(precomputed_and_potential_indices));
    if (*ppi_head == NULL) {
      fprintf(stderr, "Error allocating buffer for precomputed indices.\n");
      exit(-1);
    }
    ppi = *ppi_head;
  } else {
    ppi = *ppi_head;
    while (ppi->next != NULL)
      ppi = ppi->next;
    ppi->next = calloc(1, sizeof(precomputed_and_potential_indices));
    if (ppi->next == NULL) {
      fprintf(stderr, "Error allocating buffer for precomputed indices.\n");
      exit(-1);
    }
    ppi = ppi->next;
  }

  ppi->username = args->username;
  ppi->hash = args->hash;
  ppi->num_precomputed_end_indices = output_index;

  ppi->precomputed_end_indices = calloc(ppi->num_precomputed_end_indices, sizeof(gpu_ulong));
  if (ppi->precomputed_end_indices == NULL) {
    fprintf(stderr, "Error allocating index buffer for precomputed indices.\n");
    exit(-1);
  }

  /* Store the precomputed indices into the array. */
  for (i = 0; i < ppi->num_precomputed_end_indices; i++)
    ppi->precomputed_end_indices[i] = output[i];

  /* Set the filename, so it can be deleted if the hash is cracked later. */
  ppi->index_filename = strdup(filename);

  FREE(output);
}


/* Precompute every hash, batching the GPU work wherever possible.
 *
 * Precomputation is O(chain_len^2) per hash and used to be run one hash at a
 * time, so N hashes cost N times one hash -- for a production chain length that
 * is tens of minutes each.  The chain walks for different hashes at the same
 * position are the same length, so they pack into one dispatch with no added
 * divergence, and N hashes end up costing about the same as one.
 *
 * The NTLM8 and NTLM9 tables keep their own optimized single-hash kernels and
 * so are precomputed one at a time, exactly as before. */
void precompute_hashes(unsigned int num_devices, thread_args *args, precomputed_and_potential_indices **ppi_head, char **usernames, char **hashes, unsigned int num_hashes) {
  pthread_t threads[MAX_NUM_DEVICES] = {0};
  char index_data[256] = {0}, filename[128] = {0}, time_str[128] = {0};
  struct timespec start_time = {0};
  unsigned int i = 0, j = 0, group_start = 0, cached_index_count = 0;
  char **pending_hashes = NULL, **pending_usernames = NULL;
  unsigned int num_pending = 0;
  int can_batch = 0;

  /* Only the generic kernel has a batched counterpart. */
  can_batch = !is_ntlm8(args[0].hash_type, args[0].charset, args[0].plaintext_len_min, args[0].plaintext_len_max, args[0].reduction_offset, args[0].chain_len) &&
              !is_ntlm9(args[0].hash_type, args[0].charset, args[0].plaintext_len_min, args[0].plaintext_len_max, args[0].reduction_offset, args[0].chain_len);

  if (!can_batch) {
    for (i = 0; i < num_hashes; i++) {
      printf("Pre-computing hash #%u: %s...\n", i + 1, hashes[i]);  fflush(stdout);
      for (j = 0; j < num_devices; j++) {
        args[j].username = usernames[i];
        args[j].hash = hashes[i];
      }
      precompute_hash(num_devices, args, ppi_head, /*results_ready=*/0, /*batch_slot=*/0);
    }
    return;
  }

  pending_hashes = calloc(num_hashes, sizeof(char *));
  pending_usernames = calloc(num_hashes, sizeof(char *));
  if ((pending_hashes == NULL) || (pending_usernames == NULL)) {
    fprintf(stderr, "Error while allocating buffers for precomputation batching.\n");
    exit(-1);
  }

  /* Resolve cache hits first so only hashes that actually need GPU work get
   * batched.  A hit is nearly free, and mixing them into a group would size the
   * dispatch for work that is not going to happen. */
  for (i = 0; i < num_hashes; i++) {
    uint64_t *cached = NULL;

    for (j = 0; j < num_devices; j++) {
      args[j].username = usernames[i];
      args[j].hash = hashes[i];
    }

    build_precompute_index_data(index_data, sizeof(index_data), &(args[0]), hashes[i]);
    cached = search_precompute_cache(index_data, &cached_index_count, filename, sizeof(filename));

    if (cached != NULL) {
      FREE(cached);
      printf("Pre-computing hash #%u: %s...\n", i + 1, hashes[i]);  fflush(stdout);
      /* Re-reads the cache and builds the ppi node; the cheap path. */
      precompute_hash(num_devices, args, ppi_head, /*results_ready=*/0, /*batch_slot=*/0);
    } else {
      pending_hashes[num_pending] = hashes[i];
      pending_usernames[num_pending] = usernames[i];
      num_pending++;
    }
  }

  if (num_pending == 0) {
    FREE(pending_hashes);
    FREE(pending_usernames);
    return;
  }

  /* Work through the misses in groups.  The group size is bounded because the
   * output buffer is (group size * positions per device * 8) bytes on each GPU;
   * at a production chain length that is a few MB per hash. */
  for (group_start = 0; group_start < num_pending; group_start += PRECOMPUTE_BATCH_MAX) {
    unsigned int group_size = num_pending - group_start;
    if (group_size > PRECOMPUTE_BATCH_MAX)
      group_size = PRECOMPUTE_BATCH_MAX;

    printf("Pre-computing %u hash%s in one batch:\n", group_size, (group_size == 1) ? "" : "es");
    for (i = 0; i < group_size; i++)
      printf("  #%u: %s\n", group_start + i + 1, pending_hashes[group_start + i]);
    fflush(stdout);

    for (j = 0; j < num_devices; j++) {
      args[j].batch_hashes = &(pending_hashes[group_start]);
      args[j].num_batch_hashes = group_size;
      /* Kept in step so any per-hash reporting inside the thread is sane. */
      args[j].hash = pending_hashes[group_start];
      args[j].username = pending_usernames[group_start];
    }

    start_timer(&start_time);

    for (j = 0; j < num_devices; j++) {
      if (pthread_create(&(threads[j]), NULL, &host_thread_precompute_batch, &(args[j]))) {
        perror("Failed to create thread");
        exit(-1);
      }
    }
    for (j = 0; j < num_devices; j++) {
      if (pthread_join(threads[j], NULL) != 0) {
        perror("Failed to join with thread");
        exit(-1);
      }
    }

    num_hashes_precomputed += group_size;
    seconds_to_human_time(time_str, sizeof(time_str), get_elapsed(&start_time));
    printf("  Completed %u hash%s in %s.\n", group_size, (group_size == 1) ? "" : "es", time_str);
    fflush(stdout);
    print_eta_precompute();

    /* Store each hash's slice of the shared results. */
    for (i = 0; i < group_size; i++) {
      for (j = 0; j < num_devices; j++) {
        args[j].username = pending_usernames[group_start + i];
        args[j].hash = pending_hashes[group_start + i];
      }
      precompute_hash(num_devices, args, ppi_head, /*results_ready=*/1, /*batch_slot=*/i);
    }

    for (j = 0; j < num_devices; j++) {
      FREE(args[j].results);
      args[j].num_results = 0;
      args[j].batch_hashes = NULL;
      args[j].num_batch_hashes = 0;
    }
  }

  FREE(pending_hashes);
  FREE(pending_usernames);
}


/* --- Parallel table preloading -------------------------------------------
 *
 * Table loading used to be one thread walking the directory tree and reading
 * each table inline, with at most two tables in flight.  On a large table set
 * that made loading the bottleneck for the entire run: the reader could never
 * get more than one table ahead, so the GPU sat idle waiting on it.  Measured on
 * 16 of the 2 GiB Net-NTLMv1 tables, loading accounted for roughly 70 of a 90
 * second run even with the file data already in the page cache.
 *
 * Now the walk and the reading are separated.  The tree is walked once up front
 * to collect paths (cheap; it only stats), then a pool of workers each claim the
 * next unclaimed path and read it.  The consumer contract is unchanged --
 * get_preloaded_table() still pops from preloaded_table_list under
 * preloaded_tables_lock -- and workers honour the same sliding-window throttle,
 * so memory use stays bounded.
 */

/* A table path collected during the directory walk. */
typedef struct {
  char **paths;
  unsigned int num_paths;
  unsigned int capacity;
} table_path_list;

/* Shared state for the loader pool. */
typedef struct {
  table_path_list *list;
  unsigned int next_idx;
  pthread_mutex_t lock;
} table_load_pool;

/* Published so search_tables() can stop the workers when every hash is cracked
 * before the tables run out.  Only one lookup is ever in flight. */
table_load_pool *active_load_pool = NULL;

/* One-way stop flag for the loader pool.  Only ever goes 0 -> 1, so an unlocked
 * read is safe: the worst case is one extra table being loaded before a worker
 * notices.  That keeps it readable under either lock without ordering rules. */
volatile int table_loading_abort = 0;

/* Handle for the preloader, so the consumer can join it before tearing down the
 * preloaded table list. */
pthread_t preload_thread_id = {0};
int preload_thread_running = 0;


static void table_path_list_add(table_path_list *list, const char *path) {
  if (list->num_paths == list->capacity) {
    unsigned int new_cap = (list->capacity == 0) ? 256 : list->capacity * 2;
    char **grown = realloc(list->paths, new_cap * sizeof(*grown));
    if (grown == NULL) {
      fprintf(stderr, "Failed to allocate table path list.\n");
      exit(-1);
    }
    list->paths = grown;
    list->capacity = new_cap;
  }
  list->paths[list->num_paths] = strdup(path);
  if (list->paths[list->num_paths] == NULL) {
    fprintf(stderr, "Failed to allocate table path.\n");
    exit(-1);
  }
  list->num_paths++;
}


/* Recursively collect every rainbow table path under rt_dir.  This only reads
 * directory metadata, so it is fast even for thousands of tables. */
static void collect_table_paths(const char *rt_dir, table_path_list *list) {
  DIR *dir = NULL;
  struct dirent *de = NULL;
  struct stat st;
  char filepath[512];

  memset(&st, 0, sizeof(st));
  memset(filepath, 0, sizeof(filepath));

  dir = opendir(rt_dir);
  if (dir == NULL)  /* This directory may not allow the current process permission. */
    return;

  while ((de = readdir(dir)) != NULL) {
    filepath_join(filepath, sizeof(filepath), rt_dir, de->d_name);

    if ((strcmp(de->d_name, ".") != 0) && (strcmp(de->d_name, "..") != 0) && (stat(filepath, &st) == 0) && S_ISDIR(st.st_mode)) {
      collect_table_paths(filepath, list);
    } else if (str_ends_with(de->d_name, ".rt") || str_ends_with(de->d_name, ".rtc") || str_ends_with(de->d_name, ".rt.rar") || str_ends_with(de->d_name, ".rtc.rar")) {
      table_path_list_add(list, filepath);
    }
  }

  closedir(dir); dir = NULL;
}


/* Read one table off disk.  Returns a preloaded_table on success, or NULL if the
 * table was unreadable or failed verification (both already reported).
 * `io_secs` accumulates this thread's read time; the caller folds it into the
 * global total once, so the threads do not race on it. */
static preloaded_table *load_one_table(const char *filepath, double *io_secs) {
  gpu_ulong *rainbow_table = NULL;
  unsigned int num_chains = 0, is_uncompressed_table = 0;
  struct timespec start_time_io = {0};
  preloaded_table *pt = NULL;

  if (str_ends_with(filepath, ".rt.rar") || str_ends_with(filepath, ".rtc.rar")) {
    int ret = 0;

    start_timer(&start_time_io);
    if ((ret = rar_decompress((char *)filepath, &rainbow_table, &num_chains)) != 0) {
      fprintf(stderr, "Error while decompressing RAR table %s: %d\n", filepath, ret);
      exit(-1);
    }
    *io_secs += get_elapsed(&start_time_io);
  } else if (str_ends_with(filepath, ".rtc")) {
    int ret = 0;

    start_timer(&start_time_io);    /* For loading the table only. */
    if ((ret = rtc_decompress((char *)filepath, &rainbow_table, &num_chains)) != 0) {
      fprintf(stderr, "Error while decompressing RTC table %s: %d\n", filepath, ret);
      exit(-1);
    }
    *io_secs += get_elapsed(&start_time_io);
  } else {
    FILE *f = NULL;

    is_uncompressed_table = 1;
    start_timer(&start_time_io);    /* For loading the table only. */
    f = fopen(filepath, "rb");
    if (f != NULL) {
      long file_size = get_file_size(f);

      if ((file_size % (sizeof(gpu_ulong) * 2) == 0) && (file_size > 0)) {
        unsigned int num_longs = file_size / sizeof(gpu_ulong);

        /* malloc rather than calloc: every byte is overwritten by the read
         * below, so zeroing first only doubles the memory traffic. */
        rainbow_table = malloc((size_t)num_longs * sizeof(gpu_ulong));
        if (rainbow_table == NULL) {
          fprintf(stderr, "Failed to allocate %"PRIu64" bytes for rainbow table!: %s\n", (uint64_t)num_longs * sizeof(gpu_ulong), filepath);
          exit(-1);
        }

        if (fread(rainbow_table, sizeof(gpu_ulong), num_longs, f) != num_longs) {
          fprintf(stderr, "Error while reading rainbow table: %s\n", strerror(errno));
          exit(-1);
        }

        *io_secs += get_elapsed(&start_time_io);
        num_chains = num_longs / 2;
      } else
        fprintf(stderr, "Rainbow table size is not a multiple of %"PRIu64": %ld\n", sizeof(gpu_ulong) * 2, file_size);

      FCLOSE(f);
    } else
      fprintf(stderr, "Could not open file for reading: %s", strerror(errno));
  }

  if (rainbow_table == NULL)
    return NULL;

  /* If the table is uncompressed (*.rt), then there's a possibility its unsorted on accident.  We will
   * verify them first to make sure. */
  if (is_uncompressed_table == 1) {
    if (!verify_rainbowtable(rainbow_table, num_chains, VERIFY_TABLE_TYPE_LOOKUP, 0, 0, NULL)) {
      fprintf(stderr, "\nError: %s is not a valid table suitable for lookups!  (Hint: it may not be sorted.)  Skipping...\n\n", filepath);  fflush(stderr);
      FREE(rainbow_table);
      return NULL;
    }
  }

  pt = calloc(1, sizeof(preloaded_table));
  if (pt == NULL) {
    printf("Failed to allocate memory for preload_table.\n");
    exit(-1);
  }

  pt->filepath = strdup(filepath);
  pt->rainbow_table = rainbow_table;
  pt->num_chains = num_chains;
  return pt;
}


/* Loader worker: claim the next path, read it, publish it, repeat. */
static void *table_load_worker(void *arg) {
  table_load_pool *pool = (table_load_pool *)arg;
  double io_secs = 0.0;

  for (;;) {
    unsigned int idx = 0;

    pthread_mutex_lock(&pool->lock);
    if (table_loading_abort || (pool->next_idx >= pool->list->num_paths)) {
      pthread_mutex_unlock(&pool->lock);
      break;
    }
    idx = pool->next_idx++;
    pthread_mutex_unlock(&pool->lock);

    preloaded_table *pt = load_one_table(pool->list->paths[idx], &io_secs);
    if (pt == NULL)
      continue;   /* unreadable or unsorted; already reported */

    pthread_mutex_lock(&preloaded_tables_lock);

    num_preloaded_tables_available++;

    if (preloaded_table_list == NULL)
      preloaded_table_list = pt;
    else {
      preloaded_table *ptr = preloaded_table_list;
      while (ptr->next != NULL)
        ptr = ptr->next;
      ptr->next = pt;
    }

    /* Tell the main thread that we have a table available. */
    pthread_cond_signal(&condition_wait_for_tables);

    /* Hold here while the window is full, so memory stays bounded.  Also wakes
     * on abort, otherwise a consumer that stopped early would leave every worker
     * parked here forever and the join below would hang. */
    while ((num_preloaded_tables_available >= max_preload_num) && !table_loading_abort)
      pthread_cond_wait(&condition_continue_loading_tables, &preloaded_tables_lock);

    pthread_mutex_unlock(&preloaded_tables_lock);
  }

  /* Fold this worker's read time into the global total once. */
  pthread_mutex_lock(&preloaded_tables_lock);
  time_io += io_secs;
  pthread_mutex_unlock(&preloaded_tables_lock);

  return NULL;
}


/* Stop the loader pool and wait for it to exit.
 *
 * The consumer must call this before freeing preloaded_table_list: the workers
 * append to that list, so tearing it down underneath them would be a use after
 * free.  Safe to call more than once, and when no pool ever started. */
void stop_table_loading(void) {
  table_loading_abort = 1;

  /* Wake any worker parked on the in-flight window. */
  pthread_mutex_lock(&preloaded_tables_lock);
  pthread_cond_broadcast(&condition_continue_loading_tables);
  pthread_mutex_unlock(&preloaded_tables_lock);

  /* Joined without the lock held, since the workers need it to finish. */
  if (preload_thread_running) {
    pthread_join(preload_thread_id, NULL);
    preload_thread_running = 0;
  }
}


/* Decide how many tables may be in flight and how many threads read them.
 * Each in-flight table is held whole in memory, so the window is clamped
 * against total RAM using the largest table's size. */
static void size_load_pool(const table_path_list *list) {
  unsigned int threads = 0, window = 0, ram_limit = 0;
  uint64_t largest = 0;
  unsigned int i = 0;
  const char *env = NULL;

  /* Largest table decides how many fit; they are usually all the same size, so
   * sample rather than stat every one of potentially thousands. */
  for (i = 0; (i < list->num_paths) && (i < 16); i++) {
    struct stat st;
    if (stat(list->paths[i], &st) == 0 && (uint64_t)st.st_size > largest)
      largest = (uint64_t)st.st_size;
  }

  threads = get_num_cpu_cores();
  if (threads > 8) threads = 8;   /* reads stop scaling well past this */
  if (threads < 1) threads = 1;

  window = threads + 2;

  if (largest > 0) {
    /* get_total_memory() covers Linux, macOS and Windows, so the clamp applies
     * everywhere.  Without it a machine with many cores and little RAM would
     * size the window off the core count alone and try to hold far more table
     * than it has memory for. */
    uint64_t total_ram = get_total_memory();
    if (total_ram > 0)
      ram_limit = (unsigned int)((total_ram / PRELOAD_RAM_FRACTION) / largest);

    if (ram_limit > 0) {
      if (window > ram_limit) window = ram_limit;
      if (threads > window) threads = window;
    }
  }

  if (window < MAX_PRELOAD_NUM_DEFAULT) window = MAX_PRELOAD_NUM_DEFAULT;
  if (threads < 1) threads = 1;

  /* Explicit overrides win over both heuristics. */
  env = getenv("RCRACK_LOAD_THREADS");
  if ((env != NULL) && (*env != '\0')) {
    long v = strtol(env, NULL, 10);
    if ((v >= 1) && (v <= 256)) threads = (unsigned int)v;
  }
  env = getenv("MAX_PRELOAD_NUM");
  if ((env != NULL) && (*env != '\0')) {
    long v = strtol(env, NULL, 10);
    if ((v >= 1) && (v <= 256)) window = (unsigned int)v;
  }

  /* A window smaller than the worker count just parks workers on the throttle. */
  if (window < threads) window = threads;

  num_load_threads = threads;
  max_preload_num = window;
}


/* The thread which preloads tables in the background while the main thread performs binary searching & false
 * alarm checks. */
void *preloading_thread(void *ptr) {
  char *xrt_dir = ((preloading_thread_args *)ptr)->rt_dir;
  char rt_dir[512];
  table_path_list list = {0};
  table_load_pool pool = {0};
  pthread_t *workers = NULL;
  unsigned int i = 0;

  memset(rt_dir, 0, sizeof(rt_dir));

  /* Copy the rainbow table path from the heap to the local stack, then free the source. */
  strncpy(rt_dir, xrt_dir, sizeof(rt_dir) - 1);
  free(xrt_dir); xrt_dir = ((preloading_thread_args *)ptr)->rt_dir = NULL;

  collect_table_paths(rt_dir, &list);
  size_load_pool(&list);

  if (list.num_paths > 0) {
    printf("Loading %u table%s with %u reader thread%s (up to %u in memory at once).\n",
           list.num_paths, (list.num_paths == 1) ? "" : "s",
           num_load_threads, (num_load_threads == 1) ? "" : "s",
           max_preload_num);
    fflush(stdout);
  }

  pool.list = &list;
  pool.next_idx = 0;
  pthread_mutex_init(&pool.lock, NULL);

  pthread_mutex_lock(&preloaded_tables_lock);
  active_load_pool = &pool;
  pthread_mutex_unlock(&preloaded_tables_lock);

  workers = calloc(num_load_threads, sizeof(pthread_t));
  if (workers == NULL) {
    fprintf(stderr, "Failed to allocate loader threads.\n");
    exit(-1);
  }

  for (i = 0; i < num_load_threads; i++) {
    if (pthread_create(&(workers[i]), NULL, &table_load_worker, &pool)) {
      perror("Failed to create table loader thread");
      exit(-1);
    }
  }

  for (i = 0; i < num_load_threads; i++)
    pthread_join(workers[i], NULL);

  FREE(workers);

  pthread_mutex_lock(&preloaded_tables_lock);
  active_load_pool = NULL;
  pthread_mutex_unlock(&preloaded_tables_lock);

  pthread_mutex_destroy(&pool.lock);

  for (i = 0; i < list.num_paths; i++)
    FREE(list.paths[i]);
  FREE(list.paths);

  /* We've reached the end of all the tables, so tell the main thread. */
  table_loading_complete = 1;

  /* If the main thread is still waiting on new tables, wake it up. */
  pthread_mutex_lock(&preloaded_tables_lock);
  pthread_cond_signal(&condition_wait_for_tables);
  pthread_mutex_unlock(&preloaded_tables_lock);
  return NULL;
}


/* Given the number of hashes processed out of the total, prints the estimated time left to
 * completion. */
void print_eta_precompute() {
  char eta_str[64] = {0};

  strncpy(eta_str, "Unknown", sizeof(eta_str) - 1);
  if ((num_hashes_precomputed > 0) && (num_hashes_precomputed_total >= num_hashes_precomputed)) {
    double seconds_per_hash = (double)(get_elapsed(&precompute_start_time) / (double)num_hashes_precomputed);
    unsigned int num_hashes_left = num_hashes_precomputed_total - num_hashes_precomputed;
    unsigned int num_seconds_left = num_hashes_left * seconds_per_hash;

    seconds_to_human_time(eta_str, sizeof(eta_str), num_seconds_left);
  }
  printf("  Estimated time to complete pre-computation (at most): %s\n\n", eta_str); fflush(stdout);
}


/* Given the number of tables processed out of the total, prints the estimated time left to
 * completion. */
void print_eta_search(unsigned int num_tables_processed, unsigned int num_tables_total) {
  char eta_str[64] = {0};

  strncpy(eta_str, "Unknown", sizeof(eta_str) - 1);
  if ((num_tables_processed > 0) && (num_tables_total >= num_tables_processed)) {
    double seconds_per_table = (double)(get_elapsed(&search_start_time) / (double)num_tables_processed);
    unsigned int num_tables_left = num_tables_total - num_tables_processed;
    unsigned int num_seconds_left = num_tables_left * seconds_per_table;

    seconds_to_human_time(eta_str, sizeof(eta_str), num_seconds_left);
  }
  printf("  Estimated time remaining (at most): %s\n", eta_str); fflush(stdout);
}


void print_usage_and_exit(char *prog_name, int exit_code) {
#ifdef _WIN32
  char *dir1 = "D:\\rt_ntlm\\";
  char *dir2 = "C:\\Users\\jsmith\\Desktop\\";
#else
  char *dir1 = "/export/rt_ntlm/";
  char *dir2 = "/home/user/";
#endif

  fprintf(stderr, "%sUsage:%s %s rainbow_table_directory (single_hash | filename_with_many_hashes.txt) [-gws GWS] [-disable-platform N] [-fa-batch N] [-precompute-batch N] [-precompute-gws N]\n\n", WHITEB, CLR, prog_name);
  fprintf(stderr, "    %s-gws GWS%s    (Optional) Sets the global work size for each GPU.  This can significantly affect the speed.  To tune this setting, start with multiplying the max compute units by the max work group size (both are reported on program start-up).  Then increase/decrease the value and time the results.  For example, if the max compute units is 20, and the max work group size is 1024, try using 20 x 1024 = 20480, then 20480 - 1024 = 19456, 20480 - 2048 = 18432, 2048 + 1024 = 21504, etc.  If you find a value that works better than the automatic setting, please report your findings at: https://github.com/jtesta/rainbowcrackalack/issues\n\n", WHITEB, CLR);
  fprintf(stderr, "    %s-disable-platform N%s    (Optional) Disables a platform from being used (platform numbers are reported on program start-up).  Useful when experiencing strange problems on mixed-GPU systems.  Try disabling each platform one at a time and see if the program behaves normally.\n\n", WHITEB, CLR);
  fprintf(stderr, "    %s-fa-batch N%s    (Optional) Number of false alarm candidates to pool across tables before running them on the GPU (default: 16384).  A single table rarely produces enough candidates to keep a GPU busy, so pooling them turns many tiny dispatches into a few large ones.  Raise it if your GPU still looks idle during false alarm checks; set it to 1 to disable pooling entirely.\n\n", WHITEB, CLR);
  fprintf(stderr, "    %s-precompute-batch N%s    (Optional) How many hashes to pre-compute in a single GPU dispatch (default: %u).  Pre-computation costs roughly chain_len^2 / 2 hash operations per hash and used to run one hash at a time, so N hashes cost N times one hash.  Chain walks for different hashes at the same chain position are the same length, so batching them adds parallelism without adding divergence and N hashes cost about as much as one.  Set to 1 to disable.  Does not apply to the NTLM8/NTLM9 tables, which use their own optimized kernels.\n\n", WHITEB, CLR, (unsigned int)PRECOMPUTE_BATCH_MAX_DEFAULT);
  fprintf(stderr, "    %s-precompute-gws N%s   (Optional) Global work size for the precomputation phase, per GPU.  The default is one work group per compute unit.  Measured on an RTX 4000 SFF Ada, changing this moves precomputation by under 20%% and not even in a consistent direction, so it is here for retuning a specific GPU rather than because a better value is known.  tests/bench_precompute.py sweeps it without waiting on a full-length run.\n\n\n", WHITEB, CLR);
  fprintf(stderr, "%sExamples:%s\n    %s %s 64f12cddaa88057e06a81b54e73b949b\n    %s %s %shashes_one_per_line.txt\n    %s %s %spwdump.txt\n\n", WHITEB, CLR, prog_name, dir1, prog_name, dir1, dir2, prog_name, dir1, dir2);
  exit(exit_code);
}


/* Helper function for rt_binary_search(). */
unsigned int _rt_binary_search(gpu_ulong *rainbow_table, unsigned int low, unsigned int high, gpu_ulong search_index, gpu_ulong *start) {
  unsigned int chain = 0;


  /*printf("_rt_binary_search(%u, %u, %lu)\n", low, high, search_index);*/
  if (high - low <= 8) {
    for (chain = low; chain < high; chain++) {
      if (search_index == rainbow_table[(chain * 2) + 1]) {
	*start = rainbow_table[chain * 2];
	/*printf("\nbinary search: found %lu at %u (between %u and %u)\n", *start, chain, low, high);*/
	return 1;
      }
    }
  } else {
    chain = ((high - low) / 2) + low;
    if (search_index >= rainbow_table[(chain * 2) + 1])
      return _rt_binary_search(rainbow_table, chain, high, search_index, start);
    else
      return _rt_binary_search(rainbow_table, low, chain, search_index, start);
  }

  return 0;
}


void *rt_binary_search_thread(void *ptr) {
  search_thread_args *args = (search_thread_args *)ptr;
  precomputed_and_potential_indices *ppi_cur = args->ppi_head;
  unsigned int i = 0;
  gpu_ulong start = 0;


  while (ppi_cur != NULL) {
    if (ppi_cur->plaintext == NULL) { /* If this hash isn't cracked yet... */
      for (i = 0 + args->thread_number; i < ppi_cur->num_precomputed_end_indices; i += args->total_threads) {
	if (_rt_binary_search(args->rainbow_table, 0, args->num_chains, ppi_cur->precomputed_end_indices[i], &start)) {
	  add_potential_start_index_and_position(ppi_cur, start, i);
	}
      }
    }
    ppi_cur = ppi_cur->next;
  }

  pthread_exit(NULL);
  return NULL;
}


/* Rainbow table binary search.  Searches a table's end indices for any matches with
 * precomputed end indices.  If/when matches are found, the corresponding start indices
 * are added to the precomputed_and_potential_indices's potential_start_indices
 * array. */
void rt_binary_search(gpu_ulong *rainbow_table, unsigned int num_chains, precomputed_and_potential_indices *ppi_head) {
  struct timespec start_time_searching = {0};
  char time_searching_str[64] = {0};
  unsigned int num_threads = get_num_cpu_cores();
  pthread_t *threads = NULL;
  search_thread_args *args = NULL;
  unsigned int i = 0;
  double s_time = 0;


  start_timer(&start_time_searching);
  args = calloc(num_threads, sizeof(search_thread_args));
  threads = calloc(num_threads, sizeof(pthread_t));
  if ((args == NULL) || (threads == NULL)) {
    fprintf(stderr, "Failed to create thread/args for searching.\n");
    exit(-1);
  }

  printf("  Searching table for matching endpoints...\n");  fflush(stdout);

  for (i = 0; i < num_threads; i++) {
    args[i].thread_number = i;
    args[i].total_threads = num_threads;
    args[i].rainbow_table = rainbow_table;
    args[i].num_chains = num_chains;
    args[i].ppi_head = ppi_head;

    if (pthread_create(&(threads[i]), NULL, &rt_binary_search_thread, &(args[i]))) {
      perror("Failed to create thread");
      exit(-1);
    }
  }

  /* Wait for all threads to finish. */
  for (i = 0; i < num_threads; i++) {
    if (pthread_join(threads[i], NULL) != 0) {
      perror("Failed to join with thread");
      exit(-1);
    }
  }

  s_time = get_elapsed(&start_time_searching);
  seconds_to_human_time(time_searching_str, sizeof(time_searching_str), s_time);
  printf("  Table searched in %s.\n", time_searching_str);  fflush(stdout);

  time_searching += s_time;
  FREE(args);
  FREE(threads);
}


void save_cracked_hash(precomputed_and_potential_indices *ppi, unsigned int hash_type) {
  FILE *jtr_file = fopen(jtr_pot_filename, "ab"), *hashcat_file = fopen(hashcat_pot_filename, "ab");
  unsigned int hash_len = 0, plaintext_len = 0;
  if (is_netntlmv1_family(hash_type)) {
    hash_len = strlen(ppi->hash);
    plaintext_len = 7;
  }
  else {
    hash_len = strlen(ppi->hash);
    plaintext_len = strlen(ppi->plaintext);
  }
  char *dot_pos = strrchr(ppi->index_filename, '.');


  if (jtr_file == NULL) {
    fprintf(stderr, "Error: could not open pot file for writing: %s: %s\n", jtr_pot_filename, strerror(errno));
    exit(-1);
  } else if (hashcat_file == NULL) {
    fprintf(stderr, "Error: could not open pot file for writing: %s: %s\n", hashcat_pot_filename, strerror(errno));
    exit(-1);
  }

  /* The JTR pot file format requires NTLM hashes to be prepended with "$NT$". */
  if ((hash_type == HASH_NTLM) && (fwrite("$NT$", sizeof(char), 4, jtr_file) != 4)) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  }

  if (fwrite(ppi->hash, sizeof(char), hash_len, jtr_file) != hash_len) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  } else if (fwrite(ppi->hash, sizeof(char), hash_len, hashcat_file) != hash_len) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  }

  if (fwrite(":", sizeof(char), 1, jtr_file) != 1) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  } else if (fwrite(":", sizeof(char), 1, hashcat_file) != 1) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  }

  if (fwrite(ppi->plaintext, sizeof(char), plaintext_len, jtr_file) != plaintext_len) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  } else if (fwrite(ppi->plaintext, sizeof(char), plaintext_len, hashcat_file) != plaintext_len) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  }

  if (fwrite("\n", sizeof(char), 1, jtr_file) != 1) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  } else if (fwrite("\n", sizeof(char), 1, hashcat_file) != 1) {
    fprintf(stderr, "Error while writing to pot file: %s\n", strerror(errno));
    exit(-1);
  }

  FCLOSE(jtr_file);
  FCLOSE(hashcat_file);

  /* Delete the index file containing information about the precomputed indices.  Since
   * this hash was cracked, this is no longer needed. */
  if (unlink(ppi->index_filename) != 0) {
    fprintf(stderr, "Error while deleting precompute index file: %s: %s\n", ppi->index_filename, strerror(errno));
    /*exit(-1);*/
  }

  /* Truncate the ".index" off the end of the filename; this forms the precomputation
   * filename. */
  *dot_pos = '\0';
  if (unlink(ppi->index_filename) != 0) {
    fprintf(stderr, "Error while deleting precompute file: %s: %s\n", ppi->index_filename, strerror(errno));
    /*exit(-1);*/
  }

  num_cracked++;
  num_falsealarms--;
}


/* Searches the precompute cache for matching index data.  If found, an array of
 * indices is returned, num_indices set to the array size, and the filename buffer
 * is set to the *.index cache file. */
gpu_ulong *search_precompute_cache(char *index_data, unsigned int *num_indices, char *filename, unsigned int filename_size) {
  char buf[256] = {0};
  int file_size = 0;
  DIR *d = NULL;
  struct dirent *de = NULL;
  FILE *f = NULL;
  gpu_ulong *ret = NULL;


  *num_indices = 0;
  memset(filename, 0, filename_size);


  /* Go through all *.index files in the current directory and find any that match
   * the hash passed to us.  If found, we already pre-computed the values. */
  d = opendir(".");
  if (d == NULL) {
    fprintf(stderr, "Can't open current directory.\n");
    exit(-1);
  }
  while ((de = readdir(d)) != NULL) {
    if (str_ends_with(de->d_name, ".index")) {
      /*printf("Looking at %s\n", de->d_name);*/

      /* Open this *.index file. */
      f = fopen(de->d_name, "rb");
      if (f == NULL) {
	fprintf(stderr, "Failed to open %s for reading.\n", de->d_name);
	exit(-1);
      }

      file_size = get_file_size(f);

      /* Read the index data.*/
      if ((file_size >= sizeof(buf)) || (fread(buf, sizeof(char), file_size, f) != file_size)) {
	fprintf(stderr, "Failed to read index data: %s\n", strerror(errno));
	exit(-1);
      }

      FCLOSE(f);

      /* We found an index file that matches all our parameters.  Open its related
       * file containing precomputed indices. */
      if (strcmp(index_data, buf) == 0) {

	/* Set the filename to the *.index file for the caller. */
	strncpy(filename, de->d_name, filename_size - 1);
	de->d_name[strlen(de->d_name) - 6] = '\0';

	f = fopen(de->d_name, "rb");
	if (f == NULL) {
	  fprintf(stderr, "Failed to open precomputed index file: %s\n", de->d_name);
	  exit(-1);
	}

	file_size = get_file_size(f);

	if (file_size % sizeof(gpu_ulong) != 0) {
	  fprintf(stderr, "Precomputed indices file is not a multiple of %"PRIu64": %u\n", sizeof(gpu_ulong), file_size);
	  exit(-1);
	}

	*num_indices = file_size / sizeof(gpu_ulong);

	ret = calloc(*num_indices, sizeof(gpu_ulong));
	if (ret == NULL) {
	  fprintf(stderr, "Failed to create indices buffer.\n");
	  exit(-1);
	}

	if (fread(ret, sizeof(gpu_ulong), *num_indices, f) != *num_indices) {
	  fprintf(stderr, "Failed to read indices file.\n");
	  exit(-1);
	}
	FCLOSE(f);

	break;
      }
    }
  }
  closedir(d); d = NULL;  
  return ret;
}


/* Returns a preloaded_table entry, or NULL if no more tables are left to process.  The caller must
 * free it and all member variables. */
preloaded_table *get_preloaded_table() {
  preloaded_table *ret = NULL;

  pthread_mutex_lock(&preloaded_tables_lock);

  /* If no tables have been preloaded yet, wait until at least one becomes available. */
  while ((num_preloaded_tables_available == 0) && (table_loading_complete == 0))
    pthread_cond_wait(&condition_wait_for_tables, &preloaded_tables_lock);

  /* Return the head of the list. */
  ret = preloaded_table_list;

  /* If the head of the list isn't NULL, advance it by one. */
  if (preloaded_table_list != NULL) {
    preloaded_table_list = preloaded_table_list->next;

    if (num_preloaded_tables_available > 0)
      num_preloaded_tables_available--;

    /* Wake up the preloading thread if its waiting because it loaded the max.  Now that we're
     * consuming one table, it can load the next concurrently. */
    pthread_cond_signal(&condition_continue_loading_tables);
  }

  pthread_mutex_unlock(&preloaded_tables_lock);
  return ret;
}


void search_tables(unsigned int total_tables, precomputed_and_potential_indices *ppi, thread_args *args) {
  unsigned int num_uncracked = 0, current_table = 0;
  struct timespec start_time_table = {0};
  precomputed_and_potential_indices *ppi_cur = NULL;
  preloaded_table *pt = NULL;

  fa_batch_t fa_batch = {0};
  gpu_ulong plaintext_space_up_to_index[MAX_PLAINTEXT_LEN] = {0};
  gpu_ulong plaintext_space_total = 0;
  int charset_len = 0;

  /* Every table in a run shares one set of table parameters (find_rt_params
   * picks them once), so the reduction offset and plaintext space feeding
   * hash_to_index are constant.  That is what makes it safe to pool candidates
   * from different tables into a single dispatch. */
  if (strcmp(args[0].charset_name, "byte") == 0)
    charset_len = 256;
  else
    charset_len = strlen(args[0].charset)   /* NOT +1: radix, not a buffer size */;

  plaintext_space_total = fill_plaintext_space_table(charset_len,
      args[0].plaintext_len_min, args[0].plaintext_len_max, plaintext_space_up_to_index);

  if (fa_batch_init(&fa_batch, fa_batch_threshold, 0) != 0) {
    fprintf(stderr, "Error while initializing the false alarm batch (out of memory).\n");
    exit(-1);
  }

  while (1) {

    /* Count the number of uncracked hashes we have left. */
    ppi_cur = ppi;
    num_uncracked = 0;
    while (ppi_cur != NULL) {
      if (ppi_cur->plaintext == NULL)
	num_uncracked++;

      ppi_cur = ppi_cur->next;
    }

    /* If all the hashes were cracked, there's no need to continue processing
     * tables. */
    if (num_uncracked == 0) {
      printf("All hashes cracked.  Skipping rest of tables.\n");
      break;
    }

    /* Get the next preloaded table.  If NULL, we reached the end. */
    pt = get_preloaded_table();
    if (pt == NULL)
      break;

    current_table++;
    printf("[%u of %u] Processing table: %s...\n", current_table, total_tables, pt->filepath);  fflush(stdout);

    start_timer(&start_time_table);
    rt_binary_search(pt->rainbow_table, pt->num_chains, ppi);

    num_chains_processed += pt->num_chains;
    num_tables_processed++;

    /* Free the preloaded table. */
    FREE(pt->filepath);
    FREE(pt->rainbow_table);
    pt->num_chains = 0;
    FREE(pt);

    /* Pool this table's endpoint matches instead of dispatching them now.  One
     * table's worth of candidates is far too little work to fill a GPU, and the
     * per-dispatch setup gets paid either way. */
    if (fa_batch_append(&fa_batch, ppi, args[0].reduction_offset, plaintext_space_total) != 0) {
      fprintf(stderr, "Error while pooling false alarm candidates (out of memory).\n");
      exit(-1);
    }

    /* Safe to clear now: fa_batch_append has copied the indices out. */
    clear_potential_start_indices(ppi);

    if (fa_batch_should_flush(&fa_batch, /*force=*/0)) {
      check_false_alarms(&fa_batch, args);
      fa_batch_reset(&fa_batch);
    }

    printf("  Table fully processed in %.1f seconds.\n", get_elapsed(&start_time_table)); fflush(stdout);
    print_eta_search(num_tables_processed, total_tables);
    printf("  Cracked %u of %u hashes.\n\n", num_cracked, num_hashes);
  }

  /* Drain whatever is left.  Without this, up to (flush_threshold - 1)
   * candidates would never be checked and their hashes would be reported
   * uncracked -- including the run's very last table, which is exactly the case
   * a small table set hits every time.
   *
   * Skipped when every hash is already cracked: the pooled candidates can only
   * belong to hashes that are now solved, so the dispatch would be pure waste. */
  num_uncracked = 0;
  for (ppi_cur = ppi; ppi_cur != NULL; ppi_cur = ppi_cur->next) {
    if (ppi_cur->plaintext == NULL)
      num_uncracked++;
  }

  if ((num_uncracked > 0) && fa_batch_should_flush(&fa_batch, /*force=*/1)) {
    check_false_alarms(&fa_batch, args);
    fa_batch_reset(&fa_batch);
    printf("  Cracked %u of %u hashes.\n\n", num_cracked, num_hashes);
  }
  fa_batch_free(&fa_batch);

  /* Stop the loader and wait for it before draining the list.  The workers
   * append to preloaded_table_list, so freeing it while any of them is still
   * running would be a use after free -- which is why this joins rather than
   * just setting a flag. */
  stop_table_loading();

  pthread_mutex_lock(&preloaded_tables_lock);
  while (preloaded_table_list != NULL) {
    preloaded_table *pt_next = preloaded_table_list->next;

    FREE(preloaded_table_list->filepath);
    FREE(preloaded_table_list->rainbow_table);
    preloaded_table_list->num_chains = 0;
    FREE(preloaded_table_list);

    preloaded_table_list = pt_next;
  }
  pthread_mutex_unlock(&preloaded_tables_lock);
}


int main(int ac, char **av) {
  char *rt_dir = NULL, *single_hash = NULL, *filename = NULL, *file_data = NULL, **usernames = NULL, **hashes = NULL, *line = NULL, *pot_file_data = NULL;
  unsigned int i = 0, j = 0, max_num_hashes = 0, num_colons = 0, file_format = 0, err = 0;
  FILE *f = NULL;
  struct stat st = {0};
  thread_args *args = NULL;
  char time_precomp_str[64] = {0}, time_io_str[64] = {0}, time_searching_str[64] = {0}, time_falsealarms_str[64] = {0}, time_total_str[64] = {0}, time_per_table_str[64] = {0};

  rt_parameters rt_params = {0};

  gpu_platform platforms[MAX_NUM_PLATFORMS] = {0};
  gpu_device devices[MAX_NUM_DEVICES] = {0};

  gpu_uint num_platforms = 0, num_devices = 0;

  precomputed_and_potential_indices *ppi_head = NULL, *ppi_cur = NULL;

  preloading_thread_args preload_thread_args = {0};


  ENABLE_CONSOLE_COLOR();
  PRINT_PROJECT_HEADER();
  setlocale(LC_NUMERIC, "");
  if (ac < 3)
    print_usage_and_exit(av[0], -1);

  /* Optional third positional argument is the pot file (undocumented; used by
   * the test suite).  Anything starting with '-' from there on is a flag, so
   * flags can be combined instead of being limited to one, as they used to be. */
  {
    int argi = 3;

    if ((argi < ac) && (av[argi][0] != '-'))
      argi++;  /* pot filename; consumed further below */

    for (; argi < ac; argi += 2) {
      if (argi + 1 >= ac) {
        fprintf(stderr, "Error: %s requires a value.\n\n", av[argi]);
        print_usage_and_exit(av[0], -1);
      }

      if (strcmp(av[argi], "-gws") == 0)
        user_provided_gws = (size_t)atoi(av[argi + 1]);
      else if (strcmp(av[argi], "-disable-platform") == 0)
        disable_platform = atoi(av[argi + 1]);
      else if (strcmp(av[argi], "-precompute-gws") == 0) {
        int v = atoi(av[argi + 1]);
        if (v < 1) {
          fprintf(stderr, "Error: -precompute-gws must be at least 1.\n\n");
          print_usage_and_exit(av[0], -1);
        }
        user_provided_precompute_gws = (size_t)v;
      }
      else if (strcmp(av[argi], "-precompute-batch") == 0) {
        int v = atoi(av[argi + 1]);
        if (v < 1) {
          fprintf(stderr, "Error: -precompute-batch must be at least 1 (1 disables batching).\n\n");
          print_usage_and_exit(av[0], -1);
        }
        PRECOMPUTE_BATCH_MAX = (unsigned int)v;
      }
      else if (strcmp(av[argi], "-fa-batch") == 0) {
        int v = atoi(av[argi + 1]);
        if (v < 1) {
          fprintf(stderr, "Error: -fa-batch must be at least 1 (1 disables batching).\n\n");
          print_usage_and_exit(av[0], -1);
        }
        fa_batch_threshold = (unsigned int)v;
      } else {
        fprintf(stderr, "Error: unrecognized option: %s\n\n", av[argi]);
        print_usage_and_exit(av[0], -1);
      }
    }
  }

  /* Initialize the devices. */
  get_platforms_and_devices(disable_platform, MAX_NUM_PLATFORMS, platforms, &num_platforms, MAX_NUM_DEVICES, devices, &num_devices, VERBOSE);

  /* Check the device type and set flags.*/
  if (num_devices > 0) {
    char device_vendor[128] = {0};

    get_device_str(devices[0], CL_DEVICE_VENDOR, device_vendor, sizeof(device_vendor) - 1);
    if (strstr(device_vendor, "Advanced Micro Devices") != NULL)
      is_amd_gpu = 1;
  }

  /* Print a warning on Windows 7 systems, as they are observed to be highly
   * unstable for performing lookups on. */
  PRINT_WIN7_LOOKUP_WARNING();

  /* Check that this system has sufficient RAM. */
  CHECK_MEMORY_SIZE();

  /* Initialize the barrier.  This is used in some cases to ensure kernels across
   * multiple devices run concurrently. */
  if (pthread_barrier_init(&barrier, NULL, num_devices) != 0) {
    fprintf(stderr, "pthread_barrier_init() failed.\n");
    exit(-1);
  }

  printf("Binary searching will be done with %u threads.\n", get_num_cpu_cores());

  /* First arg is the directory (and/or sub-directories) containing rainbow tables. */
  rt_dir = av[1];

  /* The default rainbowcrackalack.pot file can be overridden with a third argument.
   * This is undocumented since its probably only useful for automated testing. */
  if ((ac >= 4) && (av[3][0] != '-')) {
    strncpy(jtr_pot_filename, av[3], sizeof(jtr_pot_filename) - 1);
    jtr_pot_filename[sizeof(jtr_pot_filename) - 1] = '\0';
    strncpy(hashcat_pot_filename, av[3], sizeof(hashcat_pot_filename) - 1);
    hashcat_pot_filename[sizeof(hashcat_pot_filename) - 1] = '\0';
    strncat(hashcat_pot_filename, ".hashcat",
            sizeof(hashcat_pot_filename) - strlen(hashcat_pot_filename) - 1);
  }

  /* Open the JTR pot file for reading.  We will check the hash(es) to see if any are
   * already cracked. */
  f = fopen(jtr_pot_filename, "rb");
  if (f) {
    unsigned long file_size = get_file_size(f);

    pot_file_data = calloc(file_size, sizeof(char));
    if (pot_file_data == NULL) {
      fprintf(stderr, "Failed to allocate buffer for pot file.\n");
      exit(-1);
    }

    if (fread(pot_file_data, sizeof(char), file_size, f) != file_size) {
      fprintf(stderr, "Error reading pot file: %s\n", strerror(errno));
      exit(-1);
    }
  } else {
    /* Allocate an empty string. */
    pot_file_data = calloc(1, sizeof(char));
    if (pot_file_data == NULL) {
      fprintf(stderr, "Failed to allocate buffer for pot file.\n");
      exit(-1);
    }
  }

  FCLOSE(f);

  /* Check if the second arg is a hash or a file containing hashes. */
  if (stat(av[2], &st) == 0)
    filename = av[2];
  else {
    single_hash = av[2];

    /* Ensure that hash is lowercase. */
    str_to_lowercase(single_hash);

    /* If this hash is already in the pot file, then there's nothing else to do. */
    if (pot_file_data && strstr(pot_file_data, single_hash)) {
      printf("Specified hash has already been cracked!  Check %s.\n", jtr_pot_filename);
      exit(0);
    }
  }

  if (filename) {
    FILE *f = fopen(filename, "rb");
    unsigned int previously_cracked = 0;


    if (f == NULL) {
      fprintf(stderr, "Error while opening file %s for reading: %s\n", filename, strerror(errno));
      goto err;
    }

    file_data = calloc(st.st_size + 1, sizeof(char));
    if (file_data == NULL) {
      fprintf(stderr, "Error while allocating buffer for hash file.\n");
      goto err;
    }

    if (fread(file_data, sizeof(char), st.st_size, f) != st.st_size) {
      fprintf(stderr, "Error while reading hash file: %s\n", strerror(errno));
      goto err;
    }

    FCLOSE(f);

    /* Count the number of newlines in the file so we know how large to make the
     * hash array. */
    for (i = 0; i < st.st_size; i++) {
      if (file_data[i] == '\n')
	max_num_hashes++;
    }
    max_num_hashes++;  /* In case the last line doesn't end with an LF. */

    num_colons = 0;
    for (i = 0; i < st.st_size; i++) {
      if (file_data[i] == ':')
        num_colons++;
      else if (file_data[i] == '\n')
        break;
    }

    if (num_colons == 0) {
      file_format = HASH_FILE_FORMAT_PLAIN;
      printf("Hash file contains plain hashes.\n");
    } else if (num_colons == 6) {
      file_format = HASH_FILE_FORMAT_PWDUMP;
      printf("Hash file is pwdump format.\n");
    } else {
      fprintf(stderr, "Error: hash file format is not recognized (number of colons in first line is %u, instead of 0 or 6).\n", num_colons);
      goto err;
    }

    usernames = calloc(max_num_hashes, sizeof(char *));
    hashes = calloc(max_num_hashes, sizeof(char *));
    if ((usernames == NULL) || (hashes == NULL)) {
      fprintf(stderr, "Error while allocating buffer for hashes.\n");
      goto err;
    }

    /* Tokenize the hash file by line.  Store each hash in the array. */
    num_hashes = 0;
    line = strtok(file_data, "\n");
    while (line && (num_hashes < max_num_hashes)) {

      /* Skip empty lines.  */
      if (strlen(line) > 0) {

	/* Skip previously-cracked hashes. */
	if (strstr(pot_file_data, line) != NULL)
	  previously_cracked++;
	else {
          /* If we're dealing with CRLF line endings, cut off the trailing CR. */
          if (line[strlen(line) - 1] == '\r')
            line[strlen(line) - 1] = '\0';

          if (file_format == HASH_FILE_FORMAT_PLAIN) {
            /* Ensure that hash is lowercase. */
            str_to_lowercase(line);

            hashes[num_hashes] = strdup(line);
            if (hashes[num_hashes] == NULL) {
              fprintf(stderr, "Error while allocating buffer for hashes.\n");
              goto err;
            }
            num_hashes++;
          } else {  /* HASH_FILE_FORMAT_PWDUMP */
            char *line_copy = strdup(line);
            char *hash = NULL;
            unsigned int line_copy_len = strlen(line_copy);
            unsigned int hash_start = 0, hash_end = 0;


            /* Get the username from position zero until the first colon. */
            for (i = 0; i < line_copy_len; i++) {
              if (line_copy[i] == ':') {
                line_copy[i] = '\0';
                usernames[num_hashes] = strdup(line_copy);
                if (usernames[num_hashes] == NULL) {
                  fprintf(stderr, "Error while allocating buffer for usernames.\n");
                  goto err;
                }
                break;
              }
            }

            /* Find the start and end positions of the hash, based on the number of colons. */
            num_colons = 1;
            hash_start = 0;
            hash_end = 0;
            for (i = i + 1; i < line_copy_len; i++) {
              if (line_copy[i] == ':')
                num_colons++;

              if ((num_colons == 3) && (hash_start == 0))
                hash_start = i + 1;
              else if (num_colons == 4) {
                hash_end = i;
                break;
              }
            }

            if ((hash_start == 0) || (hash_end == 0)) {
              fprintf(stderr, "Error: failed to extract hash from line: [%s]\n", line);
              goto err;
            }

            *(line_copy + hash_end) = '\0';
            hash = line_copy + hash_start;
            /*printf("Found hash at %u:%u: [%s]\n", hash_start, hash_end, hash);*/

            /* Make sure the hash is 32 bytes. */
            if (strlen(hash) != 32) {
              fprintf(stderr, "Error: hash is length %u instead of 32: [%s]\n", (unsigned int)strlen(hash), hash);
              goto err;
            }

            str_to_lowercase(hash);  /* Ensure hash is lowercase. */

            if (strstr(pot_file_data, hash) != NULL) {
              previously_cracked++;
            } else {
              hashes[num_hashes] = strdup(hash);
              if (hashes[num_hashes] == NULL) {
                fprintf(stderr, "Error while allocating buffer for hashes.\n");
                goto err;
              }
              num_hashes++;
            }
            FREE(line_copy);

          }
        }
	line = strtok(NULL, "\n");
      }
    }

    FREE(file_data);

    if (num_hashes == 0) {
      printf("All hashes have already been cracked!  Check %s.\n", jtr_pot_filename);
      exit(0);
    } else {
      printf("Loaded %u of %u uncracked hashes from %s.\n", num_hashes, num_hashes + previously_cracked, filename);  fflush(stdout);
    }

  } else { /* A single hash was provided. */
    usernames = calloc(1, sizeof(char *));
    hashes = calloc(1, sizeof(char *));
    if ((usernames == NULL) || (hashes == NULL)) {
      fprintf(stderr, "Error while allocating buffer for hashes.\n");
      goto err;
    }

    usernames[0] = NULL;
    hashes[0] = strdup(single_hash);
    num_hashes = 1;
  }

  /* We're done checking the pot file for previously-cracked hashes. */
  FREE(pot_file_data);

  /* Look through the supplied rainbow table directory, and infer the parameters via
   * the filenames. */
  find_rt_params(rt_dir, &rt_params);
  if (!rt_params.parsed) {
    fprintf(stderr, "Failed to infer rainbow table parameters from files in directory.  Ensure that valid rainbow table files are in %s (and/or its sub-directories).\n", rt_dir);
    exit(-1);
  }

  /* At this time, only NTLM hashes are supported. 
  if (rt_params.hash_type != HASH_NTLM) {
    fprintf(stderr, "Unfortunately, only NTLM hashes are supported at this time.  Terminating.\n");
    exit(-1);
  }
  */

  /* Ensure that valid hashes were provided. */
  if (rt_params.hash_type == HASH_NTLM) {
    for (i = 0; i < num_hashes; i++) {
      if (strlen(hashes[i]) != 32) {
	fprintf(stderr, "Error: invalid NTLM hash (length is not 32!): %s\n", hashes[i]);
	exit(-1);
      }
    }
  }

  /* Issue a warning if more than 5,000 hashes were provided, as rainbow tables may
   * start to become not as efficient as brute-force. */
  if (num_hashes > 5000) {
    printf("\n\n\n\t!! WARNING !!\n\nA large group of hashes was provided (%u).  In general, rainbow tables are only effective to use for small numbers of hashes because there is a pre-computation step that must be done on *each hash*; eventually this pre-computation cost becomes high enough that brute-force would be a better strategy.  The point at which this happens depends on your specific GPU hardware.\n\nFor example, suppose the pre-computation step takes 2.8 seconds per hash, and brute-forcing takes 16 hours (57,600 seconds).  Not counting search time nor false alarm checking, the point at which brute-forcing becomes more efficient than rainbow tables is: 57,600 / 2.8 = ~20,571 hashes.  Trying to crack more than this number of hashes is clearly less effective than brute-force.\n\nPay attention to the pre-computation times below, and compare with the reported estimate that hashcat gives after a few minutes for brute-forcing 8-character NTLM (hint: ./hashcat -m 1000 -a 3 -w 3 -O ffffffffffffffffffffffffffffffff ?a?a?a?a?a?a?a?a).\n\n\n\n", num_hashes);  fflush(stdout);
  }

  args = calloc(num_devices, sizeof(thread_args));
  if (args == NULL) {
    fprintf(stderr, "Error while creating thread arg array.\n");
    goto err;
  }

  /* We set most of the args once, since all GPUs & hashes need all the same
   * parameters. */
  for (i = 0; i < num_devices; i++) {
    args[i].hash_type = rt_params.hash_type;
    args[i].hash_name = rt_params.hash_name;
    args[i].username = NULL;  /* Filled in below. */
    args[i].hash = NULL;      /* Filled in below. */
    args[i].charset = validate_charset(rt_params.charset_name);
    args[i].charset_name = rt_params.charset_name;
    args[i].plaintext_len_min = rt_params.plaintext_len_min;
    args[i].plaintext_len_max = rt_params.plaintext_len_max;
    args[i].table_index = rt_params.table_index;
    args[i].reduction_offset = rt_params.reduction_offset;
    args[i].chain_len = rt_params.chain_len;
    args[i].total_devices = num_devices;
    args[i].gpu.device_number = i;
    args[i].gpu.device = devices[i];
    get_device_uint(args[i].gpu.device, CL_DEVICE_MAX_COMPUTE_UNITS, &(args[i].gpu.num_work_units));
  }

  num_hashes_precomputed_total = num_hashes;
  start_timer(&precompute_start_time);
  precompute_hashes(num_devices, args, &ppi_head, usernames, hashes, num_hashes);
  time_precomp = get_elapsed(&precompute_start_time);
  seconds_to_human_time(time_precomp_str, sizeof(time_precomp_str), time_precomp);
  printf("\nPre-computation finished in %s.\n\n", time_precomp_str);  fflush(stdout);

  /* If too much memory is taken up by the pre-computed indices, print a warning to the
   * user.  Strange crashes in the OpenCL functions can occur when memory is exhausted,
   * and its not obvious that this is the culprit. */
  check_memory_usage();

  /* Start preloading tables into memory. */
  preload_thread_args.rt_dir = strdup(rt_dir);
  err = pthread_create(&preload_thread_id, NULL, preloading_thread, &preload_thread_args);
  if (err == 0)
    preload_thread_running = 1;
  if (err != 0) {
    printf("Failed to create thread: %d\n", err);
    return -1;
  }

  /* Using the pre-computed end indices, perform a binary search on all rainbow tables
   * in the target directory.  Any matching indices will trigger false alarm checks. */
  total_tables = count_tables(rt_dir);
  start_timer(&search_start_time);
  search_tables(total_tables, ppi_head, args);

  seconds_to_human_time(time_precomp_str, sizeof(time_precomp_str), time_precomp);
  seconds_to_human_time(time_io_str, sizeof(time_io_str), time_io);
  seconds_to_human_time(time_searching_str, sizeof(time_searching_str), time_searching);
  seconds_to_human_time(time_falsealarms_str, sizeof(time_falsealarms_str), time_falsealarms);
  seconds_to_human_time(time_total_str, sizeof(time_total_str), time_precomp + /*time_io +*/ time_searching + time_falsealarms);
  seconds_to_human_time(time_per_table_str, sizeof(time_per_table_str), (double)(time_precomp + time_io + time_searching + time_falsealarms) / (double)num_tables_processed);

  printf("\n\n        %sRAINBOW CRACKALACK LOOKUP REPORT%s\n\n", WHITEB, CLR);

  if (num_cracked == 0)
    printf("\nNo hashes were cracked.  :(\n\n\n");
  else {
    printf(" %s* Crack Summary *%s\n\n", WHITEB, CLR);
    printf("   Of the %u hashes loaded, %u were cracked, or %.2f%%.\n\n", num_hashes, num_cracked, ((double)num_cracked / (double)num_hashes) * 100);

    printf(" Results\n -------\n%s", GREENB);
    ppi_cur = ppi_head;
    while(ppi_cur != NULL) {
      if (ppi_cur->plaintext != NULL) {
        if (is_netntlmv1_family(rt_params.hash_type)) {
          char ptxt_hex[15] = {0};
          bytes_to_hex((unsigned char*)ppi_cur->plaintext, 7, ptxt_hex, sizeof(ptxt_hex));
	  printf(" %s  %s\n", (ppi_cur->username != NULL) ? ppi_cur->username : ppi_cur->hash, ptxt_hex);
        } else {
	  printf(" %s  %s\n", (ppi_cur->username != NULL) ? ppi_cur->username : ppi_cur->hash, ppi_cur->plaintext);
        }
      }

      ppi_cur = ppi_cur->next;
    }
    printf("%s -------\n\n", CLR);
    printf("%s Results have been written in JTR format to:     %s\n", WHITEB, jtr_pot_filename);
    printf(" Results have been written in hashcat format to: %s%s\n\n\n", hashcat_pot_filename, CLR);
  }

  printf(" %s* Time Summary *%s\n\n      Precomputation: %s\n      Table loading: %s (aggregate across %u reader threads)\n           Searching: %s\n  False alarm checks: %s\n\n               Total: %s\n\n\n", WHITEB, CLR, time_precomp_str, time_io_str, num_load_threads, time_searching_str, time_falsealarms_str, time_total_str);

  printf(" %s* Statistics *%s\n\n          Number of tables processed: %u\n              Number of false alarms: %" QUOTE PRIu64"\n          Number of chains processed: %" QUOTE PRIu64"\n\n                Time spent per table: %s\n     False alarms checked per second: %" QUOTE ".1f\n\n         False alarms per no. chains: %.5f%%\n  Successful cracks per false alarms: %.5f%%\n  Successful cracks per total chains: %.8f%%\n\n\n", WHITEB, CLR, num_tables_processed, num_falsealarms, num_chains_processed, time_per_table_str, (double)num_falsealarms / time_falsealarms, ((double)num_falsealarms / (double)num_chains_processed) * 100.0, ((double)num_cracked / (double)num_falsealarms) * 100.0, ((double)num_cracked / (double)num_chains_processed) * 100.0);

  free_precomputed_and_potential_indices(&ppi_head);
  free_loaded_hashes(usernames, hashes);
  FREE(args);
  pthread_barrier_destroy(&barrier);
  return 0;

 err:
  FCLOSE(f);
  FREE(file_data);
  free_precomputed_and_potential_indices(&ppi_head);
  free_loaded_hashes(usernames, hashes);
  FREE(args);
  pthread_barrier_destroy(&barrier);
  return -1;
}
