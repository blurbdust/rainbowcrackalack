#ifndef _COMPAT_H
#define _COMPAT_H

#ifdef __APPLE__

#include <pthread.h>

#define PTHREAD_BARRIER_SERIAL_THREAD -1

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  unsigned int count;
  unsigned int waiting;
  unsigned int phase;
} pthread_barrier_t;

typedef void *pthread_barrierattr_t;

static inline int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int count) {
  (void)attr;
  if (count == 0) return -1;
  barrier->count = count;
  barrier->waiting = 0;
  barrier->phase = 0;
  pthread_mutex_init(&barrier->mutex, NULL);
  pthread_cond_init(&barrier->cond, NULL);
  return 0;
}

static inline int pthread_barrier_wait(pthread_barrier_t *barrier) {
  pthread_mutex_lock(&barrier->mutex);
  unsigned int phase = barrier->phase;
  barrier->waiting++;
  if (barrier->waiting == barrier->count) {
    barrier->waiting = 0;
    barrier->phase++;
    pthread_cond_broadcast(&barrier->cond);
    pthread_mutex_unlock(&barrier->mutex);
    return PTHREAD_BARRIER_SERIAL_THREAD;
  }
  while (phase == barrier->phase)
    pthread_cond_wait(&barrier->cond, &barrier->mutex);
  pthread_mutex_unlock(&barrier->mutex);
  return 0;
}

static inline int pthread_barrier_destroy(pthread_barrier_t *barrier) {
  pthread_mutex_destroy(&barrier->mutex);
  pthread_cond_destroy(&barrier->cond);
  return 0;
}

#endif /* __APPLE__ */

#endif /* _COMPAT_H */
