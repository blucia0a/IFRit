#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>


#define MAX_THDS 256

/* IFRs begin after acquire calls, after unknown function calls, at
   the beginning of basic blocks, and after variable declarations. */
extern "C" void IFRit_begin_ifrs(unsigned long, unsigned long, unsigned long, ... );
extern "C" void IFRit_begin_one_read_ifr(unsigned long, unsigned long);
extern "C" void IFRit_begin_one_write_ifr(unsigned long, unsigned long);

/* These calls have release semantics. All IFRs should be killed,
   except variables that are known to be accessed after the call. */
extern "C" int IFRit_pthread_mutex_unlock(pthread_mutex_t *, unsigned long,
					  unsigned long, ...);
extern "C" int IFRit_pthread_create(pthread_t *, const pthread_attr_t *,
				    void *(*thread) (void *), void *,
				    unsigned long numMay,
				    unsigned long numMust, ...);
extern "C" void IFRit_free(void *ptr, unsigned long, unsigned long, ...);
extern "C" int IFRit_pthread_rwlock_unlock(pthread_rwlock_t *rwlock,
					   unsigned long, unsigned long, ...);

/* These calls perform what amounts to a release followed by an
   acquire. That means other threads could safely modify any variable
   during the call, so all IFRs must be killed at this call. */
extern "C" int IFRit_pthread_cond_wait(pthread_cond_t *cond,
				       pthread_mutex_t *mutex);
extern "C" int IFRit_pthread_cond_timedwait(pthread_cond_t *cond,
					    pthread_mutex_t *mutex,
					    const struct timespec *abstime);
extern "C" int IFRit_pthread_barrier_wait(pthread_barrier_t *);
extern "C" void *IFRit_realloc(void *ptr, size_t size);

/* Generic end IFR call */
extern "C" void IFRit_end_ifrs();
