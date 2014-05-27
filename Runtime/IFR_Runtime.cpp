#include <signal.h>//for siginfo_t and sigaction
#include <stdarg.h>//for varargs
#include <stdio.h>//for fprintf
#include <stdlib.h>//for malloc
#include <string.h>//for memset
#include <unistd.h>//For rand()
#include <execinfo.h>//for backtrace() and backtrace_symbols()

#include <assert.h>
#include <stdbool.h>

#include <glib.h>//for GHashTable



/*MAC OSX Pthread barrier hack -- 
http://blog.albertarmea.com/post/47089939939/using-pthread-barrier-on-mac-os-x
*/
#ifdef __APPLE__

#ifndef PTHREAD_BARRIER_H_
#define PTHREAD_BARRIER_H_

#include <pthread.h>
#include <errno.h>

typedef int pthread_barrierattr_t;
typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
    int tripCount;
} pthread_barrier_t;


int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int count)
{
    if(count == 0)
    {
        errno = EINVAL;
        return -1;
    }
    if(pthread_mutex_init(&barrier->mutex, 0) < 0)
    {
        return -1;
    }
    if(pthread_cond_init(&barrier->cond, 0) < 0)
    {
        pthread_mutex_destroy(&barrier->mutex);
        return -1;
    }
    barrier->tripCount = count;
    barrier->count = 0;

    return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
    pthread_cond_destroy(&barrier->cond);
    pthread_mutex_destroy(&barrier->mutex);
    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
    pthread_mutex_lock(&barrier->mutex);
    ++(barrier->count);
    if(barrier->count >= barrier->tripCount)
    {
        barrier->count = 0;
        pthread_cond_broadcast(&barrier->cond);
        pthread_mutex_unlock(&barrier->mutex);
        return 1;
    }
    else
    {
        pthread_cond_wait(&barrier->cond, &(barrier->mutex));
        pthread_mutex_unlock(&barrier->mutex);
        return 0;
    }
}

#endif // PTHREAD_BARRIER_H_
#endif // __APPLE__




#include "IFR.h"
#include "IFR_Runtime.h"

//#define USE_TBB
#ifdef USE_TBB
#include "tbb/concurrent_hash_map.h"
#endif

#define NDEBUG

//#define DEBUG
#undef DEBUG

//#define RACESTACK
//#undef RACESTACK

unsigned SRATE;
unsigned SOFF;

#ifdef DEBUG
#define dbprintf(...) fprintf(__VA_ARGS__)
#else
#define dbprintf(...)
#endif

pthread_key_t dkey;

//#define THREAD_LOCAL_OPT
#ifdef THREAD_LOCAL_OPT
typedef struct {
  bool local;
  pthread_t owner;
} ThreadLocalInfo;
GHashTable *ThreadLocalTable;
pthread_mutex_t TLMutex;
#endif

//#define READ_SHARED_OPT
#ifdef READ_SHARED_OPT
GHashTable *ReadSharedTable;
pthread_mutex_t RSMutex;
#endif

//#define PROGRAM_POINT_OPT
#ifdef PROGRAM_POINT_OPT
__thread GHashTable *PCTable;
#define PROGRAM_POINT_MAX 10
#endif

#define CHECK_FOR_RACES
#ifdef CHECK_FOR_RACES
#ifdef USE_TBB
// Map pointer -> IFR
typedef tbb::concurrent_hash_map<unsigned long, IFR *> IFRMap;

// Map pointer -> pointer -> IFR
typedef tbb::concurrent_hash_map<unsigned long, IFRMap *> IFRMapMap;

IFRMapMap *ActiveMayWriteIFR;
IFRMap *ActiveMustWriteIFR;
#else
#define VARG_MASK_BITS 5
#ifdef VARG_MASK_BITS
unsigned long VARG_MASK = (((1 << VARG_MASK_BITS) - 1) << 3);
#define NUM_VARG_MASKS (1 << VARG_MASK_BITS)
pthread_mutex_t drMutex[NUM_VARG_MASKS];
GHashTable *ActiveMustWriteIFR[NUM_VARG_MASKS];
GHashTable *ActiveMayWriteIFR[NUM_VARG_MASKS];
//#define VARG_MASK_COUNT
#ifdef VARG_MASK_COUNT
unsigned long partition_counters[NUM_VARG_MASKS];
#endif
#else
pthread_mutex_t drMutex;
GHashTable *ActiveMustWriteIFR;//A hash table mapping from variable -> list of ifrs
GHashTable *ActiveMayWriteIFR;//A hash table mapping from variable -> list of ifrs
#endif
#endif
#endif

#ifdef CHECK_FOR_RACES
#ifdef USE_TBB
#define LOCK_GLOBAL_INFO(varg) do { } while(0)
#define UNLOCK_GLOBAL_INFO(varg) do { } while(0)
#else
#ifdef VARG_MASK_BITS
#define TAKE_VARG_MASK(varg) ((varg & VARG_MASK) >> 3)
#define LOCK_GLOBAL_INFO(varg) pthread_mutex_lock(&drMutex[TAKE_VARG_MASK(varg)])
#define UNLOCK_GLOBAL_INFO(varg) pthread_mutex_unlock(&drMutex[TAKE_VARG_MASK(varg)])
#define ACTIVE_MAY_WRITE_TABLE(varg) (ActiveMayWriteIFR[TAKE_VARG_MASK(varg)])
#define ACTIVE_MUST_WRITE_TABLE(varg) (ActiveMustWriteIFR[TAKE_VARG_MASK(varg)])
#else
#define LOCK_GLOBAL_INFO(varg) pthread_mutex_lock(&drMutex)
#define UNLOCK_GLOBAL_INFO(varg) pthread_mutex_unlock(&drMutex)
#define ACTIVE_MAY_WRITE_TABLE(varg) ActiveMayWriteIFR
#define ACTIVE_MUST_WRITE_TABLE(varg) ActiveMustWriteIFR
#endif
#endif
#else
#define LOCK_GLOBAL_INFO(varg) do { } while(0)
#define UNLOCK_GLOBAL_INFO(varg) do { } while(0)
#endif

//#define IFRIT_ARRAY
#ifdef IFRIT_ARRAY
#define INIT_ACTIVE 512
__thread int curWIFRVar = 0;
__thread int curRIFRVar = 0;
__thread int maxWIFRVar = INIT_ACTIVE;
__thread int maxRIFRVar = INIT_ACTIVE;
__thread unsigned long *myWIFRVars = NULL;
__thread unsigned long *myRIFRVars = NULL;
#endif

#define IFRIT_HASH_TABLE
#ifdef IFRIT_HASH_TABLE
__thread GHashTable *myWriteIFRs;
__thread GHashTable *myReadIFRs;
#endif

//#define DUPLICATE_STATS
#ifdef DUPLICATE_STATS
__thread unsigned long duplicates = 0;
__thread unsigned long total = 0;
__thread unsigned long total_begin_ifrs_calls = 0;
__thread unsigned long total_begin_read_calls = 0;
__thread unsigned long total_begin_write_calls = 0;
#endif

__thread IFR *raceCheckIFR;

#define SAMPLING
#ifdef SAMPLING
bool gSampleState;
pthread_t samplingAlarmThread;
#endif

pthread_mutex_t allThreadsLock;
pthread_t allThreads[MAX_THDS];

#define SINGLE_THREADED_OPT
#ifdef SINGLE_THREADED_OPT
int num_threads;
#endif

void print_trace(){
  void *array[10];
  int size;
  char **strings;
  int i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  for (i = 2; i < size; i++){
    fprintf (stderr,"  %s\n", strings[i]);
  }

  free (strings);
}

void IFRit_end_ifrs_internal(unsigned long numMay, unsigned long numMust, va_list *ap);

typedef struct _threadInitData {
  void *(*start_routine)(void*);
  void *arg;
} threadInitData;

void *threadStartFunc(void *data){
  /*This looks weird, but it sets the value associated with dkey to 0x1
   *  forcing thd_dtr() to run when the thread terminates.  */
  pthread_setspecific(dkey,(void*)0x1);

#ifdef IFRIT_ARRAY
  curWIFRVar = 0;
  curRIFRVar = 0;
  maxWIFRVar = INIT_ACTIVE;
  maxRIFRVar = INIT_ACTIVE;
  myWIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long));
  myRIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long));
#endif

#ifdef IFRIT_HASH_TABLE
  myWriteIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
  myReadIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif

  pthread_mutex_lock(&allThreadsLock);
  int i = 0;
  for(i = 0; i < MAX_THDS; i++){
    if( allThreads[i] == (pthread_t)0 ){
      allThreads[i] = pthread_self();
      break;
    }
  }

#ifdef SINGLE_THREADED_OPT
  num_threads++;
#endif

  pthread_mutex_unlock(&allThreadsLock);

  raceCheckIFR = new_ifr(pthread_self(), 0, 0, 0);

#ifdef PROGRAM_POINT_OPT
  PCTable = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif

  void *(*start_routine)(void*) = ((threadInitData *)data)->start_routine;
  void *arg = ((threadInitData *) data)->arg;
  free(data);
  return (start_routine(arg));
}

#ifdef SAMPLING
void *sample(void *v) {

  sigset_t set;
  sigfillset(&set);
  pthread_sigmask(SIG_BLOCK, &set, NULL); 

  char *csrate = getenv("IFR_SRATE");
  char *csoff = getenv("IFR_SOFF");

  if (csrate && csoff) {
    SRATE = atoi( csrate );
    SOFF = atoi( csoff );
    fprintf(stderr, "[IFRit] Sampling enabled with SRATE=%u, SOFF=%u (rate=%f)\n",
	    SRATE, SOFF, (float)SRATE / ((float)(SOFF + SRATE)));
  } else {
    gSampleState = true;
    fprintf(stderr, "[IFRit] Sampling disabled\n");
    return NULL;
  }

  gSampleState = true;
  while (1) {
    if (gSampleState) {
      usleep(SRATE);//On time
    } else {
      usleep(SOFF);
    }
    gSampleState = !gSampleState;
  }
}
#endif

void thd_dtr(void*d){
  /*Destructor*/
  pthread_mutex_lock(&allThreadsLock);
  int i = 0;
  for(i = 0; i < MAX_THDS; i++){
    if( allThreads[i] != (pthread_t)0 &&
        pthread_equal(allThreads[i],pthread_self()) ){
      allThreads[i] = 0;
      break;
    }
  }

#ifdef SINGLE_THREADED_OPT
  num_threads--;
#endif

  pthread_mutex_unlock(&allThreadsLock);

  IFRit_end_ifrs_internal(0, 0, NULL);

  //fprintf(stderr, "[IFRit] total: %lu redundant: %lu stack: %lu\n", totalStarts, alreadyActive, stackAddress);
  //fprintf(stderr, "[IFRit] Rough insertion weight (thread %p): %lu\n", pthread_self(), insertionCount);

#ifdef IFRIT_ARRAY
  free(myWIFRVars);
  free(myRIFRVars);
#endif

#ifdef IFRIT_HASH_TABLE
  if( myWriteIFRs != NULL ){
    g_hash_table_destroy(myWriteIFRs);
  }
  if( myReadIFRs != NULL ){
    g_hash_table_destroy(myReadIFRs);
  }
#endif

#ifdef DUPLICATE_STATS
  fprintf(stderr, "[IFRit] %lu/%lu = %f\n", duplicates, total, ((double) duplicates)/total);
  fprintf(stderr, "[IFRit] ifrs %lu read %lu write %lu\n", total_begin_ifrs_calls,
	  total_begin_read_calls, total_begin_write_calls);
#endif

  delete_ifr(raceCheckIFR);

#ifdef PROGRAM_POINT_OPT
  if( PCTable != NULL ){
    g_hash_table_destroy(PCTable);
  }
#endif
}

void sigint(int sig) {
  fprintf(stderr, "[IFRit] Received signal\n");
  pthread_cancel(samplingAlarmThread);
  pthread_join(samplingAlarmThread,NULL);
  exit(0);
}

/*extern "C" */void __attribute__((constructor)) IFR_Init(void){
  signal(SIGINT, sigint);
  signal(SIGKILL, sigint);

  dbprintf(stderr,"Initializing IFR Runtime\n");

#ifdef IFRIT_ARRAY
  fprintf(stderr, "[IFRit] Array-based implementation in use.\n");
#endif

#ifdef IFRIT_HASH_TABLE
  fprintf(stderr, "[IFRit] Hash-table-based implementation in use.\n");
#endif

#ifdef SINGLE_THREADED_OPT
  fprintf(stderr, "[IFRit] Single-threaded optimization enabled.\n");
#endif

#ifdef THREAD_LOCAL_OPT
  fprintf(stderr, "[IFRit] Thread-local optimization enabled.\n");
#endif

#ifdef READ_SHARED_OPT
  fprintf(stderr, "[IFRit] Read-shared optimization enabled.\n");
#endif

#ifdef PROGRAM_POINT_OPT
  fprintf(stderr, "[IFRit] Program point optimization enabled.\n");
#endif

#ifdef CHECK_FOR_RACES
#ifdef VARG_MASK_BITS
  fprintf(stderr, "[IFRit] Partitioning global state into %d partitions.\n",
	  NUM_VARG_MASKS);
#endif
#else
  fprintf(stderr, "[IFRit] Not checking for races.\n");
#endif

  g_thread_init(NULL);
  
  pthread_mutex_init(&allThreadsLock, NULL);
  int i ;
  for(i = 0; i < MAX_THDS; i++){
    allThreads[i] = (pthread_t)0;
  }

  allThreads[0] = pthread_self();

#ifdef SINGLE_THREADED_OPT
  num_threads = 1;
#endif

#ifdef SAMPLING
  //Release allThreads to samplingAlarmThread
  pthread_create(&samplingAlarmThread,NULL,sample,NULL);
#else
  fprintf (stderr, "[IFRit] Sampling disabled.\n");
#endif

  pthread_key_create(&dkey,thd_dtr);

#ifdef CHECK_FOR_RACES
#ifdef USE_TBB
  ActiveMayWriteIFR = new IFRMapMap();
  ActiveMustWriteIFR = new IFRMap();
  fprintf(stderr, "[IFRit] Using TBB concurrent_hash_map.\n");
#else
#ifdef VARG_MASK_BITS
  for (i = 0; i < NUM_VARG_MASKS; i++) {
    pthread_mutex_init(&drMutex[i], NULL);
    ActiveMustWriteIFR[i] = g_hash_table_new(g_direct_hash,g_direct_equal);
    ActiveMayWriteIFR[i] = g_hash_table_new(g_direct_hash,g_direct_equal);
#ifdef VARG_MASK_COUNT
    partition_counters[i] = 0;
#endif
  }
#else
  pthread_mutex_init(&drMutex, NULL);
  ActiveMustWriteIFR = g_hash_table_new(g_direct_hash,g_direct_equal);
  ActiveMayWriteIFR = g_hash_table_new(g_direct_hash,g_direct_equal);
#endif
#endif
#endif

  //warningCount = 0;

#ifdef IFRIT_ARRAY
  curWIFRVar = 0;
  curRIFRVar = 0;
  maxWIFRVar = INIT_ACTIVE;
  maxRIFRVar = INIT_ACTIVE;
  myWIFRVars = (unsigned long *) calloc(INIT_ACTIVE , sizeof(unsigned long));
  myRIFRVars = (unsigned long *) calloc(INIT_ACTIVE , sizeof(unsigned long));
#endif

#ifdef IFRIT_HASH_TABLE
  myWriteIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
  myReadIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif

  //wq = g_queue_new();
  //rq = g_queue_new();

#ifdef THREAD_LOCAL_OPT
  ThreadLocalTable = g_hash_table_new(g_direct_hash, g_direct_equal);
  pthread_mutex_init(&TLMutex, NULL);
#endif

#ifdef READ_SHARED_OPT
  ReadSharedTable = g_hash_table_new(g_direct_hash, g_direct_equal);
  pthread_mutex_init(&RSMutex, NULL);
#endif

  raceCheckIFR = new_ifr(pthread_self(), 0, 0, 0);

#ifdef PROGRAM_POINT_OPT
  PCTable = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif
}

/*extern "C" */void __attribute__((destructor)) IFR_Exit(void){
  //fprintf(stderr, "[IFRit] Rough insertion weight (thread %p): %lu\n", pthread_self(), insertionCount);

#ifdef THREAD_LOCAL_OPT
  if( ThreadLocalTable != NULL ){
    g_hash_table_destroy(ThreadLocalTable);
  }
#endif

#ifdef READ_SHARED_OPT
  if( ReadSharedTable != NULL ){
    g_hash_table_destroy(ReadSharedTable);
  }
#endif

#ifdef DUPLICATE_STATS
  fprintf(stderr, "[IFRit] %lu/%lu = %f\n", duplicates, total, ((double) duplicates)/total);
  fprintf(stderr, "[IFRit] ifrs %lu read %lu write %lu\n", total_begin_ifrs_calls,
	  total_begin_read_calls, total_begin_write_calls);
#endif

#ifdef VARG_MASK_COUNT
  int i;
  for (i = 0; i < NUM_VARG_MASKS; i++) {
    fprintf(stderr, "[IFRit] Partition %d: %lu total\n", i, partition_counters[i]);
  }
#endif

  fprintf(stderr, "[IFRit] Bye!\n");
}

#ifdef IFRIT_ARRAY
int PointerCompareAscNH(const void *e1, const void *e2) {
  unsigned long n1 = *((unsigned long *) e1);
  unsigned long n2 = *((unsigned long *) e2);

  if (n1 == n2) {
    return 0;
  }
  if (n1 == 0) {
    return 1;
  }
  if (n2 == 0) {
    return -1;
  }
  if (n1 < n2) {
    return -1;
  }
  return 1;
}

int PointerCompareAsc(const void *e1, const void *e2){
  if( *(unsigned long *)e1 > *(unsigned long *)e2 ){
    return 1;
  }
  if( *(unsigned long *)e1 == *(unsigned long *)e2 ){
    return 0;
  }
  return -1;
}
#endif

#ifdef CHECK_FOR_RACES
#ifdef USE_TBB
IFR *getWriteIFR(unsigned long varg) {
  IFRMap::const_accessor a;
  if (ActiveMustWriteIFR->find(a, varg) ||
      !pthread_equal(a->second->thread, pthread_self())) {
    // a write-write race caused our write IFR to be deleted.
    IFR *i = new_ifr(pthread_self(), 0, 0, varg);
    //a.release();
    return i;
  }
  IFR *i = a->second;
  //a.release();
  return i;
}

void activateReadIFR(unsigned long varg, void *PC, unsigned long id){
  assert(varg);

  IFRMapMap::accessor a;
  if (ActiveMayWriteIFR->insert(a, varg)) {
    a->second = new IFRMap();
    IFRMap::accessor b;
    a->second->insert(b, (unsigned long) &raceCheckIFR);
    b->second = new_ifr(pthread_self(), id, (unsigned long) PC, varg);
    //b.release();
  } else {
    IFRMap *map = a->second;
    IFRMap::accessor b;
    if (map->insert(b, (unsigned long) &raceCheckIFR)) {
      b->second = new_ifr(pthread_self(), id, (unsigned long) PC, varg);
    } else {
      fprintf(stderr, "[IFRit] ERROR: activateReadIFR called on IFR which is already active\n");
      exit(1);
    }
    //b.release();
  }
  //a.release();
}

void activateWriteIFR(unsigned long varg, void *PC, unsigned long id){
  assert(varg);

  IFRMap::accessor a;
  if (!ActiveMustWriteIFR->insert(a, varg)) {
    delete_ifr(a->second);
  }
  a->second = new_ifr(pthread_self(), id, (unsigned long) PC, varg);
  //a.release();
}

void deactivateReadIFR(unsigned long varg) {
  IFRMapMap::accessor a;
  if (ActiveMayWriteIFR->find(a, varg)) {
    IFRMap *map = a->second;
    IFRMap::accessor b;
    if (map->find(b, (unsigned long) &raceCheckIFR)) {
      delete_ifr(b->second);
      map->erase(b);
      if (map->size() == 0) {
	delete(map);
	ActiveMayWriteIFR->erase(a);
      }
      //b.release();
      //a.release();
      return;
    }
  }

  fprintf(stderr, "[IFRit] ERROR: deactivateReadIFR called on IFR which is not active %lu\n", varg);
  exit(1);
}

void deactivateWriteIFR(unsigned long varg) {
  IFRMap::accessor a;
  if (ActiveMustWriteIFR->find(a, varg)) {
    if (pthread_equal(a->second->thread, pthread_self())) {
      delete_ifr(a->second);
      ActiveMustWriteIFR->erase(a);
      //a.release();
    }
  }
  //a.release();
}

void IFR_raceCheck(IFR *me, IFR *ifr){
  if (!pthread_equal(ifr->thread, me->thread)) {
    //raceCount++;
    fprintf(stderr,"[IFRit] %lu %lu : %p %p\n", me->id, ifr->id,
	    (void *) me->instAddr, (void *) ifr->instAddr);
#ifdef RACESTACK
    print_trace();
#endif
  }
}
#else
IFR *getWriteIFR(unsigned long varg) {
  IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg),
				       (gconstpointer) varg);
  if (!i || !pthread_equal(i->thread, pthread_self())) {
    // a write-write race caused our write IFR to be deleted.
    return new_ifr(pthread_self(), 0, 0, varg);
  }
  return i;
}

void activateReadIFR(unsigned long varg, void *PC, unsigned long id){
  assert(varg);

  GHashTable *ifrs = NULL;
  if( !(ifrs = (GHashTable *) g_hash_table_lookup(ACTIVE_MAY_WRITE_TABLE(varg), (gconstpointer)varg)) ){
    g_hash_table_insert(ACTIVE_MAY_WRITE_TABLE(varg), (gpointer)varg, g_hash_table_new(g_direct_hash,g_direct_equal));
    ifrs = (GHashTable *) g_hash_table_lookup(ACTIVE_MAY_WRITE_TABLE(varg), (gconstpointer)varg);
  }

  IFR *i;
  if( !(i = (IFR *) g_hash_table_lookup(ifrs,(gconstpointer)&raceCheckIFR)) ){     /*TODO: rip*/
    g_hash_table_insert(ifrs,(gpointer)&raceCheckIFR,new_ifr(pthread_self(),id,(unsigned long)PC,varg));
  } else {
    fprintf(stderr, "[IFRit] ERROR: activateReadIFR called on IFR which is already active\n");
    exit(1);
  }

#ifdef VARG_MASK_COUNT
  partition_counters[TAKE_VARG_MASK(varg)]++;
#endif
}

void activateWriteIFR(unsigned long varg, void *PC, unsigned long id){
  assert(varg);

  IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg),
				       (gconstpointer)varg);
  g_hash_table_insert(ACTIVE_MUST_WRITE_TABLE(varg), (gpointer) varg,
		      new_ifr(pthread_self(), id, (unsigned long) PC, varg));
  if (i) {
    delete_ifr(i);
  }

#ifdef VARG_MASK_COUNT
  partition_counters[TAKE_VARG_MASK(varg)]++;
#endif
}

void deactivateReadIFR(unsigned long varg){
  GHashTable *ifrs;

  if( (ifrs = (GHashTable *) g_hash_table_lookup(ACTIVE_MAY_WRITE_TABLE(varg), (gconstpointer)varg)) ){

    IFR *i;
    if( (i = (IFR *) g_hash_table_lookup(ifrs,(gconstpointer)&raceCheckIFR)) ){     /*TODO: rip*/
      g_hash_table_remove(ifrs,(gconstpointer)&raceCheckIFR);
      delete_ifr(i);
    } else {
      fprintf(stderr, "[IFRit] ERROR: deactivateReadIFR called on IFR which is not active %lu\n", varg);
      exit(1);
    }

    if( ifrs != NULL ){
      if( !g_hash_table_size(ifrs) ){
        g_hash_table_remove(ACTIVE_MAY_WRITE_TABLE(varg),(gconstpointer)varg);
        g_hash_table_destroy(ifrs);
      }
    }

  } else {
    fprintf(stderr, "[IFRit] ERROR: deactivateReadIFR called on IFR which is not active\n");
    exit(1);
  }
}

void deactivateWriteIFR(unsigned long varg){
  IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg),
				       (gconstpointer) varg);
  if (i && pthread_equal(pthread_self(), i->thread)) {
    g_hash_table_remove(ACTIVE_MUST_WRITE_TABLE(varg),(gconstpointer)varg);
    delete_ifr(i);
  }
}

void IFR_raceCheck(gpointer key, gpointer value, gpointer data){
  IFR *me = (IFR *) data;
  IFR *ifr = (IFR *) value;
  if (!pthread_equal(ifr->thread, me->thread)) {
    //raceCount++;
    fprintf(stderr,"[IFRit] %lu %lu : %p %p\n", me->id, ifr->id,
	    (void *) me->instAddr, (void *) ifr->instAddr);
#ifdef RACESTACK
    print_trace();
#endif
  }
}
#endif
#endif

#ifdef IFRIT_ARRAY
#define GET_NUM_ACTIVE_IFRS (curRIFRVar + curWIFRVar)
#endif

#ifdef IFRIT_HASH_TABLE
#define GET_NUM_ACTIVE_IFRS \
  (g_hash_table_size(myWriteIFRs) + g_hash_table_size(myReadIFRs))
#endif

#define IFR_TABLES_VALID (myWriteIFRs != NULL && myReadIFRs != NULL)

#ifdef IFRIT_ARRAY
/* sorts an array in which only the last element is unsorted. order n instead of nlogn */
void insertElement(unsigned long *array,
		   int oldLength,
		   unsigned long newElement) {
  int i;

  assert(oldLength >= 0);
  if (array == myRIFRVars)
    assert(oldLength < maxRIFRVar);
  else
    assert(oldLength < maxWIFRVar);

  for (i = oldLength - 1; i >= 0; i--) {
    if (array[i] > newElement) {
      array[i + 1] = array[i];
    } else if (array[i] == newElement) {
      fprintf(stderr, "[IFRit] ERROR: duplicate inserted in myIFRVar\n");
      exit(1);
    } else {
      break;
    }
  }

  array[i+1] = newElement;
}

void assertSorted(unsigned long *array, int length) {
  if (length == 0) return;
  int i;
  unsigned long prev = array[0];
  assert(prev);
  for (i = 1; i < length; i++) {
    assert(prev);
    assert(array[i] > prev);
    prev = array[i];
  }
}
#endif

#ifdef IFRIT_ARRAY
void add_ifrs_to_local_state(int num_new_ifrs, unsigned long *new_ifrs, int write) {
  int *curIFRVar;
  int *maxIFRVar;
  unsigned long **myIFRVars;

  if (write) {
    curIFRVar = &curWIFRVar;
    maxIFRVar = &maxWIFRVar;
    myIFRVars = &myWIFRVars;
  } else {
    curIFRVar = &curRIFRVar;
    maxIFRVar = &maxRIFRVar;
    myIFRVars = &myRIFRVars;
  }

  /* Expand the array if necessary. */
  while (*curIFRVar + num_new_ifrs > *maxIFRVar) {
    *myIFRVars = (unsigned long *) realloc(*myIFRVars, 2 * (*maxIFRVar)
					   * sizeof(unsigned long));
    if (!(*myIFRVars)) {
      fprintf(stderr, "[IFRit] ERROR: Could not allocate more memory for weak monitors\n");
      exit(1);
    }
    *maxIFRVar = (*maxIFRVar) * 2;
  }

  /* Insert the IFRs into the array. */
  int v;
  for (v = 0; v < num_new_ifrs; v++){
    insertElement(*myIFRVars, *curIFRVar, new_ifrs[v]);
    *curIFRVar = (*curIFRVar) + 1;
    assertSorted(*myIFRVars, *curIFRVar);
  }
}
#endif

#ifdef IFRIT_HASH_TABLE
void add_ifrs_to_local_state(int num_new_ifrs, unsigned long *new_ifrs, int write) {
  GHashTable *myIFRs = write ? myWriteIFRs : myReadIFRs;
  int v;
  for (v = 0; v < num_new_ifrs; v++) {
    gpointer varg = (gpointer) new_ifrs[v];
    assert(varg != NULL);
    assert(g_hash_table_lookup(myIFRs, varg) == NULL);
    g_hash_table_insert(myIFRs, varg, varg);
    assert(g_hash_table_lookup(myIFRs, varg) == varg);
  }
}
#endif

#ifdef THREAD_LOCAL_OPT
inline bool checkThreadLocal(unsigned long varg) {
  bool local;
  pthread_mutex_lock(&TLMutex);
  ThreadLocalInfo *tlinfo = g_hash_table_lookup(ThreadLocalTable,
						(gconstpointer) varg);
  if (tlinfo) {
    if (tlinfo->local) {
      if (tlinfo->owner == pthread_self()) {
	local = true;
      } else {
	tlinfo->local = false;
	local = false;
      }
    } else {
      local = false;
    }
  } else {
    // First access to this variable. Claim as thread-local.
    tlinfo = (ThreadLocalInfo *) malloc(sizeof(ThreadLocalInfo));
    tlinfo->local = true;
    tlinfo->owner = pthread_self();
    g_hash_table_insert(ThreadLocalTable, (gpointer) varg, (gpointer) tlinfo);
    local = true;
  }
  pthread_mutex_unlock(&TLMutex);
  return local;
}
#endif

#ifdef READ_SHARED_OPT
inline bool checkReadShared(unsigned long varg, bool is_write) {
  bool readonly;
  pthread_mutex_lock(&RSMutex);
  bool writeshared = g_hash_table_lookup(ReadSharedTable,
					 (gconstpointer) varg);
  if (writeshared) {
    readonly = false;
  } else {
    if (is_write) {
      //fprintf(stderr, "[IFRit] Write-sharing %lu\n", varg);
      g_hash_table_insert(ReadSharedTable, (gpointer) varg, (gpointer) true);
      readonly = false;
    } else {
      readonly = true;
    }
  }
  pthread_mutex_unlock(&RSMutex);
  return readonly;
}
#endif

#ifdef IFRIT_HASH_TABLE
#define READ_IFR_EXISTS(varg)					\
  (g_hash_table_lookup(myReadIFRs, (gconstpointer) varg))

#define WRITE_IFR_EXISTS(varg)					\
  (g_hash_table_lookup(myWriteIFRs, (gconstpointer) varg))

#define READ_IFR_INSERT(varg)						\
  do {									\
    g_hash_table_insert(myReadIFRs, (gpointer) varg, (gpointer) varg);	\
  } while(0)

#define WRITE_IFR_INSERT(varg)						\
  do {									\
    g_hash_table_insert(myWriteIFRs, (gpointer) varg, (gpointer) varg); \
  } while(0)
#endif

#ifdef IFRIT_ARRAY
#define READ_IFR_EXISTS(varg)						\
  (bsearch(&varg, myRIFRVars, curRIFRVar, sizeof(unsigned long),	\
	   PointerCompareAsc))

#define WRITE_IFR_EXISTS(varg)						\
  (bsearch(&varg, myWIFRVars, curWIFRVar, sizeof(unsigned long),	\
	   PointerCompareAsc))

#define READ_IFR_INSERT(varg)						\
  do {									\
    if (curRIFRVar == maxRIFRVar) {					\
      myRIFRVars = (unsigned long *) realloc(myRIFRVars,		\
					     2 * maxRIFRVar *		\
					     sizeof(unsigned long));	\
      if (!myRIFRVars) {						\
	fprintf(stderr, "[IFRit] ERROR: Could not allocate more memory for weak monitors\n"); \
	exit(1);							\
      }									\
      maxRIFRVar = maxRIFRVar * 2;					\
    }									\
    insertElement(myRIFRVars, curRIFRVar, varg);			\
    curRIFRVar++;							\
    assertSorted(myRIFRVars, curRIFRVar);				\
  } while(0)

#define WRITE_IFR_INSERT(varg)						\
  do {									\
    if (curWIFRVar == maxWIFRVar) {					\
      myWIFRVars = (unsigned long *) realloc(myWIFRVars,		\
					     2 * maxWIFRVar *		\
					     sizeof(unsigned long));	\
      if (!myWIFRVars) {						\
	fprintf(stderr, "[IFRit] ERROR: Could not allocate more memory for strong monitors\n"); \
	exit(1);							\
      }									\
      maxWIFRVar = maxWIFRVar * 2;					\
    }									\
    									\
    insertElement(myWIFRVars, curWIFRVar, varg);			\
    curWIFRVar++;							\
    assertSorted(myWIFRVars, curWIFRVar);				\
  } while(0)
#endif

#ifdef SAMPLING
#define CHECK_SAMPLE_STATE			\
  do {						\
    if (!gSampleState) {			\
      return;					\
    }						\
  } while(0)
#endif

/*extern "C" */void IFRit_begin_ifrs(unsigned long id,
				     unsigned long num_reads,
				     unsigned long num_writes, ... ){
#ifdef DUPLICATE_STATS
  total_begin_ifrs_calls++;
#endif

  CHECK_SAMPLE_STATE;

#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
#endif

  unsigned int i;
  va_list ap;

#ifdef CHECK_FOR_RACES
  unsigned long all_rvargs[num_reads];
  unsigned long all_wvargs[num_writes];
  int numNewReads = 0;
  int numNewWrites = 0;
#endif

#ifdef DUPLICATE_STATS
  total += num_reads;
  total += num_writes;
#endif

  va_start(ap, num_writes);

  // Find the set of non-duplicate read IFRs.
  for (i = 0; i < num_reads; i++) {
    unsigned long varg = va_arg(ap, unsigned long);
    assert(varg);

#ifdef THREAD_LOCAL_OPT
    if (checkThreadLocal(varg)) {
      continue;
    }
#endif

#ifdef READ_SHARED_OPT
    if (checkReadShared(varg, false)) {
      continue;
    }
#endif

    if (READ_IFR_EXISTS(varg)) {
#ifdef DUPLICATE_STATS
      duplicates++;
#endif
    } else {
      READ_IFR_INSERT(varg);
#ifdef CHECK_FOR_RACES
      all_rvargs[numNewReads++] = varg;
#endif
    }
  }

  // Find the set of non-duplicate write IFRs.
  for( i = 0; i < num_writes; i++ ){
    unsigned long varg = va_arg(ap, unsigned long);
    assert(varg);

#ifdef READ_SHARED_OPT
    checkReadShared(varg, true);
#endif

#ifdef THREAD_LOCAL_OPT
    if (checkThreadLocal(varg)) {
      continue;
    }
#endif

    if (WRITE_IFR_EXISTS(varg)) {
#ifdef DUPLICATE_STATS
      duplicates++;
#endif
    } else {
      WRITE_IFR_INSERT(varg);
#ifdef CHECK_FOR_RACES
      all_wvargs[numNewWrites++] = varg;
#endif
    }
  }

#ifdef CHECK_FOR_RACES
  // No new IFRs to start.
  if (numNewReads + numNewWrites == 0) {
    return;
  }

  // Get the PC for this call and store it in an IFR struct.
  void *curProgPC = __builtin_return_address(0);
  raceCheckIFR->id = id;
  raceCheckIFR->instAddr = (unsigned long) curProgPC;

  // Check for data races.
  int v;
  for(v = 0; v < numNewReads; v++){
    unsigned long varg = all_rvargs[v];

#ifdef USE_TBB
    // Check for read/write races.
    IFRMap::const_accessor a;
    if (ActiveMustWriteIFR->find(a, varg)) {
      IFR_raceCheck(a->second, raceCheckIFR);
    }
    a.release();

    activateReadIFR(varg, curProgPC, id);
#else
    LOCK_GLOBAL_INFO(varg);

    /*Looking in a map from variable -> IFR record */
    IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg), (gconstpointer) varg);
    if (i) {
      IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
    }

    activateReadIFR(varg, curProgPC, id);

    UNLOCK_GLOBAL_INFO(varg);
#endif
  }

  for (v = 0; v < numNewWrites; v++) {
    unsigned long varg = all_wvargs[v];
    dbprintf(stderr, "handling write varg %p\n",varg);
    
#ifdef USE_TBB
    // Check for read/write data races.
    IFRMapMap::const_accessor b;
    if (ActiveMayWriteIFR->find(b, varg)) {
      IFRMap *map = b->second;
      IFRMap::iterator i = map->begin(), e = map->end();
      for (; i != e; i++) {
	IFR_raceCheck(i->second, raceCheckIFR);
      }
    }
    b.release();

    // Check for write/write races and activate the write IFR.
    IFRMap::accessor a;
    IFR *i = NULL;
    if (ActiveMustWriteIFR->insert(a, varg)) {
      a->second = new_ifr(pthread_self(), id, (unsigned long) curProgPC, varg);
      a.release();
    } else {
      i = a->second;
      a->second = new_ifr(pthread_self(), id, (unsigned long) curProgPC, varg);
      a.release();
      IFR_raceCheck(i, raceCheckIFR);
      delete(i);
    }
#else
    LOCK_GLOBAL_INFO(varg);

    /*Looking in a map from variable -> IFR record */
    IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg), (gconstpointer)varg);
    if (i) {
      IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
    }

    /*Looking in a map from variable -> (map from thread -> IFR record)*/
    GHashTable *ifrs = (GHashTable *) g_hash_table_lookup(ACTIVE_MAY_WRITE_TABLE(varg), (gconstpointer) varg);
    if (ifrs) {
      /*Foreaching in a map from thread -> IFR record*/
      g_hash_table_foreach(ifrs, IFR_raceCheck, raceCheckIFR);
    }

    activateWriteIFR(varg, curProgPC, id);

    UNLOCK_GLOBAL_INFO(varg);
#endif
  }
#endif
}

/*extern "C" */void IFRit_begin_one_read_ifr(unsigned long id,
					     unsigned long varg) {
#ifdef DUPLICATE_STATS
  total_begin_read_calls++;
#endif

  CHECK_SAMPLE_STATE;

#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
#endif

#ifdef DUPLICATE_STATS
  total++;
#endif

#ifdef THREAD_LOCAL_OPT
  if (checkThreadLocal(varg)) {
    return;
  }
#endif

#ifdef READ_SHARED_OPT
  if (checkReadShared(varg, false)) {
    return;
  }
#endif

  if (READ_IFR_EXISTS(varg)) {
#ifdef DUPLICATE_STATS
    duplicates++;
#endif
    return;
  }

#ifdef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
  unsigned long count = (unsigned long)
    g_hash_table_lookup(PCTable, (gconstpointer) curProgPC);
  if (count < PROGRAM_POINT_MAX) {
    g_hash_table_insert(PCTable, (gpointer) curProgPC, (gpointer) (count + 1));
  } else {
    return;
  }
#endif

  READ_IFR_INSERT(varg);

#ifdef CHECK_FOR_RACES
  // Get the program counter.
#ifndef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
#endif
  raceCheckIFR->id = id;
  raceCheckIFR->instAddr = (unsigned long) curProgPC;

#ifdef USE_TBB
  // Check for read/write races.
  IFRMap::const_accessor a;
  if (ActiveMustWriteIFR->find(a, varg)) {
    IFR_raceCheck(a->second, raceCheckIFR);
  }
  a.release();

  /* Start IFR by adding it to the hash table. */
  activateReadIFR(varg, curProgPC, id);
#else
  // Check for read/write races.
  LOCK_GLOBAL_INFO(varg);
  IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg),
				       (gconstpointer) varg);
  if (i) {
    IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
  }

  /* Start IFR by adding it to the hash table. */
  activateReadIFR(varg, curProgPC, id);
  UNLOCK_GLOBAL_INFO(varg);
#endif
#endif
}

/*extern "C" */void IFRit_begin_one_write_ifr(unsigned long id, 
					      unsigned long varg) {
#ifdef DUPLICATE_STATS
  total_begin_write_calls++;
#endif

  CHECK_SAMPLE_STATE;

#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
#endif

#ifdef DUPLICATE_STATS
  total++;
#endif

#ifdef THREAD_LOCAL_OPT
  if (checkThreadLocal(varg)) {
    return;
  }
#endif

#ifdef READ_SHARED_OPT
  checkReadShared(varg, true);
#endif

  if (WRITE_IFR_EXISTS(varg)) {
#ifdef DUPLICATE_STATS
    duplicates++;
#endif
    return;
  }

#ifdef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
  unsigned long count = (unsigned long)
    g_hash_table_lookup(PCTable, (gconstpointer) curProgPC);
  if (count < PROGRAM_POINT_MAX) {
    g_hash_table_insert(PCTable, (gpointer) curProgPC, (gpointer) (count + 1));
  } else {
    return;
  }
#endif

  WRITE_IFR_INSERT(varg);

#ifdef CHECK_FOR_RACES
#ifndef PROGRAM_POINT_OPT
  // Get the program counter.
  void *curProgPC = __builtin_return_address(0);
#endif
  raceCheckIFR->id = id;
  raceCheckIFR->instAddr = (unsigned long) curProgPC;

#ifdef USE_TBB
  // Check for read/write data races.
  IFRMapMap::const_accessor b;
  if (ActiveMayWriteIFR->find(b, varg)) {
    IFRMap *map = b->second;
    IFRMap::iterator i = map->begin(), e = map->end();
    for (; i != e; i++) {
      IFR_raceCheck(i->second, raceCheckIFR);
    }
  }
  b.release();

  // Check for write/write races and activate the write IFR.
  IFRMap::accessor a;
  IFR *i = NULL;
  if (ActiveMustWriteIFR->insert(a, varg)) {
    a->second = new_ifr(pthread_self(), id, (unsigned long) curProgPC, varg);
    a.release();
  } else {
    i = a->second;
    a->second = new_ifr(pthread_self(), id, (unsigned long) curProgPC, varg);
    a.release();
    IFR_raceCheck(i, raceCheckIFR);
    delete(i);
  }
#else
  // Check for read/write and write/write data races.
  LOCK_GLOBAL_INFO(varg);
  IFR *i = (IFR *) g_hash_table_lookup(ACTIVE_MUST_WRITE_TABLE(varg),
				       (gconstpointer) varg);
  if (i) {
    IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
  }
  GHashTable *ifrs = (GHashTable *) g_hash_table_lookup(ACTIVE_MAY_WRITE_TABLE(varg),
							(gconstpointer) varg);
  if (ifrs) {
    g_hash_table_foreach(ifrs, IFR_raceCheck, raceCheckIFR);
  }

  /* Start IFR by adding it to the hash table. */
  activateWriteIFR(varg, curProgPC, id);
  UNLOCK_GLOBAL_INFO(varg);
#endif
#endif
}

/* Information about a release "end IFRs" action. */
struct EndIFRsInfo {
  int numMay;
  unsigned long *mayArgs;
  int numMust;
  unsigned long *mustArgs;
  int numDowngrade;
  unsigned long *downgradeVars;
};

/* Process an active write IFR during end_ifrs. Returns true if the
   write should be deleted from the local state. */
gboolean process_end_write(gpointer key, gpointer value, gpointer user_data) {
  unsigned long varg = (unsigned long) key;
  struct EndIFRsInfo *endIFRsInfo = (struct EndIFRsInfo *) user_data;

  // Check to see if this IFR continues through this release.
  bool keepMust = false;
  int q;
  for (q = 0; q < endIFRsInfo->numMust; q++){
    if (endIFRsInfo->mustArgs[q] == varg){
      keepMust = true;
      break;
    }
  }

  if (keepMust) {
    return FALSE;
  }

  // If not, check if should be downgraded to a read IFR.
  bool downgrade = false;
  for (q = 0; q < endIFRsInfo->numMay; q++) {
    if (endIFRsInfo->mayArgs[q] == varg
	&& !(READ_IFR_EXISTS(varg))) {
      downgrade = true;
      break;
    }
  }

#ifdef CHECK_FOR_RACES
  LOCK_GLOBAL_INFO(varg);
#endif

  if (downgrade) {
#ifdef CHECK_FOR_RACES
    IFR *ifr = getWriteIFR(varg);
    activateReadIFR(varg, (void *) ifr->instAddr, ifr->id);
#endif
    endIFRsInfo->downgradeVars[endIFRsInfo->numDowngrade] = varg;
    endIFRsInfo->numDowngrade = endIFRsInfo->numDowngrade + 1;
    assert(endIFRsInfo->numDowngrade <= endIFRsInfo->numMay);
  }

#ifdef CHECK_FOR_RACES
  // Deactivate the write IFR
  deactivateWriteIFR(varg);
  UNLOCK_GLOBAL_INFO(varg);
#endif

  return TRUE;
}

/* Process an active read IFR for an end IFRs action. Returns true if
   the IFR should be deleted from local state. */
gboolean process_end_read(gpointer key, gpointer value, gpointer user_data) {
  unsigned long varg = (unsigned long) key;
  struct EndIFRsInfo *endIFRsInfo = (struct EndIFRsInfo *) user_data;

  // Check to see if read or write IFRs for this varg continue through
  //this release.
  bool keepMay = false;
  int q;

  for (q = 0; q < endIFRsInfo->numMay; q++){
    if (endIFRsInfo->mayArgs[q] == varg) {
      keepMay = true;
      break;
    }
  }

  if (!keepMay) {
    for (q = 0; q < endIFRsInfo->numMust; q++){
      if (endIFRsInfo->mustArgs[q] == varg) {
	keepMay = true;
	break;
      }
    }
  }

  if (keepMay) {
    return FALSE;
  }

#ifdef CHECK_FOR_RACES
  LOCK_GLOBAL_INFO(varg);
  deactivateReadIFR(varg);
  UNLOCK_GLOBAL_INFO(varg);
#endif

  return TRUE;
}

#ifdef IFRIT_HASH_TABLE
#define PROCESS_END_IFRS						\
  do {									\
    g_hash_table_foreach_remove(myWriteIFRs,				\
				process_end_write,			\
				endIFRsInfo);				\
    g_hash_table_foreach_remove(myReadIFRs,				\
				process_end_read,			\
				endIFRsInfo);				\
  } while(0)  
#endif

#ifdef IFRIT_ARRAY
#define PROCESS_END_IFRS						\
  do {									\
    int i;								\
									\
    int oldCurWIFRVar = curWIFRVar;					\
    for (i = 0; i < oldCurWIFRVar; i++) {				\
      unsigned long varg = myWIFRVars[i];				\
      if (process_end_write((gpointer) varg, (gpointer) varg,		\
			    endIFRsInfo)) {				\
	myWIFRVars[i] = 0;						\
	curWIFRVar--;							\
      }									\
    }									\
									\
    int oldCurRIFRVar = curRIFRVar;					\
    for (i = 0; i < oldCurRIFRVar; i++) {				\
      unsigned long varg = myRIFRVars[i];				\
      if (process_end_read((gpointer) varg, (gpointer) varg,		\
			   endIFRsInfo)) {				\
	myRIFRVars[i] = 0;						\
	curRIFRVar--;							\
      }									\
    }									\
									\
    qsort(myWIFRVars, oldCurWIFRVar, sizeof(unsigned long),		\
	  PointerCompareAscNH);						\
    assertSorted(myWIFRVars, curWIFRVar);				\
									\
    qsort(myRIFRVars, oldCurRIFRVar, sizeof(unsigned long),		\
	  PointerCompareAscNH);						\
    assertSorted(myRIFRVars, curRIFRVar);				\
									\
    if (maxRIFRVar > 8 * INIT_ACTIVE && curRIFRVar <= INIT_ACTIVE) {	\
      maxRIFRVar = INIT_ACTIVE;						\
      myRIFRVars = (unsigned long *) realloc(myRIFRVars, maxRIFRVar * sizeof(unsigned long)); \
    }									\
    									\
    if (maxWIFRVar >= 8 * INIT_ACTIVE && curWIFRVar <= INIT_ACTIVE) {	\
      maxWIFRVar = INIT_ACTIVE;						\
      myWIFRVars = (unsigned long *) realloc(myWIFRVars, maxWIFRVar * sizeof(unsigned long)); \
    }									\
  } while (0)
#endif

void IFRit_end_ifrs_internal(unsigned long numMay, unsigned long numMust, va_list *ap) {
  if (IFR_TABLES_VALID && GET_NUM_ACTIVE_IFRS == 0) {
    return;
  }

#ifdef PROGRAM_POINT_OPT
  if( PCTable != NULL ){
    g_hash_table_destroy(PCTable);
  }
  PCTable = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif

  struct EndIFRsInfo *endIFRsInfo = (struct EndIFRsInfo *)
    malloc(sizeof (struct EndIFRsInfo));

  endIFRsInfo->numMay = numMay;
  endIFRsInfo->mayArgs = (unsigned long *) calloc(numMay,
						  sizeof(unsigned long));
  endIFRsInfo->numMust = numMust;
  endIFRsInfo->mustArgs = (unsigned long *) calloc(numMust,
						   sizeof(unsigned long));

  unsigned int v;
  for (v = 0; v < numMay; v++) {
    endIFRsInfo->mayArgs[v] = va_arg(*ap, unsigned long);
  }

  for (v = 0; v < numMust; v++) {
    endIFRsInfo->mustArgs[v] = va_arg(*ap, unsigned long);
  }

  endIFRsInfo->numDowngrade = 0;
  endIFRsInfo->downgradeVars = (unsigned long *)
    calloc(numMay, sizeof(unsigned long));

  if( IFR_TABLES_VALID ){
    PROCESS_END_IFRS;
  }

  /* Insert downgraded IFRs into the read IFR array. */
  add_ifrs_to_local_state(endIFRsInfo->numDowngrade,
			  endIFRsInfo->downgradeVars, 0);
  free(endIFRsInfo->mayArgs);
  free(endIFRsInfo->mustArgs);
  free(endIFRsInfo);
}

/*extern "C" */int IFRit_pthread_mutex_unlock(pthread_mutex_t *lock, unsigned long numMay, unsigned long numMust, ... ){
  va_list ap;
  va_start(ap, numMust);

  IFRit_end_ifrs_internal(numMay, numMust, &ap);

  return pthread_mutex_unlock(lock);
}

/*extern "C" */int IFRit_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg, unsigned long numMay, unsigned long numMust, ...){
  va_list ap;
  va_start(ap, numMust);

  IFRit_end_ifrs_internal(numMay, numMust, &ap);

  threadInitData *tid = (threadInitData*)malloc(sizeof(*tid));
  tid->start_routine = start_routine;
  tid->arg = arg;
  int ret = pthread_create(thread,attr,threadStartFunc,(void*)tid);
  return ret;
}

/*extern "C" */int IFRit_pthread_rwlock_unlock(pthread_rwlock_t *rwlock, unsigned long numMay, unsigned long numMust, ...){
  va_list ap;
  va_start(ap, numMust);

  IFRit_end_ifrs_internal(numMay, numMust, &ap);

  return pthread_rwlock_unlock(rwlock);
}

/*extern "C" */void IFRit_free(void *mem, unsigned long numMay, unsigned long numMust, ...) {
  va_list ap;
  va_start(ap, numMust);

  IFRit_end_ifrs_internal(numMay, numMust, &ap);

  free(mem);
}

/*extern "C" */int IFRit_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex){
  IFRit_end_ifrs_internal(0, 0, NULL);

  return pthread_cond_wait(cond, mutex);
}

/*extern "C" */int IFRit_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime){
  IFRit_end_ifrs_internal(0, 0, NULL);

  return pthread_cond_timedwait(cond, mutex, abstime);
}

/*extern "C" */int IFRit_pthread_barrier_wait(pthread_barrier_t *barrier) {
  IFRit_end_ifrs_internal(0, 0, NULL);

  return pthread_barrier_wait(barrier);
}

/*extern "C" */void *IFRit_realloc(void *ptr, size_t size) {
  IFRit_end_ifrs_internal(0, 0, NULL);

  return realloc(ptr, size);
}

/*extern "C" */void IFRit_end_ifrs(){
  IFRit_end_ifrs_internal(0, 0, NULL);
}

#ifdef IFRIT_HASH_TABLE
void IFRit_check_ifr(unsigned long id, unsigned long varg, unsigned long is_write) {
#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
#endif

  bool ok;
  if (is_write) {
    ok = g_hash_table_lookup(myWriteIFRs, (gconstpointer) varg);
  } else {
    ok = g_hash_table_lookup(myWriteIFRs, (gconstpointer) varg) ||
      g_hash_table_lookup(myReadIFRs, (gconstpointer) varg);
  }
  if (!ok) {
    fprintf(stderr, "[IFRit] Check failed: ID %lu varg %lu %s\n", id, varg,
	    (is_write ? "write" : "read"));
    print_trace();
  }
}
#endif
