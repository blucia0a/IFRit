#include <signal.h>//for siginfo_t and sigaction
#include <stdarg.h>//for varargs
#include <stdio.h>//for fprintf
#include <stdlib.h>//for malloc
#include <string.h>//for memset
#include <unistd.h>//For rand()
#include <execinfo.h>//for backtrace() and backtrace_symbols()

//#define NDEBUG

#include <assert.h>
#include <stdbool.h>

#include <glib.h>//for GHashTable

#include "IFR.h"
#include "IFR_Runtime.h"

//#define DEBUG
#undef DEBUG

//#define RACESTACK
#undef RACESTACK

unsigned SRATE;
unsigned SOFF;

#ifdef DEBUG
#define dbprintf(...) fprintf(__VA_ARGS__)
#else
#define dbprintf(...)
#endif

pthread_key_t dkey;
pthread_rwlock_t drMutex;

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
__thread unsigned long filtered_pc = 0;
#define PROGRAM_POINT_MAX 10
#endif

GHashTable *ActiveMustWriteIFR;//A hash table mapping from variable -> list of ifrs
GHashTable *ActiveMayWriteIFR;//A hash table mapping from variable -> list of ifrs

__thread bool *samp = NULL;
__thread GHashTable *myWriteIFRs;
__thread GHashTable *myReadIFRs;

//#define DUPLICATE_STATS
#ifdef DUPLICATE_STATS
__thread unsigned long duplicates = 0;
__thread unsigned long total = 0;
#endif

__thread IFR *raceCheckIFR;

bool gSampleState;
pthread_t samplingAlarmThread;

pthread_mutex_t allThreadsLock;
pthread_t allThreads[MAX_THDS];
bool threadSampleState[MAX_THDS];

#define SINGLE_THREADED_OPT
#ifdef SINGLE_THREADED_OPT
int num_threads;
#endif

__thread GHashTable *mallocSizes;

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

/*Thread constructor Code*/
typedef struct _threadInitData{
  void *(*start_routine)(void*);
  void *arg;
} threadInitData;

void thd_ctr(){
  /*Constructor*/
  /*This looks weird, but it sets the value associated with dkey to 0x1
   *  forcing thd_dtr() to run when the thread terminates.  */
  pthread_setspecific(dkey,(void*)0x1);
/*   curWIFRVar = 0; */
/*   curRIFRVar = 0; */
/*   maxWIFRVar = INIT_ACTIVE; */
/*   maxRIFRVar = INIT_ACTIVE; */
/*   myWIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long)); */
/*   myRIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long)); */
  myWriteIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
  myReadIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
  //raceCount = 0;
  samp = NULL;
  //totalStarts = alreadyActive = stackAddress = 0;

  pthread_mutex_lock(&allThreadsLock);
  int i = 0;
  for(i = 0; i < MAX_THDS; i++){
    if( allThreads[i] == (pthread_t)0 ){
      allThreads[i] = pthread_self();
      samp = &(threadSampleState[i]);
      break;
    }
  }
  if( !samp ){
    fprintf(stderr,"[IFRit] WARNING: Could not allocate thread storage space for thread %lu\n", (unsigned long)pthread_self());
  }

#ifdef SINGLE_THREADED_OPT
  num_threads++;
#endif

  pthread_mutex_unlock(&allThreadsLock);

  //wq = g_queue_new();
  //rq = g_queue_new();

  raceCheckIFR = new_ifr(pthread_self(), 0, 0, 0);

  mallocSizes = g_hash_table_new(g_direct_hash, g_direct_equal);

#ifdef PROGRAM_POINT_OPT
  PCTable = g_hash_table_new(g_direct_hash, g_direct_equal);
  filtered_pc = 0;
#endif
}

void *threadStartFunc(void *data){
  void *(*start_routine)(void*) = ((threadInitData *)data)->start_routine;
  void *arg = ((threadInitData *) data)->arg;
  free(data);

  thd_ctr();

  return (start_routine(arg));

}

/*End thread constructor code*/

void *sample(void *v){

  char *csrate = getenv("IFR_SRATE");
  char *csoff = getenv("IFR_SOFF");
  if( csrate && csoff ){
    SRATE = atoi( csrate );
    SOFF = atoi( csoff );
    fprintf(stderr, "[IFRit] Sampling enabled with SRATE=%u, SOFF=%u (rate=%f)\n", SRATE, SOFF, (float)SRATE / ((float)(SOFF + SRATE))  );
  }else{
    gSampleState = true;
    pthread_mutex_lock(&allThreadsLock);
    int i;
    for(i = 0; i < MAX_THDS; i++){
      threadSampleState[i] = true;
    }
    pthread_mutex_unlock(&allThreadsLock);
    fprintf(stderr, "[IFRit] Sampling disabled\n");
    return NULL;
  }

  while(1){

    if( gSampleState ){
      usleep(SRATE);//On time
    }else{
      usleep(SOFF);
    }
    gSampleState = !gSampleState;
    pthread_mutex_lock(&allThreadsLock);
    int i;
    for(i = 0; i < MAX_THDS; i++){

      if( allThreads[i] != (pthread_t)0 ){
        threadSampleState[i] = gSampleState;
      }

    }
    pthread_mutex_unlock(&allThreadsLock);
    if(gSampleState && SOFF == 0){
      pthread_exit(NULL);
    }

  }

}

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

  //free(myWIFRVars);
  //free(myRIFRVars);

  g_hash_table_destroy(myWriteIFRs);
  g_hash_table_destroy(myReadIFRs);

#ifdef DUPLICATE_STATS
  fprintf(stderr, "[IFRit] %lu/%lu = %f\n", duplicates, total, ((double) duplicates)/total);
#endif

  delete_ifr(raceCheckIFR);

#ifdef PROGRAM_POINT_OPT
  g_hash_table_destroy(PCTable);
#endif
}

void sigint(int sig) {
  fprintf(stderr, "[IFRit] Received signal\n");
  exit(0);
}

/*extern "C" */void __attribute__((constructor)) IFR_Init(void){

  signal(SIGINT, sigint);
  signal(SIGKILL, sigint);

  dbprintf(stderr,"Initializing IFR Runtime\n");

/* #ifndef INCLUDE_STACK_ACCESSES */
/*   fprintf(stderr, "[IFRit] Ignoring stack accesses.\n"); */
/* #else */
/*   fprintf(stderr, "[IFRit] Monitoring all accesses.\n"); */
/* #endif */

#ifdef THREAD_LOCAL_OPT
  fprintf(stderr, "[IFRit] Thread-local optimization enabled.\n");
#endif

#ifdef READ_SHARED_OPT
  fprintf(stderr, "[IFRit] Read-shared optimization enabled.\n");
#endif

  g_thread_init(NULL);
  
#ifdef SINGLE_THREADED_OPT
  fprintf(stderr, "[IFRit] Single-threaded optimization enabled\n");
#endif

  //srand(time(NULL));

  pthread_mutex_init(&allThreadsLock, NULL);
  int i ;
  for(i = 0; i < MAX_THDS; i++){
    allThreads[i] = (pthread_t)0;
  }

  allThreads[0] = pthread_self();

#ifdef SINGLE_THREADED_OPT
  num_threads = 1;
#endif

  samp = &(threadSampleState[0]); //Thread 0's thread local state

  gSampleState = false;

  //Release allThreads to samplingAlarmThread
  pthread_create(&samplingAlarmThread,NULL,sample,NULL);

  pthread_key_create(&dkey,thd_dtr);

  pthread_rwlock_init(&drMutex, NULL);

  /*Must only be accessed under protectin of drMutex*/
  ActiveMustWriteIFR = g_hash_table_new(g_direct_hash,g_direct_equal);
  ActiveMayWriteIFR = g_hash_table_new(g_direct_hash,g_direct_equal);

  //warningCount = 0;

/*   curWIFRVar = 0; */
/*   curRIFRVar = 0; */
/*   maxWIFRVar = INIT_ACTIVE; */
/*   maxRIFRVar = INIT_ACTIVE; */
/*   myWIFRVars = (unsigned long *) calloc(INIT_ACTIVE , sizeof(unsigned long)); */
/*   myRIFRVars = (unsigned long *) calloc(INIT_ACTIVE , sizeof(unsigned long)); */
  myWriteIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);
  myReadIFRs = g_hash_table_new(g_direct_hash, g_direct_equal);

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

  mallocSizes = g_hash_table_new(g_direct_hash, g_direct_equal);

#ifdef PROGRAM_POINT_OPT
  PCTable = g_hash_table_new(g_direct_hash, g_direct_equal);
  filtered_pc = 0;
#endif
}

/*extern "C" */void __attribute__((destructor)) IFR_Exit(void){
  //fprintf(stderr, "[IFRit] Rough insertion weight (thread %p): %lu\n", pthread_self(), insertionCount);

#ifdef THREAD_LOCAL_OPT
  g_hash_table_destroy(ThreadLocalTable);
#endif

#ifdef READ_SHARED_OPT
  g_hash_table_destroy(ReadSharedTable);
#endif

#ifdef DUPLICATE_STATS
  fprintf(stderr, "[IFRit] %lu/%lu = %f\n", duplicates, total, ((double) duplicates)/total);
#endif

  fprintf(stderr, "[IFRit] Bye!\n");
}

/* int PointerCompareAscNH(const void *e1, const void *e2) { */
/*   unsigned long n1 = *((unsigned long *) e1); */
/*   unsigned long n2 = *((unsigned long *) e2); */

/*   if (n1 == n2) { */
/*     return 0; */
/*   } */
/*   if (n1 == 0) { */
/*     return 1; */
/*   } */
/*   if (n2 == 0) { */
/*     return -1; */
/*   } */
/*   if (n1 < n2) { */
/*     return -1; */
/*   } */
/*   return 1; */
/* } */

int PointerCompareAsc(const void *e1, const void *e2){
  if( *(unsigned long *)e1 > *(unsigned long *)e2 ){
    return 1;
  }
  if( *(unsigned long *)e1 == *(unsigned long *)e2 ){
    return 0;
  }
  return -1;
}

IFR *getIFR(GHashTable *h, unsigned long varg) {
  GHashTable *ifrs;
  if ((ifrs = g_hash_table_lookup(h, (gconstpointer) varg))) {

    IFR *i;
    if ((i = g_hash_table_lookup(ifrs, (gconstpointer) &myReadIFRs))) {
      return i;
    }
  }
  return NULL;
}

void activateReadIFR(unsigned long varg, void *PC, unsigned long id){
  assert(varg);

  GHashTable *ifrs = NULL;
  if( !(ifrs = (GHashTable *) g_hash_table_lookup(ActiveMayWriteIFR, (gconstpointer)varg)) ){
    g_hash_table_insert(ActiveMayWriteIFR, (gpointer)varg, g_hash_table_new(g_direct_hash,g_direct_equal));
    ifrs = (GHashTable *) g_hash_table_lookup(ActiveMayWriteIFR, (gconstpointer)varg);
  }

  IFR *i;
  if( !(i = (IFR *) g_hash_table_lookup(ifrs,(gconstpointer)&myReadIFRs)) ){     /*TODO: rip*/
    g_hash_table_insert(ifrs,(gpointer)&myReadIFRs,new_ifr(pthread_self(),id,(unsigned long)PC,varg));
  } else {
    fprintf(stderr, "[IFRit] ERROR: activateReadIFR called on IFR which is already active\n");
    exit(1);
  }
}

void activateWriteIFR(unsigned long varg, void *PC, unsigned long id){
  assert(varg);

  IFR *i = g_hash_table_lookup(ActiveMustWriteIFR,(gconstpointer)varg);
  g_hash_table_insert(ActiveMustWriteIFR, (gpointer)varg, new_ifr(pthread_self(),id,(unsigned long)PC,varg));
  if (i) {
    delete_ifr(i);
  }
}

void deactivateReadIFR(unsigned long varg){
  GHashTable *ifrs;
  if( (ifrs = (GHashTable *) g_hash_table_lookup(ActiveMayWriteIFR, (gconstpointer)varg)) ){

    IFR *i;
    if( (i = (IFR *) g_hash_table_lookup(ifrs,(gconstpointer)&myReadIFRs)) ){     /*TODO: rip*/
      g_hash_table_remove(ifrs,(gconstpointer)&myReadIFRs);
      delete_ifr(i);
    } else {
      fprintf(stderr, "[IFRit] ERROR: deactivateReadIFR called on IFR which is not active\n");
      exit(1);
    }

    if( !g_hash_table_size(ifrs) ){
      g_hash_table_remove(ActiveMayWriteIFR,(gconstpointer)varg);
      g_hash_table_destroy(ifrs);
    }

  } else {
    fprintf(stderr, "[IFRit] ERROR: deactivateReadIFR called on IFR which is not active\n");
    exit(1);
  }
}

void deactivateWriteIFR(unsigned long varg){
  IFR *i = g_hash_table_lookup(ActiveMustWriteIFR,(gconstpointer)varg);
  g_hash_table_remove(ActiveMustWriteIFR,(gconstpointer)varg);
  if (i) {
    delete_ifr(i);
  }
}

/* void assertSorted(unsigned long *array, int length) { */
/*   if (length == 0) return; */
/*   int i; */
/*   unsigned long prev = array[0]; */
/*   if (prev == 0) { */
/*     fprintf(stderr, "[IFRit] ERROR: zero in vars array\n"); */
/*     exit(1); */
/*   } */
/*   for (i = 1; i < length; i++) { */
/*     if (array[i] <= prev) { */
/*       fprintf(stderr, "[IFRit] ERROR: vars array is not sorted!\n"); */
/*       exit(1); */
/*     } */
/*     if (array[i] == 0) { */
/*       fprintf(stderr, "[IFRit] ERROR: zero in vars array\n"); */
/*       exit(1); */
/*     } */
/*   } */
/* } */

/* Takes a sorted array with oldLength elements and inserts newElement at the proper place. */
/* void insertElement(unsigned long *array, */
/* 		   int oldLength, */
/* 		   unsigned long newElement) { */
/*   int i; */

/*   assert(oldLength >= 0); */
/*   if (array == myRIFRVars) */
/*     assert(oldLength < maxRIFRVar); */
/*   else */
/*     assert(oldLength < maxWIFRVar); */

/*   for (i = oldLength - 1; i >= 0; i--) { */
/*     if (array[i] > newElement) { */
/*       array[i + 1] = array[i]; */
/*     } else if (array[i] == newElement) { */
/*       fprintf(stderr, "[IFRit] ERROR: duplicate inserted in myIFRVar\n"); */
/*       exit(1); */
/*     } else { */
/*       break; */
/*     } */
/*   } */

/*   array[i+1] = newElement; */
/*   //insertionCount += oldLength - (i+1); */
/* } */

int get_num_active_ifrs() {
  return g_hash_table_size(myWriteIFRs) + g_hash_table_size(myReadIFRs);
}

/* int already_active(unsigned long varg, int is_write) { */
/*   if(is_write) { */
/*     return bsearch(&varg, myWIFRVars, curWIFRVar, sizeof(unsigned long), */
/* 		   PointerCompareAsc) != NULL; */
/*   } else { */
/*     return bsearch(&varg, myRIFRVars, curRIFRVar, sizeof(unsigned long), */
/* 		   PointerCompareAsc) != NULL */
/*       || bsearch(&varg, myWIFRVars, curWIFRVar, sizeof(unsigned long), */
/* 		 PointerCompareAsc) != NULL; */
/*   } */
/* } */

inline int already_active(unsigned long varg, int is_write) {
  int ret;
  if (is_write) {
    ret = g_hash_table_lookup(myWriteIFRs, (gconstpointer) varg) != NULL;
    //    if (g_queue_find(wq, (gconstpointer) varg)) {
    //      recent++;
    //    }
  } else {
    ret = g_hash_table_lookup(myReadIFRs, (gconstpointer) varg) != NULL;
    //    || g_hash_table_lookup(myWriteIFRs,(gconstpointer) varg) != NULL;
    //    if (g_queue_find(rq, (gconstpointer) varg)) {
    //      recent++;
    //    }
  }
#ifdef DUPLICATE_STATS
  if (ret) duplicates++;
  total++;
#endif
  return ret;
}

void IFR_raceCheck(gpointer key, gpointer value, gpointer data){
  IFR *me = (IFR *) data;
  IFR *ifr = (IFR *) value;
  if (!pthread_equal(ifr->thread, me->thread)) {
    //raceCount++;
    fprintf(stderr,"[IFRit] %p %p %p %lu %lu : %p %p\n",
	    ifr->thread, me->thread,
	    key, me->id, ifr->id,
            me->instAddr, ifr->instAddr);
#ifdef RACESTACK
    print_trace();
#endif
  }
}

/* void add_ifrs_to_local_state(int num_new_ifrs, unsigned long *new_ifrs, int write) { */
/*   int *curIFRVar; */
/*   int *maxIFRVar; */
/*   unsigned long **myIFRVars; */

/*   if (write) { */
/*     curIFRVar = &curWIFRVar; */
/*     maxIFRVar = &maxWIFRVar; */
/*     myIFRVars = &myWIFRVars; */
/*   } else { */
/*     curIFRVar = &curRIFRVar; */
/*     maxIFRVar = &maxRIFRVar; */
/*     myIFRVars = &myRIFRVars; */
/*   } */

/*   /\* Expand the array if necessary. *\/ */
/*   while (*curIFRVar + num_new_ifrs > *maxIFRVar) { */
/*     *myIFRVars = (unsigned long *) realloc(*myIFRVars, 2 * (*maxIFRVar) */
/* 					   * sizeof(unsigned long)); */
/*     if (!(*myIFRVars)) { */
/*       fprintf(stderr, "[IFRit] ERROR: Could not allocate more memory for weak monitors\n"); */
/*       exit(1); */
/*     } */
/*     *maxIFRVar = (*maxIFRVar) * 2; */
/*   } */

/*   /\* Insert the IFRs into the array. *\/ */
/*   int v; */
/*   for (v = 0; v < num_new_ifrs; v++){ */
/*     insertElement(*myIFRVars, *curIFRVar, new_ifrs[v]); */
/*     *curIFRVar = (*curIFRVar) + 1; */
/*   } */
/* } */

void add_ifrs_to_local_state(int num_new_ifrs, unsigned long *new_ifrs, int write) {
  GHashTable *myIFRs = write ? myWriteIFRs : myReadIFRs;
  //GQueue *q = write ? wq : rq;
  int v;
  for (v = 0; v < num_new_ifrs; v++) {
    gpointer varg = (gpointer) new_ifrs[v];
    assert(varg != NULL);
    assert(g_hash_table_lookup(myIFRs, varg) == NULL);
    g_hash_table_insert(myIFRs, varg, varg);
    assert(g_hash_table_lookup(myIFRs, varg) == varg);

    //    if (g_queue_get_length(q) == MAX_Q) {
    //      g_queue_pop_tail(q);
    //    }
    //    g_queue_push_head(q, varg);
  }

}

void checkLocalToGlobal(gpointer key, gpointer value, gpointer data) {
  assert(key == value);
  GHashTable *table = (GHashTable *) data;
  GHashTable *ifrs = (GHashTable *) g_hash_table_lookup(table, key);
  assert(ifrs != NULL);
  IFR *ifr = g_hash_table_lookup(ifrs, (gconstpointer) &myReadIFRs);
  assert(ifr != NULL);
}

void checkInvariants() {
  pthread_rwlock_rdlock(&drMutex);
  //g_hash_table_foreach(myWriteIFRs, checkLocalToGlobal, ActiveMustWriteIFR);
  g_hash_table_foreach(myReadIFRs, checkLocalToGlobal, ActiveMayWriteIFR);
  pthread_rwlock_unlock(&drMutex);
}

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

/*extern "C" */void IFRit_begin_ifrs(unsigned long id,
				     unsigned long num_reads,
				     unsigned long num_writes, ... ){
/*   if (!myWriteIFRs || !myReadIFRs) { */
/*     fprintf(stderr, "[IFRit] ERROR: thread state not properly initialized.\n"); */
/*     exit(-1); */
/*   } */

/*   if( !samp || !(*samp) ){ */
/*     if (get_num_active_ifrs() > 0) { */
/*       IFRit_end_ifrs_internal(0, 0, NULL); */
/*     } */
/*     return; */
/*   } */

#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
#endif

  int i;
  va_list ap;

/*   assert(num_reads < 1024); */
/*   assert(num_writes < 1024); */

//  checkInvariants();

/*   unsigned long *all_rvargs = (unsigned long *) calloc(num_reads, sizeof(unsigned long)); */
/*   unsigned long *all_wvargs = (unsigned long *) calloc(num_writes, sizeof(unsigned long)); */
  unsigned long all_rvargs[num_reads];
  unsigned long all_wvargs[num_writes];

  int numNewReads = 0;
  int numNewWrites = 0;
#ifdef DUPLICATE_STATS
  total += num_reads;
  total += num_writes;
#endif

  va_start(ap, num_writes);

  // Find the set of non-duplicate read IFRs.
  for (i = 0; i < num_reads; i++) {
    unsigned long varg = va_arg(ap, unsigned long);
    assert(varg);

/* #ifndef INCLUDE_STACK_ACCESSES */
/*     if( varg > STACK_LOW_ADDR ){ */
/*       continue; */
/*     } */
/* #endif */

#ifdef READ_SHARED_OPT
    if (checkReadShared(varg, false)) {
      continue;
    }
#endif

#ifdef THREAD_LOCAL_OPT
    if (checkThreadLocal(varg)) {
      continue;
    }
#endif

    if (g_hash_table_lookup(myReadIFRs, (gconstpointer) varg)) {
#ifdef DUPLICATE_STATS
      duplicates++;
#endif
    } else {
      g_hash_table_insert(myReadIFRs, (gpointer) varg, (gpointer) varg);
      all_rvargs[numNewReads++] = varg;
    }

/*     int j; */
/*     int duplicate = false; */
/*     for (j = 0; j < numNewReads; j++) { */
/*       if (all_rvargs[j] == varg) { */
/*         duplicate = true; */
/*       } */
/*     } */
/*     if (duplicate) continue; */

/*     if (!already_active(varg, 0)) { */
/*       all_rvargs[numNewReads++] = varg; */
/*     } */
  }

  // Find the set of non-duplicate write IFRs.
  for( i = 0; i < num_writes; i++ ){
    unsigned long varg = va_arg(ap, unsigned long);
    assert(varg);

/* #ifndef INCLUDE_STACK_ACCESSES */
/*     if( varg > STACK_LOW_ADDR ){ */
/*       continue; */
/*     } */
/* #endif */

#ifdef READ_SHARED_OPT
    checkReadShared(varg, true);
#endif

#ifdef THREAD_LOCAL_OPT
    if (checkThreadLocal(varg)) {
      continue;
    }
#endif

    if (g_hash_table_lookup(myWriteIFRs, (gconstpointer) varg)) {
#ifdef DUPLICATE_STATS
      duplicates++;
#endif
    } else {
      g_hash_table_insert(myWriteIFRs, (gpointer) varg, (gpointer) varg);
      all_wvargs[numNewWrites++] = varg;
    }

/*     int j; */
/*     int duplicate = false; */
/*     for (j = 0; j < numNewWrites; j++) { */
/*       if (all_wvargs[j] == varg) { */
/*         duplicate = true; */
/*       } */
/*     } */
/*     if (duplicate) continue; */

/*     if (!already_active(varg, 1)) { */
/*       all_wvargs[numNewWrites++] = varg; */
/*     } */
  }

  // No new IFRs to start.
  if (numNewReads + numNewWrites == 0) {
/*     free(all_rvargs); */
/*     free(all_wvargs); */
    //    checkInvariants();
    return;
  }

  // Get the PC for this call and store it in an IFR struct.
  void *curProgPC = __builtin_return_address(0);
  raceCheckIFR->id = id;
  raceCheckIFR->instAddr = (unsigned long) curProgPC;

  // Check for data races.
  pthread_rwlock_rdlock(&drMutex);

  int v;
  for(v = 0; v < numNewReads; v++){
    unsigned long varg = all_rvargs[v];
    dbprintf(stderr, "handling read varg %p\n",varg);

    /*Looking in a map from variable -> IFR record */
    IFR *i = (IFR *) g_hash_table_lookup(ActiveMustWriteIFR, (gconstpointer) varg);
    if (i) {
      IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
    }
  }

  for(v = 0; v < numNewWrites; v++){
    unsigned long varg = all_wvargs[v];
    dbprintf(stderr, "handling write varg %p\n",varg);

    /*Looking in a map from variable -> IFR record */
    IFR *i = (IFR *) g_hash_table_lookup(ActiveMustWriteIFR, (gconstpointer)varg);
    if (i) {
      IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
    }

    /*Looking in a map from variable -> (map from thread -> IFR record)*/
    GHashTable *ifrs = (GHashTable *) g_hash_table_lookup(ActiveMayWriteIFR, (gconstpointer) varg);
    if (ifrs) {
      /*Foreaching in a map from thread -> IFR record*/
      g_hash_table_foreach(ifrs, IFR_raceCheck, raceCheckIFR);
    }/*else NULL, indicates not found*/
  }

  pthread_rwlock_unlock(&drMutex);

  //free(ifr);

  pthread_rwlock_wrlock(&drMutex);

  /* Start IFRs by adding them to the hash tables. */
  for (v = 0; v < numNewReads; v++) {
    activateReadIFR(all_rvargs[v], curProgPC, id);
    dbprintf(stderr,"INSERTED %p\n", all_rvargs[v]);
  }

  for (v = 0; v < numNewWrites; v++) {
    activateWriteIFR(all_wvargs[v], curProgPC, id);
    dbprintf(stderr,"INSERTED %p\n", all_wvargs[v]);
  }

  pthread_rwlock_unlock(&drMutex);

  /* Add the new IFRs to our local state. */
/*   add_ifrs_to_local_state(numNewReads, all_rvargs, 0); */
/*   add_ifrs_to_local_state(numNewWrites, all_wvargs, 1); */

  /* assertSorted(myRIFRVars, curRIFRVar); */
  /* assertSorted(myWIFRVars, curWIFRVar); */

  //  checkInvariants();

/*   free(all_rvargs); */
/*   free(all_wvargs); */
}

/*extern "C" */void IFRit_begin_one_read_ifr(unsigned long id,
					     unsigned long varg) {
#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
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

  if (g_hash_table_lookup(myReadIFRs, (gconstpointer) varg)) {
    return;
  }

#ifdef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
  unsigned long count = (unsigned long)
    g_hash_table_lookup(PCTable, (gconstpointer) curProgPC);
  if (count < PROGRAM_POINT_MAX) {
    g_hash_table_insert(PCTable, (gpointer) curProgPC, (gpointer) (count + 1));
  } else {
    filtered_pc++;
    return;
  }
#endif

  g_hash_table_insert(myReadIFRs, (gpointer) varg, (gpointer) varg);

  // Get the program counter.
#ifndef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
#endif
  raceCheckIFR->id = id;
  raceCheckIFR->instAddr = (unsigned long) curProgPC;

  // Check for read/write races.
  pthread_rwlock_rdlock(&drMutex);
  IFR *i = (IFR *) g_hash_table_lookup(ActiveMustWriteIFR,
				       (gconstpointer) varg);
  if (i) {
    IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
  }
  pthread_rwlock_unlock(&drMutex);

  /* Start IFR by adding it to the hash table. */
  pthread_rwlock_wrlock(&drMutex);
  activateReadIFR(varg, curProgPC, id);
  pthread_rwlock_unlock(&drMutex);
}

/*extern "C" */void IFRit_begin_one_write_ifr(unsigned long id, 
					      unsigned long varg) {
#ifdef SINGLE_THREADED_OPT
  if (num_threads == 1) {
    return;
  }
#endif

#ifdef THREAD_LOCAL_OPT
  if (checkThreadLocal(varg)) {
    return;
  }
#endif

#ifdef READ_SHARED_OPT
  checkReadShared(varg, true);
#endif

  if (g_hash_table_lookup(myWriteIFRs, (gconstpointer) varg)) {
    return;
  }

#ifdef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
  unsigned long count = (unsigned long)
    g_hash_table_lookup(PCTable, (gconstpointer) curProgPC);
  if (count < PROGRAM_POINT_MAX) {
    g_hash_table_insert(PCTable, (gpointer) curProgPC, (gpointer) (count + 1));
  } else {
    filtered_pc++;
    return;
  }
#endif

  g_hash_table_insert(myWriteIFRs, (gpointer) varg, (gpointer) varg);

  // Get the program counter.
#ifndef PROGRAM_POINT_OPT
  void *curProgPC = __builtin_return_address(0);
#endif
  raceCheckIFR->id = id;
  raceCheckIFR->instAddr = (unsigned long) curProgPC;

  // Check for read/write and write/write data races.
  pthread_rwlock_rdlock(&drMutex);
  IFR *i = (IFR *) g_hash_table_lookup(ActiveMustWriteIFR,
				       (gconstpointer) varg);
  if (i) {
    IFR_raceCheck((gpointer) varg, i, raceCheckIFR);
  }
  GHashTable *ifrs = (GHashTable *) g_hash_table_lookup(ActiveMayWriteIFR,
							(gconstpointer) varg);
  if (ifrs) {
    g_hash_table_foreach(ifrs, IFR_raceCheck, raceCheckIFR);
  }
  pthread_rwlock_unlock(&drMutex);

  /* Start IFR by adding it to the hash table. */
  pthread_rwlock_wrlock(&drMutex);
  activateWriteIFR(varg, curProgPC, id);
  pthread_rwlock_unlock(&drMutex);
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
    if (endIFRsInfo->mayArgs[q] == varg) {
      downgrade = true;
      break;
    }
  }

  if (downgrade) {
    IFR *ifr = getIFR(ActiveMustWriteIFR, varg);
    activateReadIFR(varg, (void *) ifr->instAddr, ifr->id);
    endIFRsInfo->downgradeVars[endIFRsInfo->numDowngrade] = varg;
    endIFRsInfo->numDowngrade = endIFRsInfo->numDowngrade + 1;
    assert(endIFRsInfo->numDowngrade <= endIFRsInfo->numMay);
  }

  // Deactivate the write IFR
  deactivateWriteIFR(varg);

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

  deactivateReadIFR(varg);
  return TRUE;
}

void IFRit_end_ifrs_internal(unsigned long numMay, unsigned long numMust, va_list *ap) {
  if (get_num_active_ifrs() == 0) {
    return;
  }

#ifdef PROGRAM_POINT_OPT
  g_hash_table_destroy(PCTable);
  PCTable = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif

  //checkInvariants();

  pthread_t self = pthread_self();

  struct EndIFRsInfo *endIFRsInfo = (struct EndIFRsInfo *)
    malloc(sizeof (struct EndIFRsInfo));

  endIFRsInfo->numMay = numMay;
  endIFRsInfo->mayArgs = calloc(numMay, sizeof(unsigned long));
  endIFRsInfo->numMust = numMust;
  endIFRsInfo->mustArgs = calloc(numMust, sizeof(unsigned long));

  int v;
  for (v = 0; v < numMay; v++) {
    endIFRsInfo->mayArgs[v] = va_arg(*ap, unsigned long);
  }

  for (v = 0; v < numMust; v++) {
    endIFRsInfo->mustArgs[v] = va_arg(*ap, unsigned long);
  }

  endIFRsInfo->numDowngrade = 0;
  endIFRsInfo->downgradeVars = calloc(numMay, sizeof(unsigned long));

  pthread_rwlock_wrlock(&drMutex);
  g_hash_table_foreach_remove(myWriteIFRs, process_end_write, endIFRsInfo);
  g_hash_table_foreach_remove(myReadIFRs, process_end_read, endIFRsInfo);
  pthread_rwlock_unlock(&drMutex);

  /* Insert downgraded IFRs into the read IFR array. */
  add_ifrs_to_local_state(endIFRsInfo->numDowngrade,
			  endIFRsInfo->downgradeVars, 0);
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

/*extern "C" */void IFRit_end_ifrs(){
  IFRit_end_ifrs_internal(0, 0, NULL);
}

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
