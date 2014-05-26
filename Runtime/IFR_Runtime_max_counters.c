#include <signal.h>//for siginfo_t and sigaction
#include <stdarg.h>//for varargs
#include <stdio.h>//for fprintf
#include <stdlib.h>//for malloc
#include <string.h>//for memset
#include <unistd.h>//For rand()
#include <execinfo.h>//for backtrace() and backtrace_symbols()
#include <assert.h>
#include <signal.h>

#define __USE_GNU
#include <ucontext.h>//for getcontext

#include <glib.h>//for GHashTable

#include "IFR.h"
#include "IFR_Runtime.h"

//#define DEBUG
#undef DEBUG

//#define RACESTACK
#undef RACESTACK

#define STACK_LOW_ADDR 0x7000000000 //Max Heap is 448 GB; Max Stack is 0xFFFFFFFFFFFFFFFF - 0x7000000000
//                     0x7fffbab29f9c <-stack value
unsigned SRATE;
unsigned SOFF;

unsigned warningCount;
#define MAX_WARNINGS 5

#define CAS(a,b,c) __sync_bool_compare_and_swap(a, b, c)

#ifdef DEBUG
#define dbprintf(...) fprintf(__VA_ARGS__)
#else
#define dbprintf(...)
#endif

#define REPORT(V) printf("%s: %i\n", #V, V);

pthread_key_t dkey;

__thread unsigned raceCount;
__thread unsigned int randState;
/* __thread unsigned long totalStarts; */
/* __thread unsigned long alreadyActive; */
/* __thread unsigned long stackAddress; */
pthread_mutex_t drMutex;

GHashTable *ActiveMustWriteIFR;//A hash table mapping from variable -> list of ifrs
GHashTable *ActiveMayWriteIFR;//A hash table mapping from variable -> list of ifrs

#define MAX_ACTIVE 4096
#define INIT_ACTIVE 512
__thread int curWIFRVar;
__thread int curRIFRVar;
__thread int maxWIFRVar;
__thread int maxRIFRVar;
__thread unsigned long *myWIFRVars;
__thread unsigned long *myRIFRVars;
__thread int maxRIFRVarOverAllTime;
__thread int maxWIFRVarOverAllTime;

bool gSampleState;
pthread_t samplingAlarmThread;

pthread_mutex_t allThreadsLock;
pthread_t allThreads[MAX_THDS];
int num_threads;
bool threadSampleState[MAX_THDS];

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

void ___end_ifrs_internal(unsigned long numMay, unsigned long numMust, va_list *ap);

__thread bool *samp;

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
  curWIFRVar = 0;
  curRIFRVar = 0;
  maxWIFRVar = INIT_ACTIVE;
  maxRIFRVar = INIT_ACTIVE;
  myWIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long));
  myRIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long));
  maxRIFRVarOverAllTime = 0;
  maxWIFRVarOverAllTime = 0;
  raceCount = 0;
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
  num_threads++;
  pthread_mutex_unlock(&allThreadsLock);
}

void *threadStartFunc(void *arg){

  threadInitData *tid = (threadInitData *)arg;

  thd_ctr();

  return (tid->start_routine(tid->arg));

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
    return;
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
  num_threads--;
  pthread_mutex_unlock(&allThreadsLock);

  ___end_ifrs_internal(0, 0, NULL);

  //fprintf(stderr, "[IFRit] total: %lu redundant: %lu stack: %lu\n", totalStarts, alreadyActive, stackAddress);

  free(myWIFRVars);
  free(myRIFRVars);

  fprintf(stderr, "[IFRit] Max RIFR over all time for thread %p: %d\n",
	  pthread_self(), maxRIFRVarOverAllTime);
  fprintf(stderr, "[IFRit] Max WIFR over all time for thread %p: %d\n",
	  pthread_self(), maxWIFRVarOverAllTime);
}

void sigint(int sig) {
  fprintf(stderr, "[IFRit] Received signal\n");
  exit(0);
}

/*extern "C" */void __attribute__((constructor)) IFR_Init(void){

  signal(SIGINT, sigint);
  signal(SIGKILL, sigint);

  dbprintf(stderr,"Initializing IFR Runtime\n");

  fprintf(stderr, "[IFRit] Single-threaded optimization enabled\n");

  //srand(time(NULL));

  pthread_mutex_init(&allThreadsLock, NULL);
  int i ;
  for(i = 0; i < MAX_THDS; i++){
    allThreads[i] = (pthread_t)0;
  }

  allThreads[0] = pthread_self();

  num_threads = 1;

  samp = &(threadSampleState[0]); //Thread 0's thread local state

  gSampleState = false;

  //Release allThreads to samplingAlarmThread
  pthread_create(&samplingAlarmThread,NULL,sample,NULL);

  pthread_key_create(&dkey,thd_dtr);

  pthread_mutex_init(&drMutex, NULL);

  /*Must only be accessed under protectin of drMutex*/
  ActiveMustWriteIFR = g_hash_table_new(g_direct_hash,g_direct_equal);
  ActiveMayWriteIFR = g_hash_table_new(g_direct_hash,g_direct_equal);

  warningCount = 0;

  curWIFRVar = 0;
  curRIFRVar = 0;
  maxWIFRVar = INIT_ACTIVE;
  maxRIFRVar = INIT_ACTIVE;
  myWIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long));
  myRIFRVars = (unsigned long *) malloc(INIT_ACTIVE * sizeof(unsigned long));
  maxRIFRVarOverAllTime = 0;
  maxWIFRVarOverAllTime = 0;

  //totalStarts = alreadyActive = stackAddress = 0;
}

/*extern "C" */void __attribute__((destructor)) IFR_Exit(void){
  //fprintf(stderr, "[IFRit] total: %lu redundant: %lu stack: %lu\n", totalStarts, alreadyActive, stackAddress);
  fprintf(stderr, "[IFRit] Max RIFR over all time for thread %p: %d\n",
	  pthread_self(), maxRIFRVarOverAllTime);
  fprintf(stderr, "[IFRit] Max WIFR over all time for thread %p: %d\n",
	  pthread_self(), maxWIFRVarOverAllTime);
  fprintf(stderr, "[IFRit] Bye!\n");
}

void ___begin_ifrs_internal(unsigned long num, va_list *ap) {

}

int PointerCompareDsc(const void *e1, const void *e2){

  if( *(unsigned long *)e1 == *(unsigned long *)e2 ){
    return 0;
  }

  if( *(unsigned long *)e1 > *(unsigned long *)e2){
    return -1;
  }

  return 1;

}

int PointerCompareAscNH(const void *e1, const void *e2){

  int m = INT_MAX;
  if( *(unsigned long *)e1 == 0 ){
    e1 = &m;
  }
  if( *(unsigned long *)e2 == 0 ){
    e2 = &m;
  }

  if( *(unsigned long *)e1 > *(unsigned long *)e2 ){
    return 1;
  }
  if( *(unsigned long *)e1 == *(unsigned long *)e2 ){
    return 0;
  }
  return -1;
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

/* IFR *getIFR(GHashTable *h, unsigned long varg){ */

/*   GHashTable *ifrs;  */
/*   if( (ifrs = g_hash_table_lookup(h, (gconstpointer)varg)) ){ */

/*     IFR *i; */
/*     if( (i = g_hash_table_lookup(ifrs,(gconstpointer)pthread_self())) ){     /\*TODO: rip*\/ */
/*       return i; */
/*     } */
/*   } */
/*   return NULL; */

/* } */

void activateIFR(GHashTable *h, unsigned long varg, void *PC, unsigned long id){

    GHashTable *ifrs = NULL;
    if( !(ifrs = g_hash_table_lookup(h, (gconstpointer)varg)) ){
      g_hash_table_insert(h, (gpointer)varg, g_hash_table_new(g_direct_hash,g_direct_equal));
      ifrs = g_hash_table_lookup(h, (gconstpointer)varg);
    }

    IFR *i;
    if( !(i = g_hash_table_lookup(ifrs,(gconstpointer)&myRIFRVars)) ){     /*TODO: rip*/
      g_hash_table_insert(ifrs,(gpointer)&myRIFRVars,new_ifr(pthread_self(),id,(unsigned long)PC,varg));
    } else {
      fprintf(stderr, "[IFRit] ERROR: activateIFR called on IFR which is already active\n");
      exit(1);
    }
}

void deactivateIFR(GHashTable *h, unsigned long varg){

  GHashTable *ifrs;
  if( (ifrs = g_hash_table_lookup(h, (gconstpointer)varg)) ){

    IFR *i;
    if( (i = g_hash_table_lookup(ifrs,(gconstpointer)&myRIFRVars)) ){     /*TODO: rip*/
      g_hash_table_remove(ifrs,(gconstpointer)&myRIFRVars);
      delete_ifr(i);
    } else {
      fprintf(stderr, "[IFRit] ERROR: deactivateIFR called on IFR which is not active\n");
      exit(1);
    }

    if( !g_hash_table_size(ifrs) ){
      g_hash_table_remove(h,(gconstpointer)varg);
      g_hash_table_destroy(ifrs);
    }

  } else {
    fprintf(stderr, "[IFRit] ERROR: deactivateIFR called on IFR which is not active\n");
    exit(1);
  }

}

void assertSorted(unsigned long *array, int length) {
  if (length == 0) return;
  int i;
  unsigned long prev = array[0];
  if (prev == 0) {
    fprintf(stderr, "[IFRit] ERROR: zero in vars array\n");
    exit(1);
  }
  for (i = 1; i < length; i++) {
    if (array[i] <= prev) {
      fprintf(stderr, "[IFRit] ERROR: vars array is not sorted!\n");
      exit(1);
    }
    if (array[i] == 0) {
      fprintf(stderr, "[IFRit] ERROR: zero in vars array\n");
      exit(1);
    }
  }
}

void ___end_ifrs_internal(unsigned long numMay, unsigned long numMust, va_list *ap) {


  if( curRIFRVar == 0 && curWIFRVar == 0){
    return;
  }

  pthread_t self = pthread_self();

  int v;
  unsigned long mayvargs[numMay];
  unsigned long mustvargs[numMust];

  for(v = 0; v < numMay; v++){
    mayvargs[v] = va_arg(*ap, unsigned long);
  }

  for(v = 0; v < numMust; v++){
    mustvargs[v] = va_arg(*ap, unsigned long);
  }

  pthread_mutex_lock(&drMutex);

  int i;
  int oldCurWIFRVar = curWIFRVar;
  for(i = 0; i < oldCurWIFRVar; i++){

    unsigned long varg = myWIFRVars[i];

    bool keepMust = false;

    int q;
    for (q = 0; q < numMust; q++){
      if( mustvargs[q] == varg ){
        keepMust = true;
        break;
      }
    }

    if( !keepMust ){
      deactivateIFR(ActiveMustWriteIFR,varg);
      myWIFRVars[i] = 0;
      curWIFRVar--;
    }

  }

  int oldCurRIFRVar = curRIFRVar;
  for(i = 0; i < oldCurRIFRVar; i++){

    unsigned long varg = myRIFRVars[i];

    bool keepMay = false;

    int q;
    for (q = 0; q < numMay; q++){
      if( mayvargs[q] == varg ){
        keepMay = true;
        break;
      }
    }

    if( !keepMay ){
      deactivateIFR(ActiveMayWriteIFR,varg);
      myRIFRVars[i] = 0;
      curRIFRVar--;
    }

  }

  pthread_mutex_unlock(&drMutex);

  /*Sort by pointer value, placing NULL at the end, so we can reuse them*/
  qsort(myWIFRVars, oldCurWIFRVar, sizeof(unsigned long), PointerCompareAscNH);

  /*Sort by pointer value, placing NULL at the end, so we can reuse them*/
  qsort(myRIFRVars, oldCurRIFRVar, sizeof(unsigned long), PointerCompareAscNH);

  /* Realloc smaller array */
  if (maxRIFRVar > 8 * INIT_ACTIVE && curRIFRVar <= INIT_ACTIVE) {
    maxRIFRVar = INIT_ACTIVE;
    myRIFRVars = (unsigned long *) realloc(myRIFRVars, maxRIFRVar * sizeof(unsigned long));
  }

  /* Realloc smaller array */
  if (maxWIFRVar >= 8 * INIT_ACTIVE && curWIFRVar <= INIT_ACTIVE) {
    maxWIFRVar = INIT_ACTIVE;
    myWIFRVars = (unsigned long *) realloc(myWIFRVars, maxWIFRVar * sizeof(unsigned long));
  }

  /* assertSorted(myRIFRVars, curRIFRVar); */
  /* assertSorted(myWIFRVars, curWIFRVar); */
}

void IFR_raceCheck(gpointer key, gpointer value, gpointer data){

  IFR *me = (void*)data;
  IFR *ifr = (IFR*)value;
  if( !pthread_equal(ifr->thread,pthread_self()) ){
    raceCount++;
    fprintf(stderr,"[IFRit] %lu %lu : %p %p\n", me->id, ifr->id,
	    me->instAddr, ifr->instAddr);
#ifdef RACESTACK
    print_trace();
#endif
  }

}

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

/*extern "C" */void ___begin_ifrs2(unsigned long id,
				   unsigned long num_reads,
				   unsigned long num_writes, ... ){

  if( !samp || !(*samp) ){
    if (curRIFRVar > 0 || curWIFRVar > 0) {
      ___end_ifrs_internal(0, 0, NULL);
    }
    return;
  }

  if (num_threads == 1) {
    return;
  }

  //  totalStarts += num_reads + num_writes;

  int i;
  va_list ap;
  //unsigned long all_rvargs[num_reads];
  //unsigned long all_wvargs[num_writes];
  assert(num_reads < 1024);
  assert(num_writes < 1024);

  unsigned long *all_rvargs = calloc( num_reads, sizeof(unsigned long));
  unsigned long *all_wvargs = calloc( num_writes, sizeof(unsigned long));

  //memset(all_rvargs, 0, num_reads * sizeof(unsigned long));
  //memset(all_wvargs, 0, num_writes * sizeof(unsigned long));

  int numMatched = 0;
  int numNewReads = 0;
  int numNewWrites = 0;

  va_start(ap, num_writes);
  for( i = 0; i < num_reads; i++ ){

    unsigned long varg = va_arg(ap, unsigned long);
    if( varg > STACK_LOW_ADDR ){
      //stackAddress++;
      continue;
    }

    int j;
    int duplicate = false;
    for (j = 0; j < numNewReads; j++) {
      if (all_rvargs[j] == varg) {
	duplicate = true;
      }
    }
    if (duplicate) continue;

    if( !bsearch( &varg, myRIFRVars, curRIFRVar, sizeof(unsigned long), PointerCompareAsc ) ){
      //alreadyActive++;
      assert( num_reads );
      assert( numNewReads < num_reads );
      all_rvargs[numNewReads++] = varg;
    }

  }

  for( i = 0; i < num_writes; i++ ){

    unsigned long varg = va_arg(ap, unsigned long);

    if( varg > STACK_LOW_ADDR ){
      //stackAddress++;
      continue;
    }

    int j;
    int duplicate = false;
    for (j = 0; j < numNewWrites; j++) {
      if (all_wvargs[j] == varg) {
	duplicate = true;
      }
    }
    if (duplicate) continue;

    if( !bsearch( &varg, myWIFRVars, curWIFRVar, sizeof(unsigned long), PointerCompareAsc ) ){
      //alreadyActive++;
      assert( num_writes );
      assert( numNewWrites < num_writes );
      all_wvargs[numNewWrites++] = varg;
    }

  }

  if( numNewReads + numNewWrites == 0){
    free(all_rvargs);
    free(all_wvargs);
    return;
  }


  void *curProgPCs[2] = {NULL, NULL};
  backtrace(curProgPCs,2);
  void *curProgPC = curProgPCs[1]; 
  IFR *ifr = new_ifr(pthread_self(), id, (unsigned long) curProgPC, 0);

  pthread_mutex_lock(&drMutex);
  int v;


  for(v = 0; v < numNewReads; v++){

    dbprintf(stderr, "handling read varg %p\n",varg);
    unsigned long varg = all_rvargs[v];
    GHashTable *ifrs = NULL;
    /*Looking in a map from variable -> (map from thread -> IFR record)*/
    if( (ifrs = g_hash_table_lookup(ActiveMustWriteIFR, (gconstpointer)varg)) ){

      /*Foreaching in a map from thread -> IFR record*/
      g_hash_table_foreach(ifrs, IFR_raceCheck, ifr);

    }/*else NULL, indicates not found*/

  }

  for(v = 0; v < numNewWrites; v++){

    unsigned long varg = all_wvargs[v];
    dbprintf(stderr, "handling write varg %p\n",varg);
    /*Check for conflicts here*/
    all_wvargs[v] = varg;


    GHashTable *ifrs = NULL;
    /*Looking in a map from variable -> (map from thread -> IFR record)*/
    if( (ifrs = g_hash_table_lookup(ActiveMustWriteIFR, (gconstpointer)varg)) ){

      /*Foreaching in a map from thread -> IFR record*/
      g_hash_table_foreach(ifrs, IFR_raceCheck, ifr);

    }/*else NULL, indicates not found*/

    /*Looking in a map from variable -> (map from thread -> IFR record)*/
    if( (ifrs = g_hash_table_lookup(ActiveMayWriteIFR, (gconstpointer)varg)) ){

      /*Foreaching in a map from thread -> IFR record*/
      g_hash_table_foreach(ifrs, IFR_raceCheck, ifr);

    }/*else NULL, indicates not found*/

  }

  free(ifr);

  /*Start my IFRs now*/
  for(v = 0; v < numNewReads; v++){
    activateIFR(ActiveMayWriteIFR,all_rvargs[v],curProgPC,id);
    dbprintf(stderr,"INSERTED %p\n", all_rvargs[v]);
  }

  for (v = 0; v < numNewWrites; v++){
    activateIFR(ActiveMustWriteIFR,all_wvargs[v],curProgPC,id);
    dbprintf(stderr,"INSERTED %p\n", all_wvargs[v]);
  }

  pthread_mutex_unlock(&drMutex);

  while (curRIFRVar + numNewReads > maxRIFRVar) {
    myRIFRVars = (unsigned long *) realloc(myRIFRVars, 2 * maxRIFRVar * sizeof(unsigned long));
    if (!myRIFRVars) {
      fprintf(stderr, "[IFRit] ERROR: Could not allocate more memory for weak monitors\n");
      exit(1);
    }
    maxRIFRVar = maxRIFRVar * 2;
  }

  /* if (curRIFRVar > 2096) { */
  /*   fprintf(stderr, "Using insertion sort\n"); */

  for (v = 0; v < numNewReads; v++){
    insertElement(myRIFRVars, curRIFRVar, all_rvargs[v]);
    curRIFRVar++;
  }

  if (curRIFRVar > maxRIFRVarOverAllTime) {
    maxRIFRVarOverAllTime = curRIFRVar;
  }

  /* } else { */
    /* for (v = 0; v < numNewReads; v++){ */
    /*   myRIFRVars[curRIFRVar++] = all_rvargs[v]; */
    /* } */

    /* // sort the array */
    /* qsort(myRIFRVars, curRIFRVar, sizeof(unsigned long), PointerCompareAscNH); */
  /* } */

  while (curWIFRVar + numNewWrites > maxWIFRVar) {
    myWIFRVars = (unsigned long *) realloc(myWIFRVars, 2 * maxWIFRVar * sizeof(unsigned long));
    if (!myWIFRVars) {
      fprintf(stderr, "[IFRit] ERROR: Could not allocate more memory for strong monitors\n");
      exit(1);
    }
    maxWIFRVar = maxWIFRVar * 2;
  }

  /* if (curWIFRVar > 2096) { */
  /*   fprintf(stderr, "Using insertion sort\n"); */

  for (v = 0; v < numNewWrites; v++){
    insertElement(myWIFRVars, curWIFRVar, all_wvargs[v]);
    curWIFRVar++;
  }

  if (curWIFRVar > maxWIFRVarOverAllTime) {
    maxWIFRVarOverAllTime = curWIFRVar;
  }

  /* } else { */
    /* for (v = 0; v < numNewWrites; v++){ */
    /*   myWIFRVars[curWIFRVar++] = all_wvargs[v]; */
    /* } */

    /* // sort the array */
    /* qsort(myWIFRVars, curWIFRVar, sizeof(unsigned long), PointerCompareAscNH); */
  /* } */

  // sort the array
  //qsort(myRIFRVars, curRIFRVar, sizeof(unsigned long), PointerCompareAscNH);

  // sort the array
  //qsort(myWIFRVars, curWIFRVar, sizeof(unsigned long), PointerCompareAscNH);

  /* assertSorted(myRIFRVars, curRIFRVar); */
  /* assertSorted(myWIFRVars, curWIFRVar); */

  /* dbprintf(stderr, "Starting IFR: %lu read/write IFRs, %lu write IFRs\n", */
  /* 	   num_reads, num_writes); */
  free(all_rvargs);
  free(all_wvargs);
}

/*extern "C" */int ___pthread_mutex_unlock(pthread_mutex_t *lock, unsigned long numMay, unsigned long numMust, ... ){


  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);

  return pthread_mutex_unlock(lock);
}



/*extern "C" */int ___pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg, unsigned long numMay, unsigned long numMust, ...){

  dbprintf(stderr,"IFR CREATE\n");

  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);

  threadInitData *tid = (threadInitData*)malloc(sizeof(*tid));
  tid->start_routine = start_routine;
  tid->arg = arg;
  int ret = pthread_create(thread,attr,threadStartFunc,(void*)tid);
  return ret;

}

/*extern "C" */void ___free(void *mem, unsigned long numMay, unsigned long numMust, ... ){

  dbprintf(stderr,"IFR FREE\n");

  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);

  free(mem);

}

/*extern "C" */int ___pthread_cond_signal(pthread_cond_t *cond, unsigned long numMay, unsigned long numMust, ...){

  dbprintf(stderr,"IFR COND SIGNAL\n");

  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);

  return pthread_cond_signal(cond);

}

/*extern "C" */int ___pthread_cond_broadcast(pthread_cond_t *cond, unsigned long numMay, unsigned long numMust, ...){

  dbprintf(stderr,"IFR COND BROADCAST\n");

  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);

  return pthread_cond_broadcast(cond);

}

/*extern "C" */int ___pthread_rwlock_unlock(pthread_rwlock_t *rwlock, unsigned long numMay, unsigned long numMust, ...){

  dbprintf(stderr,"IFR RWLOCK UNLOCK\n");

  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);

  return pthread_rwlock_unlock(rwlock);

}

/*extern "C" */int ___pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex){

  dbprintf(stderr,"IFR COND WAIT\n");

  ___end_ifrs_internal(0, 0, NULL);

  return pthread_cond_wait(cond, mutex);

}

/*extern "C" */int ___pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime){

  dbprintf(stderr,"IFR COND TIMEDWAIT\n");

  ___end_ifrs_internal(0, 0, NULL);

  return pthread_cond_timedwait(cond, mutex, abstime);

}

/*extern "C" */int ___pthread_barrier_wait(pthread_barrier_t *barrier) {

  dbprintf(stderr,"IFR BARRIER WAIT\n");

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(0, 0, NULL);

  return pthread_barrier_wait(barrier);

}

/*extern "C" */int ___end_ifrs(unsigned long numMay, unsigned long numMust, ...){

  dbprintf(stderr,"IFR END IFRS\n");

  va_list ap;
  va_start(ap, numMust);

  //unsigned long num = va_arg(ap, unsigned long);

  ___end_ifrs_internal(numMay, numMust, &ap);
}
