#include <stdio.h>
#include <stdlib.h>

#define MAX_STACK_DEPTH 1000
void _get_backtrace(void **baktrace,int addrs);
__thread void **btbuff = NULL;
__thread void **btbuffend = NULL;
__thread int btbuff_init = 0;

void GetThreadData();

void profile_func_enter(void *this_fn, void *call_site){

  if( btbuff == NULL ){
    btbuff = (void**)calloc(MAX_STACK_DEPTH,sizeof(void*));
    btbuffend = btbuff;
    btbuff_init = 1;
  }

  *btbuffend = __builtin_return_address(1);
  btbuffend++;
   
}

void profile_func_exit  (void *this_fn, void *call_site){
  
  btbuffend--;

}

void _get_backtrace(void **baktrace,int addrs){

  if( btbuff_init == 0 ){
    fprintf(stderr,"initializing in get_backtrace\n");
    btbuff = (void**)malloc(MAX_STACK_DEPTH*sizeof(void*));
    btbuffend = btbuff;
    btbuff_init = 1;
  }

  int a = 0;
  void **biter = btbuffend;
  biter--; 
  while(a < addrs && biter != btbuff){
    baktrace[a++] = *biter;
    biter--;
  } 

}

void *_get_bottom_return_address(){
  void **biter = btbuffend;
  biter--;
  return *biter; 
}
