#include <pthread.h>
#include <stdlib.h>
#include <glib.h>

#include "IFR.h"

IFR *new_ifr(pthread_t tid, unsigned long id, unsigned long iAddr, unsigned long dAddr){

  IFR *i = (IFR*)malloc(sizeof(IFR));
  i->thread = tid;
  i->id = id;
  i->instAddr = iAddr;
  i->dataAddr = dAddr;
  return i;

}

void delete_ifr(IFR *i){

  free(i);

}

guint ifr_hash(gconstpointer i){
  return g_direct_hash((gconstpointer)(((IFR*)i)->dataAddr));
}

gboolean ifr_equals(gconstpointer gi1, gconstpointer gi2){

  IFR *i1 = (IFR*)gi1;
  IFR *i2 = (IFR*)gi2;
  if( pthread_equal(i1->thread,i2->thread) &&
      i1->dataAddr == i2->dataAddr ){
    return TRUE;
  }
  return FALSE;

}
