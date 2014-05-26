typedef struct _IFR{
  pthread_t thread;
  unsigned long id;
  unsigned long instAddr;
  unsigned long dataAddr;
}IFR;

gboolean ifr_equals(gconstpointer i1, gconstpointer i2);
guint ifr_hash(gconstpointer i);
IFR *new_ifr(pthread_t tid, unsigned long id, unsigned long iAddr, unsigned long dAddr);
void delete_ifr(IFR *i);
