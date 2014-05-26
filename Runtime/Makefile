#CC=gcc
#CC=/sampa/home/effinger/gcc-4.6.3/install/bin/g++
CC=g++

GLIB_CFLAGS=`pkg-config --cflags glib-2.0`
GLIB_LIBS=-pthread `pkg-config --libs glib-2.0`
# -lgthread-2.0 -lrt -lglib-2.0

OPT=-O3
DBG=
CFLAGS=$(OPT) $(DBG) -fPIC $(GLIB_CFLAGS) -Wall
LDFLAGS=$(OPT) $(DBG) -shared -fPIC $(GLIB_LIBS)

SRCS= IFR_Runtime.c IFR.c
OBJS=$(SRCS:%.c=%.o)

all: Runtime

Runtime:
	$(CC) $(CFLAGS) -c $(CFLAGS) -o IFR.o IFR.c
	$(CC) $(CFLAGS) -c $(CFLAGS) -o IFR_Runtime.o IFR_Runtime.cpp
	$(CC) $(LDFLAGS) $(OBJS) -o libIFR_Runtime.so

clean:
	-rm *.so
	-rm *.o
