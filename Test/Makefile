CLANGDIR := /Users/blucia/cvsandbox/Clang/inst/bin
IFRITDIR := /Users/blucia/cvsandbox/IFRit/ifrit

IFRITPASSDIR := $(IFRITDIR)/LLVM/IFRit
IFRITRTDIR   := $(IFRITDIR)/Runtime 

CC := $(CLANGDIR)/clang
IFRITPASS := $(IFRITPASSDIR)/IFRIT.dylib
CFLAGS := -O1
LDFLAGS := -L$(IFRITRTDIR) -lIFR_Runtime

LOADPASS := -Xclang -load -Xclang $(IFRITPASS)

SOURCES := test.c
OBJECTS := $(SOURCES:.c=.elf)

all: $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) $(LOADPASS) -c -o $@ $^

%.elf: %.o 
	$(CC) $(LDFLAGS) -o $@ $^ 

.DUMMY: clean
clean:
	$(RM) *.elf *.bc *.ll *.s *.dot *.pdf *.a *.o
