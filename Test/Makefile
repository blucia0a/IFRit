CLANGDIR := /Users/blucia/cvsandbox/Clang/inst/bin
IFRITDIR := ../LLVM/IFRit/

CC := $(CLANGDIR)/clang
IFRITLIB := $(IFRITDIR)/IFRIT.dylib

LOADPASS := -Xclang -load -Xclang $(IFRITLIB)

SOURCES := test.c
OBJECTS := $(SOURCES:.c=.elf)

all: $(OBJECTS)

%.o: %.c
	$(CC) $(LOADPASS) -c -o $@ $^

%.elf: %.o 
	$(CC) -o $@ $^ 

.DUMMY: clean
clean:
	$(RM) *.elf *.bc *.ll *.s *.dot *.pdf *.a *.o
