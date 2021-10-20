CC = gcc
LIB = -lpthread -lrt -lcrypto
BINS := $(subst .c,.out,$(shell find . -name "main*.c"))
BINARIES := $(subst main,,$(BINS))
LIBS := $(shell find . -name "mta_*.c")

#mainServer.out mainClient.out mainLauncher.out
all: $(BINARIES)
#	mkdir -p $(ODIR)
	
	
%.out: $ main%.c
#	$(info compiling out file)
	$(CC) $< $(LIBS) $(LIB) -o $@

clean:
	rm -f *.out
