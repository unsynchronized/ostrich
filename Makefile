BASEDIR := .
OUTDIR := $(BASEDIR)/out
INCLUDES += -I$(BASEDIR)/common
CFLAGS += -DDEBUG -g -Wall -Werror -std=c99
LINUXROOT=/home/cstone/routers/wrt150n/WRT150N_v1_01_9_0623_US/release/src/linux/linux

COMMON_OBJS=$(patsubst %.c,%.o,$(wildcard common/*.c))
TEST_OBJS=$(patsubst %.c,%.o,$(wildcard test/*.c))
TEST_INCLUDES=-Itest

all: $(OUTDIR) tests

tests: tuntap 

tuntap: $(TEST_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(TEST_OBJS) $(COMMON_OBJS)

test/%.o: test/%.c
	$(CC) $(CFLAGS) $(TEST_INCLUDES) $(INCLUDES) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm $(TEST_OBJS) $(COMMON_OBJS) tuntap

$(OUTDIR): 
	mkdir $(OUTDIR)

linux:
	cp wrt150n/pmltypes.h $(LINUXROOT)/include/
	cp wrt150n/pmlmachdep.c $(LINUXROOT)/net/
	cp wrt150n/octrlmachdep.c $(LINUXROOT)/net/
	cp common/pmlvm.c $(LINUXROOT)/net/
	cp common/octrl.c $(LINUXROOT)/net/
	cp common/pmlutils.c $(LINUXROOT)/net/
	cp common/pmlutils.h $(LINUXROOT)/include/
	cp common/ostversion.h $(LINUXROOT)/include/
	cp common/ostversion.c $(LINUXROOT)/net/
	cp common/pmlmachdep.h $(LINUXROOT)/include/
	cp common/octrlmachdep.h $(LINUXROOT)/include/
	cp common/pmlvm.h $(LINUXROOT)/include/
	cp common/octrl.h $(LINUXROOT)/include/
	

