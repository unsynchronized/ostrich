BASEDIR := .
OUTDIR := $(BASEDIR)/out
INCLUDES += -I$(BASEDIR)/common
CFLAGS += -DDEBUG -g -Wall -Werror -std=c99

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


