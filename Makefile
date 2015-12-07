OBJS = stats.o trace-event-sorter.o utils.o
UTILS = utils.o
LIBS = -ltracecmd -lpthread
CFLAGS = -Wall

%.o: %.c
	gcc -g -c -o $@ $< $(CFLAGS)

all: syscalls blklatency blklatency-cli

blklatency-cli: blklatency-cli.c $(UTILS)
	gcc -g -o blklatency-cli blklatency-cli.c $(UTILS) $(CFLAGS)

blklatency: $(OBJS) trace-blklatency.c
	gcc -g -o trace-blklatency trace-blklatency.c $(OBJS) $(LIBS) $(CFLAGS)

syscalls: $(OBJS) trace-syscalls.c
	gcc -g -o trace-syscalls trace-syscalls.c $(OBJS) $(LIBS) $(CFLAGS)

clean:
	rm -f trace-blklatency trace-syscalls blklatency-cli *.o
