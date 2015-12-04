OBJS = stats.o trace-event-sorter.o utils.o
UTILS = utils.o
LIBS = -ltracecmd -lpthread
%.o: %.c
	gcc -g -c -o $@ $<

all: syscalls blklatency blklatency-cli

blklatency-cli: blklatency-cli.c $(UTILS)
	gcc -g -o blklatency-cli blklatency-cli.c $(UTILS)

blklatency: $(OBJS) trace-blklatency.c
	gcc -g -o trace-blklatency trace-blklatency.c $(OBJS) $(LIBS)

syscalls: $(OBJS) trace-syscalls.c
	gcc -g -o trace-syscalls trace-syscalls.c $(OBJS) $(LIBS)

clean:
	rm -f trace-blklatency trace-syscalls blklatency-cli *.o
