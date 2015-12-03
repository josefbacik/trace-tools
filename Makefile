OBJS = stats.o trace-event-sorter.o
LIBS = -ltracecmd -lpthread
%.o: %.c
	gcc -c -o $@ $<

all: syscalls blklatency blklatency-cli

blklatency-cli: blklatency-cli.c
	gcc -o blklatency-cli blklatency-cli.c

blklatency: $(OBJS) trace-blklatency.c
	gcc -o trace-blklatency trace-blklatency.c $(OBJS) $(LIBS)

syscalls: $(OBJS) trace-syscalls.c
	gcc -o trace-syscalls trace-syscalls.c $(OBJS) $(LIBS)

clean:
	rm -f trace-blklatency trace-syscalls blklatency-cli
