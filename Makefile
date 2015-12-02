OBJS = stats.o trace-event-sorter.o
LIBS = -ltracecmd -lpthread
%.o: %.c
	gcc -c -o $@ $<

all: syscalls blklatency

blklatency: $(OBJS) trace-blklatency.c
	gcc -o trace-blklatency trace-blklatency.c $(OBJS) $(LIBS)

syscalls: $(OBJS) trace-syscalls.c
	gcc -o trace-syscalls trace-syscalls.c $(OBJS) $(LIBS)

clean:
	rm -f blklatency trace-syscalls
