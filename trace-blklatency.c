/*
 * Copyright 2015 Facebook, Josef Bacik <jbacik@fb.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 */
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#include <trace-cmd/trace-cmd.h>
#include <trace-cmd/trace-hash.h>

typedef unsigned long long u64;
#define offset_of(type, field)          (long)(&((type *)0)->field)
#define container_of(p, type, field)    (type *)((long)p - offset_of(type, field))

struct event_data {
	int			id;
	struct format_field	*dev_field;
	struct format_field	*sector_field;
	struct format_field	*rwbs_field;
	struct format_field	*nr_sector_field;
};

struct blklatency_handle {
	struct tracecmd_input		*handle;
	struct pevent			*pevent;
	struct event_data		*blk_issue;
	struct event_data		*blk_complete;
	struct blklatency_handle	*next;
};

struct blklatency_stats {
	u64		*read_times;
	u64		*write_times;
	u64		nr_reads, nr_reads_alloc;
	u64		nr_writes, nr_writes_alloc;
};

struct blkio {
	struct trace_hash_item	hash;
	u64			dev;
	u64			sector;
	u64			ts;
	int			complete;
	int			missed_count;
	char			action;
	struct blkio		*next;
};

struct pending_blkio {
	struct blkio	**pending;
	int		nr_pending;
	int		nr_alloc;
	pthread_mutex_t	mutex;
	pthread_cond_t	cond;
};

struct blkio_hash {
	struct trace_hash	hash;
	pthread_mutex_t		mutex;
};

static int max_pending_events = 1024;
static struct blklatency_stats stats;
static struct blklatency_handle *handles = NULL;
static struct blklatency_handle *last_handle = NULL;
static struct pending_blkio pending;
static struct blkio_hash blkio_hash;
static pthread_t logger_thread = -1;
static unsigned exiting = 0;
/*
void die(const char *fmt, ...)
{
	va_list ap;
	int ret = errno;

	if (errno)
		perror("trace-cmd");
	else
		ret = -1;

	tracecmd_stop_threads(TRACE_TYPE_STREAM);
	va_start(ap, fmt);
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(ret);
}
*/
static inline void *malloc_or_die(size_t size)
{
	void *ret = malloc(size);
	if (!ret)
		die("malloc failed");
	return ret;
}

static void add_new_entry(char action, u64 time)
{
//	printf("adding new entry %c %llu\n", action, time);
	if (action == 'R') {
		if (stats.nr_reads == stats.nr_reads_alloc) {
			stats.nr_reads_alloc += 1024;
			stats.read_times = realloc(stats.read_times,
						   stats.nr_reads_alloc *
						   sizeof(u64));
			if (!stats.read_times)
				die("Couldn't realloc read times");
		}
		stats.read_times[stats.nr_reads++] = time;
	} else {
		if (stats.nr_writes == stats.nr_writes_alloc) {
			stats.nr_writes_alloc += 1024;
			stats.write_times = realloc(stats.write_times,
						    stats.nr_writes_alloc *
						    sizeof(u64));
			if (!stats.write_times)
				die("Couldn't realloc write times");
		}
		stats.write_times[stats.nr_writes++] = time;
	}
}

static int match_blkio(struct trace_hash_item *item, void *data)
{
	struct blkio *blkio = container_of(item, struct blkio, hash);
	struct blkio *search = (struct blkio *)data;

	/* If we recorded a complete make sure the issue is before the complete. */
	if (blkio->complete && search->ts >= blkio->ts)
		return 0;
	if (!blkio->complete && search->ts <= blkio->ts)
		return 0;

	return blkio->dev == search->dev && blkio->sector == search->sector &&
		blkio->action == search->action;
}

#if 0
static int sort_blkio(struct trace_hash_item *a, struct trace_hash_item *b)
{
	struct blkio *A = container_of(a, struct blkio, hash);
	struct blkio *B = container_of(b, struct blkio, hash);

	if (A->ts < B->ts)
		return 1;
	else if (A->ts > B->ts)
		return -1;
	return 0;
}

static void handle_event(struct blklatency_handle *h,
			 struct pevent_record *record, struct event_data *edata)
{
	struct blkio *blkio;
	unsigned long long sector, dev, nr_sector, key;
	struct trace_hash_item *item;
	struct blkio search;
	char rwbs[9];
	int ret;

	memcpy(rwbs, record->data + edata->rwbs_field->offset,
	       sizeof(char) * 8);
	rwbs[8] = '\0';
	/*
	if (rwbs[0] != 'W' && rwbs[0] != 'R')
		return;
		*/
/*
	ret = pevent_read_number_field(edata->nr_sector_field, record->data,
					&nr_sector);
	if (ret)
		die("Missing important field in event");

	/* We don't care about 0 length requests.
	if (nr_sector == 0) {
		printf("%d, 0 length request\n", edata->id);
		return;
	}
*/

	ret = pevent_read_number_field(edata->nr_sector_field, record->data,
					&nr_sector);
	ret |= pevent_read_number_field(edata->dev_field, record->data, &dev);
	ret |= pevent_read_number_field(edata->sector_field, record->data,
					&sector);
	if (ret)
		die("Missing important field in event");

printf("%llu: got a %s request, dev %llu, sector %llu, rwbs %s, nr_sector %llu\n", record->ts, edata == h->blk_issue ? "issue" : "complete", dev, sector, rwbs, nr_sector);
	if (nr_sector == 0 || (rwbs[0] != 'W' && rwbs[0] != 'R'))
		return;

	key = trace_hash(dev + sector + rwbs[0]);
	search.dev = dev;
	search.sector = sector;
	search.action = rwbs[0];
	search.ts = record->ts;
	if (edata == h->blk_issue)
		search.complete = 0;
	else
		search.complete = 1;
	/*
	 * First check and see if we have a duplicate entry, things like the
	 * super block can get written over and over again, and if it's issue
	 * or complete are on different CPUs we can have much sadness.
	 *
	 * To deal with this we need to keep track of any duplicates and then
	 * merge it all together at the end in order to ensure we are matching
	 * the proper events.
	 */
	item = trace_hash_find(&h->blk_hash, key, match_blkio, &search);
	if (item) {

	}
	if (item) {
		trace_hash_del(item);
		blkio = container_of(item, struct blkio, hash);
		printf("matched with entry at %llu\n", blkio->ts);
		pthread_mutex_lock(&stats.mutex);
		add_new_entry(blkio->action,
			blkio->complete ? blkio->ts - record->ts :
				record->ts - blkio->ts);
		pthread_mutex_unlock(&stats.mutex);
		free(blkio);
	} else {
//		printf("not found, adding new entry\n");
		blkio = malloc_or_die(sizeof(*blkio));
		memset(blkio, 0, sizeof(*blkio));
		blkio->dev = search.dev;
		blkio->sector = search.sector;
		blkio->action = search.action;
		blkio->complete = !search.complete;
		blkio->ts = record->ts;
		blkio->hash.key = trace_hash(dev + sector + rwbs[0]);
		trace_hash_add_sort(&h->blk_hash, &blkio->hash, sort_blkio);
	}
}
#endif

static void add_pending_blkio(struct blkio *blkio)
{
	if (pending.nr_pending == pending.nr_alloc) {
		pending.nr_alloc += 1024;
		pending.pending = realloc(pending.pending,
			pending.nr_alloc * sizeof(struct blkio *));
		if (!pending.pending)
			die("Couldn't realloc pending");
	}
	pending.pending[pending.nr_pending++] = blkio;
	if (pending.nr_pending >= max_pending_events)
		pthread_cond_signal(&pending.cond);
}

static void handle_event(struct blklatency_handle *h,
			 struct pevent_record *record, struct event_data *edata)
{
	struct blkio *blkio;
	unsigned long long sector, dev, nr_sector;
	char rwbs[9];
	int ret;

	memcpy(rwbs, record->data + edata->rwbs_field->offset,
	       sizeof(char) * 8);
	if (rwbs[0] != 'R' && rwbs[0] != 'W')
		return;

	ret = pevent_read_number_field(edata->nr_sector_field, record->data,
					&nr_sector);
	if (ret)
		die("Couldn't read nr_sector");
	if (nr_sector == 0)
		return;

	ret = pevent_read_number_field(edata->dev_field, record->data, &dev);
	ret |= pevent_read_number_field(edata->sector_field, record->data,
					&sector);
	if (ret)
		die("Missing important field in event");
	blkio = malloc_or_die(sizeof(*blkio));
	memset(blkio, 0, sizeof(*blkio));
	blkio->dev = dev;
	blkio->sector = sector;
	blkio->action = rwbs[0];
	blkio->complete = edata == h->blk_complete;
	blkio->ts = record->ts;
	blkio->hash.key = trace_hash(dev + sector + rwbs[0]);
	pthread_mutex_lock(&pending.mutex);
	add_pending_blkio(blkio);
	pthread_mutex_unlock(&pending.mutex);
}

static void handle_missed_events(struct blklatency_handle *h)
{
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct blkio *blkio;
	int i;

	pthread_mutex_lock(&blkio_hash.mutex);
	trace_hash_for_each_bucket(bucket, &blkio_hash.hash) {
		trace_hash_while_item(item, bucket) {
			blkio = container_of(item, struct blkio, hash);
			trace_hash_del(item);
			free(blkio);
		}
	}
	pthread_mutex_unlock(&blkio_hash.mutex);

	pthread_mutex_lock(&pending.mutex);
	for (i = 0; i < pending.nr_pending; i++)
		free(pending.pending[i]);
	pending.nr_pending = 0;
	pthread_mutex_unlock(&pending.mutex);
}

static void trace_blklatency_record(struct tracecmd_input *handle,
				    struct pevent_record *record)
{
	struct blklatency_handle *h;
	struct pevent *pevent;
	int id;
//printf("got a record\n");
	if (last_handle && last_handle->handle == handle)
		h = last_handle;
	else {
		for (h = handles; h; h = h->next) {
			if (h->handle == handle)
				break;
		}
		if (!h)
			die("Handle not found?");
		last_handle = h;
	}

	pevent = h->pevent;
	if (record->missed_events) {
		printf("we missed events\n");
		handle_missed_events(h);
	}
	id = pevent_data_type(pevent, record);
	if (id == h->blk_issue->id)
		handle_event(h, record, h->blk_issue);
	else if (id == h->blk_complete->id)
		handle_event(h, record, h->blk_complete);
}

static void setup_fields(struct blklatency_handle *h)
{
	struct event_format *event;
	struct event_data *edata;
	struct pevent *pevent = h->pevent;

	edata = malloc_or_die(sizeof(*edata));
	memset(edata, 0, sizeof(*edata));
	event = pevent_find_event_by_name(pevent, "block", "block_rq_issue");
	if (!event)
		die("Can't find block:block_rq_issue");
	edata->id = event->id;
	edata->dev_field = pevent_find_field(event, "dev");
	edata->sector_field = pevent_find_field(event, "sector");
	edata->rwbs_field = pevent_find_field(event, "rwbs");
	edata->nr_sector_field = pevent_find_field(event, "nr_sector");
	if (!edata->dev_field || !edata->sector_field || !edata->rwbs_field ||
	    !edata->nr_sector_field)
		die("Missing important fields");

	h->blk_issue = edata;

	edata = malloc_or_die(sizeof(*edata));
	memset(edata, 0, sizeof(*edata));
	event = pevent_find_event_by_name(pevent, "block", "block_rq_complete");
	if (!event)
		die("Can't find block:block_rq_complete");
	edata->id = event->id;
	printf("complete id is %d\n", edata->id);
	edata->dev_field = pevent_find_field(event, "dev");
	edata->sector_field = pevent_find_field(event, "sector");
	edata->rwbs_field = pevent_find_field(event, "rwbs");
	edata->nr_sector_field = pevent_find_field(event, "nr_sector");
	if (!edata->dev_field || !edata->sector_field || !edata->rwbs_field ||
	    !edata->nr_sector_field)
		die("Missing important fields");
	h->blk_complete = edata;
}

static int compare_u64(const void *a, const void *b)
{
	u64 * const *A = a;
	u64 * const *B = b;

	if (*A > *B)
		return 1;
	else if (*A < *B)
		return -1;
	return 0;
}

static int p_index(u64 val, int percent)
{
	return (val * percent) / 100;
}

static int compare_blkio(const void *a, const void *b)
{
	struct blkio * const *A = a;
	struct blkio * const *B = b;

	if ((*A)->ts > (*B)->ts)
		return 1;
	else if ((*A)->ts < (*B)->ts)
		return -1;
	return 0;
}

static void process_pending(void)
{
	struct blkio *blkio;
	static struct blkio *last = NULL;
	int i;

	qsort(pending.pending, pending.nr_pending, sizeof(*pending.pending),
	      compare_blkio);
	pthread_mutex_lock(&blkio_hash.mutex);
	for (i = 0; i < pending.nr_pending; i++) {
		blkio = pending.pending[i];
//printf("%llu: got a %s request, dev %llu, sector %llu, rwbs %c\n", blkio->ts, blkio->complete == 0 ? "issue" : "complete", blkio->dev, blkio->sector, blkio->action);
		if (blkio->complete) {
			struct trace_hash_item *item;
			struct blkio *issue;

			item = trace_hash_find(&blkio_hash.hash,
					       blkio->hash.key, match_blkio,
					       blkio);
			if (!item) {
				blkio->missed_count++;

				/* Probably never going to happen */
				if (blkio->missed_count == 5) {
					free(blkio);
					continue;
				}

				if (i == 0) {
					if (pending.nr_pending >=
					    max_pending_events)
						max_pending_events += 512;
					break;
				}

				/*
				 * We are missing some stuff, we probably
				 * started processing before we'd read all the
				 * buffers, so just shift stuff over and wait
				 * for more entries.
				 */
				memmove(pending.pending, pending.pending + i,
					sizeof(struct blkio *) *
					(pending.nr_pending - i));
				if (pending.pending[0] != blkio)
					printf("WE FUCKED UP\n");
				last = blkio;
				break;
			} else if (last == blkio) {
				printf("Ok we found it later, hooray!\n");
			}
			issue = container_of(item, struct blkio, hash);
			trace_hash_del(item);
			add_new_entry(issue->action, blkio->ts - issue->ts);
			free(issue);
			free(blkio);
		} else {
			trace_hash_add(&blkio_hash.hash, &blkio->hash);
		}
	}
	pthread_mutex_unlock(&blkio_hash.mutex);
	printf("nr_pending %d, i %d\n", pending.nr_pending, i);
	fflush(stdout);
	pending.nr_pending -= i;
}

static void *log_stats(void *arg)
{
	struct timespec ts;
	u64 *reads, *writes;
	u64 nr_reads, nr_writes;
	int ret;

	printf("thread started\n");
	while (!exiting) {
		ret = 0;

		pthread_mutex_lock(&pending.mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 60;
again:
		while (pending.nr_pending < max_pending_events &&
		       ret == 0 && !exiting) {
			ret = pthread_cond_timedwait(&pending.cond, &pending.mutex,
						     &ts);
		}
		process_pending();
		if (ret != ETIMEDOUT && !exiting)
			goto again;
		if (max_pending_events > 1024)
			max_pending_events = 1024;
		pthread_mutex_unlock(&pending.mutex);

		reads = stats.read_times;
		writes = stats.write_times;
		nr_reads = stats.nr_reads;
		nr_writes = stats.nr_writes;
		stats.nr_reads = 0;
		stats.nr_writes = 0;

		qsort(reads, nr_reads, sizeof(u64), compare_u64);
		qsort(writes, nr_writes, sizeof(u64), compare_u64);

		printf("blk read latency p50: %llu\n",
			(unsigned long long)reads[p_index(nr_reads, 50)]);
		printf("blk read latency p90: %llu\n",
			(unsigned long long)reads[p_index(nr_reads, 90)]);
		printf("blk read latency p99: %llu\n",
			(unsigned long long)reads[p_index(nr_reads, 99)]);
		printf("min %llu, max %llu\n", reads[0], reads[nr_reads-1]);
		printf("blk write latency p50: %llu\n",
			(unsigned long long)writes[p_index(nr_writes, 50)]);
		printf("blk write latency p90: %llu\n",
			(unsigned long long)writes[p_index(nr_writes, 90)]);
		printf("blk write latency p99: %llu\n",
			(unsigned long long)writes[p_index(nr_writes, 99)]);
		printf("min %llu, max %llu\n", writes[0], writes[nr_writes-1]);
	}

	return NULL;
}

static void alloc_stats(int nr_elements)
{
	if (nr_elements < 1024)
		nr_elements = 1024;
	stats.read_times = malloc_or_die(sizeof(u64) * nr_elements);
	stats.write_times = malloc_or_die(sizeof(u64) * nr_elements);
	memset(stats.read_times, 0, sizeof(u64) * nr_elements);
	memset(stats.write_times, 0, sizeof(u64) * nr_elements);
	stats.nr_reads_alloc = nr_elements;
	stats.nr_writes_alloc = nr_elements;
}

static void trace_blklatency_global_init(void)
{
	memset(&blkio_hash, 0, sizeof(blkio_hash));
	if (pthread_mutex_init(&blkio_hash.mutex, NULL))
		die("Failed to init blk_hash mutex");
	trace_hash_init(&blkio_hash.hash, 1024);

	memset(&stats, 0, sizeof(stats));
	alloc_stats(1024);

	memset(&pending, 0, sizeof(pending));
	pending.nr_alloc = 1024;
	pending.pending = malloc_or_die(pending.nr_alloc *
					sizeof(struct blkio *));
	if (pthread_mutex_init(&pending.mutex, NULL))
		die("Failed to init pending mutex");

	if (pthread_create(&logger_thread, NULL, log_stats, NULL))
		die("Failed to create logger thread");
}

static void trace_init_blklatency(struct tracecmd_input *handle,
				  struct hook_list *hook, int global)
{
	struct pevent *pevent = tracecmd_get_pevent(handle);
	struct blklatency_handle *h;

	printf("Getting called so this works\n");
	tracecmd_set_show_data_func(handle, trace_blklatency_record);
	h = malloc_or_die(sizeof(*h));
	memset(h, 0, sizeof(*h));
	h->next = handles;
	handles = h;

	h->handle = handle;
	h->pevent = pevent;

	setup_fields(h);
}

static void trace_blklatency_done(void)
{
	pthread_mutex_lock(&pending.mutex);
	exiting = 1;
	pthread_cond_signal(&pending.cond);
	pthread_mutex_unlock(&pending.mutex);

	pthread_join(logger_thread, NULL);
	pthread_mutex_destroy(&pending.mutex);
	pthread_mutex_destroy(&blkio_hash.mutex);
	free(pending.pending);
	free(stats.read_times);
	free(stats.write_times);

	/* TODO: free the handles and such. */
}

static int finished = 0;
static void finish(int signum)
{
	finished = 1;
}

int main(int argc, char **argv)
{
	trace_blklatency_global_init();
	/* create instances */
	tracecmd_create_top_instance("blklatency");
	/* enable events */
	tracecmd_disable_all_tracing(1);
	tracecmd_add_event("block:block_rq_issue", 0);
	tracecmd_add_event("block:block_rq_complete", 0);
	tracecmd_expand_event_list();
	tracecmd_enable_events();
	/* start threads */
	tracecmd_start_threads(TRACE_TYPE_STREAM, trace_init_blklatency, 0);
	tracecmd_enable_tracing();
	/* wait for exit condition */
	signal(SIGINT, finish);
	while (!finished) {
		struct timeval tv = { 1 , 0 };
		tracecmd_stream_loop(&tv);
	}
	tracecmd_stop_threads(TRACE_TYPE_STREAM);
	/* cleanup */
	tracecmd_disable_tracing();
	tracecmd_remove_instances();
	trace_blklatency_done();
	return 0;
}
