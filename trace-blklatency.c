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
#include "stats.h"
#include "trace-event-sorter.h"

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

struct blkio {
	struct trace_hash_item	hash;
	struct trace_event	event;
	u64			dev;
	u64			sector;
	int			complete;
	int			missed_count;
	char			action;
	struct blkio		*next;
};

struct blkio_hash {
	struct trace_hash	hash;
	pthread_mutex_t		mutex;
};

static struct stats read_stats;
static struct stats write_stats;
static struct blklatency_handle *handles = NULL;
static struct blklatency_handle *last_handle = NULL;
static struct blkio_hash blkio_hash;
static unsigned exiting = 0;

static inline void *malloc_or_die(size_t size)
{
	void *ret = malloc(size);
	if (!ret)
		die("malloc failed");
	return ret;
}

static int match_blkio(struct trace_hash_item *item, void *data)
{
	struct blkio *blkio = container_of(item, struct blkio, hash);
	struct blkio *search = (struct blkio *)data;

	/* If we recorded a complete make sure the issue is before the complete. */
	if (blkio->complete && search->event.ts >= blkio->event.ts)
		return 0;
	if (!blkio->complete && search->event.ts <= blkio->event.ts)
		return 0;

	return blkio->dev == search->dev && blkio->sector == search->sector &&
		blkio->action == search->action;
}

static int process_blkio(struct trace_event *event)
{
	struct blkio *blkio = container_of(event, struct blkio, event);

	if (blkio->complete) {
		struct trace_hash_item *item;
		struct blkio *issue;

		item = trace_hash_find(&blkio_hash.hash,
				       blkio->hash.key, match_blkio,
				       blkio);
		if (!item)
			return 1;
		issue = container_of(item, struct blkio, hash);
		trace_hash_del(item);
		if (issue->action == 'R')
			stats_add_value(&read_stats, blkio->event.ts - issue->event.ts);
		else
			stats_add_value(&write_stats, blkio->event.ts - issue->event.ts);
		free(issue);
		free(blkio);
	} else {
		pthread_mutex_lock(&blkio_hash.mutex);
		trace_hash_add(&blkio_hash.hash, &blkio->hash);
		pthread_mutex_unlock(&blkio_hash.mutex);
	}
	return 0;
}

static void free_blkio(struct trace_event *event)
{
	struct blkio *blkio = container_of(event, struct blkio, event);
	free(blkio);
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
	blkio->hash.key = trace_hash(dev + sector + rwbs[0]);
	blkio->event.free = free_blkio;
	blkio->event.process = process_blkio;
	blkio->event.ts = record->ts;
	trace_event_add_pending(&blkio->event);
}

static void handle_missed_events(struct blklatency_handle *h)
{
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct blkio *blkio;
	int i;

	trace_event_process_pending();
	trace_event_drop_pending();

	pthread_mutex_lock(&blkio_hash.mutex);
	trace_hash_for_each_bucket(bucket, &blkio_hash.hash) {
		trace_hash_while_item(item, bucket) {
			blkio = container_of(item, struct blkio, hash);
			trace_hash_del(item);
			free(blkio);
		}
	}
	pthread_mutex_unlock(&blkio_hash.mutex);
}

static void trace_blklatency_record(struct tracecmd_input *handle,
				    struct pevent_record *record)
{
	struct blklatency_handle *h;
	struct pevent *pevent;
	int id;

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
	edata->dev_field = pevent_find_field(event, "dev");
	edata->sector_field = pevent_find_field(event, "sector");
	edata->rwbs_field = pevent_find_field(event, "rwbs");
	edata->nr_sector_field = pevent_find_field(event, "nr_sector");
	if (!edata->dev_field || !edata->sector_field || !edata->rwbs_field ||
	    !edata->nr_sector_field)
		die("Missing important fields");
	h->blk_complete = edata;
}

static void log_stats(void)
{
	printf("blk read latency p50: %llu\n", stats_p_value(&read_stats, 50));
	printf("blk read latency p90: %llu\n", stats_p_value(&read_stats, 90));
	printf("blk read latency p99: %llu\n", stats_p_value(&read_stats, 99));
	printf("min %llu, max %llu\n", read_stats.min, read_stats.max);
	printf("blk write latency p50: %llu\n",
	       stats_p_value(&write_stats, 50));
	printf("blk write latency p90: %llu\n",
	       stats_p_value(&write_stats, 90));
	printf("blk write latency p99: %llu\n",
	       stats_p_value(&write_stats, 99));
	printf("min %llu, max %llu\n", write_stats.min, write_stats.max);
}

static void trace_blklatency_global_init(void)
{
	memset(&blkio_hash, 0, sizeof(blkio_hash));
	if (pthread_mutex_init(&blkio_hash.mutex, NULL))
		die("Failed to init blk_hash mutex");
	trace_hash_init(&blkio_hash.hash, 1024);

	if (trace_event_sorter_init())
		die("Couldn't init the sorter");
}

static void trace_init_blklatency(struct tracecmd_input *handle,
				  struct hook_list *hook, int global)
{
	struct pevent *pevent = tracecmd_get_pevent(handle);
	struct blklatency_handle *h;

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
	trace_event_process_pending();
	trace_event_sorter_cleanup();

	pthread_mutex_destroy(&blkio_hash.mutex);
	/* TODO: free the handles and such. */
}

static int finished = 0;
static void finish(int signum)
{
	finished = 1;
}

int main(int argc, char **argv)
{
	struct timespec start;

	stats_reset(&write_stats);
	stats_reset(&read_stats);

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
	clock_gettime(CLOCK_REALTIME, &start);
	while (!finished) {
		struct timeval tv = { 5 , 0 };
		struct timespec ts;

		tracecmd_stream_loop(&tv);
		clock_gettime(CLOCK_REALTIME, &ts);
		if ((ts.tv_sec - start.tv_sec) >= 60) {
			log_stats();
			start = ts;
		}
	}
	tracecmd_stop_threads(TRACE_TYPE_STREAM);
	/* cleanup */
	tracecmd_disable_tracing();
	tracecmd_remove_instances();
	trace_blklatency_done();
	return 0;
}
