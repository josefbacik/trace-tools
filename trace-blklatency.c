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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
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
	unsigned long long	dev;
	unsigned long long	sector;
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
pthread_mutex_t stats_mutex;
static struct blklatency_handle *handles = NULL;
static struct blklatency_handle *last_handle = NULL;
static struct blkio_hash blkio_hash;
static int finished = 0;

static inline void die(char *msg)
{
	fprintf(stderr, msg);
	finished = 1;
}

static inline void *malloc_or_die(size_t size)
{
	void *ret = malloc(size);
	if (!ret) {
		perror("malloc failed");
		finished = 1;
	}
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
		pthread_mutex_lock(&stats_mutex);
		if (issue->action == 'R')
			stats_add_value(&read_stats, blkio->event.ts - issue->event.ts);
		else
			stats_add_value(&write_stats, blkio->event.ts - issue->event.ts);
		pthread_mutex_unlock(&stats_mutex);
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
	if (ret) {
		die("Couldn't read nr_sector");
		return;
	}
	if (nr_sector == 0)
		return;

	ret = pevent_read_number_field(edata->dev_field, record->data, &dev);
	ret |= pevent_read_number_field(edata->sector_field, record->data,
					&sector);
	if (ret) {
		die("Missing important field in event");
		return;
	}
	blkio = malloc_or_die(sizeof(*blkio));
	if (!blkio)
		return;
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
		if (!h) {
			die("Handle not found?");
			return;
		}
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
	if (!edata)
		return;
	memset(edata, 0, sizeof(*edata));
	event = pevent_find_event_by_name(pevent, "block", "block_rq_issue");
	if (!event) {
		die("Can't find block:block_rq_issue");
		return;
	}
	edata->id = event->id;
	edata->dev_field = pevent_find_field(event, "dev");
	edata->sector_field = pevent_find_field(event, "sector");
	edata->rwbs_field = pevent_find_field(event, "rwbs");
	edata->nr_sector_field = pevent_find_field(event, "nr_sector");
	if (!edata->dev_field || !edata->sector_field || !edata->rwbs_field ||
	    !edata->nr_sector_field) {
		die("Missing important fields");
		return;
	}

	h->blk_issue = edata;

	edata = malloc_or_die(sizeof(*edata));
	if (!edata)
		return;
	memset(edata, 0, sizeof(*edata));
	event = pevent_find_event_by_name(pevent, "block", "block_rq_complete");
	if (!event) {
		die("Can't find block:block_rq_complete");
		return;
	}
	edata->id = event->id;
	edata->dev_field = pevent_find_field(event, "dev");
	edata->sector_field = pevent_find_field(event, "sector");
	edata->rwbs_field = pevent_find_field(event, "rwbs");
	edata->nr_sector_field = pevent_find_field(event, "nr_sector");
	if (!edata->dev_field || !edata->sector_field || !edata->rwbs_field ||
	    !edata->nr_sector_field) {
		die("Missing important fields");
		return;
	}
	h->blk_complete = edata;
}

static void *stats_fn(void *unused)
{
	struct sockaddr_un local, remote;
	int fd, confd;
	socklen_t len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		pthread_exit(NULL);
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, "/tmp/blklatency");

	/* Just in case. */
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(fd, (struct sockaddr *)&local, len) == -1) {
		perror("bind");
		pthread_exit(NULL);
	}

	if (listen(fd, 1)) {
		perror("listen");
		pthread_exit(NULL);
	}

	while (!finished) {
		fd_set rfd;
		struct timeval tv;
		unsigned long long value;
		int percent, ret, done;

		FD_ZERO(&rfd);
		FD_SET(fd, &rfd);
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		ret = select(FD_SETSIZE, &rfd, NULL, NULL, &tv);
		if (ret < 0) {
			perror("select");
			pthread_exit(NULL);
		}
		if (!ret)
			continue;
		len = sizeof(remote);
		if ((confd =
		     accept(fd, (struct sockaddr *)&remote, &len)) < 0) {
			perror("accept");
			continue;
		}

		/* Deal with incoming requests until the socket is closed. */
		done = 0;
		while (!done) {
			ret = read(confd, &percent, sizeof(percent));
			if (ret < sizeof(percent)) {
				if (ret < 0)
					perror("read");
				done = 1;
				continue;
			}
			pthread_mutex_lock(&stats_mutex);
			if (percent == -1) {
				stats_reset(&write_stats);
				stats_reset(&read_stats);
			} else {
				value = stats_p_value(&write_stats, percent);
				write(confd, &value, sizeof(unsigned long long));
				value = stats_p_value(&read_stats, percent);
				write(confd, &value, sizeof(unsigned long long));
			}
			pthread_mutex_unlock(&stats_mutex);
		}
		close(confd);
	}
	return NULL;
}

static void trace_init_blklatency(struct tracecmd_input *handle,
				  struct hook_list *hook, int global)
{
	struct pevent *pevent = tracecmd_get_pevent(handle);
	struct blklatency_handle *h;

	tracecmd_set_show_data_func(handle, trace_blklatency_record);
	h = malloc_or_die(sizeof(*h));
	if (!h)
		return;
	memset(h, 0, sizeof(*h));
	h->next = handles;
	handles = h;

	h->handle = handle;
	h->pevent = pevent;

	setup_fields(h);
}

static void finish(int signum)
{
	finished = 1;
}

static void daemonize(void)
{
	pid_t pid;
	int fd;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	/* The parent can exit. */
	if (pid > 0)
		exit(0);

	if (setsid() < 0) {
		perror("setsid");
		exit(1);
	}

	if ((chdir("/")) < 0) {
		perror("chdir");
		exit(1);
	}

	fd = open("/dev/null", O_RDWR, 0);
	if (fd >= 0) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if (fd > 2)
			close(fd);
	}

	umask(027);
}

int main(int argc, char **argv)
{
	pthread_t stats_thread;
	bool foreground = false;
	char opt;

	while ((opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			foreground = true;
			break;
		default:
			fprintf(stderr, "Invalid option '%c'\n", opt);
			exit(1);
		}
	}

	if (!foreground)
		daemonize();

	/* Init the stats */
	stats_init(&write_stats);
	stats_init(&read_stats);

	/* Init our hash table */
	memset(&blkio_hash, 0, sizeof(blkio_hash));
	if (pthread_mutex_init(&blkio_hash.mutex, NULL) ||
	    pthread_mutex_init(&stats_mutex, NULL)) {
		die("Failed to init blk_hash mutex");
		exit(1);
	}
	trace_hash_init(&blkio_hash.hash, 1024);

	/* Start the trace sorter thread. */
	if (trace_event_sorter_init()) {
		die("Couldn't init the sorter");
		exit(1);
	}

	if (pthread_create(&stats_thread, NULL, stats_fn, NULL)) {
		perror("creating stats thread");
		trace_event_sorter_cleanup();
		exit(1);
	}

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
		struct timeval tv = { 5 , 0 };

		tracecmd_stream_loop(&tv);
	}
	tracecmd_stop_threads(TRACE_TYPE_STREAM);

	/* cleanup */
	tracecmd_disable_tracing();
	tracecmd_remove_instances();

	/* Do all the pending processing stuff */
	trace_event_process_pending();
	trace_event_sorter_cleanup();

	pthread_mutex_destroy(&blkio_hash.mutex);
	pthread_mutex_destroy(&stats_mutex);
	pthread_join(stats_thread, NULL);

	return 0;
}
