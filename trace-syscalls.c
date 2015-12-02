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
#include <sys/types.h>
#include <stdlib.h>
#include <signal.h>
#include <trace-cmd/trace-cmd.h>
#include <trace-cmd/trace-hash.h>
#include "stats.h"
#include "trace-event-sorter.h"

struct syscall_entry {
	char			*name;
	int			id;
	unsigned		is_write:1;
	unsigned		is_exit:1;
	struct trace_hash_item	hash;
};

struct syscall_event {
	unsigned long long	ts;
	int			pid;
	unsigned		is_write:1;
	unsigned		is_exit:1;
	struct trace_hash_item	hash;
	struct trace_event	event;
};

#define offset_of(type, field)          (long)(&((type *)0)->field)
#define container_of(p, type, field)    (type *)((long)p - offset_of(type, field))

static struct format_field *common_pid = NULL;
static struct trace_hash event_hash;
static struct trace_hash syscall_hash;
static pthread_mutex_t hash_mutex;
static int finished = 0;
static struct stats read_stats;
static struct stats write_stats;

static struct syscall_entry syscalls[] = {
	{ .name = "enter_write" , .is_write = 1, },
	{ .name = "enter_writev", .is_write = 1, },
	{ .name = "enter_pwritev", .is_write = 1, },
	{ .name = "enter_pwrite64", .is_write = 1,  },
	{ .name = "enter_read" },
	{ .name = "enter_readv" },
	{ .name = "enter_preadv" },
	{ .name = "enter_pread64" },
	{ .name = "exit_write" , .is_exit = 1, .is_write = 1, },
	{ .name = "exit_writev", .is_exit = 1, .is_write = 1, },
	{ .name = "exit_pwritev", .is_exit = 1, .is_write = 1, },
	{ .name = "exit_pwrite64", .is_exit = 1, .is_write = 1,  },
	{ .name = "exit_read", .is_exit = 1 },
	{ .name = "exit_readv", .is_exit = 1 },
	{ .name = "exit_preadv", .is_exit = 1 },
	{ .name = "exit_pread64", .is_exit = 1 },
	{ .name = NULL },
};

static void drop_hash_table(struct trace_hash *tbl)
{
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct syscall_event *event;

	trace_hash_for_each_bucket(bucket, tbl) {
		trace_hash_while_item(item, bucket) {
			event = container_of(item, struct syscall_event, hash);
			trace_hash_del(item);
			free(event);
		}
	}
}

static int match_syscall(struct trace_hash_item *item, void *data)
{
	struct syscall_event *e = container_of(item, struct syscall_event, hash);
	struct syscall_event *search = (struct syscall_event *)data;

	if (e->is_exit && search->event.ts >= e->event.ts)
		return 0;
	if (!e->is_exit && search->event.ts <= e->event.ts)
		return 0;

	return e->pid == search->pid && e->is_write == search->is_write;
}

static int process_syscall_event(struct trace_event *event)
{
	struct syscall_event *e = container_of(event, struct syscall_event,
					       event);

	if (e->is_exit) {
		struct trace_hash_item *item;
		struct syscall_event *enter;

		item = trace_hash_find(&event_hash, e->hash.key, match_syscall,
				       e);
		if (!item)
			return 1;
		enter = container_of(item, struct syscall_event, hash);
		trace_hash_del(item);
		if (e->is_write)
			stats_add_value(&write_stats,
					e->event.ts - enter->event.ts);
		else
			stats_add_value(&read_stats,
					e->event.ts - enter->event.ts);
		free(enter);
		free(e);
	} else {
		pthread_mutex_lock(&hash_mutex);
		trace_hash_add(&event_hash, &e->hash);
		pthread_mutex_unlock(&hash_mutex);
	}

	return 0;
}

static void free_syscall_event(struct trace_event *event)
{
	struct syscall_event *e = container_of(event, struct syscall_event,
					       event);
	free(e);
}

static void trace_syscalllatency_record(struct tracecmd_input *handle,
					struct pevent_record *record)
{
	struct syscall_event *e;
	struct syscall_entry *entry;
	struct trace_hash_item *item;
	unsigned long long pid;
	int ret, id;

	/* First if we missed events we need to purge everything. */
	if (record->missed_events) {
		/* Process the current queue and then drop whatever is left. */
		trace_event_process_pending();
		trace_event_drop_pending();

		/* Now drop the write and read hash. */
		pthread_mutex_lock(&hash_mutex);
		drop_hash_table(&event_hash);
		pthread_mutex_unlock(&hash_mutex);
	}

	id = pevent_data_type(tracecmd_get_pevent(handle), record);
	item = trace_hash_find(&syscall_hash, trace_hash(id), NULL, NULL);
	entry = container_of(item, struct syscall_entry, hash);
	if (entry->id != id) {
		fprintf(stderr, "WHAT THE FUCK!?!?\n");
		return;
	}
	ret = pevent_read_number_field(common_pid, record->data, &pid);
	if (ret)
		return;

	e = malloc(sizeof(struct syscall_event));
	if (!e) {
		fprintf(stderr, "Failed to alloc new event, exiting\n");
		finished = 1;
		return;
	}

	memset(e, 0, sizeof(*e));
	e->pid = (int)pid;
	e->event.ts = record->ts;
	e->event.missed_count = 0;
	e->event.free = free_syscall_event;
	e->event.process = process_syscall_event;
	e->hash.key = trace_hash(pid + entry->is_write);
	e->is_write = entry->is_write;
	e->is_exit = entry->is_exit;
	trace_event_add_pending(&e->event);
}

static int table_initted = 0;

static void trace_init_syscalllatency(struct tracecmd_input *handle,
				      struct hook_list *hook, int global)
{
	struct pevent *pevent = tracecmd_get_pevent(handle);
	struct event_format *event;
	struct syscall_entry *entry = syscalls;
	int found = 0;

	tracecmd_set_show_data_func(handle, trace_syscalllatency_record);

	if (table_initted)
		return;

	table_initted = 1;
	while (entry->name) {
		char buf[1024];

		snprintf(buf, 1024, "sys_%s", entry->name);
		event = pevent_find_event_by_name(pevent, "syscalls", buf);
		if (!event) {
			entry++;
			continue;
		}
		found++;
		if (!common_pid) {
			common_pid = pevent_find_common_field(event, "common_pid");
			if (!common_pid) {
				fprintf(stderr, "Don't have common pid\n");
				exit(1);
			}
		}
		entry->id = event->id;
		entry->hash.key = trace_hash(event->id);
		trace_hash_add(&syscall_hash, &entry->hash);
		entry++;
	}
}

static void finish(int signum)
{
	finished = 1;
}

int main(int argc, char **argv)
{
	struct syscall_entry *entry = syscalls;
	int ret;

	stats_reset(&write_stats);
	stats_reset(&read_stats);

	memset(&syscall_hash, 0, sizeof(syscall_hash));
	trace_hash_init(&syscall_hash, 32);

	memset(&event_hash, 0, sizeof(event_hash));
	trace_hash_init(&event_hash, 1024);
	if (pthread_mutex_init(&hash_mutex, NULL)) {
		perror("Couldn't init mutex");
		exit(1);
	}

	if (trace_event_sorter_init()) {
		perror("Couldn't init the sorter");
		exit(1);
	}

	tracecmd_create_top_instance("syscalllatency");
	tracecmd_disable_all_tracing(1);

	while (entry->name) {
		char buf[1024];

		snprintf(buf, 1024, "syscalls:sys_%s", entry->name);
		ret = tracecmd_add_event(strdup(buf), 0);
		entry++;
	}
	tracecmd_expand_event_list();
	tracecmd_enable_events();
	tracecmd_start_threads(TRACE_TYPE_STREAM, trace_init_syscalllatency, 0);

	signal(SIGINT, finish);
	signal(SIGALRM, finish);
	tracecmd_enable_tracing();

	alarm(5);
	while (!finished) {
		struct timeval tv = { 1, 0 };
		tracecmd_stream_loop(&tv);
	}
	tracecmd_stop_threads(TRACE_TYPE_STREAM);
	tracecmd_disable_tracing();
	tracecmd_remove_instances();

	trace_event_process_pending();
	trace_event_sorter_cleanup();

	printf("read p50 is %llu\n", stats_p_value(&read_stats, 50));
	printf("read p90 is %llu\n", stats_p_value(&read_stats, 90));
	printf("read p99 is %llu\n", stats_p_value(&read_stats, 99));

	printf("write p50 is %llu\n", stats_p_value(&write_stats, 50));
	printf("write p90 is %llu\n", stats_p_value(&write_stats, 90));
	printf("write p99 is %llu\n", stats_p_value(&write_stats, 99));

	return 0;
}
