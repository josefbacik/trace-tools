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
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "trace-event-sorter.h"

struct pending_events {
	struct trace_event	**pending;
	int			nr_pending;
	int			nr_alloc;
	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};
typedef int (process_t)(void *);

static process_t *process;

struct pending_events pending;
static int finished = 0;
static pthread_t sort_thread;
static int max_pending_events = 1024;

static int compare_events(const void *a, const void *b)
{
	struct trace_event * const *A = a;
	struct trace_event * const *B = b;

	if ((*A)->ts > (*B)->ts)
		return 1;
	else if ((*A)->ts < (*B)->ts)
		return -1;
	return 0;
}

static void process_pending(void)
{
	int i;

	qsort(pending.pending, pending.nr_pending, sizeof(*pending.pending),
	      compare_events);
	for (i = 0; i < pending.nr_pending; i++) {
		struct trace_event *cur_pending = pending.pending[i];
		int ret = cur_pending->process(cur_pending);

		if (ret > 1) {
			cur_pending->missed_count++;
			if (cur_pending->missed_count > 5) {
				cur_pending->free(cur_pending);
				continue;
			}

			memmove(pending.pending, pending.pending + i,
				sizeof(void *) * (pending.nr_pending - i));
			if (cur_pending != pending.pending[0])
				printf("WE FUCKED UP\n");
			break;
		}
	}
	pending.nr_pending -= i;
}

static void *thread_fn(void *unused)
{
	while (!finished) {
		pthread_mutex_lock(&pending.mutex);
		while (pending.nr_pending < max_pending_events && !finished)
			pthread_cond_wait(&pending.cond, &pending.mutex);
		if (finished) {
			pthread_mutex_unlock(&pending.mutex);
			break;
		}
		process_pending();
		pthread_mutex_unlock(&pending.mutex);
	}

	return NULL;
}

int trace_event_add_pending(struct trace_event *event)
{
	pthread_mutex_lock(&pending.mutex);
	if (pending.nr_pending == pending.nr_alloc) {
		pending.nr_alloc += 1024;
		pending.pending = realloc(pending.pending,
					  pending.nr_alloc *
					  sizeof(struct trace_event *));
		if (!pending.pending) {
			pthread_mutex_unlock(&pending.mutex);
			return -1;
		}
	}
	pending.pending[pending.nr_pending++] = event;
	if (pending.nr_pending >= max_pending_events)
		pthread_cond_signal(&pending.cond);
	pthread_mutex_unlock(&pending.mutex);
	return 0;
}

void trace_event_process_pending(void)
{
	pthread_mutex_lock(&pending.mutex);
	process_pending();
	pthread_mutex_unlock(&pending.mutex);
}

void trace_event_drop_pending(void)
{
	int i = 0;
	pthread_mutex_lock(&pending.mutex);
	for (i = 0; i < pending.nr_pending; i++)
		pending.pending[i]->free(pending.pending[i]);
	pending.nr_pending = 0;
	pthread_mutex_unlock(&pending.mutex);
}

void trace_event_sorter_cleanup(void)
{
	pthread_mutex_lock(&pending.mutex);
	finished = 1;
	pthread_cond_signal(&pending.cond);
	pthread_mutex_unlock(&pending.mutex);

	pthread_join(sort_thread, NULL);
	pthread_mutex_destroy(&pending.mutex);
	pthread_cond_destroy(&pending.cond);
}

int trace_event_sorter_init(void)
{
	if (pthread_mutex_init(&pending.mutex, NULL) ||
	    pthread_cond_init(&pending.cond, NULL))
		return -1;
	pending.pending = malloc(sizeof(void *) * 1024);
	if (!pending.pending)
		return -1;
	memset(pending.pending, 0, sizeof(void *) * 1024);
	pending.nr_alloc = 1024;
	pending.nr_pending = 0;

	if (pthread_create(&sort_thread, NULL, thread_fn, NULL)) {
		free(pending.pending);
		pthread_mutex_destroy(&pending.mutex);
		pthread_cond_destroy(&pending.cond);
		return -1;
	}
	return 0;
}
