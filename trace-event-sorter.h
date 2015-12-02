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
#ifndef __TRACE_EVENT_SORTER_H__
#define __TRACE_EVENT_SORTER_H__

struct trace_event {
	unsigned long long	ts;
	int			missed_count;
	int			(*process)(struct trace_event *event);
	void			(*free)(struct trace_event *event);
};

int trace_event_sorter_init(void);
int trace_event_add_pending(struct trace_event *event);
void trace_event_drop_pending(void);
void trace_event_process_pending(void);
void trace_event_sorter_cleanup(void);
#endif
