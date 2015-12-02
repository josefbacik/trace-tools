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
