#ifndef _STATS_H_
#define _STATS_H_

struct stats {
	unsigned long long	*values;
	unsigned long long	nr_values, nr_alloc;
	unsigned long long	min, max;
	unsigned		sorted:1;
};

int stats_add_value(struct stats *stats, unsigned long long value);
void stats_sort(struct stats *stats);

static inline void stats_reset(struct stats *stats)
{
	stats->nr_values = 0;
	stats->sorted = 0;
	stats->min = (unsigned long long)-1;
	stats->max = 0;
}

static inline unsigned long long stats_p_value(struct stats *stats,
					       int percent)
{
	unsigned long long index = (stats->nr_values * percent) / 100;

	if (!stats->sorted)
		stats_sort(stats);
	if (!stats->nr_values)
		return 0;
	return stats->values[index];
}

#endif
