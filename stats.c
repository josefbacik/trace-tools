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
#include <stdlib.h>
#include "stats.h"
#include <stdio.h>

static int compare(const void *a, const void *b)
{
	unsigned long long * const *A = a;
	unsigned long long * const *B = b;

	if (*A > *B)
		return 1;
	else if (*A < *B)
		return -1;
	return 0;
}

void stats_sort(struct stats *stats)
{
	qsort(stats->values, stats->nr_values, sizeof(unsigned long long),
	      compare);
	stats->sorted = 1;
}

int stats_add_value(struct stats *stats, unsigned long long value)
{
	if (stats->nr_values == stats->max_alloc)
		return 1;
	stats->sorted = 0;
	if (stats->nr_values == stats->nr_alloc) {
		stats->nr_alloc += 1024;
		stats->values = realloc(stats->values, stats->nr_alloc *
					sizeof(unsigned long long));
		if (!stats->values)
			return -1;
	}
	stats->values[stats->nr_values++] = value;
	return 0;
}
