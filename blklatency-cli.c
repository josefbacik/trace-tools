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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>

#include "utils.h"

static int fd;
static char *entity;

static int get_value(int percent, unsigned long long *value)
{
	int ret = write(fd, &percent, sizeof(percent));
	int size = sizeof(unsigned long long);
	unsigned long long *ptr;

	if (ret < sizeof(percent)) {
		perror("write");
		return -1;
	}

	ret = read(fd, &(value[0]), sizeof(unsigned long long));
	if (ret < sizeof(unsigned long long)) {
		printf("got value %llu, size %d\n", value[0], ret);
		return -1;
	}
	ret = read(fd, &(value[1]), sizeof(unsigned long long));
	if (ret < sizeof(unsigned long long)) {
		printf("got value %llu, size %d\n", value[0], ret);
		return -1;
	}
	return 0;
}

static int print_percentile(int percent, int last)
{
	unsigned long long value[2];
	int ret;

	ret = get_value(percent, value);
	if (ret)
		return ret;
	print_ods_value(entity, "kernel.device.write_latency", percent,
			value[0], 0);
	print_ods_value(entity, "kernel.device.read_latency", percent,
			value[1], last);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned long long value[2];
	struct sockaddr_un remote;
	int ret = 0, reset = -1;
	size_t len;

	entity = get_entity_name();
	if (!entity) {
		perror("get_entity_name");
		return 1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return 1;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, "/tmp/blklatency");
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(fd, (struct sockaddr *)&remote, len) < 0) {
		perror("connect");
		return 1;
	}

	printf("[");
	if (print_percentile(25, 0) ||
	    print_percentile(50, 0) ||
	    print_percentile(75, 0) ||
	    print_percentile(90, 0) ||
	    print_percentile(99, 1))
		ret = 1;
	printf("]\n");
	write(fd, &reset, sizeof(reset));
	close(fd);
	return ret;
}
