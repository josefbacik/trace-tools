#include <stdio.h>
#include <unistd.h>
#include <string.h>

void print_ods_value(const char *entity, const char *name, int percent,
		     unsigned long long value, int last)
{
	printf("{\"entity\":\"%s\",\"key\":\"%s_p%d\",\"value\":%llu}%s",
	       entity, name, percent, value, last ? "" : ",");
}

char *get_entity_name(void)
{
	char buf[256];
	char *tmp;

	gethostname(buf, 255);
	buf[255] = '\0';
	tmp = strstr(buf, ".facebook.com");
	if (tmp)
		*tmp = '\0';
	return strdup(buf);
}
