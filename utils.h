#ifndef _FORMAT_H_
#define _FORMAT_H_

void print_ods_value(const char *entity, const char *name, int percent,
		     unsigned long long value, int last);
char *get_entity_name(void);
#endif
