#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "utils.h"

int strtosint(const char *s, int *err_or_overflow)
{
	char *end;
	long sl;	
	errno = 0;

	sl = strtol(s, &end, 10);

	if (end == s || *end != '\0' || errno == ERANGE || 
	    sl < INT_MIN || sl > INT_MAX) {
		*err_or_overflow = 1;
		return 0;
	}

	*err_or_overflow = 0;
	return (int)sl;		
}

int strtime(time_t t, char *buff, size_t len)
{
	int ret;
	struct tm *tm = localtime(&t);
	
	if (!tm) {
		fprintf(stderr, "localtime() failed\n");
		return -1;
	}

	ret = strftime(buff, len, "%H:%M", tm);
	return ((size_t)ret != len - 1);
}

void purge_stdin(const char *s)
{
	int c;

	if (!strchr(s, '\n'))
		while ((c = getchar()) != '\n');
} 
