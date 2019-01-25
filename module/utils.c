#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/tpyes.h>
#include <linux/limits.h>
#include "utils.h"

void str_replace(char *s, size_t len, const char c, const char r) 
{
	if (!s)
		return;

	for (; len--; s++) 
		if (*s == c)
			*s = r;
}

char *is_a_symlink(const char *argv, int link_level)
{
	ssize_t n;
	char link[PATH_MAX];
	char *tmp_link;

	if (link_level == MAX_SYMLINK_LEVEL)
		return NULL;

	n = readlink(argv, link, PATH_MAX);
	if (n < 0)
		return NULL;

	link[n] = '\0';

	tmp_link = is_a_symlink(link, link_level + 1);
	if (!tmp_link)
		return strdup(link);

	return tmp_link;
}

unsigned strtou(const char *s, int *err_or_overflow)
{
	char *end;
	const long sl;	
	unsigned retval;
	errno = 0;

	sl = strtol(s, &end, 10);

	if (end == s || *end != '\0' || errno == ERANGE || 
	    sl < 0 || sl > UINT_MAX) {
		*err_or_overflow = 1;
		return 0;
	}

	*err_or_overflow = 0;
	return (unsigned)sl;		
}
