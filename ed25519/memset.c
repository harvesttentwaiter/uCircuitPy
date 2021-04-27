#include<stddef.h>

// needed for xtensawin
void *memset(void *s, int c, size_t n)
{
	char* sc = (char*)s;
	int i;
	for (i=0; i<n; i++) {
		*sc = c;
	}
	return s;
}
