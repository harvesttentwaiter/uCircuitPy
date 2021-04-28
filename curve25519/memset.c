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

void* memcpy(void *dest, const void *src, size_t n)
{
	const char *s = (const char*)src;
	char *d = (char*)dest;
	size_t i;
	for (i=0; i<n; i++) {
		d[i] = s[i];
	}
	return dest;
}
