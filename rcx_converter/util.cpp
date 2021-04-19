#include "util.h"

BYTE* util::dexor(BYTE *buf, size_t buf_size, BYTE key)
{
	for (size_t i = 0; i < buf_size; i++) {
		buf[i] ^= key;
	}
	return buf;
}
