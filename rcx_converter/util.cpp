#include "util.h"

#include "aes.hpp"

BYTE* util::dexor(BYTE *buf, size_t buf_size, BYTE key)
{
	for (size_t i = 0; i < buf_size; i++) {
		buf[i] ^= key;
	}
	return buf;
}

BYTE* util::aes_decrypt(BYTE *buf, size_t buf_size, BYTE *key)
{
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);

	for (size_t i = 0; i < buf_size; i+=16) {
		AES_ECB_decrypt(&ctx, buf + i);
	}
	return buf;
}
