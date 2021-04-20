#pragma once

#include <Windows.h>
#include <iostream>

typedef struct _custom_iat
{
	void *VirtualAlloc;
	void *VirtualFree;
	void *GetProcessHeap;
	void *RtlAllocateHeap;
	void *RtlFreeHeap;
	void *NtQueryInformationProcess;
} custom_iat;

namespace util {
	BYTE* dexor(BYTE *buf, size_t buf_size, BYTE key);
	BYTE* aes_decrypt(BYTE *buf, size_t buf_size, BYTE *key);

	int decompress(BYTE *in_buf, int in_size, BYTE *out_buf, unsigned int out_size);

	int lzma_decompress(BYTE *in_buf, int in_size, BYTE *out_buf, unsigned int out_size);
};
