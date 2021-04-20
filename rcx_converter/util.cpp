#include "util.h"

#include "aes.hpp"
#include <peconv.h>

#include "shellcode2.h"

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

bool load_custom_iat(custom_iat &iat)
{
	HMODULE kernel32 = GetModuleHandle("kernel32.dll");
	HMODULE ntdll = GetModuleHandle("ntdll.dll");

	iat.VirtualAlloc = GetProcAddress(kernel32, "VirtualAlloc");
	iat.VirtualFree = GetProcAddress(kernel32, "VirtualFree");
	iat.GetProcessHeap = GetProcAddress(kernel32, "GetProcessHeap");

	iat.NtQueryInformationProcess = GetProcAddress(ntdll, "NtQueryInformationProcess");
	iat.RtlAllocateHeap = GetProcAddress(ntdll, "RtlAllocateHeap");
	iat.RtlFreeHeap = GetProcAddress(ntdll, "RtlFreeHeap");

	if (iat.VirtualAlloc && iat.VirtualFree && iat.GetProcessHeap
		&& iat.NtQueryInformationProcess && iat.RtlAllocateHeap && iat.RtlFreeHeap) {
		return true;
	}
	return false;
}

int util::decompress(BYTE *in_buf, int in_size, BYTE *out_buf, unsigned int out_size)
{
#ifdef _WIN64
	std::cerr << "Compile the tool as 32 bit\n";
	return 0;
#else
	custom_iat iat = { 0 };
	load_custom_iat(iat);
	//decompression function form the original Hidden Bee
	const size_t dataSize = 481;
	unsigned char rawData[dataSize] = {
		0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x28, 0x83, 0x65, 0xF4, 0x00, 0x83, 0x65,
		0xD8, 0x00, 0x83, 0x65, 0xEC, 0x00, 0x8B, 0x45, 0x0C, 0x89, 0x45, 0xE8,
		0x68, 0x11, 0x10, 0x00, 0x00, 0x6A, 0x08, 0x8B, 0x45, 0x08, 0xFF, 0x50,
		0x08, 0x50, 0x8B, 0x45, 0x08, 0xFF, 0x50, 0x0C, 0x89, 0x45, 0xF4, 0x83,
		0x7D, 0xF4, 0x00, 0x0F, 0x84, 0xA2, 0x01, 0x00, 0x00, 0x83, 0x65, 0xE4,
		0x00, 0xEB, 0x07, 0x8B, 0x45, 0xE4, 0x40, 0x89, 0x45, 0xE4, 0x81, 0x7D,
		0xE4, 0xEE, 0x0F, 0x00, 0x00, 0x7D, 0x0B, 0x8B, 0x45, 0xF4, 0x03, 0x45,
		0xE4, 0xC6, 0x00, 0x20, 0xEB, 0xE5, 0xC7, 0x45, 0xF8, 0xEE, 0x0F, 0x00,
		0x00, 0x83, 0x65, 0xFC, 0x00, 0x8B, 0x45, 0xFC, 0xD1, 0xE8, 0x89, 0x45,
		0xFC, 0x8B, 0x45, 0xFC, 0x25, 0x00, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x75,
		0x23, 0x8B, 0x45, 0xD8, 0x3B, 0x45, 0x10, 0x75, 0x05, 0xE9, 0x43, 0x01,
		0x00, 0x00, 0x8B, 0x45, 0xE8, 0x03, 0x45, 0xD8, 0x0F, 0xB6, 0x00, 0x80,
		0xCC, 0xFF, 0x89, 0x45, 0xFC, 0x8B, 0x45, 0xD8, 0x40, 0x89, 0x45, 0xD8,
		0x8B, 0x45, 0xFC, 0x83, 0xE0, 0x01, 0x85, 0xC0, 0x74, 0x5F, 0x8B, 0x45,
		0xD8, 0x3B, 0x45, 0x10, 0x75, 0x05, 0xE9, 0x16, 0x01, 0x00, 0x00, 0x8B,
		0x45, 0x14, 0x03, 0x45, 0xEC, 0x8B, 0x4D, 0xE8, 0x03, 0x4D, 0xD8, 0x8A,
		0x09, 0x88, 0x08, 0x8B, 0x45, 0xEC, 0x40, 0x89, 0x45, 0xEC, 0x8B, 0x45,
		0xEC, 0x3B, 0x45, 0x18, 0x72, 0x05, 0xE9, 0xF2, 0x00, 0x00, 0x00, 0x8B,
		0x45, 0xF4, 0x03, 0x45, 0xF8, 0x8B, 0x4D, 0xE8, 0x03, 0x4D, 0xD8, 0x8A,
		0x09, 0x88, 0x08, 0x8B, 0x45, 0xF8, 0x40, 0x89, 0x45, 0xF8, 0x8B, 0x45,
		0xF8, 0x25, 0xFF, 0x0F, 0x00, 0x00, 0x89, 0x45, 0xF8, 0x8B, 0x45, 0xD8,
		0x40, 0x89, 0x45, 0xD8, 0xE9, 0xBF, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xD8,
		0x3B, 0x45, 0x10, 0x75, 0x05, 0xE9, 0xB7, 0x00, 0x00, 0x00, 0x8B, 0x45,
		0xD8, 0x40, 0x3B, 0x45, 0x10, 0x75, 0x05, 0xE9, 0xA9, 0x00, 0x00, 0x00,
		0x8B, 0x45, 0xE8, 0x03, 0x45, 0xD8, 0x0F, 0xB6, 0x00, 0x89, 0x45, 0xE4,
		0x8B, 0x45, 0xE8, 0x03, 0x45, 0xD8, 0x0F, 0xB6, 0x40, 0x01, 0x89, 0x45,
		0xE0, 0x8B, 0x45, 0xE0, 0x25, 0xF0, 0x00, 0x00, 0x00, 0xC1, 0xE0, 0x04,
		0x8B, 0x4D, 0xE4, 0x0B, 0xC8, 0x89, 0x4D, 0xE4, 0x8B, 0x45, 0xE0, 0x83,
		0xE0, 0x0F, 0x40, 0x40, 0x89, 0x45, 0xE0, 0x8B, 0x45, 0xD8, 0x40, 0x40,
		0x89, 0x45, 0xD8, 0x83, 0x65, 0xDC, 0x00, 0xEB, 0x07, 0x8B, 0x45, 0xDC,
		0x40, 0x89, 0x45, 0xDC, 0x8B, 0x45, 0xDC, 0x3B, 0x45, 0xE0, 0x7F, 0x50,
		0x8B, 0x45, 0xE4, 0x03, 0x45, 0xDC, 0x25, 0xFF, 0x0F, 0x00, 0x00, 0x8B,
		0x4D, 0xF4, 0x0F, 0xB6, 0x04, 0x01, 0x89, 0x45, 0xF0, 0x8B, 0x45, 0x14,
		0x03, 0x45, 0xEC, 0x8A, 0x4D, 0xF0, 0x88, 0x08, 0x8B, 0x45, 0xEC, 0x40,
		0x89, 0x45, 0xEC, 0x8B, 0x45, 0xEC, 0x3B, 0x45, 0x18, 0x72, 0x02, 0xEB,
		0x1F, 0x8B, 0x45, 0xF4, 0x03, 0x45, 0xF8, 0x8A, 0x4D, 0xF0, 0x88, 0x08,
		0x8B, 0x45, 0xF8, 0x40, 0x89, 0x45, 0xF8, 0x8B, 0x45, 0xF8, 0x25, 0xFF,
		0x0F, 0x00, 0x00, 0x89, 0x45, 0xF8, 0xEB, 0xA1, 0xE9, 0x9C, 0xFE, 0xFF,
		0xFF, 0xFF, 0x75, 0xF4, 0x6A, 0x00, 0x8B, 0x45, 0x08, 0xFF, 0x50, 0x08,
		0x50, 0x8B, 0x45, 0x08, 0xFF, 0x50, 0x10, 0x8B, 0x45, 0xEC, 0xC9, 0xC2,
		0x14
	};

	BYTE *buf = peconv::alloc_aligned(dataSize, PAGE_EXECUTE_READWRITE);
	memcpy(buf, rawData, dataSize);

	int(__stdcall *_decompress)(custom_iat*, BYTE *, int, BYTE *, unsigned int)
		= (int(__stdcall *)(custom_iat*, BYTE *, int, BYTE *, unsigned int))(buf);

	int decompressed_size = _decompress(&iat, in_buf, in_size, out_buf, out_size);

	peconv::free_aligned(buf);
	return decompressed_size;
#endif
}

int util::lzma_decompress(BYTE *in_buf, int in_size, BYTE *out_buf, unsigned int out_size)
{
#ifdef _WIN64
	std::cerr << "Compile the tool as 32 bit\n";
	return 0;
#else
	custom_iat iat = { 0 };
	load_custom_iat(iat);

	BYTE *buf = peconv::alloc_aligned(shellcode2_size, PAGE_EXECUTE_READWRITE);
	memcpy(buf, shellcode2_data, shellcode2_size);

	int(__stdcall *_lzma_decompress)(custom_iat *, BYTE *, DWORD *, BYTE *, int )
		= (int(__stdcall *)(custom_iat *, BYTE *, DWORD *, BYTE *, int))(buf + 0x666);

	DWORD decompressed_size = out_size;
	_lzma_decompress(&iat, out_buf, &decompressed_size, in_buf, in_size);

	peconv::free_aligned(buf);
	return decompressed_size;
#endif
}

