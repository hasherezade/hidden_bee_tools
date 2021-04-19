#pragma once

#include <Windows.h>

const DWORD RCX_MAGIC = 'xcr!';

namespace rcx_fs {

	enum record_type {
		RCX_PLAIN_SHELLCODE = 0,
		RCX_XOR_COMPRESSED_SHELLCODE = 0xB,
		RCX_UNK_C = 0xC,
		RCX_AES_KEY = 0x15,
		RCX_AES_LZMA_BLOB = 0x16,
		RCX_PLAIN_URLS = 0x28
	};

	typedef struct _rcx_record
	{
		DWORD next_offset;
		DWORD type;
		DWORD data_size;
		DWORD output_size;
		BYTE data_buf[1]; //buffer of data_size
	} rcx_record;

	typedef struct _rcx_struct
	{
		DWORD rcx_magic; // '!rcx'
		DWORD rcx_size;
		BYTE sha256[32];
		rcx_record records[1]; // 0 terminated list of records
	} rcx_struct;

	size_t enum_modules(BYTE* buf, size_t buf_size);
	size_t dump_modules(BYTE* buf, size_t buf_size);
};
