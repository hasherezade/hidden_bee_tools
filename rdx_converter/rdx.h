#pragma once

#include <Windows.h>

const DWORD RDX_MAGIC = 'xdr!';

namespace rdx_fs {

	typedef struct _rdx_record {
		DWORD next_record;
		DWORD offset;
		DWORD size;
		char name[1];
	} rdx_record;

	typedef struct _rdx_struct {
		DWORD rdx_magic; // '!rdx'
		rdx_record records[1]; // 0 terminated list of records
	} rdx_struct;

	size_t enum_modules(BYTE* buf, size_t buf_size);
	size_t dump_modules(BYTE* buf, size_t buf_size);
};
