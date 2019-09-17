#pragma once

#include <Windows.h>

const DWORD RDX_MAGIC = 'xdr!';

namespace rdx_fs {

	typedef struct {
		DWORD next_record;
		DWORD offset;
		DWORD size;
		char name[1];
	} t_RDX_record;

	size_t enum_modules(BYTE* buf, size_t buf_size);
	size_t dump_modules(BYTE* buf, size_t buf_size);
};
