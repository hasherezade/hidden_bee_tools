#pragma once

#include <Windows.h>

const WORD XS_MAGIC = 0x5358;

namespace xs_exe {

	const size_t XS_DATA_DIR_COUNT = 3;

	enum data_dir_id {
		XS_IMPORTS = 0,
		XS_RELOCATIONS = 2
	};

	typedef struct {
		DWORD dir_size;
		DWORD dir_va;
	} t_XS_data_dir;

	typedef struct {
		DWORD va;
		DWORD raw_addr;
		DWORD size;
		DWORD unk;
	} t_XS_section;

	typedef struct {
		DWORD dll_name_rva;
		DWORD first_thunk;
		DWORD original_first_thunk;
		DWORD obf_dll_len;
	} t_XS_import;

	typedef struct {
		WORD magic;
		WORD imp_checksums_rva;
		WORD sections_count;
		WORD imp_key;
		WORD hdr_size;
		WORD unk_3;
		DWORD module_size;
		DWORD entry_point;
		t_XS_data_dir data_dir[XS_DATA_DIR_COUNT];
		t_XS_section sections;
	} t_XS_format;

	BLOB unscramble_pe(BYTE *buf, size_t buf_size);
};
