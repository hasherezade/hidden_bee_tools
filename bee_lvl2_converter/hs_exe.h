#pragma once

#include <Windows.h>

const WORD HS_MAGIC = 0x5348;

namespace hs_exe {

	const size_t HS_DATA_DIR_COUNT = 3;

	enum data_dir_id {
		HS_IMPORTS = 0,
		HS_EXCEPTIONS,
		HS_RELOCATIONS = 2
	};

	typedef struct {
		DWORD dir_va;
		DWORD dir_size;
	} t_HS_data_dir;

	typedef struct {
		DWORD va;
		DWORD size;
		DWORD raw_addr;
	} t_HS_section;

	typedef struct {
		DWORD dll_name_rva;
		DWORD original_first_thunk;
		DWORD first_thunk;
	} t_HS_import;

	typedef struct {
		WORD magic; // 0x5352
		WORD machine_id;
		WORD sections_count;
		WORD hdr_size;
		DWORD entry_point;
		DWORD module_size;
		DWORD unk1;
		DWORD module_base_hi;
		DWORD module_base_low;
		DWORD unk2;
		t_HS_data_dir data_dir[HS_DATA_DIR_COUNT];
		t_HS_section sections;
	} t_HS_format;

	BLOB unscramble_pe(BYTE *buf, size_t buf_size, bool isMapped);
};
