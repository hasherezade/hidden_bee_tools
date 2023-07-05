#pragma once

#include <Windows.h>

const WORD RS_MAGIC = 0x5352;

namespace rs_exe {

	const size_t RS_DATA_DIR_COUNT = 3;

	enum data_dir_id {
		RS_IMPORTS = 0,
		RS_EXCEPTIONS,
		RS_RELOCATIONS = 2
	};

	typedef struct {
		DWORD dir_size;
		DWORD dir_va;
	} t_RS_data_dir;

	typedef struct {
		DWORD raw_addr;
		DWORD va;
		DWORD size;
	} t_RS_section;

	typedef struct {
		DWORD dll_name_rva;
		DWORD first_thunk;
		DWORD original_first_thunk;
	} t_RS_import;

	typedef struct {
		WORD magic; // 0x5352
		WORD machine_id;
		WORD sections_count;
		WORD hdr_size;
		DWORD entry_point;
		DWORD module_size;
		t_RS_data_dir data_dir[RS_DATA_DIR_COUNT];
		t_RS_section sections;
	} t_RS_format;

	BLOB unscramble_pe(BYTE *buf, size_t buf_size, bool isMapped);
};
