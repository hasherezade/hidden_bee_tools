#pragma once

#include <Windows.h>

const WORD NS_MAGIC = 0x534e;

namespace ns_exe {

	const size_t NS_DATA_DIR_COUNT = 6;

	enum data_dir_id {
		NS_IMPORTS = 1,
		NS_RELOCATIONS = 3,
		NS_IAT = 4
	};

	typedef struct {
		DWORD dir_va;
		DWORD dir_size;
	} t_NS_data_dir;

	typedef struct {
		DWORD va;
		DWORD size;
		DWORD raw_addr;
		DWORD characteristics;
	} t_NS_section;

	typedef struct {
		DWORD dll_name_rva;
		DWORD original_first_thunk;
		DWORD first_thunk;
		DWORD unknown;
	} t_NS_import;

	typedef struct {
		WORD magic; // 0x534e
		WORD machine_id;
		WORD sections_count;
		WORD hdr_size;
		DWORD entry_point;
		DWORD module_size;
		DWORD image_base;
		DWORD unknown0;
		DWORD saved;
		DWORD unknown1;
		t_NS_data_dir data_dir[NS_DATA_DIR_COUNT];
		t_NS_section sections;
	} t_NS_format;

	bool unscramble_pe(BYTE *buf, size_t buf_size);
};
