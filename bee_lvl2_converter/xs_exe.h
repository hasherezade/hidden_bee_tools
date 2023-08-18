#pragma once

#include <Windows.h>

const WORD XS_MAGIC = 0x5358;

namespace xs_exe {

	const size_t XS_DATA_DIR_COUNT = 3;

	enum data_dir_id {
		XS_IMPORTS = 0,
		XS_EXCEPTIONS = 1,
		XS_RELOCATIONS = 2
	};

	typedef struct {
		DWORD va;
		DWORD raw_addr;
		DWORD size;
		DWORD flags;
	} t_XS_section;

	struct xs_relocs_block
	{
		DWORD page_rva;
		DWORD entries_count;
	};

	struct xs_relocs
	{
		DWORD count;
		xs_relocs_block blocks[1];
	};

	struct xs_reloc_entry {
		BYTE field1_hi;
		BYTE mid;
		BYTE field2_low;
	};

	namespace xs1 {

		typedef struct {
			DWORD dir_size;
			DWORD dir_va;
		} t_XS_data_dir;

		typedef struct {
			DWORD dll_name_rva;
			DWORD first_thunk;
			DWORD original_first_thunk;
			DWORD obf_dll_len;
		} t_XS_import;

		typedef struct {
			WORD magic;
			WORD nt_magic;
			WORD sections_count;
			WORD imp_key;
			WORD hdr_size;
			WORD unk_2;
			DWORD module_size;
			DWORD entry_point;
			t_XS_data_dir data_dir[XS_DATA_DIR_COUNT];
			t_XS_section sections;
		} t_XS_format;

		BLOB unscramble_pe(BYTE* buf, size_t buf_size, bool isMapped);
	}; // xs1

	namespace xs2
	{
		typedef struct {
			DWORD dir_va;
			DWORD dir_size;
		} t_XS_data_dir;

		typedef struct {
			WORD magic;
			WORD sections_count;
			WORD hdr_size;
			WORD imp_key;
			DWORD module_size;
			DWORD entry_point;
			DWORD entry_point_alt;
			t_XS_data_dir data_dir[XS_DATA_DIR_COUNT];
			t_XS_section sections;
		} t_XS_format;

		#pragma pack(1) 
		typedef struct {
			DWORD dll_name_rva;
			DWORD first_thunk;
			DWORD original_first_thunk;
			WORD obf_dll_len;
		} t_XS_import;

		BLOB unscramble_pe(BYTE* buf, size_t buf_size, bool isMapped, bool is32bit);
	}; // xs2

	enum xs_variants {
		XS_NONE = 0,
		XS_VARIANT1 = 1,
		XS_VARIANT2 = 2
	};

	xs_variants check_xs_variant(BYTE* buf);
};
