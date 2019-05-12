#pragma once

#include <Windows.h>
#include <iostream>

const WORD MAGIC1 = 0x454e;
const DWORD MAGIC2 = 0x0EF1FAB9;
const WORD NS_MAGIC = 0x534e;

enum BEE_TYPE {
	BEE_NONE,
	BEE_SCRAMBLED1,
	BEE_NS_FORMAT,
	BEE_SCRAMBLED2
};

typedef struct {
	WORD magic; // 0x454e
	WORD machine_id;
	WORD pe_offset;
} t_scrambled1;

typedef struct {
	DWORD magic; // 0x0EF1FAB9
	WORD machine_id;
	WORD pe_offset;
} t_scrambled2;

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
	DWORD saved[3];
	t_NS_data_dir data_dir[6];
	t_NS_section sections;
} t_NS_format;

BEE_TYPE check_type(BYTE *buf, size_t buf_size);

bool unscramble_bee_to_pe(BYTE *buf, size_t buf_size);

