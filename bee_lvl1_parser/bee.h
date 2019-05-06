#pragma once

#include <Windows.h>
#include <iostream>

typedef struct {
	DWORD magic;

	WORD dll_list;
	WORD iat;
	DWORD ep;
	DWORD mod_size;

	DWORD relocs_size;
	DWORD relocs;
} t_bee_hdr;

typedef struct {
	WORD func_count;
	char name;
} t_dll_name;


DWORD checksum(const char *func_name);

bool parse_bee(std::string filename);

