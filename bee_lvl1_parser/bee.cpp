#include "bee.h"

#include <string>
#include <fstream>

#include <peconv.h>

std::ofstream patch_report;

bool init_tag_file(std::string reportPath)
{
	patch_report.open(reportPath);
	if (patch_report.is_open() == false) {
		return false;
	}
	return true;
}

bool append_tag(DWORD tag_addr, const std::string name)
{
	if (patch_report.is_open() == false) {
		return false;
	}
	patch_report << std::hex << tag_addr << ";" << name << std::endl;
	return true;
}

bool close_tag_file()
{
	if (patch_report.is_open()) {
		patch_report.close();
	}
	return true;
}

DWORD checksum(const char *func_name)
{
	DWORD result = 0x1505;
	while ( *func_name )
		result = *func_name++ + 33 * result;
	return result;
}

void print_iat(BYTE* mod, size_t mod_size, t_bee_hdr* hdr, size_t start, size_t count, HMODULE lib)
{
	std::vector<std::string> names_list;
	size_t names_count = peconv::get_exported_names(lib, names_list);

	DWORD* iat_ptr = (DWORD*)((ULONGLONG)mod + hdr->iat);
	for (size_t i = start; i < start + count; i++) {
		DWORD needed = iat_ptr[i];
		DWORD tag_addr =  (hdr->iat + i*sizeof(DWORD));
		std::cout << "\t" << std::hex << iat_ptr[i] << " : ";
		for (size_t i = 0; i < names_count; i++) {
			DWORD checks = checksum(names_list[i].c_str());
			if (checks == needed) {
				std::cout << names_list[i];
				append_tag(tag_addr, names_list[i]);
				break;
			}
		}
		std::cout << std::endl;
	}
}

void print_dlls(BYTE* mod, size_t mod_size, t_bee_hdr* hdr)
{
	std::cout << "--IMPORTS--" << std::endl;
	BYTE* names_ptr = (BYTE*)((ULONGLONG)mod + hdr->dll_list);
	size_t total_func = 0;

	for (size_t i = 0; i < 10; i++) {
		t_dll_name* names = (t_dll_name*) names_ptr;

		if (names == nullptr) break;
		if (names->name == 0) break;
		
		char *dll_name = &names->name;

		std::cout << std::hex << names->func_count << " : ";
		std::cout << dll_name << std::endl;

		HMODULE lib = LoadLibraryA(dll_name);
		print_iat(mod, mod_size, hdr, total_func, names->func_count, lib);

		size_t len = strlen(dll_name);
		names_ptr += len + 3;
		total_func += names->func_count;
	}
	std::cout << "Total func: " << std::hex << total_func << std::endl;
}

void print_relocs(BYTE* mod, size_t mod_size, t_bee_hdr* hdr)
{
	std::cout << "--RELOCS--" << std::endl;
	DWORD* relocs_ptr = (DWORD*)((ULONGLONG)mod + hdr->relocs);
	size_t relocs_num = hdr->relocs_size / sizeof(DWORD);

	for (size_t i = 0; i < relocs_num; i++) {
		DWORD reloc_offset = *relocs_ptr;
		DWORD* reloc_field = (DWORD*)((ULONGLONG)mod + reloc_offset);
		DWORD value = *reloc_field;
		if ( value > hdr->mod_size) {
			std::cout << "[ERROR] Invalid reloc field" << std::endl;
		}
		std::cout << *relocs_ptr << " : " << value << std::endl;
		relocs_ptr++;
	}
}

t_bee_hdr* fetch_main_header(BYTE* mod, size_t mod_size)
{
	t_bee_hdr* hdr = (t_bee_hdr*)mod;
	if (hdr->magic != 0x10000301) {
		std::cout << "[ERROR] Unrecognized magic!" << std::endl;
		return nullptr;
	}
	if (hdr->mod_size != mod_size) {
		std::cout << "[ERROR] Size mismatch! " << hdr->mod_size << " vs " << mod_size << std::endl;
		return nullptr;
	}
	return hdr;
}

bool print_main_header(t_bee_hdr* hdr)
{
	std::cout << "--HEADERS--" << std::endl;
	std::cout << "magic  : " << std::hex << hdr->magic << std::endl;
	std::cout << "DLLs: " << std::hex << hdr->dll_list << std::endl;
	std::cout << "IAT: " << std::hex << hdr->iat << std::endl;
	std::cout << "EP  : " << std::hex << hdr->ep << std::endl;
	std::cout << "size  : " << std::hex << hdr->mod_size << std::endl;
	std::cout << "relocs_size  : " << std::hex << hdr->relocs_size << std::endl;
	std::cout << "relocs  : " << std::hex << hdr->relocs << std::endl;
	return true;
}

bool parse_bee(std::string filename)
{
	size_t mod_size = 0;
	BYTE* mod = peconv::load_file(filename.c_str(), mod_size);
	if (!mod) {
		return false;
	}
	t_bee_hdr* hdr = fetch_main_header(mod, mod_size);
	if (!hdr) {
		std::cout << "[ERROR] Invalid header!" << mod_size << std::endl;
		return false;
	}
	print_main_header(hdr);

	init_tag_file(filename + ".tag");
	print_dlls(mod, mod_size, hdr);
	close_tag_file();

	print_relocs(mod, mod_size, hdr);
	peconv::free_file(mod);
	return true;
}
