#include "ns_exe.h"
#include <peconv.h>
#include <iostream>

#include "util.h"

using namespace ns_exe;

template <typename T_IMAGE_OPTIONAL_HEADER>
bool fill_nt_hdrs(t_NS_format *bee_hdr, T_IMAGE_OPTIONAL_HEADER *nt_hdr)
{
	nt_hdr->SectionAlignment = util::calc_sec_alignment(&bee_hdr->sections, bee_hdr->sections_count, true);
	nt_hdr->FileAlignment = util::calc_sec_alignment(&bee_hdr->sections, bee_hdr->sections_count, false);
	if (nt_hdr->SectionAlignment != nt_hdr->FileAlignment) {
		std::cout << "[WARNING] Raw Alignment if different than Virtual Alignment!\n";
	}

	nt_hdr->ImageBase = bee_hdr->image_base;
	nt_hdr->AddressOfEntryPoint = bee_hdr->entry_point;

	nt_hdr->SizeOfHeaders = bee_hdr->hdr_size;
	nt_hdr->SizeOfImage = bee_hdr->module_size;

	nt_hdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	nt_hdr->NumberOfRvaAndSizes = 16;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = bee_hdr->data_dir[NS_IMPORTS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = bee_hdr->data_dir[NS_IMPORTS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = bee_hdr->data_dir[NS_RELOCATIONS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = bee_hdr->data_dir[NS_RELOCATIONS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = bee_hdr->data_dir[NS_IAT].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = bee_hdr->data_dir[NS_IAT].dir_size;
	return true;
}

bool fill_sections(t_NS_section *ns_section, IMAGE_SECTION_HEADER *sec_hdr, size_t sections_count)
{

	for (size_t i = 0; i < sections_count; i++) {
		sec_hdr[i].VirtualAddress = ns_section[i].va;
		sec_hdr[i].PointerToRawData = ns_section[i].raw_addr;
		sec_hdr[i].SizeOfRawData = ns_section[i].size;
		sec_hdr[i].Misc.VirtualSize = ns_section[i].size;
		sec_hdr[i].Characteristics = ns_section[i].characteristics;
	}
	return true;
}

size_t count_imports(t_NS_import *ns_import)
{
	for (size_t i = 0; true; i++) {
		if (ns_import[i].first_thunk == 0 && ns_import[i].original_first_thunk == 0) {
			return i;
		}
	}
	return 0;
}

bool fill_imports(t_NS_import *ns_import, IMAGE_IMPORT_DESCRIPTOR *imp_desc, size_t dlls_count)
{
	for (size_t i = 0; i < dlls_count; i++) {
		if (ns_import[i].first_thunk == 0 && ns_import[i].original_first_thunk == 0) break;
		imp_desc[i].FirstThunk = ns_import[i].first_thunk;
		imp_desc[i].OriginalFirstThunk = ns_import[i].original_first_thunk;
		imp_desc[i].Name = ns_import[i].dll_name_rva;
	}
	return true;
}

void print_format(t_NS_format *bee_hdr)
{
	std::cout << std::hex
		<<   "Magic:         " << bee_hdr->magic
		<< "\nMachineId:     " << bee_hdr->machine_id
		<< "\nEP:            " << bee_hdr->entry_point
		<< "\nModuleSize:    " << bee_hdr->module_size 
		<< "\n" << std::endl;
}

void print_sections(t_NS_section *ns_section, size_t sections_count)
{
	std::cout << "---SECTIONS---\n";
	for (size_t i = 0; i < sections_count; i++) {
		std::cout << "VA: " << std::hex << ns_section[i].va << "\t"
			<< "raw: " << std::hex << ns_section[i].raw_addr << "\t"
			<< "Size: " << ns_section[i].size << "\n";
	}
}

void print_saved_values(t_NS_format *bee_hdr, BYTE* bee_module, size_t bee_module_size)
{
	DWORD saved = bee_hdr->saved;
	if (saved == 0) return;
	std::cout << "Saved val :" << std::hex << saved << std::endl;
	if (saved >= bee_module_size) return;
	std::cout << (char*)(bee_module + saved) << std::endl;
}

bool ns_exe::unscramble_pe(BYTE *buf, size_t buf_size)
{
	t_NS_format *bee_hdr = (t_NS_format*)buf;

	print_format(bee_hdr);
	print_sections(&bee_hdr->sections, bee_hdr->sections_count);
	print_saved_values(bee_hdr, buf, buf_size);

	size_t rec_size = PAGE_SIZE;
	if (bee_hdr->hdr_size > rec_size) return false;

	BYTE *rec_hdr = new BYTE[rec_size];
	memset(rec_hdr, 0, rec_size);

	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)rec_hdr;
	dos_hdr->e_magic = IMAGE_DOS_SIGNATURE;
	dos_hdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	DWORD *pe_ptr = (DWORD*)(dos_hdr->e_lfanew + (ULONG_PTR)rec_hdr);
	*pe_ptr = IMAGE_NT_SIGNATURE;

	IMAGE_FILE_HEADER* file_hdrs = (IMAGE_FILE_HEADER*)((ULONG_PTR)rec_hdr + dos_hdr->e_lfanew + sizeof(IMAGE_NT_SIGNATURE));
	file_hdrs->Machine = bee_hdr->machine_id;
	file_hdrs->NumberOfSections = bee_hdr->sections_count;

	BYTE *opt_hdr = (BYTE*)((ULONG_PTR)file_hdrs + sizeof(IMAGE_FILE_HEADER));
	size_t opt_hdr_size = 0;
	if (bee_hdr->machine_id == IMAGE_FILE_MACHINE_AMD64) {
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER64);
		IMAGE_OPTIONAL_HEADER64* opt_hdr64 = (IMAGE_OPTIONAL_HEADER64*)opt_hdr;
		opt_hdr64->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		fill_nt_hdrs(bee_hdr, opt_hdr64);
	}
	else {
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER32);
		IMAGE_OPTIONAL_HEADER32* opt_hdr32 = (IMAGE_OPTIONAL_HEADER32*)opt_hdr;
		opt_hdr32->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		fill_nt_hdrs(bee_hdr, opt_hdr32);
	}

	file_hdrs->SizeOfOptionalHeader = (WORD)opt_hdr_size;
	IMAGE_SECTION_HEADER *sec_hdr = (IMAGE_SECTION_HEADER*)((ULONG_PTR)opt_hdr + opt_hdr_size);

	fill_sections(&bee_hdr->sections, sec_hdr, bee_hdr->sections_count);

	//WARNING: if the file alignment differs from virtual alignmnent it needs to be converted!
	DWORD imports_raw = bee_hdr->data_dir[NS_IMPORTS].dir_va;

	t_NS_import *ns_import = (t_NS_import*)((ULONG_PTR)buf + imports_raw);
	size_t dlls_count = count_imports(ns_import);

	std::cout << "DLLs count: " << dlls_count << std::endl;
	const size_t imp_area_size = dlls_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

	BYTE *rec_imports = new BYTE[imp_area_size];
	memset(rec_imports, 0, imp_area_size);
	fill_imports(ns_import, (IMAGE_IMPORT_DESCRIPTOR*)rec_imports, dlls_count);

	memcpy(buf, rec_hdr, bee_hdr->hdr_size);
	delete[]rec_hdr; rec_hdr = nullptr;

	memcpy(buf + imports_raw, rec_imports, imp_area_size);
	delete[]rec_imports; rec_imports = nullptr;
	return true;
}
