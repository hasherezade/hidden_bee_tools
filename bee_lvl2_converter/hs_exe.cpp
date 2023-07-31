#include "hs_exe.h"
#include <peconv.h>
#include <iostream>

#include <string>
#include <map>
#include <vector>

#include "util.h"
using namespace hs_exe;

namespace hs_exe {
	DWORD calc_sec_alignment(t_HS_section* section, size_t sections_count, bool is_virtual = true)
	{
		DWORD prev = 0;
		for (size_t i = 0; i < sections_count; i++) {
			DWORD section_offst = is_virtual ? section[i].va : section[i].raw_addr;
			if (prev != 0) {
				prev = gcd(prev, section_offst);
			}
			else {
				prev = section_offst;
			}
		}
		return prev;
	}

	DWORD get_first_section(t_HS_section* section, size_t sections_count, bool is_virtual = true)
	{
		DWORD min = 0;
		for (size_t i = 0; i < sections_count; i++) {
			DWORD section_offst = is_virtual ? section[i].va : section[i].raw_addr;
			if (min != 0) {
				min = min < section_offst ? min : section_offst;
			}
			else {
				min = section_offst;
			}
		}
		return min;
	}

	uint64_t make_img_base(t_HS_format* bee_hdr)
	{
		const uint64_t img_base = ((uint64_t)bee_hdr->module_base_hi) << (sizeof(DWORD) * 8) | bee_hdr->module_base_low;
		return img_base;
	}
}

template <typename T_IMAGE_OPTIONAL_HEADER>
bool fill_nt_hdrs(t_HS_format *bee_hdr, T_IMAGE_OPTIONAL_HEADER *nt_hdr)
{
	const int kMinAlign = get_first_section(&bee_hdr->sections, bee_hdr->sections_count, true);
	nt_hdr->SectionAlignment = calc_sec_alignment(&bee_hdr->sections, bee_hdr->sections_count, true);
	nt_hdr->FileAlignment = nt_hdr->SectionAlignment;

	nt_hdr->ImageBase = make_img_base(bee_hdr);
	nt_hdr->AddressOfEntryPoint = bee_hdr->entry_point;

	nt_hdr->SizeOfHeaders = kMinAlign;
	nt_hdr->SizeOfImage = bee_hdr->module_size;

	nt_hdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	nt_hdr->NumberOfRvaAndSizes = 16;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = bee_hdr->data_dir[HS_IMPORTS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = bee_hdr->data_dir[HS_IMPORTS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = bee_hdr->data_dir[HS_EXCEPTIONS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = bee_hdr->data_dir[HS_EXCEPTIONS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = bee_hdr->data_dir[HS_RELOCATIONS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = bee_hdr->data_dir[HS_RELOCATIONS].dir_size;
	return true;
}

bool fill_sections(t_HS_section* rs_section, IMAGE_SECTION_HEADER* sec_hdr, size_t sections_count)
{
	for (size_t i = 0; i < sections_count; i++) {

		sec_hdr[i].VirtualAddress = rs_section[i].va;
		sec_hdr[i].PointerToRawData = rs_section[i].va;
		sec_hdr[i].SizeOfRawData = rs_section[i].size;
		sec_hdr[i].Misc.VirtualSize = rs_section[i].size;
		sec_hdr[i].Characteristics = 0xE0000000;
	}
	return true;
}

size_t count_imports(t_HS_import *rs_import)
{
	for (size_t i = 0; true; i++) {
		if (rs_import[i].first_thunk == 0 && rs_import[i].original_first_thunk == 0) {
			return i;
		}
	}
	return 0;
}

bool fill_imports(t_HS_import *rs_import, IMAGE_IMPORT_DESCRIPTOR *imp_desc, size_t dlls_count)
{
	for (size_t i = 0; i < dlls_count; i++) {
		if (rs_import[i].first_thunk == 0 && rs_import[i].original_first_thunk == 0) break;
		imp_desc[i].FirstThunk = rs_import[i].first_thunk;
		imp_desc[i].OriginalFirstThunk = rs_import[i].original_first_thunk;
		imp_desc[i].Name = rs_import[i].dll_name_rva;
	}
	return true;
}
namespace hs_exe {
	void print_format(t_HS_format* bee_hdr)
	{
		std::cout << "Format: HS\n";
		std::cout << std::hex
			<< "Magic:         " << bee_hdr->magic
			<< "\nMachineId:     " << bee_hdr->machine_id
			<< "\nEP:            " << bee_hdr->entry_point
			<< "\nModuleSize:    " << bee_hdr->module_size
			<< "\nSectionsCount: " << bee_hdr->sections_count
			<< "\nUnk1:          " << bee_hdr->unk1
			<< "\nImgBase:       " << make_img_base(bee_hdr)
			<< "\nUnk2:          " << bee_hdr->unk2
			<< "\n" << std::endl;
	}
};


void print_sections(t_HS_section *rs_section, size_t sections_count)
{
	std::cout << "---SECTIONS---\n";
	for (size_t i = 0; i < sections_count; i++) {
		std::cout << "VA: " << std::hex << rs_section[i].va << "\t"
			<< "raw: " << std::hex << rs_section[i].raw_addr << "\t"
			<< "Size: " << rs_section[i].size << "\n";
	}
}

void copy_sections(t_HS_format* bee_hdr, BYTE* in_buf, BYTE* out_buf, size_t out_size, bool isMapped)
{
	t_HS_section* rs_section = &bee_hdr->sections;
	for (size_t i = 0; i < bee_hdr->sections_count; i++) {
		const DWORD raw = isMapped ? rs_section[i].va : rs_section[i].raw_addr;
		::memcpy((BYTE*)((ULONG_PTR)out_buf + rs_section[i].va), (BYTE*)((ULONG_PTR)in_buf + raw), rs_section[i].size);
	}
}

BLOB hs_exe::unscramble_pe(BYTE *in_buf, size_t buf_size, bool isMapped)
{
	BLOB mod = { 0 };
	t_HS_format *bee_hdr = (t_HS_format*)in_buf;
	size_t out_size = buf_size > bee_hdr->module_size ? buf_size : bee_hdr->module_size;
	if (out_size < PAGE_SIZE) out_size = PAGE_SIZE;

	BYTE* out_buf = (BYTE*)::malloc(out_size);
	if (!out_buf) return mod;

	::memset(out_buf, 0, out_size);

	hs_exe::print_format(bee_hdr);
	print_sections(&bee_hdr->sections, bee_hdr->sections_count);

	const size_t rec_size = PAGE_SIZE;
	if (bee_hdr->hdr_size > rec_size) return mod;

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
		file_hdrs->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER64);
		IMAGE_OPTIONAL_HEADER64* opt_hdr64 = (IMAGE_OPTIONAL_HEADER64*)opt_hdr;
		opt_hdr64->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		fill_nt_hdrs(bee_hdr, opt_hdr64);

	}
	else {
		file_hdrs->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER32);
		IMAGE_OPTIONAL_HEADER32* opt_hdr32 = (IMAGE_OPTIONAL_HEADER32*)opt_hdr;
		opt_hdr32->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		fill_nt_hdrs(bee_hdr, opt_hdr32);
	}

	file_hdrs->SizeOfOptionalHeader = (WORD)opt_hdr_size;
	IMAGE_SECTION_HEADER *sec_hdr = (IMAGE_SECTION_HEADER*)((ULONG_PTR)opt_hdr + opt_hdr_size);
	peconv::dump_to_file("rec_hdr1.bin", rec_hdr, rec_size);
	fill_sections(&bee_hdr->sections, sec_hdr, bee_hdr->sections_count);

	peconv::dump_to_file("rec_hdr2.bin", rec_hdr, rec_size);
	::memcpy(out_buf, rec_hdr, PAGE_SIZE);
	delete[]rec_hdr; rec_hdr = nullptr;

	copy_sections(bee_hdr, in_buf, out_buf, out_size, isMapped);
	
	//WARNING: if the file alignment differs from virtual alignmnent it needs to be converted!
	DWORD imports_raw = bee_hdr->data_dir[HS_IMPORTS].dir_va;

	t_HS_import *rs_import = (t_HS_import*)((ULONG_PTR)out_buf + imports_raw);
	size_t dlls_count = count_imports(rs_import);

	//std::cout << "DLLs count: " << dlls_count << std::endl;
	const size_t imp_area_size = dlls_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

	BYTE *rec_imports = new BYTE[imp_area_size];
	memset(rec_imports, 0, imp_area_size);
	fill_imports(rs_import, (IMAGE_IMPORT_DESCRIPTOR*)rec_imports, dlls_count);

	memcpy(out_buf + imports_raw, rec_imports, imp_area_size);
	delete[]rec_imports; rec_imports = nullptr;

	std::cout << "Finished...\n";
	mod.pBlobData = out_buf;
	mod.cbSize = out_size;
	return mod;
}
