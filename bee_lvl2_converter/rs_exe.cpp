#include "rs_exe.h"
#include <peconv.h>
#include <iostream>

#include <string>
#include <map>
#include <vector>

#include "util.h"
using namespace rs_exe;

DWORD calc_sec_alignment(t_RS_section *rs_section, size_t sections_count, bool is_virtual=true)
{
	DWORD prev = 0;
	for (size_t i = 0; i < sections_count; i++) {
		DWORD section_offst = is_virtual ? rs_section[i].va : rs_section[i].raw_addr;
		if (prev != 0) {
			prev = gcd(prev, section_offst);
		}
		else {
			prev = section_offst;
		}
	}
	return prev;
}

template <typename T_IMAGE_OPTIONAL_HEADER>
bool fill_nt_hdrs(t_RS_format *bee_hdr, T_IMAGE_OPTIONAL_HEADER *nt_hdr)
{
	const int kMinAlign = 0x200;
	nt_hdr->SectionAlignment = calc_sec_alignment(&bee_hdr->sections, bee_hdr->sections_count, true);
	nt_hdr->FileAlignment = nt_hdr->SectionAlignment;

	nt_hdr->ImageBase = 0;
	nt_hdr->AddressOfEntryPoint = bee_hdr->entry_point;

	nt_hdr->SizeOfHeaders = kMinAlign;// bee_hdr->hdr_size;
	nt_hdr->SizeOfImage = bee_hdr->module_size;

	nt_hdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = bee_hdr->data_dir[RS_IMPORTS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = bee_hdr->data_dir[RS_IMPORTS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = bee_hdr->data_dir[RS_RELOCATIONS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = bee_hdr->data_dir[RS_RELOCATIONS].dir_size;

	return true;
}

bool fill_sections(t_RS_section *rs_section, IMAGE_SECTION_HEADER *sec_hdr, size_t sections_count)
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

size_t count_imports(t_RS_import *rs_import)
{
	for (size_t i = 0; true; i++) {
		if (rs_import[i].first_thunk == 0 && rs_import[i].original_first_thunk == 0) {
			return i;
		}
	}
	return 0;
}

bool fill_imports(t_RS_import *rs_import, IMAGE_IMPORT_DESCRIPTOR *imp_desc, size_t dlls_count)
{
	for (size_t i = 0; i < dlls_count; i++) {
		if (rs_import[i].first_thunk == 0 && rs_import[i].original_first_thunk == 0) break;
		imp_desc[i].FirstThunk = rs_import[i].first_thunk;
		imp_desc[i].OriginalFirstThunk = rs_import[i].original_first_thunk;
		imp_desc[i].Name = rs_import[i].dll_name_rva;
	}
	return true;
}

void print_format(t_RS_format *bee_hdr)
{
	std::cout << std::hex
		<<   "Magic:         " << bee_hdr->magic
		<< "\nMachineId:     " << bee_hdr->machine_id
		<< "\nEP:            " << bee_hdr->entry_point
		<< "\nModuleSize:    " << bee_hdr->module_size 
		<< "\n" << std::endl;
}

void print_sections(t_RS_section *rs_section, size_t sections_count)
{
	std::cout << "---SECTIONS---\n";
	for (size_t i = 0; i < sections_count; i++) {
		std::cout << "VA: " << std::hex << rs_section[i].va << "\t"
			<< "raw: " << std::hex << rs_section[i].raw_addr << "\t"
			<< "Size: " << rs_section[i].size << "\n";
	}
}

void copy_sections(t_RS_format* bee_hdr, BYTE* in_buf, BYTE* out_buf, size_t out_size)
{
	t_RS_section* rs_section = &bee_hdr->sections;
	for (size_t i = 0; i < bee_hdr->sections_count; i++) {
		::memcpy((BYTE*)((ULONG_PTR)out_buf + rs_section[i].va), (BYTE*)((ULONG_PTR)in_buf + rs_section[i].raw_addr), rs_section[i].size);
	}
}

DWORD calc_checksum(BYTE* a1)
{
	BYTE* ptr; // edx
	unsigned int result; // eax
	char i; // cl
	int v4; // esi
	int v5; // eax

	ptr = a1;
	result = 0;
	for (i = *a1; i; ++ptr)
	{
		v4 = (result >> 13) | (result << 19);
		v5 = i;
		i = ptr[1];
		result = v4 + v5;
	}
	return result;
}

class ChecksumFiller : public peconv::ImportThunksCallback
{
public:
	ChecksumFiller(BYTE* _modulePtr, size_t _moduleSize)
		: ImportThunksCallback(_modulePtr, _moduleSize)
	{
	}

	virtual bool processThunks(LPSTR lib_name, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr)
	{
		if (this->is64b) {
			IMAGE_THUNK_DATA64* desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);
			ULONGLONG* call_via = reinterpret_cast<ULONGLONG*>(firstThunkPtr);
			return processThunks_tpl<ULONGLONG, IMAGE_THUNK_DATA64>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG64);

		}
		else {

			IMAGE_THUNK_DATA32* desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);
			DWORD* call_via = reinterpret_cast<DWORD*>(firstThunkPtr);
			return processThunks_tpl<DWORD, IMAGE_THUNK_DATA32>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG32);
		}
	}

protected:
	template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
	bool processThunks_tpl(LPSTR lib_name, T_IMAGE_THUNK_DATA* desc, T_FIELD* call_via, T_FIELD ordinal_flag)
	{
		if (call_via == nullptr) {
			return false;
		}

		//thunkToFunc[rva] = func;
		const std::string short_name = peconv::get_dll_shortname(lib_name);
		const bool is_by_ord = (desc->u1.Ordinal & ordinal_flag) != 0;
		if (is_by_ord) {
			return true;
		}
		PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
		const DWORD rva = MASK_TO_DWORD((ULONG_PTR)by_name->Name - (ULONG_PTR)modulePtr);
		DWORD* checks = (DWORD*)(by_name);

		std::vector<std::string> names;
		HMODULE lib = LoadLibraryA(lib_name);
		if (!lib) return false;

		peconv::get_exported_names(lib, names);
		for (auto itr = names.begin(); itr != names.end(); itr++) {
			DWORD checks1 = calc_checksum((BYTE*)itr->c_str());
			if (checks1 == (*checks)) {
				::memcpy(by_name->Name, itr->c_str(), itr->length());
				break;
			}
		}
		FreeLibrary(lib);
		return true;
	}
};

BYTE* rs_exe::unscramble_pe(BYTE *in_buf, size_t buf_size)
{
	t_RS_format *bee_hdr = (t_RS_format*)in_buf;
	size_t out_size = buf_size > bee_hdr->module_size ? buf_size : bee_hdr->module_size;
	if (out_size < PAGE_SIZE) out_size = PAGE_SIZE;

	BYTE* out_buf = (BYTE*)::malloc(out_size);
	if (!out_buf) return nullptr;

	::memset(out_buf, 0, out_size);

	print_format(bee_hdr);
	print_sections(&bee_hdr->sections, bee_hdr->sections_count);

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

	::memcpy(out_buf, rec_hdr, rec_size);
	delete[]rec_hdr; rec_hdr = nullptr;

	copy_sections(bee_hdr, in_buf, out_buf, out_size);

	//WARNING: if the file alignment differs from virtual alignmnent it needs to be converted!
	DWORD imports_raw = bee_hdr->data_dir[RS_IMPORTS].dir_va;

	t_RS_import *rs_import = (t_RS_import*)((ULONG_PTR)out_buf + imports_raw);
	size_t dlls_count = count_imports(rs_import);

	std::cout << "DLLs count: " << dlls_count << std::endl;
	const size_t imp_area_size = dlls_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

	BYTE *rec_imports = new BYTE[imp_area_size];
	memset(rec_imports, 0, imp_area_size);
	fill_imports(rs_import, (IMAGE_IMPORT_DESCRIPTOR*)rec_imports, dlls_count);

	memcpy(out_buf + imports_raw, rec_imports, imp_area_size);
	delete[]rec_imports; rec_imports = nullptr;

	ChecksumFiller collector(out_buf, out_size);
	peconv::process_import_table(out_buf, out_size, &collector);
	std::cout << "Finished...\n";
	return out_buf;
}
