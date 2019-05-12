#include "bee.h"
#include <peconv.h>

BEE_TYPE check_type(BYTE *buf, size_t buf_size)
{
	if (memcmp(buf, &MAGIC2, sizeof(MAGIC2)) == 0) {
		return BEE_SCRAMBLED2;
	}
	if (memcmp(buf, &MAGIC1, sizeof(MAGIC1)) == 0) {
		return BEE_SCRAMBLED1;
	}
	if (memcmp(buf, &NS_MAGIC, sizeof(NS_MAGIC)) == 0) {
		return BEE_NS_FORMAT;
	}
	return BEE_NONE;
}

template <typename T_BEE_SCRAMBLED>
bool unscramble_pe(BYTE *buf, size_t buf_size)
{
	T_BEE_SCRAMBLED *hdr = (T_BEE_SCRAMBLED*)buf;
	std::cout << std::hex 
		<< "Magic:     " << hdr->magic
		<< "\nMachineId: " << hdr->machine_id 
		<< "\nOffset:    " << hdr->pe_offset 
		<< std::endl;

	WORD *mz_ptr = (WORD*)buf;
	DWORD *pe_ptr = (DWORD*)(buf + hdr->pe_offset);

	*mz_ptr = IMAGE_DOS_SIGNATURE;
	*pe_ptr = IMAGE_NT_SIGNATURE;

	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)buf;
	dos_hdr->e_lfanew = hdr->pe_offset;

	IMAGE_FILE_HEADER* file_hdrs = const_cast<IMAGE_FILE_HEADER*>(peconv::get_file_hdr(buf, buf_size));
	if (!file_hdrs) return false;

	file_hdrs->Machine = hdr->machine_id;
	return true;
}

DWORD gcd(DWORD a, DWORD b)
{
	while (b != 0) {
		DWORD t = b;
		b = a % b;
		a = t;
	}
	return a;
}

DWORD calc_sec_alignment(t_NS_section *ns_section, size_t sections_count)
{
	DWORD prev = 0;
	for (size_t i = 0; i < sections_count; i++) {
		if (prev != 0) {
			prev = gcd(prev, ns_section[i].va);
		}
		else {
			prev = ns_section[i].va;
		}
	}
	std::cout << "GCD: " << std::hex << prev << "\n";
	return prev;
}

template <typename T_IMAGE_OPTIONAL_HEADER>
bool fill_nt_hdrs(t_NS_format *bee_hdr, T_IMAGE_OPTIONAL_HEADER *nt_hdr)
{
	DWORD alignment = calc_sec_alignment(&bee_hdr->sections, bee_hdr->sections_count);
	nt_hdr->SectionAlignment = alignment;
	nt_hdr->FileAlignment = alignment;

	nt_hdr->ImageBase = bee_hdr->image_base;
	nt_hdr->AddressOfEntryPoint = bee_hdr->entry_point;

	nt_hdr->SizeOfHeaders = bee_hdr->hdr_size;
	nt_hdr->SizeOfImage = bee_hdr->module_size;

	nt_hdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = bee_hdr->data_dir[1].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = bee_hdr->data_dir[1].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = bee_hdr->data_dir[3].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = bee_hdr->data_dir[3].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = bee_hdr->data_dir[4].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = bee_hdr->data_dir[4].dir_size;
	return true;
}

bool fill_sections(t_NS_section *ns_section, IMAGE_SECTION_HEADER *sec_hdr, size_t sections_count)
{
	
	for (size_t i = 0; i < sections_count; i++) {

		std::cout << "VA: " << std::hex << ns_section[i].va << "\t" <<
			"Size: " << ns_section[i].size << "\n";

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

bool ns_unscramble(BYTE *buf, size_t buf_size)
{
	t_NS_format *bee_hdr = (t_NS_format*)buf;
	
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
	file_hdrs->SizeOfOptionalHeader = opt_hdr_size;
	IMAGE_SECTION_HEADER *sec_hdr = (IMAGE_SECTION_HEADER*)((ULONG_PTR)opt_hdr + opt_hdr_size);
	
	fill_sections(&bee_hdr->sections, sec_hdr, bee_hdr->sections_count);
	std::cout << std::hex
		<< "Magic:     " << bee_hdr->magic
		<< "\nMachineId: " << bee_hdr->machine_id
		<< "\nEP:    " << bee_hdr->entry_point
		<< std::endl;

	//WARNING: if file alignment differs from virtual alignmnent it needs to be converted!
	DWORD imports_raw = bee_hdr->data_dir[1].dir_va;

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

bool unscramble_bee_to_pe(BYTE *buf, size_t buf_size)
{
	BEE_TYPE type = check_type(buf, buf_size);
	if (type == BEE_NONE) {
		std::cout << "Not a Hidden Bee module!\n";
		return false;
	}
	std::cout << "Type: " << type << std::endl;
	if (type == BEE_SCRAMBLED2) {
		unscramble_pe<t_scrambled2>(buf, buf_size);
	}
	if (type == BEE_SCRAMBLED1) {
		unscramble_pe<t_scrambled1>(buf, buf_size);
	}
	if (type == BEE_NS_FORMAT) {
		ns_unscramble(buf, buf_size);
	}
	return true;
}
