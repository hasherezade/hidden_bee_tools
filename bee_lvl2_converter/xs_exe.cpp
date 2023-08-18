#include "xs_exe.h"
#include <peconv.h>
#include <iostream>

#include <string>
#include <map>
#include <vector>

#include "util.h"
using namespace xs_exe;

template <typename XS_FORMAT, typename T_IMAGE_OPTIONAL_HEADER>
bool fill_nt_hdrs(XS_FORMAT* bee_hdr, T_IMAGE_OPTIONAL_HEADER *nt_hdr)
{
	const int kMinAlign = util::get_first_section(&bee_hdr->sections, bee_hdr->sections_count, true);
	nt_hdr->SectionAlignment = util::calc_sec_alignment(&bee_hdr->sections, bee_hdr->sections_count, true);
	nt_hdr->FileAlignment = nt_hdr->SectionAlignment;

	nt_hdr->AddressOfEntryPoint = bee_hdr->entry_point;

	nt_hdr->SizeOfHeaders = kMinAlign;
	nt_hdr->SizeOfImage = bee_hdr->module_size;

	nt_hdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	nt_hdr->NumberOfRvaAndSizes = 16;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = bee_hdr->data_dir[XS_IMPORTS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = bee_hdr->data_dir[XS_IMPORTS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = bee_hdr->data_dir[XS_EXCEPTIONS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = bee_hdr->data_dir[XS_EXCEPTIONS].dir_size;

	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = bee_hdr->data_dir[XS_RELOCATIONS].dir_va;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = bee_hdr->data_dir[XS_RELOCATIONS].dir_size;
	return true;
}

bool fill_sections(t_XS_section *rs_section, IMAGE_SECTION_HEADER *sec_hdr, size_t sections_count)
{
	for (size_t i = 0; i < sections_count; i++) {
		size_t v_size = rs_section[i].size;
		if ((sections_count > 1) && i < (sections_count - 1)) {
			const size_t diff = rs_section[i + 1].va - rs_section[i].va;
			v_size = (diff > v_size) ? diff : v_size;
		}
		sec_hdr[i].VirtualAddress = rs_section[i].va;
		sec_hdr[i].PointerToRawData = rs_section[i].va;
		sec_hdr[i].SizeOfRawData = rs_section[i].size;
		sec_hdr[i].Misc.VirtualSize = v_size;
		sec_hdr[i].Characteristics = 0xE0000000;
	}
	return true;
}


template <typename T_IMAGE_OPTIONAL_HEADER>
bool build_relocs_table(BYTE* mapped_xs, std::map<DWORD, std::vector<DWORD>> &relocs_list, T_IMAGE_OPTIONAL_HEADER* nt_hdr)
{
	typedef struct _BASE_RELOCATION_ENTRY {
		WORD Offset : 12;
		WORD Type : 4;
	} BASE_RELOCATION_ENTRY;

	WORD RELOC_32BIT_FIELD = 3;
	WORD RELOC_64BIT_FIELD = 0xA;
	WORD RELOC_FIELD = (nt_hdr->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? RELOC_64BIT_FIELD : RELOC_32BIT_FIELD;

	size_t table_size = sizeof(IMAGE_BASE_RELOCATION) * relocs_list.size();

	for (auto itr = relocs_list.begin(); itr != relocs_list.end(); ++itr) {
		table_size += sizeof(BASE_RELOCATION_ENTRY) * itr->second.size();
	}

	BYTE* table = new BYTE[table_size];
	::memset(table, 0, table_size);

	BYTE* table_ptr = table;

	for (auto itr = relocs_list.begin(); itr != relocs_list.end(); ++itr) {

		IMAGE_BASE_RELOCATION* record = (IMAGE_BASE_RELOCATION*)table_ptr;
		record->VirtualAddress = itr->first;
		record->SizeOfBlock = sizeof(BASE_RELOCATION_ENTRY) * itr->second.size() + sizeof(IMAGE_BASE_RELOCATION);
		table_ptr += sizeof(IMAGE_BASE_RELOCATION);

		for (auto itr2 = itr->second.begin(); itr2 != itr->second.end(); ++itr2) {
			BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)table_ptr;
			entry->Offset = *itr2;
			entry->Type = RELOC_FIELD;
			table_ptr += sizeof(BASE_RELOCATION_ENTRY);
		}
	}
	DWORD rva = nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	nt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = table_size;

	::memcpy(mapped_xs + rva, table, table_size);
	return true;
}

bool build_relocs_table(BYTE* mapped_xs, std::map<DWORD, std::vector<DWORD>>& relocs_list)
{
	bool is_ok = false;
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)mapped_xs;
	IMAGE_FILE_HEADER* file_hdrs = (IMAGE_FILE_HEADER*)((ULONG_PTR)mapped_xs + dos_hdr->e_lfanew + sizeof(IMAGE_NT_SIGNATURE));
	BYTE* opt_hdr = (BYTE*)((ULONG_PTR)file_hdrs + sizeof(IMAGE_FILE_HEADER));
	if (file_hdrs->Machine == IMAGE_FILE_MACHINE_AMD64) {
		IMAGE_OPTIONAL_HEADER64* opt_hdr64 = (IMAGE_OPTIONAL_HEADER64*)opt_hdr;
		is_ok = build_relocs_table(mapped_xs, relocs_list, opt_hdr64);
	}
	else {
		IMAGE_OPTIONAL_HEADER32* opt_hdr32 = (IMAGE_OPTIONAL_HEADER32*)opt_hdr;
		is_ok = build_relocs_table(mapped_xs, relocs_list, opt_hdr32);
	}
	return is_ok;
}

template <typename XS_FORMAT>
bool fill_relocations_table(XS_FORMAT& bee_hdr, BYTE* mapped_xs, DWORD img_base)
{
	if (!mapped_xs) return false;

	std::map<DWORD, std::vector<DWORD>> relocs_list;

	DWORD dir_rva = bee_hdr.data_dir[XS_RELOCATIONS].dir_va;
	DWORD dir_size = bee_hdr.data_dir[XS_RELOCATIONS].dir_size;
	if (dir_rva == 0 || dir_size == 0) {
		return true; // nothing to apply
	}
	xs_relocs* reloc_ptr = (xs_relocs*)((ULONG_PTR)mapped_xs + dir_rva);
	std::cout << "relocs: rva: " << std::hex << dir_rva << " size: " << dir_size << "\n";

	DWORD parsed_entries = 0;
	xs_reloc_entry* element = (xs_reloc_entry*)((ULONG_PTR)&reloc_ptr->blocks[reloc_ptr->count]);

	WORD saved_field = 0;
	WORD field_rva = 0;
	for (DWORD i = 0; i < reloc_ptr->count; i++) {
		
		xs_relocs_block* block = &reloc_ptr->blocks[i];
		std::cout << "#"<< i << std::hex << " : page_rva: " << block->page_rva << " count: " << block->entries_count << "\n";

		for (DWORD k = 0; k < block->entries_count; ) {
			
			if (saved_field) {
				field_rva = saved_field;
				saved_field = 0;

				relocs_list[block->page_rva].push_back(field_rva);
				DWORD* field = (DWORD*)((ULONG_PTR)mapped_xs + block->page_rva + field_rva);
				(*field) += img_base;
#ifdef _DEBUG
				std::cout << k << " : saved:" << " Field to reloc: " << field_rva << " Relocated: " << (*field) << " \n";
#endif
				k++;
				continue;
			}

			for (size_t indx = 0; indx < 2; indx++, k++) {
				if (indx == 0) {
					field_rva = (16 * element->field1_hi | (element->mid >> 4));
				}
				else {
					BYTE* _field_rva = (BYTE*)((ULONG_PTR)&field_rva);
					_field_rva[1] = element->mid & 0x0F;
					_field_rva[0] = element->field2_low;
				}
				if (k >= block->entries_count) {
					saved_field = field_rva;
					break;
				}
				relocs_list[block->page_rva].push_back(field_rva);
				DWORD* field = (DWORD*)((ULONG_PTR)mapped_xs + block->page_rva + field_rva);
				(*field) += img_base;
#ifdef _DEBUG
				std::cout << k << " : " << indx << " Field to reloc: " << field_rva <<  " Relocated: " << (*field) << " \n";
#endif
			}

			element++;
		}
	}
	return build_relocs_table(mapped_xs, relocs_list);
}


template <typename XS_IMPORT>
size_t count_imports(XS_IMPORT *xs_import)
{
	for (size_t i = 0; true; i++) {
		if (xs_import[i].first_thunk == 0) {
			return i;
		}
	}
	return 0;
}

void __cdecl decode_name(BYTE* library_name, WORD lib_decode_key)
{
	BYTE* _val_ptr = 0; // eax
	char flag; // dl

	_val_ptr = library_name;
	if (_val_ptr)
	{
		do
		{
			*_val_ptr = lib_decode_key ^ (*_val_ptr);
			if ((*_val_ptr) == 0) break;

			flag = (char)lib_decode_key;
			lib_decode_key >>= 1;
			if ((flag & 1) != 0)
				lib_decode_key ^= 0xB400u;
			++_val_ptr;
		} while ( true );
	}
	std::cout << "Name: " << library_name << "\n";
}

template <typename XS_IMPORT>
bool fill_imports(BYTE* mapped_xs, XS_IMPORT*rs_import, IMAGE_IMPORT_DESCRIPTOR *imp_desc, size_t dlls_count, WORD imp_key)
{
	for (size_t i = 0; i < dlls_count; i++) {
		if (rs_import[i].first_thunk == 0) break;
		imp_desc[i].FirstThunk = rs_import[i].first_thunk;
		imp_desc[i].OriginalFirstThunk = rs_import[i].original_first_thunk;
		imp_desc[i].Name = rs_import[i].dll_name_rva;

		std::cout << "#" << i << ": "
			<< "first_thunk: " << std::hex << rs_import[i].first_thunk << "\t"
			<< "original_first_thunk: " << std::hex << rs_import[i].original_first_thunk << "\t"
			<< "dll_name_rva: " << rs_import[i].dll_name_rva << "\t"
			//<< "Unk: " << rs_import[i].obf_dll_len 
			<< "\n";
#ifdef _DEBUG
		std::cout << "Decoding name at: " << std::hex << rs_import[i].dll_name_rva << "\n";
#endif
		BYTE* lib_name = (BYTE*)((ULONG_PTR)mapped_xs + rs_import[i].dll_name_rva);
		decode_name(lib_name, imp_key);
	}
	return true;
}

template <typename XS_FORMAT>
void print_data_dirs(XS_FORMAT* ddir, size_t sections_count)
{
	std::cout << "---DATA DIRS---\n";
	for (size_t i = 0; i < sections_count; i++) {
		std::cout << "#" << i << ": VA: " << std::hex << ddir[i].dir_va << "\t"
			<< "Size: " << ddir[i].dir_size << "\n";
	}
}

template <typename XS_FORMAT>
void copy_sections(XS_FORMAT* bee_hdr, BYTE* in_buf, BYTE* out_buf, size_t out_size, bool isMapped)
{
	t_XS_section* rs_section = &bee_hdr->sections;
	for (size_t i = 0; i < bee_hdr->sections_count; i++) {
		const DWORD raw = isMapped ? rs_section[i].va : rs_section[i].raw_addr;
		::memcpy((BYTE*)((ULONG_PTR)out_buf + rs_section[i].va), (BYTE*)((ULONG_PTR)in_buf + raw), rs_section[i].size);
	}
}

void print_sections(t_XS_section *rs_section, size_t sections_count)
{
	std::cout << "---SECTIONS---\n";
	for (size_t i = 0; i < sections_count; i++) {
		std::cout << "#" << i << ": VA: " << std::hex << rs_section[i].va << "\t"
			<< "raw: " << std::hex << rs_section[i].raw_addr << "\t"
			<< "Size: " << rs_section[i].size << "\t"
			<< "Flags: " << rs_section[i].flags << "\n";
	}
}

namespace xs_exe {

	namespace xs1 {
		void print_format(xs_exe::xs1::t_XS_format* xs_hdr)
		{
			std::cout << std::hex
				<< "Magic:         " << xs_hdr->magic
				<< "\nEP:            " << xs_hdr->entry_point
				<< "\nModuleSize:    " << xs_hdr->module_size
				<< "\nSec count:     " << xs_hdr->sections_count
				<< "\nHdr Size:      " << xs_hdr->hdr_size
				<< "\nNT magic:      " << xs_hdr->nt_magic
				<< "\nImp Key:       " << xs_hdr->imp_key
				<< "\nUnk2           " << xs_hdr->unk_2
				<< "\n" << std::endl;
		}
	};

	namespace xs2 {
		void print_format(xs_exe::xs2::t_XS_format* xs_hdr)
		{
			std::cout << std::hex
				<< "Magic:         " << xs_hdr->magic
				<< "\nEP:            " << xs_hdr->entry_point
				<< "\nModuleSize:    " << xs_hdr->module_size
				<< "\nSec count:     " << xs_hdr->sections_count
				<< "\nHdr Size:      " << xs_hdr->hdr_size
				<< "\nImp Key:       " << xs_hdr->imp_key
				<< "\nEP Alt         " << xs_hdr->entry_point_alt
				<< "\n" << std::endl;
		}
	};

	int calc_checksum(BYTE* name_ptr, int imp_key)
	{
		while (*name_ptr)
		{
			int val = (unsigned __int8)*name_ptr++ ^ (16777619 * imp_key);
			imp_key = val;
		}
		return imp_key;
	}

	class ChecksumFiller : public peconv::ImportThunksCallback
	{
	public:
		ChecksumFiller(BYTE* _modulePtr, size_t _moduleSize, DWORD _imp_key, bool _is32b)
			: ImportThunksCallback(_modulePtr, _moduleSize),
			imp_key(_imp_key), is32b(_is32b)
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
				std::cout << "Call via is empty!\n";
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

			std::vector<std::string> names;
			HMODULE lib = LoadLibraryA(lib_name);
			if (!lib) return false;


			DWORD* checks_ptr = (DWORD*)(by_name->Name);
			DWORD curr_checks = (*checks_ptr);
			peconv::get_exported_names(lib, names);
			bool is_found = false;
			for (auto itr = names.begin(); itr != names.end(); itr++) {
				DWORD checks1 = xs_exe::calc_checksum((BYTE*)itr->c_str(), imp_key);
				if (checks1 == curr_checks) {
					::memset(by_name->Name, 0, itr->length() + 1);
					::memcpy(by_name->Name, itr->c_str(), itr->length());
					is_found = true;
					break;
				}
			}
			FreeLibrary(lib);
			if (!is_found) {
				std::cerr << "Not found: " << lib_name << " Checksum: " << std::hex << curr_checks << "\n";
			}
			return true;
		}

		DWORD imp_key;
		bool is32b;
	};
};


template <typename XS_FORMAT>
bool fill_headers(BYTE* rec_hdr, bool is32bit, DWORD img_base, XS_FORMAT bee_hdr)
{
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)rec_hdr;
	dos_hdr->e_magic = IMAGE_DOS_SIGNATURE;
	dos_hdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	DWORD* pe_ptr = (DWORD*)(dos_hdr->e_lfanew + (ULONG_PTR)rec_hdr);
	*pe_ptr = IMAGE_NT_SIGNATURE;

	IMAGE_FILE_HEADER* file_hdrs = (IMAGE_FILE_HEADER*)((ULONG_PTR)rec_hdr + dos_hdr->e_lfanew + sizeof(IMAGE_NT_SIGNATURE));
	if (is32bit) {
		file_hdrs->Machine = IMAGE_FILE_MACHINE_I386;
	}
	else {
		file_hdrs->Machine = IMAGE_FILE_MACHINE_AMD64;
	}
	file_hdrs->NumberOfSections = bee_hdr->sections_count;

	//DWORD img_base = isMapped ? 0 : 0x100000;
	BYTE* opt_hdr = (BYTE*)((ULONG_PTR)file_hdrs + sizeof(IMAGE_FILE_HEADER));
	size_t opt_hdr_size = 0;
	if (file_hdrs->Machine == IMAGE_FILE_MACHINE_AMD64) {
		file_hdrs->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER64);
		IMAGE_OPTIONAL_HEADER64* opt_hdr64 = (IMAGE_OPTIONAL_HEADER64*)opt_hdr;
		opt_hdr64->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		opt_hdr64->ImageBase = img_base;
		fill_nt_hdrs(bee_hdr, opt_hdr64);
	}
	else {
		file_hdrs->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER32);
		IMAGE_OPTIONAL_HEADER32* opt_hdr32 = (IMAGE_OPTIONAL_HEADER32*)opt_hdr;
		opt_hdr32->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		opt_hdr32->ImageBase = img_base;
		fill_nt_hdrs(bee_hdr, opt_hdr32);
	}

	file_hdrs->SizeOfOptionalHeader = (WORD)opt_hdr_size;

	IMAGE_SECTION_HEADER* sec_hdr = (IMAGE_SECTION_HEADER*)((ULONG_PTR)opt_hdr + opt_hdr_size);
	return fill_sections(&bee_hdr->sections, sec_hdr, bee_hdr->sections_count);
}


BLOB xs_exe::xs1::unscramble_pe(BYTE *in_buf, size_t buf_size, bool isMapped)
{
	BLOB mod = { 0 };
	t_XS_format* bee_hdr = (t_XS_format*)in_buf;

	bool is32b = (bee_hdr->nt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? false : true;
	if (bee_hdr->nt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && bee_hdr->nt_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return mod; // not XS1
	}

	size_t out_size = buf_size > bee_hdr->module_size ? buf_size : bee_hdr->module_size;
	if (out_size < PAGE_SIZE) out_size = PAGE_SIZE;

	BYTE* out_buf = (BYTE*)::malloc(out_size);
	if (!out_buf) return mod;

	::memset(out_buf, 0, out_size);

	xs1::print_format(bee_hdr);
	print_sections(&bee_hdr->sections, bee_hdr->sections_count);
	print_data_dirs(bee_hdr->data_dir, 3);

	size_t rec_size = PAGE_SIZE;
	if (bee_hdr->hdr_size > rec_size) return mod;

	DWORD img_base = isMapped ? 0 : 0x100000;
	BYTE *rec_hdr = new BYTE[rec_size];
	memset(rec_hdr, 0, rec_size);

	fill_headers(rec_hdr, is32b, img_base, bee_hdr);

	copy_sections(bee_hdr, in_buf, out_buf, out_size, isMapped);

	::memcpy(out_buf, rec_hdr, rec_size);
	delete[]rec_hdr; rec_hdr = nullptr;

	//WARNING: if the file alignment differs from virtual alignmnent it needs to be converted!
	DWORD imports_raw = bee_hdr->data_dir[XS_IMPORTS].dir_va;

	t_XS_import *xs_import = (t_XS_import*)((ULONG_PTR)out_buf + imports_raw);
	size_t dlls_count = count_imports(xs_import);

	std::cout << "DLLs count: " << std::dec << dlls_count << std::endl;
	const size_t imp_area_size = dlls_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

	BYTE *rec_imports = new BYTE[imp_area_size];
	memset(rec_imports, 0, imp_area_size);
	if (!fill_imports(out_buf, xs_import, (IMAGE_IMPORT_DESCRIPTOR*)rec_imports, dlls_count, bee_hdr->imp_key)) {
		std::cerr << "Failed to fill imports\n";
	}

	memcpy(out_buf + imports_raw, rec_imports, imp_area_size);
	delete[]rec_imports; rec_imports = nullptr;

	xs_exe::ChecksumFiller collector(out_buf, out_size, bee_hdr->imp_key, is32b);
	if (!peconv::process_import_table(out_buf, out_size, &collector)) {
		std::cerr << "Failed to process the import table\n";
	}
	
	fill_relocations_table(*bee_hdr, out_buf, img_base);
	std::cout << "Finished...\n";
	mod.pBlobData = out_buf;
	mod.cbSize = out_size;
	return mod;
}

BLOB xs_exe::xs2::unscramble_pe(BYTE* in_buf, size_t buf_size, bool isMapped, bool is32bit)
{
	BLOB mod = { 0 };
	t_XS_format* bee_hdr = (t_XS_format*)in_buf;
	size_t out_size = buf_size > bee_hdr->module_size ? buf_size : bee_hdr->module_size;
	if (out_size < PAGE_SIZE) out_size = PAGE_SIZE;

	BYTE* out_buf = (BYTE*)::malloc(out_size);
	if (!out_buf) return mod;

	::memset(out_buf, 0, out_size);

	print_format(bee_hdr);
	print_sections(&bee_hdr->sections, bee_hdr->sections_count);
	print_data_dirs(bee_hdr->data_dir, 3);

	size_t rec_size = PAGE_SIZE;
	if (bee_hdr->hdr_size > rec_size) {
		std::cerr << "Invalid hdr size: " << bee_hdr->hdr_size << "\n";
		return mod;
	}
	DWORD img_base = isMapped ? 0 : 0x100000;
	BYTE* rec_hdr = new BYTE[rec_size];
	memset(rec_hdr, 0, rec_size);

	fill_headers(rec_hdr, is32bit, img_base, bee_hdr);
	copy_sections(bee_hdr, in_buf, out_buf, out_size, isMapped);

	::memcpy(out_buf, rec_hdr, rec_size);
	delete[]rec_hdr; rec_hdr = nullptr;

	//WARNING: if the file alignment differs from virtual alignmnent it needs to be converted!
	DWORD imports_raw = bee_hdr->data_dir[XS_IMPORTS].dir_va;

	t_XS_import* xs_import = (t_XS_import*)((ULONG_PTR)out_buf + imports_raw);
	size_t dlls_count = count_imports(xs_import);

	std::cout << "DLLs count: " << std::dec << dlls_count << std::endl;
	const size_t imp_area_size = dlls_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

	BYTE* rec_imports = new BYTE[imp_area_size];
	memset(rec_imports, 0, imp_area_size);
	if (!fill_imports(out_buf, xs_import, (IMAGE_IMPORT_DESCRIPTOR*)rec_imports, dlls_count, bee_hdr->imp_key)) {
		std::cerr << "Failed to fill imports\n";
	}

	memcpy(out_buf + imports_raw, rec_imports, imp_area_size);
	delete[]rec_imports; rec_imports = nullptr;

	xs_exe::ChecksumFiller collector(out_buf, out_size, bee_hdr->imp_key, is32bit);
	if (!peconv::process_import_table(out_buf, out_size, &collector)) {
		std::cerr << "Failed to process the import table\n";
	}
	fill_relocations_table(*bee_hdr, out_buf, img_base);
	std::cout << "Finished...\n";

	mod.pBlobData = out_buf;
	mod.cbSize = out_size;
	return mod;
}

xs_variants xs_exe::check_xs_variant(BYTE* in_buf)
{
	if (!in_buf) return xs_variants::XS_NONE;

	xs1::t_XS_format* xs_hdr = (xs1::t_XS_format*)in_buf;
	if (xs_hdr->magic != XS_MAGIC) {
		return xs_variants::XS_NONE;
	}
	if (xs_hdr->nt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC || xs_hdr->nt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return xs_variants::XS_VARIANT1;
	}
	return xs_variants::XS_VARIANT2;
}
