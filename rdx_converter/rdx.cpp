#include "rdx.h"
#include <iostream>
#include <peconv.h>

#include "dir_util.h"

using namespace rdx_fs;

bool is_rdx(BYTE* buf, size_t buf_size)
{
	if (!buf || !buf_size) return false;
	const DWORD *magic = (DWORD*)buf;
	if (*magic != RDX_MAGIC) {
		std::cout << "[!] Magic number mismatch: " << std::hex << *magic << " vs: " << RDX_MAGIC << "\n";
		return false;
	}
	return true;
}

size_t rdx_fs::enum_modules(BYTE* buf, size_t buf_size)
{
	if (!is_rdx(buf, buf_size)) return 0;

	rdx_struct *rdx_buf = (rdx_struct*) buf;
	size_t count = 0;

	rdx_record *record = (rdx_record*)rdx_buf->records;
	while (true) {
		
		if (record->offset > buf_size || record->size > buf_size) {
			break;
		}
		std::cout << std::hex << "next:" << record->next_record << "\n";
		std::cout << std::hex << "start: " << record->offset << "\nsize: " << record->size << "\n";
		std::cout << record->name << "\n";
		count++;

		if (record->next_record == 0) break;
		record = (rdx_record*) buf + record->next_record;
	}
	return count;
}

char* convert_name(char* name)
{
	for (size_t i = 0; i < strlen(name); i++) {
		if (name[i] == '/' || name[i] == '\\') {
			name[i] = '_';
		}
	}
	return name;
}

size_t rdx_fs::dump_modules(BYTE* buf, size_t buf_size)
{
	if (!is_rdx(buf, buf_size)) return 0;

	BYTE *buf_ptr = buf + sizeof(DWORD);
	size_t count = 0;
	while (true) {
		rdx_record *record = (rdx_record*)buf_ptr;
		std::cout << "[*] " << record->name << "\n";

		if (record->offset > buf_size || record->size > buf_size) {
			break;
		}
		BYTE *content_ptr = buf + record->offset;
		char *new_path = record->name;
		
		std::string dir = get_directory_name(record->name);
		if (dir.length() > 0) {
			if (!create_dir_recursively(dir)) {
				std::cout << "[!] Failed to create directory structure\n";
				new_path = convert_name(record->name);
			}
		}
		if (peconv::dump_to_file(new_path, content_ptr, record->size)) {
			std::cout << "[*] Saved to: " << new_path << "\n";
			count++;
		}
		if (record->next_record == 0) break;
		buf_ptr = buf + record->next_record;
	}
	return count;
}
