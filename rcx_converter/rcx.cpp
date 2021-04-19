#include "rcx.h"
#include <iostream>
#include <peconv.h>

#include "util.h"
#include <sstream>

using namespace rcx_fs;

bool is_rcx(BYTE* buf, size_t buf_size)
{
	if (!buf || !buf_size) return false;
	const DWORD *magic = (DWORD*)buf;
	if (*magic != RCX_MAGIC) {
		std::cout << "[!] Magic number mismatch: " << std::hex << *magic << " vs: " << RCX_MAGIC << "\n";
		return false;
	}
	return true;
}

std::string translate_type(DWORD type)
{
	switch (type) {
	case RCX_PLAIN_SHELLCODE:
		return "plain: shellcode";
	case RCX_XOR_COMPRESSED_SHELLCODE:
		return "XORed and compressed shellcode";
	case RCX_UNK_C:
		return "Unknown - type C";
	case RCX_AES_KEY:
		return "AES key";
	case RCX_AES_LZMA_BLOB:
		return "AES encrypted & LZMA compressed RDX module";
	case RCX_PLAIN_URLS:
		return "plain: URLs";
	}
	return "Unknown";
}

size_t rcx_fs::enum_modules(BYTE* buf, size_t buf_size)
{
	if (!is_rcx(buf, buf_size)) return 0;

	rcx_struct *rcx_buf = (rcx_struct*) buf;
	size_t count = 0;

	std::cout << std::hex << "RCX size: " << rcx_buf->rcx_size << "\n\n";

	rcx_record *record = (rcx_record*)rcx_buf->records;
	while (record) {
		if (record->data_size == 0) {
			break;
		}
		std::cout << std::hex << "next: " << record->next_offset << "\n";
		std::cout << std::hex << "type: " << record->type  << " : " << translate_type (record->type) << "\n"
			<< "size: " << record->data_size << "\n"
			<< "out_size: " << record->output_size << "\n\n";

		count++;
		DWORD offset = record->next_offset;
		if (offset == 0 || offset > buf_size) break;
		
		record = (rcx_record*)(buf + offset);
	}
	return count;
}

std::string make_name(rcx_record *record, DWORD offset)
{
	std::stringstream ss;
	ss << std::hex << record->type << "_" << offset << ".bin";
	return ss.str();
}

size_t rcx_fs::dump_modules(BYTE* buf, size_t buf_size)
{
	if (!is_rcx(buf, buf_size)) return 0;

	rcx_struct *rcx_buf = (rcx_struct*)buf;
	size_t count = 0;

	rcx_record *record = (rcx_record*)rcx_buf->records;
	DWORD offset = FIELD_OFFSET(rcx_struct, records);
	while (record) {
		if (record->data_size == 0) {
			break;
		}
		std::string name  = make_name(record, offset);
		if (peconv::dump_to_file(name.c_str(), record->data_buf, record->data_size)) {
			std::cout << "[*] Saved to: " << name << "\n";
			count++;
		}
		offset = record->next_offset;
		if (offset == 0 || offset > buf_size) break;

		record = (rcx_record*)(buf + offset);
	}
	return count;
}
